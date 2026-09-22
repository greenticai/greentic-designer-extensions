//! End-to-end test for `ExtensionRuntime::validate_content` against the
//! real adaptive-cards extension.
//!
//! Mirrors the gating of `ac_invoke.rs`: skips when `GTDX_TEST_GTXPACK` is
//! unset or points to a missing artifact, so the test stays optional
//! locally while CI can opt-in by building the extension first.

use std::path::PathBuf;

use greentic_ext_runtime::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig, Severity};

// `#[ignore]` rather than a bare `return`. Printing "skipping" and returning
// reports the test as **passed**, in a run indistinguishable from one that
// actually exercised a real component — so a regression here was invisible to
// CI while the suite read green. Ignored tests are counted and named instead.
// The `fixture-tests` workflow builds the pack and runs these with
// `cargo test -- --ignored`.
#[ignore = "needs GTDX_TEST_GTXPACK; run via the fixture-tests workflow or `cargo test -- --ignored`"]
#[test]
fn validate_content_on_ac_extension_accepts_minimal_card() {
    let Ok(raw) = std::env::var("GTDX_TEST_GTXPACK") else {
        panic!("GTDX_TEST_GTXPACK is not set (see ac_invoke.rs for setup)");
    };
    let pack = PathBuf::from(raw);
    assert!(
        pack.exists(),
        "GTDX_TEST_GTXPACK points to a non-existent file: {}",
        pack.display()
    );

    let tmp = tempfile::TempDir::new().unwrap();
    let ext_dir = tmp.path().join("ext");
    greentic_extension_sdk_testing::unpack_to_dir(&pack, &ext_dir).unwrap();

    // Trust root inside the existing tempdir: the default root is the
    // developer's real ~/.greentic, which tests must never pin into.
    let config = RuntimeConfig::from_paths(DiscoveryPaths::new(tmp.path().to_path_buf()))
        .with_trust_root(tmp.path().join("trust-root"));
    let mut rt = ExtensionRuntime::new(config).unwrap();
    rt.register_loaded_from_dir(&ext_dir).unwrap();

    let result = rt
        .validate_content(
            "greentic.adaptive-cards",
            "AdaptiveCard",
            r#"{"type":"AdaptiveCard","version":"1.6"}"#,
        )
        .expect("validate_content should succeed on a valid card");

    assert!(result.valid, "expected valid=true, got: {result:#?}");
    let errors = result
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    assert_eq!(
        errors, 0,
        "expected zero error diagnostics, got: {result:#?}"
    );
}
