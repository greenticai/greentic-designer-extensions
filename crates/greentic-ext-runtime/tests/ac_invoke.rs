//! End-to-end test that loads a real `.gtxpack` and invokes the runtime's
//! WASM dispatch.
//!
//! Looks for the artifact at the path given by the `GTDX_TEST_GTXPACK`
//! env var (e.g. set in CI by a step that builds the AC extension from
//! the `greentic-biz/greentic-adaptive-card-mcp` repo). Self-skips if
//! unset or path does not exist — keeps the test optional locally
//! without coupling this repo to that one.

use std::path::PathBuf;

use greentic_ext_runtime::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig};

// `#[ignore]` rather than a bare `return`. Printing "skipping" and returning
// reports the test as **passed**, in a run indistinguishable from one that
// actually exercised a real component — so a regression in `invoke_tool`
// against real WASM was invisible to CI while the suite read green. Ignored
// tests are counted and named in the summary. Run them with
// `cargo test -- --ignored` once the fixture is built.
#[ignore = "needs GTDX_TEST_GTXPACK; see the module docs to build the fixture"]
#[test]
fn invoke_validate_card_on_ac_extension() {
    let Ok(raw) = std::env::var("GTDX_TEST_GTXPACK") else {
        eprintln!("skipping: GTDX_TEST_GTXPACK not set. To run this test:");
        eprintln!("  1. Build the AC ext from greentic-adaptive-card-mcp:");
        eprintln!("     git clone git@github.com:greentic-biz/greentic-adaptive-card-mcp");
        eprintln!("     cd greentic-adaptive-card-mcp");
        eprintln!("     crates/adaptive-card-extension/build.sh");
        eprintln!("  2. Set the env var to its absolute path:");
        eprintln!(
            "     export GTDX_TEST_GTXPACK=$(pwd)/crates/adaptive-card-extension/greentic.adaptive-cards-1.6.0.gtxpack"
        );
        panic!("GTDX_TEST_GTXPACK is not set");
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
        .invoke_tool(
            "greentic.adaptive-cards",
            "validate_card",
            r#"{"card":{"type":"AdaptiveCard","version":"1.6"}}"#,
        )
        .expect("invoke_tool should succeed on valid card");

    let parsed: serde_json::Value =
        serde_json::from_str(&result).expect("result should be valid JSON");
    assert_eq!(
        parsed["valid"],
        serde_json::Value::Bool(true),
        "expected valid=true for a minimal valid AdaptiveCard, got: {parsed:#}"
    );
    eprintln!("AC extension validate_card returned: {parsed:#}");
}
