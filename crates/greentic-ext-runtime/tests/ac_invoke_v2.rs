//! End-to-end test that loads a *v2-built* `.gtxpack` and exercises the
//! runtime's WASM dispatch on both the success and error paths.
//!
//! Mirrors `ac_invoke.rs`, but reads the `GTDX_TEST_GTXPACK_V2` env var
//! so it can be pointed at the adaptive-cards extension built against the
//! v2 contract (extension-base@0.2.0, extension-design@0.3.0, 6-variant
//! extension-error). Self-skips when the env var is unset or points to a
//! missing artifact — keeps the test optional locally without coupling
//! this repo to `greentic-biz/greentic-adaptive-card-mcp`.
//!
//! Fixture provenance: AC-MCP PR #74, version `2.0.4-research`
//! (`greentic.adaptive-cards`, world
//! `greentic:adaptive-cards-extension/design-extension@1.0.0`).
//!
//! NOTE: the v2 fixture is built locally and ships *unsigned* (no
//! `signature` field / `manifest.json`), unlike the published, signed v1
//! pack that `ac_invoke.rs` consumes. Signature verification now fails
//! closed, so this test must run with the dev escape hatch:
//!
//! ```bash
//! GREENTIC_EXT_ALLOW_UNSIGNED=1 \
//!   GTDX_TEST_GTXPACK_V2=/path/to/ac-v2.gtxpack \
//!   cargo test -p greentic-ext-runtime --features dev-allow-unsigned \
//!     --test ac_invoke_v2 -- --nocapture
//! ```

use std::path::PathBuf;

use greentic_ext_runtime::{
    DiscoveryPaths, ExtensionRuntime, HostExtensionError, RuntimeConfig, RuntimeError,
};

/// Real extension id as published in the v2 fixture's `describe.json`
/// (`metadata.id`).
const AC_EXT_ID: &str = "greentic.adaptive-cards";

fn load_v2_runtime() -> Option<(ExtensionRuntime, tempfile::TempDir)> {
    let Ok(raw) = std::env::var("GTDX_TEST_GTXPACK_V2") else {
        eprintln!("skipping: GTDX_TEST_GTXPACK_V2 not set. To run this test:");
        eprintln!("  1. Build/obtain the v2 AC ext from greentic-adaptive-card-mcp");
        eprintln!("     (PR #74, version 2.0.4-research).");
        eprintln!("  2. Set the env var to its absolute path and run with the");
        eprintln!("     unsigned-dev escape (the v2 fixture ships unsigned):");
        eprintln!("     GREENTIC_EXT_ALLOW_UNSIGNED=1 \\");
        eprintln!("       GTDX_TEST_GTXPACK_V2=/path/to/ac-v2.gtxpack \\");
        eprintln!("       cargo test -p greentic-ext-runtime --features dev-allow-unsigned \\");
        eprintln!("         --test ac_invoke_v2 -- --nocapture");
        return None;
    };
    let pack = PathBuf::from(raw);
    if !pack.exists() {
        eprintln!(
            "skipping: GTDX_TEST_GTXPACK_V2 points to non-existent file: {}",
            pack.display()
        );
        return None;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let ext_dir = tmp.path().join("ext");
    greentic_extension_sdk_testing::unpack_to_dir(&pack, &ext_dir).unwrap();

    // Trust root inside the existing tempdir: the default root is the
    // developer's real ~/.greentic, which tests must never pin into.
    let config = RuntimeConfig::from_paths(DiscoveryPaths::new(tmp.path().to_path_buf()))
        .with_trust_root(tmp.path().join("trust-root"));
    let mut rt = ExtensionRuntime::new(config).unwrap();
    rt.register_loaded_from_dir(&ext_dir).unwrap();
    Some((rt, tmp))
}

/// SUCCESS path: invoking `validate_card` on a minimal, valid card via the
/// v2-built extension returns `valid=true`. This proves the v2 dispatch
/// ABI (extension-design@0.3.0 / 6-variant error) resolves and round-trips
/// a successful `Result::Ok`.
// `#[ignore]` rather than a bare `return`. Printing "skipping" and returning
// reports the test as **passed**, in a run indistinguishable from one that
// actually exercised a real component — so a regression here was invisible to
// CI while the suite read green. Ignored tests are counted and named instead.
// The `fixture-tests` workflow builds the pack and runs these with
// `cargo test -- --ignored`.
#[ignore = "needs GTDX_TEST_GTXPACK_V2; run via the fixture-tests workflow or `cargo test -- --ignored`"]
#[test]
fn invoke_validate_card_v2_success() {
    let Some((rt, _tmp)) = load_v2_runtime() else {
        return;
    };

    let result = rt
        .invoke_tool(
            AC_EXT_ID,
            "validate_card",
            r#"{"card":{"type":"AdaptiveCard","version":"1.6"}}"#,
        )
        .expect("invoke_tool should succeed on a valid card");

    let parsed: serde_json::Value =
        serde_json::from_str(&result).expect("result should be valid JSON");
    assert_eq!(
        parsed["valid"],
        serde_json::Value::Bool(true),
        "expected valid=true for a minimal valid AdaptiveCard, got: {parsed:#}"
    );
    eprintln!("v2 AC extension validate_card returned: {parsed:#}");
}

/// ERROR path: calling a tool name that the extension does not export must
/// surface a typed `RuntimeError::Extension(HostExtensionError)` carrying a
/// stable `.code()` — never collapse into an opaque `Wasmtime` trap. The
/// v2 6-variant error ABI is what carries this code across the boundary.
#[ignore = "needs GTDX_TEST_GTXPACK_V2; run via the fixture-tests workflow or `cargo test -- --ignored`"]
#[test]
fn invoke_unknown_tool_v2_returns_typed_error() {
    let Some((rt, _tmp)) = load_v2_runtime() else {
        return;
    };

    let err = rt
        .invoke_tool(
            AC_EXT_ID,
            "this_tool_does_not_exist",
            r#"{"card":{"type":"AdaptiveCard","version":"1.6"}}"#,
        )
        .expect_err("invoke_tool on an unknown tool name should error");

    eprintln!("v2 AC extension unknown-tool error: {err:?}");
    match err {
        RuntimeError::Extension(host_err) => {
            let code = host_err.code();
            eprintln!("typed extension error code = {code}");
            assert!(
                matches!(
                    host_err,
                    HostExtensionError::NotFound(_) | HostExtensionError::InvalidInput(_)
                ),
                "expected a typed not-found/invalid-input extension error, got: {host_err:?} (code={code})"
            );
        }
        other => {
            panic!("expected RuntimeError::Extension for an unknown tool name, got: {other:?}")
        }
    }
}
