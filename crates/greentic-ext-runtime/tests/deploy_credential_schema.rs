//! End-to-end test for deploy host bindings against a real deploy extension.
//!
//! Gated on `GTDX_TEST_DEPLOY_GTXPACK` env var pointing to a signed
//! `.gtxpack` of a deploy extension (e.g. deploy-aws). Skips locally when
//! unset; CI opts in by building and pointing at a fixture.

use std::path::PathBuf;

use greentic_ext_runtime::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig};

fn load_rt_from_pack() -> (tempfile::TempDir, ExtensionRuntime, String) {
    let raw =
        std::env::var("GTDX_TEST_DEPLOY_GTXPACK").expect("GTDX_TEST_DEPLOY_GTXPACK is not set");
    let pack = PathBuf::from(&raw);
    assert!(
        pack.exists(),
        "GTDX_TEST_DEPLOY_GTXPACK points to a non-existent file: {}",
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

    // Find the registered extension id.
    let id = rt
        .loaded()
        .keys()
        .next()
        .map(|k| k.as_str().to_string())
        .expect("at least one extension loaded");
    (tmp, rt, id)
}

// `#[ignore]` rather than a bare `return`. Printing "skipping" and returning
// reports the test as **passed**, in a run indistinguishable from one that
// actually exercised a real component — so a regression here was invisible to
// CI while the suite read green. Ignored tests are counted and named instead.
// The `fixture-tests` workflow builds the pack and runs these with
// `cargo test -- --ignored`.
#[ignore = "needs GTDX_TEST_DEPLOY_GTXPACK; run via the fixture-tests workflow or `cargo test -- --ignored`"]
#[test]
fn list_targets_returns_non_empty_for_deploy_extension() {
    let (_tmp, rt, id) = load_rt_from_pack();
    let targets = rt.list_targets(&id).expect("list_targets should succeed");
    assert!(!targets.is_empty(), "expected at least one target");
    let first = &targets[0];
    assert!(!first.id.is_empty());
    assert!(!first.display_name.is_empty());
}

#[ignore = "needs GTDX_TEST_DEPLOY_GTXPACK; run via the fixture-tests workflow or `cargo test -- --ignored`"]
#[test]
fn credential_schema_returns_valid_json_schema() {
    let (_tmp, rt, id) = load_rt_from_pack();
    let targets = rt.list_targets(&id).unwrap();
    let target_id = &targets[0].id;
    let schema = rt
        .credential_schema(&id, target_id)
        .expect("credential_schema should succeed");
    let parsed: serde_json::Value =
        serde_json::from_str(&schema).expect("schema should be valid JSON");
    assert_eq!(
        parsed.get("type").and_then(|v| v.as_str()),
        Some("object"),
        "credential schema top-level type should be 'object', got: {schema}"
    );
}

#[ignore = "needs GTDX_TEST_DEPLOY_GTXPACK; run via the fixture-tests workflow or `cargo test -- --ignored`"]
#[test]
fn validate_credentials_returns_diagnostics_slice() {
    let (_tmp, rt, id) = load_rt_from_pack();
    let targets = rt.list_targets(&id).unwrap();
    let target_id = &targets[0].id;
    // Empty JSON object is a valid shape; diagnostics may or may not be empty
    // depending on the target's schema — just assert the call returns Ok.
    let result = rt
        .validate_credentials(&id, target_id, r"{}")
        .expect("validate_credentials should succeed");
    // Sanity check: if diagnostics are present, each one has non-empty message.
    for d in &result {
        assert!(
            !d.message.is_empty(),
            "diagnostic message should be non-empty"
        );
    }
}

#[ignore = "needs GTDX_TEST_DEPLOY_GTXPACK; run via the fixture-tests workflow or `cargo test -- --ignored`"]
#[test]
fn deploy_on_mode_a_extension_surfaces_typed_internal_error() {
    let (_tmp, rt, id) = load_rt_from_pack();
    let req = greentic_ext_runtime::DeployRequest {
        target_id: "anything".into(),
        artifact_bytes: vec![],
        credentials_json: "{}".into(),
        config_json: "{}".into(),
        deployment_name: "smoke".into(),
    };
    match rt.deploy(&id, req) {
        Err(greentic_ext_runtime::RuntimeError::Deploy(
            greentic_ext_runtime::DeployExtensionError::Internal(msg),
        )) => assert!(!msg.is_empty(), "Mode A stub should carry a message"),
        other => panic!("expected Deploy(Internal), got {other:?}"),
    }
}
