//! Kind versus capability, as tests.
//!
//! The question: may a hosting provider be a NEW `ExtensionKind`? These tests
//! are the proof that it may not, and that declaring it as an existing
//! `DeployExtension` offering `greentic:hosting/provider` is backwards
//! compatible. They run against the SDK contract crate this runtime resolves
//! (the one every reader of `describe.json` shares).

#[path = "support/mod.rs"]
mod support;

use greentic_ext_runtime::hosting::HOSTING_PROVIDER_CAPABILITY;
use greentic_extension_sdk_contract::{DescribeJson, ExtensionKind};
use serde_json::{Value, json};

fn describe_value() -> Value {
    let wasm = wat::parse_str("(component)").unwrap();
    let fx = support::hosting::pack(ExtensionKind::Deploy, "greentic.hosting-compat", wasm, true);
    serde_json::from_str(&std::fs::read_to_string(fx.root().join("describe.json")).unwrap())
        .unwrap()
}

fn parses(v: &Value) -> Result<DescribeJson, serde_json::Error> {
    serde_json::from_value(v.clone())
}

#[test]
fn a_hosting_provider_describe_is_an_ordinary_deploy_describe() {
    let v = describe_value();
    assert_eq!(v["kind"], "DeployExtension");
    let d = parses(&v).expect("the current contract reads it");
    assert_eq!(d.kind, ExtensionKind::Deploy);
    assert!(
        d.capabilities
            .offered
            .iter()
            .any(|c| c.id.as_str() == HOSTING_PROVIDER_CAPABILITY)
    );
    // Round-trips, so re-signing a describe never drops the capability.
    let again = parses(&serde_json::to_value(&d).unwrap()).unwrap();
    assert_eq!(
        again.capabilities.offered.len(),
        d.capabilities.offered.len()
    );
}

#[test]
fn the_capability_id_must_fit_the_describe_schema() {
    // `cap://...` is the spelling used for dwProviders capabilities; the v2
    // describe schema for `capabilities.offered[].id` does not admit it, so
    // an extension offering it would not even register.
    let mut v = describe_value();
    v["capabilities"]["offered"][0]["id"] = json!("cap://hosting/provider");
    let wasm = wat::parse_str("(component)").unwrap();
    let fx = support::hosting::pack(
        ExtensionKind::Deploy,
        "greentic.hosting-compat2",
        wasm,
        true,
    );
    let path = fx.root().join("describe.json");
    std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let mut rt = greentic_ext_runtime::ExtensionRuntime::new(
        greentic_ext_runtime::RuntimeConfig::from_paths(greentic_ext_runtime::DiscoveryPaths::new(
            "/dev/null".into(),
        ))
        .with_trust_root(tempfile::TempDir::new().unwrap().keep()),
    )
    .unwrap();
    let err = rt
        .register_loaded_from_dir(fx.root())
        .expect_err("schema must refuse it");
    assert!(err.to_string().contains("does not match"), "{err}");
}

#[test]
fn a_new_extension_kind_is_not_additive() {
    // PROOF that a `HostingExtension` kind would unload on every reader built
    // before it: `ExtensionKind` has no catch-all variant.
    let mut v = describe_value();
    v["kind"] = json!("HostingExtension");
    let err = parses(&v).expect_err("an unknown kind fails the whole describe");
    assert!(err.to_string().contains("unknown variant"), "{err}");
}

#[test]
fn a_new_top_level_hosting_block_is_not_additive_either() {
    // And so would a `hosting` key in describe.json: `DescribeJson` is
    // `deny_unknown_fields`. This is why the endpoint declaration travels in
    // the guest's pure `describe-provider` export instead.
    let mut v = describe_value();
    v["hosting"] = json!({"endpoints": []});
    let err = parses(&v).expect_err("an unknown top-level key fails the whole describe");
    assert!(err.to_string().contains("unknown field"), "{err}");

    // The same for the places one might hide it in.
    for (path, key) in [("runtime", "hosting"), ("contributions", "hosting")] {
        let mut v = describe_value();
        v[path][key] = json!({});
        assert!(parses(&v).is_err(), "{path}.{key}");
    }
    let mut v = describe_value();
    v["runtime"]["permissions"]["hosting"] = json!({});
    assert!(parses(&v).is_err(), "runtime.permissions.hosting");
}

#[test]
fn an_older_shaped_describe_without_the_capability_still_parses() {
    let mut v = describe_value();
    v["capabilities"]["offered"] = json!([{"id": "greentic:test/ping", "version": "1.0.0"}]);
    let d = parses(&v).expect("older shape");
    assert!(
        !d.capabilities
            .offered
            .iter()
            .any(|c| c.id.as_str() == HOSTING_PROVIDER_CAPABILITY)
    );
}
