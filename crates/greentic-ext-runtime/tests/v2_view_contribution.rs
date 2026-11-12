//! `view_to_definition` (via `ExtensionRuntime::list_views`) is the whole view
//! surface of an extension: declaration-only, straight from
//! `describe.contributions.views[]`, with the asset location resolved against
//! the extension's real on-disk `source_dir`. Anything this mapper drops, or
//! resolves to the wrong path, is unreachable — or worse, silently wrong —
//! for every host that ever renders the view. Mirrors
//! `tests/v2_tool_contribution.rs`, but exercises the whole
//! sign-and-register path (`register_loaded_from_dir`) rather than calling
//! the mapper directly, because unlike a tool a view's output includes a
//! resolved filesystem path that only a real `source_dir` can prove correct.

#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use greentic_ext_runtime::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig};
use greentic_extension_sdk_contract::ExtensionKind;
use greentic_extension_sdk_contract::describe::contributions::{
    Placement, Surface, Tool, View, Visibility,
};

use support::{finalize_signed_with_manifest, populate_gtpack_for_local_load};

fn full_view() -> View {
    View {
        id: "settings".into(),
        surface: Surface::Designer,
        title_key: "ext.telco.view.settings.title".into(),
        title_fallback: "Settings".into(),
        icon: Some("icons/settings.svg".into()),
        entry: "index.html".into(),
        placement: Placement {
            slot: "designer.sidebar".into(),
            path: vec!["Extensions".into()],
            order: Some(10),
        },
        min_visibility: Visibility::TenantAdmin,
        tools: vec!["run_telco_playbook".into()],
    }
}

/// The tool `full_view()`'s `tools` list names. `DescribeJson`'s deserializer
/// rejects a view that lists a tool absent from `contributions.tools`, so any
/// test that registers `full_view()` must also declare this.
fn matching_tool() -> Tool {
    Tool {
        name: "run_telco_playbook".into(),
        export: "greentic:extension-design/tools.invoke-tool".into(),
        runtime_ref: None,
        capabilities: None,
        secret_requirements: Vec::new(),
        description: None,
        input_schema: None,
        output_schema: None,
        agentic_worker_metadata: None,
    }
}

/// Build a signed extension whose describe.json carries `views` (and
/// `tools`, so a non-empty `View::tools` has something to reference), laid
/// out at `<root>/<kind_dir>/<id>/` — the shape a real install uses. Returns
/// the root `TempDir` (keep it alive for the caller's lifetime), the
/// extension's directory, and its signing key.
///
/// For each declared view this also writes the entry asset it points at, at
/// `<dir>/assets/views/<view_id>/<entry>`, so a test can assert the resolved
/// path actually resolves to real bytes on disk.
fn signed_view_fixture(
    id: &str,
    views: Vec<View>,
    tools: Vec<Tool>,
) -> (tempfile::TempDir, PathBuf, SigningKey) {
    let wasm = wat::parse_str(r"(component)").expect("wat component must compile");

    // Baseline describe.json + a coherent wasm reference, from the same
    // fixture builder every other test in this crate uses.
    let baseline = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(
        ExtensionKind::Design,
        id,
        "1.0.0",
    )
    .with_wasm(wasm.clone())
    .build()
    .expect("fixture build");
    let raw =
        std::fs::read_to_string(baseline.root().join("describe.json")).expect("read describe");
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).expect("parse describe");
    populate_gtpack_for_local_load(&mut describe);
    describe.contributions.tools = tools;
    describe.contributions.views = views;

    // Real installs lay an extension out at `<root>/<kind>/<id>/`.
    // `register_loaded_from_dir` itself doesn't require that shape, but the
    // resolved `asset_dir`/`entry_path` under test should reflect a
    // realistic `source_dir` rather than a bare temp root.
    let root = tempfile::TempDir::new().expect("temp root");
    let dir = root.path().join(ExtensionKind::Design.dir_name()).join(id);
    std::fs::create_dir_all(&dir).expect("create extension dir");
    std::fs::write(dir.join("extension.wasm"), &wasm).expect("write wasm");

    for view in &describe.contributions.views {
        let asset_dir = dir.join("assets").join("views").join(&view.id);
        std::fs::create_dir_all(&asset_dir).expect("create asset dir");
        std::fs::write(
            asset_dir.join(&view.entry),
            format!("<html><body>{}</body></html>", view.id),
        )
        .expect("write entry asset");
    }

    // Manifest is built over `dir`'s files as they stand right now, so the
    // view asset written above is covered by the ledger the signature
    // transitively protects.
    let sk = SigningKey::generate(&mut OsRng);
    finalize_signed_with_manifest(&dir, &mut describe, &sk);

    (root, dir, sk)
}

/// `RuntimeConfig::from_paths` + a fresh trust root, mirroring
/// `runtime_load.rs`'s setup: the default trust root is the developer's real
/// `~/.greentic`, and each fixture mints its own signing key, so a
/// default-rooted test would pin junk into a real trust store and fail every
/// later run. Returns the `TempDir` too — the caller must keep it alive for
/// as long as the runtime is used, since dropping it deletes the trust root
/// out from under any later registration or verification.
fn runtime_with_fresh_trust_root() -> (ExtensionRuntime, tempfile::TempDir) {
    let trust = tempfile::TempDir::new().expect("temp trust root");
    let config = RuntimeConfig::from_paths(DiscoveryPaths::new(PathBuf::from("/dev/null")))
        .with_trust_root(trust.path().to_path_buf());
    (
        ExtensionRuntime::new(config).expect("engine construction"),
        trust,
    )
}

#[tokio::test]
async fn every_declared_view_field_reaches_the_definition_with_a_resolved_asset_path() {
    let view = full_view();
    let (_root, dir, _sk) = signed_view_fixture(
        "greentic.view-full",
        vec![view.clone()],
        vec![matching_tool()],
    );

    let (mut rt, _trust) = runtime_with_fresh_trust_root();
    rt.register_loaded_from_dir(&dir).expect("register");

    let mut defs = rt.list_views("greentic.view-full").expect("list_views");
    assert_eq!(defs.len(), 1);
    let def = defs.remove(0);

    assert_eq!(def.id, view.id);
    assert_eq!(def.surface, view.surface);
    assert_eq!(def.title_key, view.title_key);
    assert_eq!(def.title_fallback, view.title_fallback);
    assert_eq!(def.icon, view.icon);
    assert_eq!(def.entry, view.entry);
    assert_eq!(def.placement, view.placement);
    assert_eq!(def.min_visibility, view.min_visibility);
    assert_eq!(def.tools, view.tools);

    let expected_asset_dir = dir.join("assets").join("views").join(&view.id);
    assert_eq!(def.asset_dir, expected_asset_dir);
    let expected_entry_path = expected_asset_dir.join(&view.entry);
    assert_eq!(def.entry_path, expected_entry_path);

    assert!(
        def.entry_path.is_file(),
        "entry_path must point at the file the fixture actually wrote: {:?}",
        def.entry_path
    );
    let content = std::fs::read_to_string(&def.entry_path).expect("read resolved entry");
    assert!(
        content.contains(&view.id),
        "resolved entry_path did not read back the fixture's own asset bytes"
    );
}

#[tokio::test]
async fn an_extension_with_no_views_returns_an_empty_vec_not_an_error() {
    let (_root, dir, _sk) = signed_view_fixture("greentic.view-none", vec![], vec![]);

    let (mut rt, _trust) = runtime_with_fresh_trust_root();
    rt.register_loaded_from_dir(&dir).expect("register");

    let defs = rt.list_views("greentic.view-none").expect("list_views");
    assert!(defs.is_empty(), "no declared views must yield Ok(vec![])");
}

#[tokio::test]
async fn list_views_reports_an_unknown_extension_as_not_found() {
    let (rt, _trust) = runtime_with_fresh_trust_root();
    assert!(matches!(
        rt.list_views("greentic.absent"),
        Err(greentic_ext_runtime::RuntimeError::NotFound(_))
    ));
}
