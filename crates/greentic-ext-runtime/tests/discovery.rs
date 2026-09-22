use std::fs;

use greentic_ext_runtime::discovery::scan_kind_dir;
use greentic_extension_sdk_contract::describe::contributions::{
    Placement, Surface, View, Visibility,
};
use greentic_extension_sdk_contract::{DescribeJson, ExtensionKind};
use greentic_extension_sdk_testing::ExtensionFixtureBuilder;
use tempfile::TempDir;

#[test]
fn scans_kind_directory_and_returns_extension_paths() {
    let tmp = TempDir::new().unwrap();
    let design_dir = tmp.path().join("design");
    fs::create_dir_all(&design_dir).unwrap();

    let fixture = ExtensionFixtureBuilder::new(ExtensionKind::Design, "greentic.first", "0.1.0")
        .offer("greentic:first/y", "1.0.0")
        .with_wasm(wat::parse_str("(component)").unwrap())
        .build()
        .unwrap();

    let target = design_dir.join("greentic.first-0.1.0");
    fs::create_dir_all(&target).unwrap();
    for entry in fs::read_dir(fixture.root()).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
    }

    let found = scan_kind_dir(&design_dir).unwrap();
    assert_eq!(found.len(), 1);
    assert!(found[0].ends_with("greentic.first-0.1.0"));
}

/// The property the `research.3` -> `research.4` contract bump exists for:
/// `Contributions` is `#[serde(deny_unknown_fields)]`, and `research.3`
/// predates the `views` field, so a describe carrying `contributions.views`
/// failed `serde_json::from_value` outright and the extension refused to
/// load. Against `research.4` it must round-trip.
#[test]
fn describe_json_with_contributions_views_round_trips() {
    let fixture = ExtensionFixtureBuilder::new(ExtensionKind::Design, "greentic.viewer", "0.1.0")
        .offer("greentic:viewer/y", "1.0.0")
        .with_wasm(wat::parse_str("(component)").unwrap())
        .build()
        .unwrap();

    let raw = fs::read_to_string(fixture.root().join("describe.json")).unwrap();
    let mut describe: DescribeJson = serde_json::from_str(&raw).unwrap();

    describe.contributions.views.push(View {
        id: "settings".to_string(),
        surface: Surface::Designer,
        title_key: "viewer.settings.title".to_string(),
        title_fallback: "Settings".to_string(),
        icon: None,
        entry: "index.html".to_string(),
        placement: Placement {
            slot: "designer.sidebar".to_string(),
            path: Vec::new(),
            order: None,
        },
        min_visibility: Visibility::default(),
        tools: Vec::new(),
    });

    let serialized = serde_json::to_string(&describe).unwrap();
    let reparsed: DescribeJson = serde_json::from_str(&serialized)
        .expect("a describe carrying contributions.views must parse at research.4");
    assert_eq!(reparsed.contributions.views.len(), 1);
    assert_eq!(reparsed.contributions.views[0].id, "settings");
}
