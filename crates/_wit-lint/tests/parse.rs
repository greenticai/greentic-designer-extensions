use std::path::PathBuf;

use wit_parser::Resolve;

fn wit_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("wit")
}

#[test]
fn all_wit_files_parse() {
    // extension-base and extension-host have no cross-package dependencies and
    // must be loaded first. The three kind-specific packages depend on both.
    // oauth-broker has no greentic deps and must be loaded before extension-design,
    // which imports it. runtime-side.wit depends on extension-base, extension-host,
    // and extension-design.
    let ordered = [
        "extension-base.wit",
        "extension-host.wit",
        "oauth-broker.wit",
        "extension-bundle.wit",
        "extension-deploy.wit",
        "extension-design.wit",
        "runtime-side.wit",
    ];
    let dir = wit_dir();
    let mut resolve = Resolve::new();
    for name in ordered {
        let path = dir.join(name);
        resolve
            .push_file(&path)
            .unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
    }
}

#[test]
fn extension_host_exposes_the_artifact_interface() {
    let dir = wit_dir();
    let mut resolve = Resolve::new();
    for name in ["extension-base.wit", "extension-host.wit"] {
        resolve
            .push_file(dir.join(name))
            .unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
    }
    let package = resolve
        .packages
        .iter()
        .find(|(_, p)| p.name.namespace == "greentic" && p.name.name == "extension-host")
        .map(|(_, p)| p)
        .expect("greentic:extension-host package");
    assert!(
        package.interfaces.contains_key("artifact"),
        "extension-host must expose the `artifact` interface"
    );
    // The package version must NOT move: a bump renames the bindgen module.
    assert_eq!(
        package
            .name
            .version
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("0.1.0")
    );
}
