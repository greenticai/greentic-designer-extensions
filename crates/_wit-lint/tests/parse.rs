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
fn extension_hosting_parses_and_is_deliberately_narrow() {
    let mut resolve = Resolve::new();
    resolve
        .push_file(wit_dir().join("extension-hosting.wit"))
        .expect("extension-hosting.wit parses");
    let (_, world) = resolve
        .worlds
        .iter()
        .find(|(_, w)| w.name == "hosting-extension")
        .expect("hosting-extension world");
    let names = |imports: bool| -> Vec<String> {
        let map = if imports {
            &world.imports
        } else {
            &world.exports
        };
        map.keys()
            .map(|k| match k {
                wit_parser::WorldKey::Name(n) => n.clone(),
                wit_parser::WorldKey::Interface(id) => {
                    resolve.interfaces[*id].name.clone().unwrap_or_default()
                }
            })
            .collect()
    };
    let mut imports = names(true);
    imports.sort();
    // Exactly log, target and api: no secrets, no http, no broker, no clocks.
    assert_eq!(imports, ["api", "log", "target"]);
    assert_eq!(names(false), ["provider"]);
}
