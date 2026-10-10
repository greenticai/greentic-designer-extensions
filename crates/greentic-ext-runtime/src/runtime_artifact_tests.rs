//! Production-path test for `ExtensionRuntime::with_artifact_port`: load a real
//! signed extension dir into a real runtime and dispatch through
//! `dispatch_instance_ctx`, the path the runner and greentic-start use. A
//! hand-built `HostState` would still pass if that method stopped forwarding
//! the port, which is the regression this exists to catch.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use greentic_extension_sdk_contract::ExtensionKind;

use crate::host_ports::{ArtifactPort, ArtifactPortError, ArtifactPutRequest, HostCallContext};
use crate::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig};

const FIXTURE: &str = include_str!("../tests/fixtures/artifact_import.wat");

#[derive(Default)]
struct RecordingPort {
    seen: Mutex<Vec<(String, Option<String>)>>,
}

impl ArtifactPort for RecordingPort {
    fn put(
        &self,
        extension_id: &str,
        ctx: &HostCallContext,
        _request: ArtifactPutRequest,
    ) -> Result<String, ArtifactPortError> {
        self.seen
            .lock()
            .unwrap()
            .push((extension_id.to_string(), ctx.tenant.clone()));
        Ok("artifact://fixed".to_string())
    }
}

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for ent in std::fs::read_dir(dir).unwrap().flatten() {
        let path = ent.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Mirrors `tests/support`: that module uses `unsafe` for env guards, which this
/// crate's `forbid(unsafe_code)` refuses inside a unit test.
fn sign_fixture_dir(
    dir: &std::path::Path,
    describe: &mut greentic_extension_sdk_contract::DescribeJson,
    sk: &ed25519_dalek::SigningKey,
) {
    use greentic_extension_sdk_contract::describe::provider::RuntimeGtpack;

    for component in describe.runtime.components.values_mut() {
        if component.gtpack.is_none() {
            component.gtpack = Some(RuntimeGtpack {
                file: "extension.wasm".to_string(),
                sha256: "0".repeat(64),
                pack_id: describe.metadata.id.clone(),
                component_version: describe.metadata.version.clone(),
            });
        }
    }
    let mut files = Vec::new();
    walk(dir, &mut files);
    let entries: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|p| {
            (
                p.strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                std::fs::read(p).unwrap(),
            )
        })
        .filter(|(rel, _)| rel != greentic_extension_sdk_contract::MANIFEST_ENTRY_NAME)
        .collect();
    let manifest = greentic_extension_sdk_contract::build_manifest(
        entries.iter().map(|(p, b)| (p.as_str(), b.as_slice())),
    );
    let bytes = serde_jcs::to_vec(&manifest).unwrap();
    std::fs::write(
        dir.join(greentic_extension_sdk_contract::MANIFEST_ENTRY_NAME),
        &bytes,
    )
    .unwrap();
    greentic_extension_sdk_contract::bind_manifest(describe, &bytes);
    greentic_extension_sdk_contract::sign_describe(describe, sk).expect("sign");
    std::fs::write(
        dir.join("describe.json"),
        serde_json::to_string_pretty(describe).unwrap(),
    )
    .unwrap();
}

const EXT_ID: &str = "greentic.artifact-probe";

/// Runtime with the artifact-importing fixture registered. Keeps the fixture
/// and trust dirs alive for the test's duration.
fn runtime_with_probe(
    port: Option<Arc<dyn ArtifactPort>>,
) -> (
    ExtensionRuntime,
    greentic_extension_sdk_testing::ExtensionFixture,
    tempfile::TempDir,
) {
    let wasm = wat::parse_str(FIXTURE).expect("fixture parses");
    let fixture = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(
        ExtensionKind::Design,
        EXT_ID,
        "0.1.0",
    )
    .offer("greentic:test/ping", "1.0.0")
    .with_wasm(wasm)
    .build()
    .expect("fixture build");

    let describe_path = fixture.root().join("describe.json");
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&std::fs::read_to_string(&describe_path).unwrap()).unwrap();
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    sign_fixture_dir(fixture.root(), &mut describe, &sk);

    let trust = tempfile::TempDir::new().expect("temp trust root");
    let config = RuntimeConfig::from_paths(DiscoveryPaths::new(PathBuf::from("/dev/null")))
        .with_trust_root(trust.path().to_path_buf());
    let mut rt = ExtensionRuntime::new(config).expect("runtime");
    if let Some(port) = port {
        rt = rt.with_artifact_port(port);
    }
    rt.register_loaded_from_dir(fixture.root())
        .expect("register fixture");
    (rt, fixture, trust)
}

fn touch(rt: &ExtensionRuntime) -> u32 {
    let ctx = HostCallContext {
        tenant: Some("acme".into()),
        user_email: None,
    };
    let (mut store, instance) = rt
        .dispatch_instance_ctx(EXT_ID, &ctx)
        .expect("dispatch instance");
    let func = instance
        .get_typed_func::<(), (u32,)>(&mut store, "touch")
        .expect("fixture exports touch");
    func.call(&mut store, ()).expect("touch must not trap").0
}

#[test]
fn dispatch_forwards_the_installed_artifact_port_to_the_guest() {
    let port = Arc::new(RecordingPort::default());
    let (rt, _fixture, _trust) = runtime_with_probe(Some(port.clone()));

    let packed = touch(&rt);

    assert_eq!(packed & 0xff, 0, "result tag must be ok");
    assert_eq!(
        *port.seen.lock().unwrap(),
        vec![(EXT_ID.to_string(), Some("acme".to_string()))],
        "the port must be reached once, with this extension and tenant"
    );
}

#[test]
fn dispatch_without_an_installed_port_answers_unsupported() {
    let (rt, _fixture, _trust) = runtime_with_probe(None);

    let packed = touch(&rt);

    assert_eq!(packed & 0xff, 1, "result tag must be err");
    assert_eq!(
        (packed >> 8) & 0xff,
        0,
        "artifact-error case 0 is `unsupported`"
    );
}
