//! Production-path test for `ExtensionRuntime::with_knowledge_port`: a real
//! signed extension dir whose describe declares `knowledge://` tokens, loaded
//! into a real runtime and dispatched through `dispatch_instance_ctx`. It
//! catches the runtime dropping the port, the call scope, or the permission
//! tokens on the way to the guest.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use greentic_extension_sdk_contract::ExtensionKind;

use crate::host_ports::{
    HostCallContext, KnowledgeCreateRequest, KnowledgeCreated, KnowledgeDocument,
    KnowledgeDocumentInfo, KnowledgePort, KnowledgePortError,
};
use crate::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig};

const FIXTURE: &str = include_str!("../tests/fixtures/knowledge_import.wat");
const EXT_ID: &str = "greentic.knowledge-probe";

#[derive(Default)]
struct RecordingPort {
    seen: Mutex<Vec<(String, HostCallContext)>>,
}

impl RecordingPort {
    fn note(&self, ext: &str, ctx: &HostCallContext) {
        self.seen
            .lock()
            .unwrap()
            .push((ext.to_string(), ctx.clone()));
    }
}

impl KnowledgePort for RecordingPort {
    fn create(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        _req: KnowledgeCreateRequest,
    ) -> Result<KnowledgeCreated, KnowledgePortError> {
        self.note(ext, ctx);
        Ok(KnowledgeCreated {
            document_id: "doc-1".into(),
            created: false,
        })
    }
    fn read(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        _: &str,
        _: &str,
    ) -> Result<KnowledgeDocument, KnowledgePortError> {
        self.note(ext, ctx);
        Err(KnowledgePortError::NotFound)
    }
    fn list(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        _: &str,
    ) -> Result<Vec<KnowledgeDocumentInfo>, KnowledgePortError> {
        self.note(ext, ctx);
        Ok(Vec::new())
    }
    fn remove(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        _: &str,
        _: &str,
    ) -> Result<bool, KnowledgePortError> {
        self.note(ext, ctx);
        Ok(false)
    }
}

fn runtime_with_probe(
    port: Option<Arc<dyn KnowledgePort>>,
    network: &[&str],
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
    describe.runtime.permissions.network = network.iter().map(ToString::to_string).collect();
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    crate::runtime_artifact_tests::sign_fixture_dir(fixture.root(), &mut describe, &sk);

    let trust = tempfile::TempDir::new().expect("temp trust root");
    let config = RuntimeConfig::from_paths(DiscoveryPaths::new(PathBuf::from("/dev/null")))
        .with_trust_root(trust.path().to_path_buf());
    let mut rt = ExtensionRuntime::new(config).expect("runtime");
    if let Some(port) = port {
        rt = rt.with_knowledge_port(port);
    }
    rt.register_loaded_from_dir(fixture.root())
        .expect("register fixture");
    (rt, fixture, trust)
}

fn probe(rt: &ExtensionRuntime, name: &str) -> u32 {
    let ctx = HostCallContext {
        tenant: Some("acme".into()),
        user_email: Some("u@example.com".into()),
        team: Some("ops".into()),
        session_id: Some("sess-7".into()),
    };
    let (mut store, instance) = rt
        .dispatch_instance_ctx(EXT_ID, &ctx)
        .expect("dispatch instance");
    let func = instance
        .get_typed_func::<(), (u32,)>(&mut store, name)
        .expect("fixture exports the probe");
    func.call(&mut store, ()).expect("probe must not trap").0
}

#[test]
fn dispatch_forwards_the_installed_port_and_the_full_call_scope() {
    let port = Arc::new(RecordingPort::default());
    let (rt, _f, _t) = runtime_with_probe(
        Some(port.clone()),
        &[
            "knowledge://create",
            "knowledge://list",
            "https://api.example.com/*",
        ],
    );

    assert_eq!(probe(&rt, "call-create") & 0xff, 0, "create is declared");
    assert_eq!(probe(&rt, "call-list") & 0xff, 0, "list is declared");
    let read = probe(&rt, "call-read");
    assert_eq!(
        (read & 0xff, (read >> 8) & 0xff),
        (1, 0),
        "read is undeclared: not-allowed"
    );

    let seen = port.seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "only the two declared calls reach the port");
    for (ext, ctx) in seen.iter() {
        assert_eq!(ext, EXT_ID);
        assert_eq!(ctx.tenant.as_deref(), Some("acme"));
        assert_eq!(ctx.team.as_deref(), Some("ops"));
        assert_eq!(ctx.session_id.as_deref(), Some("sess-7"));
    }
}

#[test]
fn dispatch_without_an_installed_port_answers_unavailable() {
    let (rt, _f, _t) = runtime_with_probe(None, &["knowledge://list"]);
    let p = probe(&rt, "call-list");
    assert_eq!((p & 0xff, (p >> 8) & 0xff), (1, 5), "case 5 is unavailable");
}
