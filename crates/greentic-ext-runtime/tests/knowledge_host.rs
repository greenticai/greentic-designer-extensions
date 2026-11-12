//! Link- and call-level tests for the `knowledge` host interface: a real
//! component guest that imports it calls every operation through the
//! production linker, against a recording fake port.

use std::sync::{Arc, Mutex};

use greentic_ext_runtime::HostState;
use greentic_ext_runtime::host_ports::{
    HostCallContext, KnowledgeCreateRequest, KnowledgeCreated, KnowledgeDocument,
    KnowledgeDocumentInfo, KnowledgePort, KnowledgePortError,
};
use greentic_extension_sdk_contract::describe::Permissions;
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

const FIXTURE: &str = include_str!("fixtures/knowledge_import.wat");
const ALL: [&str; 4] = [
    "knowledge://create",
    "knowledge://read",
    "knowledge://list",
    "knowledge://remove",
];

#[derive(Default)]
struct Recording {
    calls: Mutex<Vec<String>>,
    scopes: Mutex<Vec<HostCallContext>>,
}

impl Recording {
    fn note(&self, call: String, ctx: &HostCallContext) {
        self.calls.lock().unwrap().push(call);
        self.scopes.lock().unwrap().push(ctx.clone());
    }
}

impl KnowledgePort for Recording {
    fn create(
        &self,
        _ext: &str,
        ctx: &HostCallContext,
        req: KnowledgeCreateRequest,
    ) -> Result<KnowledgeCreated, KnowledgePortError> {
        self.note(
            format!("create:{}:{}:{}", req.knowledge_base, req.name, req.text),
            ctx,
        );
        Ok(KnowledgeCreated {
            document_id: "doc-42".into(),
            created: true,
        })
    }
    fn read(
        &self,
        _ext: &str,
        ctx: &HostCallContext,
        kb: &str,
        id: &str,
    ) -> Result<KnowledgeDocument, KnowledgePortError> {
        self.note(format!("read:{kb}:{id}"), ctx);
        Ok(KnowledgeDocument {
            name: "note.md".into(),
            text: "hello world".into(),
            truncated: true,
        })
    }
    fn list(
        &self,
        _ext: &str,
        ctx: &HostCallContext,
        kb: &str,
    ) -> Result<Vec<KnowledgeDocumentInfo>, KnowledgePortError> {
        self.note(format!("list:{kb}"), ctx);
        Ok((0..3)
            .map(|i| KnowledgeDocumentInfo {
                document_id: format!("doc-{i}"),
                name: format!("n{i}.md"),
                size_chars: 10,
            })
            .collect())
    }
    fn remove(
        &self,
        _ext: &str,
        ctx: &HostCallContext,
        kb: &str,
        id: &str,
    ) -> Result<bool, KnowledgePortError> {
        self.note(format!("remove:{kb}:{id}"), ctx);
        Ok(true)
    }
}

struct Guest {
    store: Store<HostState>,
    instance: wasmtime::component::Instance,
}

impl Guest {
    fn new(port: Option<Arc<dyn KnowledgePort>>, declared: &[&str]) -> Self {
        let engine = Engine::default();
        let bytes = wat::parse_str(FIXTURE).expect("fixture parses");
        let component = Component::from_binary(&engine, &bytes).expect("fixture is a component");
        let mut linker: Linker<HostState> = Linker::new(&engine);
        greentic_ext_runtime::host_bindings::register_host_interfaces_for_tests(&mut linker)
            .expect("register host interfaces");
        let permissions = Permissions {
            network: declared.iter().map(ToString::to_string).collect(),
            ..Permissions::default()
        };
        let state = HostState::builder("test-ext".into(), permissions)
            .call_ctx(HostCallContext {
                tenant: Some("acme".into()),
                user_email: Some("u@example.com".into()),
                team: Some("sales".into()),
                session_id: Some("sess-9".into()),
            })
            .knowledge_port(port)
            .build();
        let mut store = Store::new(&engine, state);
        let instance = linker
            .instantiate(&mut store, &component)
            .expect("instantiate");
        Self { store, instance }
    }

    fn call(&mut self, name: &str) -> u32 {
        let f = self
            .instance
            .get_typed_func::<(), (u32,)>(&mut self.store, name)
            .expect("fixture exports the probe");
        f.call(&mut self.store, ()).expect("probe must not trap").0
    }
}

fn tag(packed: u32) -> u32 {
    packed & 0xff
}
fn second(packed: u32) -> u32 {
    (packed >> 8) & 0xff
}
fn len(packed: u32) -> u32 {
    packed >> 16
}

#[test]
fn a_guest_calls_every_operation_and_the_port_sees_its_arguments_and_scope() {
    let port = Arc::new(Recording::default());
    let mut guest = Guest::new(Some(port.clone()), &ALL);

    // `doc-42` is 6 bytes and `hello world` 11: the guest reports the lengths.
    let created = guest.call("call-create");
    assert_eq!((tag(created), second(created), len(created)), (0, 1, 6));
    let read = guest.call("call-read");
    assert_eq!((tag(read), second(read), len(read)), (0, 1, 11));
    let listed = guest.call("call-list");
    assert_eq!((tag(listed), len(listed)), (0, 3));
    let removed = guest.call("call-remove");
    assert_eq!((tag(removed), second(removed)), (0, 1));

    assert_eq!(
        *port.calls.lock().unwrap(),
        vec![
            "create:Handbook:note.md:hello",
            "read:Handbook:doc-1",
            "list:Handbook",
            "remove:Handbook:doc-1",
        ]
    );
    for ctx in port.scopes.lock().unwrap().iter() {
        assert_eq!(ctx.tenant.as_deref(), Some("acme"));
        assert_eq!(ctx.team.as_deref(), Some("sales"));
        assert_eq!(ctx.session_id.as_deref(), Some("sess-9"));
    }
}

#[test]
fn an_undeclared_operation_is_refused_with_not_allowed() {
    let port = Arc::new(Recording::default());
    let mut g = Guest::new(Some(port.clone()), &["knowledge://list"]);
    let c = g.call("call-create");
    assert_eq!(
        (tag(c), second(c)),
        (1, 0),
        "knowledge-error case 0 is not-allowed"
    );
    let d = g.call("call-remove");
    assert_eq!((tag(d), second(d)), (1, 0));
    assert_eq!(tag(g.call("call-list")), 0, "the declared op still works");
    assert_eq!(*port.calls.lock().unwrap(), vec!["list:Handbook"]);
}

#[test]
fn without_an_installed_port_every_operation_answers_unavailable() {
    let mut g = Guest::new(None, &ALL);
    for probe in ["call-create", "call-read", "call-list", "call-remove"] {
        let p = g.call(probe);
        assert_eq!(
            (tag(p), second(p)),
            (1, 5),
            "{probe}: case 5 is unavailable"
        );
    }
}

#[test]
fn a_guest_importing_knowledge_fails_to_instantiate_on_a_host_without_it() {
    let engine = Engine::default();
    let bytes = wat::parse_str(FIXTURE).expect("fixture parses");
    let component = Component::from_binary(&engine, &bytes).expect("component");
    let linker: Linker<HostState> = Linker::new(&engine);
    let mut store = Store::new(
        &engine,
        HostState::builder("test-ext".into(), Permissions::default()).build(),
    );
    let err = linker
        .instantiate(&mut store, &component)
        .expect_err("an unregistered import must not instantiate");
    assert!(
        format!("{err:#}").contains("greentic:extension-host/knowledge"),
        "the error must name the missing interface, got: {err:#}"
    );
}
