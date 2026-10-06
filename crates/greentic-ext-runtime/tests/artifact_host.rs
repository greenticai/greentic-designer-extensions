//! Link-level tests for the `artifact` host interface: a guest that imports it
//! instantiates on a host that registered it, and fails with an error that
//! names the interface on a host that did not.

use std::sync::Arc;

use greentic_ext_runtime::HostState;
use greentic_ext_runtime::host_ports::{
    ArtifactPort, ArtifactPortError, ArtifactPutRequest, HostCallContext,
};
use greentic_extension_sdk_contract::describe::Permissions;
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

const FIXTURE: &str = include_str!("fixtures/artifact_import.wat");

fn engine() -> Engine {
    Engine::default()
}

fn component(engine: &Engine) -> Component {
    let bytes = wat::parse_str(FIXTURE).expect("fixture parses");
    Component::from_binary(engine, &bytes).expect("fixture is a component")
}

fn store(engine: &Engine) -> Store<HostState> {
    Store::new(
        engine,
        HostState::builder("test-ext".into(), Permissions::default()).build(),
    )
}

struct FixedPort;
impl ArtifactPort for FixedPort {
    fn put(
        &self,
        _extension_id: &str,
        _ctx: &HostCallContext,
        _request: ArtifactPutRequest,
    ) -> Result<String, ArtifactPortError> {
        Ok("artifact://fixed".to_string())
    }
}

/// Instantiate the fixture with a tenant in the call context and the given
/// port, call `touch`, and return its packed result: byte 0 is the result tag
/// (0 ok, 1 err), byte 1 the second word's low byte (the `artifact-error` case
/// on err), and the high half is the returned string's length on ok.
fn call_touch(port: Option<Arc<dyn ArtifactPort>>) -> u32 {
    let engine = engine();
    let component = component(&engine);
    let mut linker: Linker<HostState> = Linker::new(&engine);
    greentic_ext_runtime::host_bindings::register_host_interfaces_for_tests(&mut linker)
        .expect("register host interfaces");
    let state = HostState::builder("test-ext".into(), Permissions::default())
        .call_ctx(HostCallContext {
            tenant: Some("acme".into()),
            user_email: None,
        })
        .artifact_port(port)
        .build();
    let mut store = Store::new(&engine, state);
    let instance = linker
        .instantiate(&mut store, &component)
        .expect("instantiate");
    let touch = instance
        .get_typed_func::<(), (u32,)>(&mut store, "touch")
        .expect("fixture exports touch");
    let (packed,) = touch.call(&mut store, ()).expect("touch must not trap");
    packed
}

#[test]
fn a_guest_importing_artifact_instantiates_when_the_interface_is_registered() {
    let engine = engine();
    let component = component(&engine);
    let mut linker: Linker<HostState> = Linker::new(&engine);
    greentic_ext_runtime::host_bindings::register_host_interfaces_for_tests(&mut linker)
        .expect("register host interfaces");
    let mut store = store(&engine);
    linker
        .instantiate(&mut store, &component)
        .expect("guest importing artifact must instantiate");
}

#[test]
fn a_guest_importing_artifact_fails_to_instantiate_on_a_host_without_it() {
    let engine = engine();
    let component = component(&engine);
    let linker: Linker<HostState> = Linker::new(&engine); // nothing registered
    let mut store = store(&engine);
    let err = linker
        .instantiate(&mut store, &component)
        .expect_err("an unregistered import must not instantiate");
    let text = format!("{err:#}");
    assert!(
        text.contains("greentic:extension-host/artifact"),
        "the error must name the missing interface, got: {text}"
    );
}

#[test]
fn a_guest_that_does_not_import_artifact_still_instantiates_on_a_host_that_has_it() {
    // Old guests (compiled before artifact existed) import a subset; a host
    // that registers more must not reject them.
    let engine = engine();
    let empty = wat::parse_str("(component)").expect("empty component");
    let component = Component::from_binary(&engine, &empty).expect("component");
    let mut linker: Linker<HostState> = Linker::new(&engine);
    greentic_ext_runtime::host_bindings::register_host_interfaces_for_tests(&mut linker)
        .expect("register host interfaces");
    let mut store = store(&engine);
    linker
        .instantiate(&mut store, &component)
        .expect("a guest with no artifact import must still instantiate");
}

#[test]
fn put_answers_unsupported_when_no_port_is_installed() {
    let packed = call_touch(None);
    assert_eq!(packed & 0xff, 1, "result tag must be err");
    assert_eq!(
        (packed >> 8) & 0xff,
        0,
        "artifact-error case 0 is `unsupported`"
    );
}

#[test]
fn put_returns_the_ports_id_when_a_port_is_installed() {
    let packed = call_touch(Some(Arc::new(FixedPort)));
    assert_eq!(packed & 0xff, 0, "result tag must be ok");
    // The string length is the high 16 bits (the guest's realloc is a stub, so
    // only the length, not the contents, is meaningful).
    assert_eq!((packed >> 16) as usize, "artifact://fixed".len());
}
