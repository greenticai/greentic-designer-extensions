//! The three general operations: `list-bases`, `search`, `update`.

use std::sync::Arc;

use super::{ALL, Recording, host, s};
use crate::host_bindings::design_v04::greentic::extension_host::knowledge::{
    Host as KnowledgeHost, KnowledgeError,
};
use crate::host_ports::{
    HostCallContext, KnowledgeCreateRequest, KnowledgeCreated, KnowledgeDocument,
    KnowledgeDocumentInfo, KnowledgePort, KnowledgePortError,
};
use crate::host_state_knowledge::{MAX_KNOWLEDGE_TEXT_BYTES, MAX_SEARCH_QUERY_BYTES};

const GENERAL: [&str; 3] = [
    "knowledge://list-bases",
    "knowledge://search",
    "knowledge://update",
];

fn every_token() -> Vec<&'static str> {
    ALL.iter().chain(GENERAL.iter()).copied().collect()
}

#[test]
fn the_general_operations_reach_the_port_with_the_full_call_scope() {
    let port = Arc::new(Recording::default());
    let mut h = host(Some(port.clone()), Some("acme"), &every_token());

    let bases = KnowledgeHost::list_bases(&mut h).unwrap();
    assert_eq!(bases.len(), 1);
    assert_eq!(
        (
            bases[0].name.as_str(),
            bases[0].description.as_str(),
            bases[0].document_count
        ),
        ("Handbook", "Policies", 2)
    );
    let hits = KnowledgeHost::search(&mut h, s("Handbook"), s("refund"), 5).unwrap();
    assert_eq!(hits.len(), 5, "the runtime truncates to the limit");
    assert_eq!(hits[0].passage, "refund policy");
    let updated = KnowledgeHost::update(&mut h, s("Handbook"), s("doc-1"), s("v2")).unwrap();
    assert_eq!(updated.document_id, "doc-2");

    assert_eq!(
        port.ops(),
        vec![
            "list-bases",
            "search:Handbook:refund:5",
            "update:Handbook:doc-1:v2"
        ]
    );
    for (_, ext, ctx) in port.calls.lock().unwrap().iter() {
        assert_eq!(ext, "test-ext");
        assert_eq!(ctx.tenant.as_deref(), Some("acme"));
        assert_eq!(ctx.team.as_deref(), Some("sales"));
        assert_eq!(ctx.session_id.as_deref(), Some("sess-1"));
    }
}

#[test]
fn each_general_operation_is_refused_when_undeclared() {
    let port = Arc::new(Recording::default());
    // The original four only: none of the general ones.
    let mut h = host(Some(port.clone()), Some("acme"), &ALL);
    assert!(matches!(
        KnowledgeHost::list_bases(&mut h),
        Err(KnowledgeError::NotAllowed)
    ));
    assert!(matches!(
        KnowledgeHost::search(&mut h, s("Handbook"), s("q"), 3),
        Err(KnowledgeError::NotAllowed)
    ));
    assert!(matches!(
        KnowledgeHost::update(&mut h, s("Handbook"), s("doc-1"), s("x")),
        Err(KnowledgeError::NotAllowed)
    ));
    assert!(port.ops().is_empty());
}

#[test]
fn declaring_one_general_operation_grants_only_that_one() {
    let port = Arc::new(Recording::default());
    let mut h = host(Some(port.clone()), Some("acme"), &["knowledge://search"]);
    assert!(KnowledgeHost::search(&mut h, s("Handbook"), s("q"), 3).is_ok());
    assert!(matches!(
        KnowledgeHost::list_bases(&mut h),
        Err(KnowledgeError::NotAllowed)
    ));
    assert!(matches!(
        KnowledgeHost::update(&mut h, s("Handbook"), s("doc-1"), s("x")),
        Err(KnowledgeError::NotAllowed)
    ));
    assert_eq!(port.ops(), vec!["search:Handbook:q:3"]);
}

#[test]
fn list_bases_needs_a_tenant() {
    let port = Arc::new(Recording::default());
    let mut h = host(Some(port.clone()), None, &every_token());
    assert!(matches!(
        KnowledgeHost::list_bases(&mut h),
        Err(KnowledgeError::NotAllowed)
    ));
    assert!(port.ops().is_empty());
}

#[test]
fn search_clamps_the_limit_and_checks_the_query() {
    let port = Arc::new(Recording::default());
    let mut h = host(Some(port.clone()), Some("acme"), &every_token());
    let many = KnowledgeHost::search(&mut h, s("Handbook"), s("q"), 500).unwrap();
    assert_eq!(many.len(), 20);
    let one = KnowledgeHost::search(&mut h, s("Handbook"), s("q"), 0).unwrap();
    assert_eq!(one.len(), 1);
    assert!(
        KnowledgeHost::search(&mut h, s("Handbook"), s("  "), 5)
            .unwrap()
            .is_empty(),
        "a blank query matches nothing"
    );
    let long = "q".repeat(MAX_SEARCH_QUERY_BYTES + 1);
    assert!(matches!(
        KnowledgeHost::search(&mut h, s("Handbook"), long, 5),
        Err(KnowledgeError::TooLarge)
    ));
    assert!(matches!(
        KnowledgeHost::search(&mut h, s(""), s("q"), 5),
        Err(KnowledgeError::NotAllowed)
    ));
    assert_eq!(
        port.ops(),
        vec!["search:Handbook:q:20", "search:Handbook:q:1"]
    );
}

#[test]
fn update_checks_the_document_id_and_text_cap() {
    let port = Arc::new(Recording::default());
    let mut h = host(Some(port.clone()), Some("acme"), &every_token());
    assert!(matches!(
        KnowledgeHost::update(&mut h, s("Handbook"), s(" "), s("x")),
        Err(KnowledgeError::NotFound)
    ));
    let big = "x".repeat(MAX_KNOWLEDGE_TEXT_BYTES + 1);
    assert!(matches!(
        KnowledgeHost::update(&mut h, s("Handbook"), s("doc-1"), big),
        Err(KnowledgeError::TooLarge)
    ));
    assert!(port.ops().is_empty());
}

#[test]
fn update_port_errors_map_without_leaking_detail() {
    let port = Arc::new(Recording::default());
    *port.fail_with.lock().unwrap() = Some(KnowledgePortError::Unavailable(
        "postgres://10.0.0.5 secret".into(),
    ));
    let mut h = host(Some(port), Some("acme"), &every_token());
    assert!(matches!(
        KnowledgeHost::update(&mut h, s("Handbook"), s("doc-1"), s("x")),
        Err(KnowledgeError::Unavailable)
    ));
}

/// A port written before the general operations existed still compiles, and
/// each of them answers `unavailable` through it.
#[test]
fn a_port_without_the_general_operations_answers_unavailable() {
    struct FourOnly;
    impl KnowledgePort for FourOnly {
        fn create(
            &self,
            _: &str,
            _: &HostCallContext,
            _: KnowledgeCreateRequest,
        ) -> Result<KnowledgeCreated, KnowledgePortError> {
            Err(KnowledgePortError::NotAllowed)
        }
        fn read(
            &self,
            _: &str,
            _: &HostCallContext,
            _: &str,
            _: &str,
        ) -> Result<KnowledgeDocument, KnowledgePortError> {
            Err(KnowledgePortError::NotFound)
        }
        fn list(
            &self,
            _: &str,
            _: &HostCallContext,
            _: &str,
        ) -> Result<Vec<KnowledgeDocumentInfo>, KnowledgePortError> {
            Ok(Vec::new())
        }
        fn remove(
            &self,
            _: &str,
            _: &HostCallContext,
            _: &str,
            _: &str,
        ) -> Result<bool, KnowledgePortError> {
            Ok(false)
        }
    }
    let permissions = greentic_extension_sdk_contract::describe::Permissions {
        network: every_token().iter().map(ToString::to_string).collect(),
        ..Default::default()
    };
    let mut h = crate::HostState::builder("test-ext".into(), permissions)
        .call_ctx(super::scoped_ctx(Some("acme")))
        .knowledge_port(Some(Arc::new(FourOnly) as Arc<dyn KnowledgePort>))
        .build();
    assert!(matches!(
        KnowledgeHost::list_bases(&mut h),
        Err(KnowledgeError::Unavailable)
    ));
    assert!(matches!(
        KnowledgeHost::search(&mut h, s("Handbook"), s("q"), 3),
        Err(KnowledgeError::Unavailable)
    ));
    assert!(matches!(
        KnowledgeHost::update(&mut h, s("Handbook"), s("doc-1"), s("x")),
        Err(KnowledgeError::Unavailable)
    ));
}
