use std::sync::{Arc, Mutex};

use greentic_extension_sdk_contract::describe::Permissions;

use super::{MAX_KNOWLEDGE_REF_BYTES, MAX_KNOWLEDGE_TEXT_BYTES};
use crate::host_bindings::design_v04::greentic::extension_host::knowledge::{
    Host as KnowledgeHost, KnowledgeError,
};
use crate::host_ports::{
    HostCallContext, KnowledgeBaseInfo, KnowledgeCreateRequest, KnowledgeCreated,
    KnowledgeDocument, KnowledgeDocumentInfo, KnowledgePort, KnowledgePortError,
    KnowledgeSearchHit, KnowledgeSearchRequest, KnowledgeUpdateRequest, KnowledgeUpdated,
};

/// Records every call with the scope it arrived in.
#[derive(Default)]
pub(crate) struct Recording {
    pub(crate) calls: Mutex<Vec<(String, String, HostCallContext)>>,
    pub(crate) fail_with: Mutex<Option<KnowledgePortError>>,
}

impl Recording {
    fn record(&self, op: &str, ext: &str, ctx: &HostCallContext) -> Result<(), KnowledgePortError> {
        self.calls
            .lock()
            .unwrap()
            .push((op.to_string(), ext.to_string(), ctx.clone()));
        match self.fail_with.lock().unwrap().take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    pub(crate) fn ops(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.0.clone())
            .collect()
    }
}

impl KnowledgePort for Recording {
    fn create(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        req: KnowledgeCreateRequest,
    ) -> Result<KnowledgeCreated, KnowledgePortError> {
        self.record(
            &format!("create:{}:{}", req.knowledge_base, req.name),
            ext,
            ctx,
        )?;
        Ok(KnowledgeCreated {
            document_id: "doc-1".into(),
            created: true,
        })
    }
    fn read(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        kb: &str,
        id: &str,
    ) -> Result<KnowledgeDocument, KnowledgePortError> {
        self.record(&format!("read:{kb}:{id}"), ext, ctx)?;
        Ok(KnowledgeDocument {
            name: "note.md".into(),
            text: "hello".into(),
            truncated: false,
        })
    }
    fn list(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        kb: &str,
    ) -> Result<Vec<KnowledgeDocumentInfo>, KnowledgePortError> {
        self.record(&format!("list:{kb}"), ext, ctx)?;
        Ok(vec![KnowledgeDocumentInfo {
            document_id: "doc-1".into(),
            name: "note.md".into(),
            size_chars: 5,
        }])
    }
    fn remove(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        kb: &str,
        id: &str,
    ) -> Result<bool, KnowledgePortError> {
        self.record(&format!("remove:{kb}:{id}"), ext, ctx)?;
        Ok(true)
    }
    fn list_bases(
        &self,
        ext: &str,
        ctx: &HostCallContext,
    ) -> Result<Vec<KnowledgeBaseInfo>, KnowledgePortError> {
        self.record("list-bases", ext, ctx)?;
        Ok(vec![KnowledgeBaseInfo {
            name: "Handbook".into(),
            description: "Policies".into(),
            document_count: 2,
        }])
    }
    /// Returns 25 hits whatever the limit, so the runtime's truncation shows.
    fn search(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        req: KnowledgeSearchRequest,
    ) -> Result<Vec<KnowledgeSearchHit>, KnowledgePortError> {
        self.record(
            &format!("search:{}:{}:{}", req.knowledge_base, req.query, req.limit),
            ext,
            ctx,
        )?;
        Ok((0..25)
            .map(|i| KnowledgeSearchHit {
                document_id: format!("doc-{i}"),
                name: "note.md".into(),
                passage: "refund policy".into(),
                score: 0.5,
            })
            .collect())
    }
    fn update(
        &self,
        ext: &str,
        ctx: &HostCallContext,
        req: KnowledgeUpdateRequest,
    ) -> Result<KnowledgeUpdated, KnowledgePortError> {
        self.record(
            &format!(
                "update:{}:{}:{}",
                req.knowledge_base, req.document_id, req.text
            ),
            ext,
            ctx,
        )?;
        Ok(KnowledgeUpdated {
            document_id: "doc-2".into(),
        })
    }
}

pub(crate) const ALL: [&str; 4] = [
    "knowledge://create",
    "knowledge://read",
    "knowledge://list",
    "knowledge://remove",
];

pub(crate) fn scoped_ctx(tenant: Option<&str>) -> HostCallContext {
    HostCallContext {
        tenant: tenant.map(str::to_string),
        user_email: Some("u@example.com".into()),
        team: Some("sales".into()),
        session_id: Some("sess-1".into()),
    }
}

pub(crate) fn host(
    port: Option<Arc<Recording>>,
    tenant: Option<&str>,
    declared: &[&str],
) -> crate::HostState {
    let permissions = Permissions {
        network: declared.iter().map(ToString::to_string).collect(),
        ..Permissions::default()
    };
    let mut b =
        crate::HostState::builder("test-ext".into(), permissions).call_ctx(scoped_ctx(tenant));
    if let Some(p) = port {
        b = b.knowledge_port(Some(p as Arc<dyn KnowledgePort>));
    }
    b.build()
}

pub(crate) fn s(v: &str) -> String {
    v.to_string()
}

#[test]
fn every_declared_operation_reaches_the_port_with_the_full_call_scope() {
    let port = Arc::new(Recording::default());
    let mut h = host(Some(port.clone()), Some("acme"), &ALL);

    let created = KnowledgeHost::create(&mut h, s("Handbook"), s("note.md"), s("hello")).unwrap();
    assert_eq!(created.document_id, "doc-1");
    assert!(created.created);
    let doc = KnowledgeHost::read(&mut h, s("Handbook"), s("doc-1")).unwrap();
    assert_eq!(
        (doc.name.as_str(), doc.text.as_str(), doc.truncated),
        ("note.md", "hello", false)
    );
    let rows = KnowledgeHost::list(&mut h, s("Handbook")).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].size_chars, 5);
    assert!(KnowledgeHost::remove(&mut h, s("Handbook"), s("doc-1")).unwrap());

    assert_eq!(
        port.ops(),
        vec![
            "create:Handbook:note.md",
            "read:Handbook:doc-1",
            "list:Handbook",
            "remove:Handbook:doc-1"
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
fn an_undeclared_operation_is_refused_before_the_port() {
    let port = Arc::new(Recording::default());
    // Read and list only: create and remove were never declared.
    let mut h = host(
        Some(port.clone()),
        Some("acme"),
        &["knowledge://read", "knowledge://list"],
    );
    assert!(matches!(
        KnowledgeHost::create(&mut h, s("Handbook"), s("a.md"), s("x")),
        Err(KnowledgeError::NotAllowed)
    ));
    assert!(matches!(
        KnowledgeHost::remove(&mut h, s("Handbook"), s("doc-1")),
        Err(KnowledgeError::NotAllowed)
    ));
    assert!(KnowledgeHost::list(&mut h, s("Handbook")).is_ok());
    assert_eq!(port.ops(), vec!["list:Handbook"]);
}

#[test]
fn nothing_declared_refuses_everything() {
    let port = Arc::new(Recording::default());
    let mut h = host(
        Some(port.clone()),
        Some("acme"),
        &["https://api.example.com/*"],
    );
    assert!(matches!(
        KnowledgeHost::list(&mut h, s("Handbook")),
        Err(KnowledgeError::NotAllowed)
    ));
    assert!(port.ops().is_empty());
}

#[test]
fn a_missing_or_blank_tenant_is_refused_before_the_port() {
    for tenant in [None, Some(""), Some("  ")] {
        let port = Arc::new(Recording::default());
        let mut h = host(Some(port.clone()), tenant, &ALL);
        assert!(
            matches!(
                KnowledgeHost::list(&mut h, s("Handbook")),
                Err(KnowledgeError::NotAllowed)
            ),
            "{tenant:?}"
        );
        assert!(port.ops().is_empty());
    }
}

#[test]
fn no_port_reports_unavailable() {
    let mut h = host(None, Some("acme"), &ALL);
    assert!(matches!(
        KnowledgeHost::list(&mut h, s("Handbook")),
        Err(KnowledgeError::Unavailable)
    ));
}

#[test]
fn caps_and_shapes_are_checked_before_the_port() {
    let port = Arc::new(Recording::default());
    let mut h = host(Some(port.clone()), Some("acme"), &ALL);
    let big = "x".repeat(MAX_KNOWLEDGE_TEXT_BYTES + 1);
    assert!(matches!(
        KnowledgeHost::create(&mut h, s("Handbook"), s("a.md"), big),
        Err(KnowledgeError::TooLarge)
    ));
    let long_name = "n".repeat(256);
    assert!(matches!(
        KnowledgeHost::create(&mut h, s("Handbook"), long_name, s("x")),
        Err(KnowledgeError::TooLarge)
    ));
    for name in ["", "a/b.md", "a\nb", ".."] {
        assert!(
            matches!(
                KnowledgeHost::create(&mut h, s("Handbook"), s(name), s("x")),
                Err(KnowledgeError::NotAllowed)
            ),
            "{name:?}"
        );
    }
    let long_base = "b".repeat(MAX_KNOWLEDGE_REF_BYTES + 1);
    for base in ["", "  ", "a\0b", long_base.as_str()] {
        assert!(
            matches!(
                KnowledgeHost::list(&mut h, s(base)),
                Err(KnowledgeError::NotAllowed)
            ),
            "{base:?}"
        );
    }
    for id in ["", " ", "a\nb"] {
        assert!(matches!(
            KnowledgeHost::read(&mut h, s("Handbook"), s(id)),
            Err(KnowledgeError::NotFound)
        ));
    }
    assert!(port.ops().is_empty(), "no refused call reaches the port");
    // The exact cap is accepted.
    let at_cap = "x".repeat(MAX_KNOWLEDGE_TEXT_BYTES);
    assert!(KnowledgeHost::create(&mut h, s("Handbook"), s("a.md"), at_cap).is_ok());
}

#[test]
fn port_errors_map_to_typed_variants_without_leaking_detail() {
    let cases = [
        (KnowledgePortError::NotAllowed, KnowledgeError::NotAllowed),
        (KnowledgePortError::NotFound, KnowledgeError::NotFound),
        (KnowledgePortError::TooLarge, KnowledgeError::TooLarge),
        (
            KnowledgePortError::InvalidMediaType,
            KnowledgeError::InvalidMediaType,
        ),
        (
            KnowledgePortError::QuotaExceeded,
            KnowledgeError::QuotaExceeded,
        ),
        (
            KnowledgePortError::Unavailable("postgres://10.0.0.5 secret".into()),
            KnowledgeError::Unavailable,
        ),
    ];
    for (port_err, want) in cases {
        let port = Arc::new(Recording::default());
        *port.fail_with.lock().unwrap() = Some(port_err);
        let mut h = host(Some(port), Some("acme"), &ALL);
        let got = KnowledgeHost::list(&mut h, s("Handbook")).unwrap_err();
        // `unavailable` is a unit variant: the detail has no field to ride in.
        assert_eq!(format!("{got:?}"), format!("{want:?}"));
    }
}

#[test]
fn a_blank_document_id_from_the_port_is_unavailable() {
    struct Blank;
    impl KnowledgePort for Blank {
        fn create(
            &self,
            _: &str,
            _: &HostCallContext,
            _: KnowledgeCreateRequest,
        ) -> Result<KnowledgeCreated, KnowledgePortError> {
            Ok(KnowledgeCreated {
                document_id: " ".into(),
                created: true,
            })
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
    let permissions = Permissions {
        network: ALL.iter().map(ToString::to_string).collect(),
        ..Permissions::default()
    };
    let mut h = crate::HostState::builder("test-ext".into(), permissions)
        .call_ctx(scoped_ctx(Some("acme")))
        .knowledge_port(Some(Arc::new(Blank) as Arc<dyn KnowledgePort>))
        .build();
    assert!(matches!(
        KnowledgeHost::create(&mut h, s("Handbook"), s("a.md"), s("x")),
        Err(KnowledgeError::Unavailable)
    ));
}

#[path = "host_state_knowledge_general_tests.rs"]
mod general;
