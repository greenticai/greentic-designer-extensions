//! The hosting-provider world, end to end: a real guest component, the
//! restricted linker, the policy engine and the lifecycle gates.
//!
//! One component plays the honest provider and every malicious one (the
//! `scenario` target setting picks), so each test below is "same bytes, hostile
//! behaviour, here is what the host did".

#[path = "support/mod.rs"]
mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use greentic_ext_runtime::hosting::audit::{MemoryAuditSink, Outcome};
use greentic_ext_runtime::hosting::mock::MockHostingPort;
use greentic_ext_runtime::hosting::{
    DestroyMode, HostError, HostOutcome, HostSpec, HostingError, HostingLimits, PortResponse,
    Refusal, TargetPolicy,
};
use greentic_ext_runtime::HostingProvider;
use greentic_extension_sdk_contract::ExtensionKind;

use support::hosting::{self as h, fake_credential};

const ID: &str = "greentic.hosting-test";

fn spec() -> HostSpec {
    HostSpec {
        kind: "vector-store/qdrant".into(),
        version: "1".into(),
        size: "small".into(),
        hosting_json: "{}".into(),
    }
}

fn honest() -> h::Harness {
    h::harness(ExtensionKind::Deploy, ID, h::guest_wasm(false), true, None)
}

/// Provider bound to `port`/`policy`, approved for exactly what it declares.
fn approved<'a>(
    hn: &'a h::Harness,
    port: &Arc<MockHostingPort>,
    mut policy: TargetPolicy,
    audit: &Arc<MemoryAuditSink>,
) -> HostingProvider<'a> {
    let probe = hn
        .rt
        .hosting_provider(ID, h::ctx(port.clone(), policy.clone(), audit.clone()))
        .expect("provider");
    policy.approved_capability_hash = Some(probe.capability_hash().to_string());
    hn.rt
        .hosting_provider(ID, h::ctx(port.clone(), policy, audit.clone()))
        .expect("provider")
}

/// Run a probing scenario and return what the guest reported (the forged
/// trailing ref is filtered by the host, so it never appears).
fn scenario(name: &str, port: MockHostingPort, policy: TargetPolicy) -> (Vec<String>, Arc<MockHostingPort>, Arc<MemoryAuditSink>) {
    let hn = honest();
    let port = Arc::new(port.setting("scenario", name));
    let audit = Arc::new(MemoryAuditSink::new());
    let p = approved(&hn, &port, policy, &audit);
    let out = p.list_owned().expect("list-owned");
    (out.into_iter().map(|s| s.trim_start_matches("ecs:").to_string()).collect(), port, audit)
}

#[test]
fn the_honest_provider_runs_the_whole_lifecycle_against_the_mock() {
    let hn = honest();
    let port = Arc::new(h::port());
    let audit = Arc::new(MemoryAuditSink::new());
    let p = approved(&hn, &port, h::policy(), &audit);

    assert_eq!(p.declaration().provider_id, "test_ecs");
    assert!(p.capability_hash().starts_with("sha256:"));
    assert!(p.supports("{}").unwrap());
    assert!(!p.supports(r#"{"gpu":1}"#).unwrap());
    assert_eq!(p.host_ref_for("h1").unwrap(), "ecs:c/gtc-infra-h1");
    assert!(p.validate_settings(r#"{"region":"x"}"#).unwrap().is_empty());
    assert_eq!(p.validate_settings("{}").unwrap()[0].code, "region-missing");
    assert_eq!(p.preflight().unwrap()[0].code, "reachable");

    assert_eq!(p.ensure_host(&spec(), "h1").unwrap(), HostOutcome::Pending);
    let seen = port.seen();
    let create = seen.iter().find(|c| c.headers.iter().any(|(_, v)| v.ends_with("CreateSecret"))).unwrap();
    let sent = String::from_utf8(create.body.clone().unwrap()).unwrap();
    assert!(sent.contains(&fake_credential()), "the API receives the real value");
    assert!(sent.contains("fp-abc"));
    assert_eq!(create.host, "secretsmanager.eu-west-1.amazonaws.com");

    match p.describe_host("ecs:c/gtc-infra-h1").unwrap() {
        HostOutcome::Ready(handle) => {
            assert_eq!(handle.host, "h1.infra.example.com");
            assert_eq!(handle.scheme, "https");
        }
        HostOutcome::Pending => panic!("expected ready"),
    }
    p.destroy("ecs:c/gtc-infra-h1", DestroyMode::Retain).unwrap();

    let events = audit.events();
    assert!(events.iter().any(|e| e.operation == "ensure-host" && e.endpoint == "aws.secretsmanager"));
    assert!(events.iter().all(|e| e.target_id == "t1" && e.extension_version == "0.1.0"));
    assert!(!format!("{events:?}").contains(&fake_credential()));
}

#[test]
fn creating_hosts_needs_an_approval_of_exactly_this_declaration() {
    let hn = honest();
    let audit = Arc::new(MemoryAuditSink::new());
    let port = Arc::new(h::port());
    let with = |policy: TargetPolicy| {
        hn.rt.hosting_provider(ID, h::ctx(port.clone(), policy, audit.clone())).unwrap()
    };
    let refused = |p: &HostingProvider<'_>, why: Refusal| match p.ensure_host(&spec(), "h1") {
        Err(HostingError::Refused(r)) => assert_eq!(r, why),
        other => panic!("expected {why:?}, got {other:?}"),
    };

    let unapproved = with(h::policy());
    refused(&unapproved, Refusal::NotApproved);
    let hash = unapproved.capability_hash().to_string();

    refused(&with(h::policy().approved("sha256:other")), Refusal::NeedsReapproval);
    let mut frozen = h::policy().approved(hash.clone());
    frozen.frozen = true;
    refused(&with(frozen.clone()), Refusal::Frozen);
    let mut disabled = h::policy().approved(hash.clone());
    disabled.enabled = false;
    refused(&with(disabled.clone()), Refusal::TargetDisabled);

    // Existing hosts stay readable and deletable under every one of those.
    for p in [with(h::policy()), with(frozen), with(disabled)] {
        assert!(matches!(p.describe_host("ecs:c/gtc-infra-h1"), Ok(HostOutcome::Ready(_))));
        p.destroy("ecs:c/gtc-infra-h1", DestroyMode::Retain).unwrap();
        assert!(p.list_owned().is_ok());
    }
    assert_eq!(with(h::policy().approved(hash)).ensure_host(&spec(), "h1").unwrap(), HostOutcome::Pending);
}

#[test]
fn a_handle_for_a_foreign_host_never_leaves_the_runtime() {
    let hn = honest();
    let port = Arc::new(h::port());
    let audit = Arc::new(MemoryAuditSink::new());
    let p = approved(&hn, &port, h::policy(), &audit);
    assert!(matches!(
        p.describe_host("ecs:c/gtc-infra-h-forged"),
        Err(HostingError::Refused(Refusal::HandleRejected))
    ));
    assert!(matches!(p.describe_host("arn:aws:iam::1:root"), Err(HostingError::Provider(HostError::Rejected))));
    assert!(matches!(p.host_ref_for("bad id!"), Err(HostingError::Provider(HostError::Rejected))));
}

#[test]
fn a_fabricated_ref_in_list_owned_is_dropped() {
    let (out, _p, _a) = scenario("ok", h::port(), h::policy());
    assert_eq!(out.len(), 1, "the forged arn: entry was filtered: {out:?}");
}

#[test]
fn malicious_undeclared_endpoint() {
    let (out, port, audit) = scenario("undeclared-endpoint", h::port(), h::policy());
    assert_eq!(out, vec!["not-declared"]);
    assert!(port.seen().is_empty());
    assert_eq!(audit.events()[0].outcome, Outcome::NotDeclared);
}

#[test]
fn malicious_undeclared_action_header_path_and_size() {
    for (name, expect) in [
        ("undeclared-action", "denied-by-policy"),
        ("bad-header", "denied-by-policy"),
        ("path-escape", "denied-by-policy"),
        ("oversized-request", "denied-by-policy"),
    ] {
        let (out, port, _a) = scenario(name, h::port(), h::policy());
        assert_eq!(out, vec![expect], "{name}");
        assert!(port.seen().is_empty(), "{name}: the port must never see a refused call");
    }
}

#[test]
fn malicious_undeclared_host_is_refused_even_for_a_declared_endpoint() {
    // The platform admin allowed a different domain than the endpoint's host.
    let narrow = TargetPolicy::new(vec!["*.example.org".into()], vec![]);
    let (out, port, _a) = scenario("ok", h::port(), narrow);
    assert_eq!(out, vec!["denied-by-policy"]);
    assert!(port.seen().is_empty());
    // And a setting that tries to steer the template off the allow-list.
    let steered = h::port().setting("region", "eu-west-1.evil.example.net/x");
    let (out, port, _a) = scenario("ok", steered, h::policy());
    assert_eq!(out, vec!["denied-by-policy"]);
    assert!(port.seen().is_empty());
    // No confirmed host at all: nothing may be called.
    let (out, ..) = scenario("ok", h::port(), TargetPolicy::new(vec![], vec![]));
    assert_eq!(out, vec!["denied-by-policy"]);
}

#[test]
fn malicious_call_flood_is_cut_at_the_budget() {
    let (out, port, _a) = scenario("flood", h::port(), h::policy());
    assert_eq!(out, vec!["first-denied-at:151"], "150 calls allowed, the 151st refused");
    assert_eq!(port.seen().len(), 150);
    let tight = h::policy().with_limits(HostingLimits { max_calls: 5, ..HostingLimits::default() });
    let (out, ..) = scenario("flood", h::port(), tight);
    assert_eq!(out, vec!["first-denied-at:6"]);
}

#[test]
fn malicious_oversized_response_is_dropped() {
    let big = h::port().respond(|_| Ok(PortResponse { status: 200, headers: vec![], body: vec![b'x'; 4096] }));
    let small = h::policy().with_limits(HostingLimits { max_response_bytes: 1024, ..HostingLimits::default() });
    let (out, ..) = scenario("ok", big, small);
    assert_eq!(out, vec!["too-large"]);
}

#[test]
fn a_hanging_port_is_cut_at_the_per_call_timeout() {
    let slow = h::port().delay(Duration::from_millis(400));
    let short = h::policy().with_limits(HostingLimits { call_timeout: Duration::from_millis(100), ..HostingLimits::default() });
    let (out, ..) = scenario("ok", slow, short);
    assert_eq!(out, vec!["timeout"]);
}

#[test]
fn malicious_attempts_to_read_a_secret_find_nothing() {
    let leaky = h::port()
        .setting("credential", "x-not-for-guests")
        .setting("secret_access_key", "x-not-for-guests")
        .setting("api-key", "x-not-for-guests")
        .setting("session_token", "x-not-for-guests")
        .setting("password", "x-not-for-guests");
    let (out, ..) = scenario("read-secret", leaky, h::policy());
    assert_eq!(
        out,
        vec![
            "credential:false",
            "secret_access_key:false",
            "api-key:false",
            "session_token:false",
            "password:false",
            "fingerprint:true",
        ]
    );
}

#[test]
fn echoing_the_credential_back_through_the_api_yields_a_redaction() {
    let echo = h::port().respond(|c| {
        Ok(PortResponse { status: 200, headers: vec![], body: c.body.clone().unwrap_or_default() })
    });
    let (out, port, audit) = scenario("echo-credential", echo, h::policy());
    let cred = fake_credential();
    assert!(port.seen()[0].body.as_ref().is_some_and(|b| String::from_utf8_lossy(b).contains(&cred)));
    assert!(!out.concat().contains(&cred), "the guest must not learn the value: {out:?}");
    assert!(out.concat().contains("[redacted]"));
    assert!(!format!("{:?}", audit.events()).contains(&cred));
}

#[test]
fn an_infinite_loop_is_interrupted_by_the_epoch_deadline() {
    let hn = h::harness(ExtensionKind::Deploy, ID, h::guest_wasm(false), true, Some(Duration::from_secs(2)));
    let port = Arc::new(h::scenario_port("loop"));
    let audit = Arc::new(MemoryAuditSink::new());
    let p = approved(&hn, &port, h::policy(), &audit);
    let t = Instant::now();
    match p.list_owned() {
        Err(HostingError::Deadline) => {}
        other => panic!("expected Deadline, got {other:?}"),
    }
    assert!(t.elapsed() < Duration::from_secs(10), "took {:?}", t.elapsed());
    assert_eq!(HostingError::Deadline.to_host_error(), HostError::Unreachable);
    // The runtime is not wedged: the next call on a fresh store works.
    let ok = Arc::new(h::scenario_port("ok"));
    let p = approved(&hn, &ok, h::policy(), &audit);
    assert!(p.list_owned().is_ok());
}

#[test]
fn the_per_invocation_limit_also_bounds_the_guest() {
    let hn = h::harness(ExtensionKind::Deploy, ID, h::guest_wasm(false), true, None);
    let port = Arc::new(h::scenario_port("loop"));
    let audit = Arc::new(MemoryAuditSink::new());
    let short = h::policy().with_limits(HostingLimits { invocation_timeout: Duration::from_secs(2), ..HostingLimits::default() });
    let p = approved(&hn, &port, short, &audit);
    assert!(matches!(p.list_owned(), Err(HostingError::Deadline)));
}

#[test]
fn a_component_that_reads_the_clock_does_not_instantiate() {
    let hn = h::harness(ExtensionKind::Deploy, ID, h::guest_wasm(true), true, None);
    let port = Arc::new(h::port());
    let audit = Arc::new(MemoryAuditSink::new());
    match hn.rt.hosting_provider(ID, h::ctx(port, h::policy(), audit)) {
        Err(HostingError::Trapped(m)) => assert!(m.contains("monotonic-clock"), "{m}"),
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(_) => panic!("a clock-reading guest must be refused at instantiation"),
    }
}

fn wat_importing(import: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(component (import "{import}" (instance (export "f" (func)))))"#
    ))
    .expect("wat")
}

#[test]
fn components_importing_secrets_http_or_a_clock_do_not_instantiate() {
    for import in [
        "greentic:extension-host/secrets@0.1.0",
        "greentic:extension-host/http@0.1.0",
        "greentic:extension-host/broker@0.1.0",
        "greentic:extension-host/llm@0.1.0",
        "wasi:clocks/monotonic-clock@0.2.6",
        "wasi:sockets/tcp@0.2.6",
        "wasi:filesystem/preopens@0.2.6",
    ] {
        let hn = h::harness(ExtensionKind::Deploy, ID, wat_importing(import), true, None);
        let port = Arc::new(h::port());
        let audit = Arc::new(MemoryAuditSink::new());
        assert!(
            matches!(hn.rt.hosting_provider(ID, h::ctx(port, h::policy(), audit)), Err(HostingError::Trapped(_))),
            "{import} must not link into a hosting extension"
        );
    }
}

#[test]
fn only_a_deploy_extension_offering_the_capability_is_a_provider() {
    let port = Arc::new(h::port());
    let audit = Arc::new(MemoryAuditSink::new());
    let no_cap = h::harness(ExtensionKind::Deploy, ID, h::guest_wasm(false), false, None);
    assert!(matches!(
        no_cap.rt.hosting_provider(ID, h::ctx(port.clone(), h::policy(), audit.clone())),
        Err(HostingError::NotAProvider(_))
    ));
    let wrong_kind = h::harness(ExtensionKind::Design, ID, h::guest_wasm(false), true, None);
    assert!(matches!(
        wrong_kind.rt.hosting_provider(ID, h::ctx(port, h::policy(), audit)),
        Err(HostingError::NotAProvider(_))
    ));
}

#[test]
fn no_other_extension_can_import_the_hosting_api() {
    let hn = h::harness(ExtensionKind::Design, ID, wat_importing("greentic:extension-hosting/api@0.1.0"), false, None);
    let err = hn.rt.invoke_tool(ID, "anything", "{}").expect_err("must not link");
    assert!(err.to_string().contains("extension-hosting"), "{err}");
}
