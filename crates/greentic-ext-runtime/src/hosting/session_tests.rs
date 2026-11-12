use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::hosting::audit::MemoryAuditSink;
use crate::hosting::declaration::RawDescriptor;
use crate::hosting::mock::MockHostingPort;
use crate::hosting::policy::HostingLimits;
use crate::hosting::port::{PortError, PortResponse, TargetContext};

const CRED: &str = "cred-0123456789-abcdef";

fn decl() -> Arc<HostingDeclaration> {
    let endpoints = serde_json::json!([
        {"id": "aws.ecs", "host": "ecs.{region}.amazonaws.com",
         "profile": {"id": "aws-sigv4", "service": "ecs"},
         "actions": ["DescribeServices", "CreateService"]},
        {"id": "aws.secretsmanager", "host": "secretsmanager.{region}.amazonaws.com",
         "profile": {"id": "aws-sigv4", "service": "secretsmanager"},
         "actions": ["CreateSecret", "DescribeSecret"]},
        {"id": "k8s.api", "host": "{api_server}",
         "profile": {"id": "k8s-token"},
         "actions": ["GET /api/v1/namespaces/*"]}
    ]);
    Arc::new(
        HostingDeclaration::parse(&RawDescriptor {
            id: "aws_ecs".into(),
            display_name: "AWS ECS".into(),
            settings_schema: "{}".into(),
            credential_schema: "{}".into(),
            endpoints: endpoints.to_string(),
            capabilities: r#"{"persistent-data":true,"public-https":true,"reachability":"public"}"#
                .into(),
            ref_prefix: "ecs:".into(),
        })
        .expect("fixture declaration is valid"),
    )
}

fn port() -> MockHostingPort {
    MockHostingPort::new()
        .setting("region", "eu-west-1")
        .setting("api_server", "k8s.example.com:6443")
        .credential(CRED)
        .context(TargetContext {
            installation_id: "inst-1".into(),
            owner_tags: vec![("greentic:installation".into(), "inst-1".into())],
            credential_fingerprint: Some("fp-abc".into()),
        })
}

fn policy() -> TargetPolicy {
    TargetPolicy::new(
        vec!["*.amazonaws.com".into(), "k8s.example.com".into()],
        vec!["infra.example.com".into()],
    )
}

fn session_with(
    port: MockHostingPort,
    policy: TargetPolicy,
) -> (HostingSession, Arc<MemoryAuditSink>, Arc<MockHostingPort>) {
    let sink = Arc::new(MemoryAuditSink::new());
    let port = Arc::new(port);
    let s = HostingSession::new(
        decl(),
        port.clone(),
        policy,
        sink.clone(),
        SessionMeta {
            target_id: "t1".into(),
            extension_id: "greentic.hosting-test".into(),
            extension_version: "0.1.0".into(),
            operation: "ensure-host",
        },
    );
    (s, sink, port)
}

fn target(action: &str) -> Vec<(String, String)> {
    vec![("x-amz-target".into(), format!("Svc.{action}"))]
}

#[test]
fn an_approved_call_is_carried_and_audited_without_a_body() {
    let (mut s, sink, port) = session_with(port(), policy());
    let r = s
        .call(
            "aws.ecs",
            "POST",
            "/",
            Some(b"{}".to_vec()),
            target("DescribeServices"),
        )
        .expect("approved call");
    assert_eq!(r.status, 200);
    let seen = port.seen();
    assert_eq!(seen[0].host, "ecs.eu-west-1.amazonaws.com");
    let ev = &sink.events()[0];
    assert_eq!(ev.endpoint, "aws.ecs");
    assert_eq!(ev.action.as_deref(), Some("DescribeServices"));
    assert_eq!(ev.outcome, Outcome::Completed(200));
    assert_eq!(ev.operation, "ensure-host");
    assert_eq!(ev.request_bytes, 2);
}

#[test]
fn undeclared_endpoints_and_actions_are_refused_and_audited() {
    let (mut s, sink, port) = session_with(port(), policy());
    assert_eq!(
        s.call("evil.exfil", "POST", "/", None, vec![]).unwrap_err(),
        ApiError::NotDeclared
    );
    assert_eq!(
        s.call("aws.ecs", "POST", "/", None, target("DeleteCluster"))
            .unwrap_err(),
        ApiError::DeniedByPolicy
    );
    assert_eq!(
        s.call("aws.ecs", "POST", "/", None, vec![]).unwrap_err(),
        ApiError::DeniedByPolicy,
        "a request that names no action cannot satisfy an action allow-list"
    );
    assert!(port.seen().is_empty(), "the port never saw a refused call");
    let outcomes: Vec<_> = sink.events().into_iter().map(|e| e.outcome).collect();
    assert_eq!(outcomes[0], Outcome::NotDeclared);
    assert_eq!(outcomes[1], Outcome::Denied("action"));
}

#[test]
fn request_shape_rules_run_before_anything_is_carried() {
    let (mut s, _sink, port) = session_with(port(), policy());
    let ok = target("DescribeServices");
    for (method, path, headers) in [
        ("post", "/", ok.clone()),
        ("TRACE", "/", ok.clone()),
        ("POST", "//evil.com/", ok.clone()),
        ("POST", "/../x", ok.clone()),
        (
            "POST",
            "/",
            vec![("authorization".into(), "x".into()), ok[0].clone()],
        ),
    ] {
        assert_eq!(
            s.call("aws.ecs", method, path, None, headers).unwrap_err(),
            ApiError::DeniedByPolicy,
            "{method} {path}"
        );
    }
    assert!(port.seen().is_empty());
}

#[test]
fn the_host_must_be_inside_the_platform_allow_list_and_public() {
    let call = |p: TargetPolicy, m: MockHostingPort| {
        let (mut s, _k, port) = session_with(m, p);
        let r = s.call("aws.ecs", "POST", "/", None, target("DescribeServices"));
        (r, port.seen().len())
    };
    // The platform admin has not confirmed any host yet.
    let (r, seen) = call(TargetPolicy::new(vec![], vec![]), port());
    assert_eq!(r.unwrap_err(), ApiError::DeniedByPolicy);
    assert_eq!(seen, 0);
    // A setting that tries to steer the host out of the list.
    let (r, seen) = call(policy(), port().setting("region", "eu-west-1.evil.net/x"));
    assert_eq!(r.unwrap_err(), ApiError::DeniedByPolicy);
    assert_eq!(seen, 0);
    let (r, seen) = call(
        TargetPolicy::new(vec!["*.example.org".into()], vec![]),
        port(),
    );
    assert_eq!(r.unwrap_err(), ApiError::DeniedByPolicy);
    assert_eq!(seen, 0);

    // A private API server needs an explicit platform entry.
    let k8s = |p: TargetPolicy| {
        let (mut s, _k, _p) = session_with(port().setting("api_server", "10.1.2.3:6443"), p);
        s.call("k8s.api", "GET", "/api/v1/namespaces/x", None, vec![])
    };
    let mut allow_range = TargetPolicy::new(vec!["10.1.2.3".into()], vec![]);
    assert_eq!(
        k8s(allow_range.clone()).unwrap_err(),
        ApiError::DeniedByPolicy
    );
    allow_range.private_hosts = vec!["10.1.2.3:6443".into()];
    assert!(k8s(allow_range).is_ok());
}

#[test]
fn the_call_budget_counts_refused_calls_too() {
    let limits = HostingLimits {
        max_calls: 3,
        ..HostingLimits::default()
    };
    let (mut s, sink, _p) = session_with(port(), policy().with_limits(limits));
    for _ in 0..3 {
        let _ = s.call("evil", "GET", "/", None, vec![]);
    }
    assert_eq!(
        s.call("aws.ecs", "POST", "/", None, target("DescribeServices"))
            .unwrap_err(),
        ApiError::DeniedByPolicy
    );
    assert_eq!(sink.events()[3].outcome, Outcome::Denied("call-budget"));
}

#[test]
fn the_invocation_deadline_stops_further_calls() {
    let limits = HostingLimits {
        invocation_timeout: Duration::from_millis(30),
        ..HostingLimits::default()
    };
    let (mut s, _k, port) = session_with(port(), policy().with_limits(limits));
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(
        s.call("aws.ecs", "POST", "/", None, target("DescribeServices"))
            .unwrap_err(),
        ApiError::Timeout
    );
    assert!(port.seen().is_empty());
}

#[test]
fn a_port_that_overruns_its_deadline_is_a_timeout() {
    let limits = HostingLimits {
        call_timeout: Duration::from_millis(20),
        ..HostingLimits::default()
    };
    let (mut s, _k, port) = session_with(
        port().delay(Duration::from_millis(80)),
        policy().with_limits(limits),
    );
    assert_eq!(
        s.call("aws.ecs", "POST", "/", None, target("DescribeServices"))
            .unwrap_err(),
        ApiError::Timeout
    );
    assert_eq!(port.seen()[0].timeout, Duration::from_millis(20));
}

#[test]
fn sizes_are_capped_both_ways() {
    let limits = HostingLimits {
        max_request_bytes: 8,
        max_response_bytes: 16,
        ..HostingLimits::default()
    };
    let big = port().respond(|_| {
        Ok(PortResponse {
            status: 200,
            headers: vec![],
            body: vec![b'x'; 17],
        })
    });
    let (mut s, sink, port) = session_with(big, policy().with_limits(limits));
    assert_eq!(
        s.call(
            "aws.ecs",
            "POST",
            "/",
            Some(vec![0; 9]),
            target("DescribeServices")
        )
        .unwrap_err(),
        ApiError::DeniedByPolicy
    );
    assert_eq!(
        s.call("aws.ecs", "POST", "/", None, target("DescribeServices"))
            .unwrap_err(),
        ApiError::TooLarge
    );
    assert_eq!(port.seen().len(), 1);
    assert_eq!(sink.events()[1].outcome, Outcome::TooLarge);

    let err = MockHostingPort::new()
        .setting("region", "eu-west-1")
        .respond(|_| Err(PortError::TooLarge));
    let (mut s, _k, _p) = session_with(err, policy());
    assert_eq!(
        s.call("aws.ecs", "POST", "/", None, target("DescribeServices"))
            .unwrap_err(),
        ApiError::TooLarge
    );
}

#[test]
fn placeholders_are_substituted_host_side_and_the_value_never_comes_back() {
    let echo = port().respond(|c| {
        Ok(PortResponse {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Authorization".into(), "AWS4 sig".into()),
                ("Set-Cookie".into(), "a=b".into()),
                ("X-Amz-Request-Id".into(), format!("id-{CRED}")),
            ],
            body: c.body.clone().unwrap_or_default(),
        })
    });
    let (mut s, sink, port) = session_with(echo, policy());
    let body =
        br#"{"SecretString":"${resource.credential}","tag":"${resource.credential_fingerprint}"}"#;
    let mut headers = target("CreateSecret");
    headers.push((
        "idempotency-key".into(),
        "k-${resource.credential_fingerprint}".into(),
    ));
    let r = s
        .call(
            "aws.secretsmanager",
            "POST",
            "/",
            Some(body.to_vec()),
            headers,
        )
        .expect("create secret");

    // The provider API received the real value ...
    let sent = String::from_utf8(port.seen()[0].body.clone().unwrap()).unwrap();
    assert!(sent.contains(CRED) && sent.contains("fp-abc"), "{sent}");
    assert!(port.seen()[0].headers.iter().any(|(_, v)| v == "k-fp-abc"));
    // ... and the guest got an echo with the credential redacted.
    let back = String::from_utf8(r.body).unwrap();
    assert!(!back.contains(CRED), "{back}");
    assert!(back.contains("[redacted]") && back.contains("fp-abc"));
    // Only benign response headers survive, themselves redacted.
    let names: Vec<_> = r
        .headers
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    assert_eq!(names, vec!["content-type", "x-amz-request-id"]);
    assert!(r.headers.iter().all(|(_, v)| !v.contains(CRED)));
    // The audit stream names the call and nothing it carried.
    assert!(!format!("{:?}", sink.events()).contains(CRED));
}

#[test]
fn values_the_port_holds_are_redacted_too() {
    let echo = port().also_redact("AKIAEXAMPLEKEYID0001").respond(|_| {
        Ok(PortResponse {
            status: 200,
            headers: vec![],
            body: b"signed by AKIAEXAMPLEKEYID0001".to_vec(),
        })
    });
    let (mut s, _k, _p) = session_with(echo, policy());
    let r = s
        .call("aws.ecs", "POST", "/", None, target("DescribeServices"))
        .unwrap();
    assert_eq!(r.body, b"signed by [redacted]");
}

#[test]
fn target_get_never_answers_with_key_material() {
    let (s, _k, _p) = session_with(
        port()
            .setting("credential", "x-secret-value")
            .setting("secret_access_key", "x-secret-value")
            .setting("api-key", "x-secret-value")
            .setting("kms_key_id", "alias/ok"),
        policy(),
    );
    for k in [
        "credential",
        "secret_access_key",
        "api-key",
        "session_token",
        "password",
        "private_key",
        "kubeconfig",
        "bearer-token",
        "has space",
        "UPPER",
        "",
    ] {
        assert_eq!(s.target_get(k), None, "{k:?}");
    }
    assert_eq!(s.target_get("region").as_deref(), Some("eu-west-1"));
    assert_eq!(s.target_get("kms_key_id").as_deref(), Some("alias/ok"));
    assert_eq!(s.target_get("installation-id").as_deref(), Some("inst-1"));
    assert_eq!(
        s.target_get("credential-fingerprint").as_deref(),
        Some("fp-abc")
    );
    let tags: Vec<[String; 2]> =
        serde_json::from_str(&s.target_get("owner-tags").unwrap()).unwrap();
    assert_eq!(tags[0][1], "inst-1");
}

#[test]
fn user_info_is_stripped_from_log_lines() {
    assert_eq!(
        strip_userinfo("dial https://user:pw@host.example/path ok"),
        "dial https://<redacted>@host.example/path ok"
    );
    assert_eq!(strip_userinfo("no urls here"), "no urls here");
}

#[test]
fn limits_are_clamped_to_the_platform_maximum() {
    let l = HostingLimits {
        max_request_bytes: usize::MAX,
        max_response_bytes: usize::MAX,
        call_timeout: Duration::from_hours(24),
        invocation_timeout: Duration::from_hours(24),
        max_calls: u32::MAX,
        max_log_lines: u32::MAX,
        max_log_bytes: usize::MAX,
    }
    .clamped();
    assert_eq!(l.max_calls, crate::hosting::platform_max::CALLS);
    assert_eq!(
        l.invocation_timeout,
        crate::hosting::platform_max::INVOCATION_TIMEOUT
    );
    assert_eq!(
        l.max_response_bytes,
        crate::hosting::platform_max::RESPONSE_BYTES
    );
    let z = HostingLimits {
        max_calls: 0,
        call_timeout: Duration::ZERO,
        ..HostingLimits::default()
    }
    .clamped();
    assert!(z.max_calls >= 1 && !z.call_timeout.is_zero());
}
