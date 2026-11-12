//! Test-only hosting provider. One lifecycle implementation, many behaviours:
//! the `scenario` target setting picks what `list-owned` / `ensure-host` /
//! `describe-host` do, so a single signed component can play the honest
//! provider and every malicious one. Results of probing scenarios come back as
//! the strings of `list-owned`, which is the one export that returns free text
//! to the test.

wit_bindgen::generate!({ path: "../../wit/extension-hosting.wit", world: "hosting-extension" });

use exports::greentic::extension_hosting::provider::{
    DestroyMode, Diagnostic, DiagnosticLevel, Guest, HostError, HostHandle, HostOutcome, HostSpec,
    ProviderDescriptor,
};
use greentic::extension_hosting::api::{self, ApiError};
use greentic::extension_hosting::log::{self, Level};
use greentic::extension_hosting::target;

struct G;

const ENDPOINTS: &str = r#"[
 {"id":"aws.ecs","host":"ecs.{region}.amazonaws.com",
  "profile":{"id":"aws-sigv4","service":"ecs"},
  "actions":["DescribeServices","CreateService"]},
 {"id":"aws.secretsmanager","host":"secretsmanager.{region}.amazonaws.com",
  "profile":{"id":"aws-sigv4","service":"secretsmanager"},
  "actions":["CreateSecret","DescribeSecret"]}
]"#;

fn scenario() -> String {
    target::get("scenario").unwrap_or_else(|| "lifecycle".to_string())
}

fn tag(e: ApiError) -> &'static str {
    match e {
        ApiError::NotDeclared => "not-declared",
        ApiError::DeniedByPolicy => "denied-by-policy",
        ApiError::Timeout => "timeout",
        ApiError::Transport => "transport",
        ApiError::TooLarge => "too-large",
    }
}

fn target_header(action: &str) -> Vec<(String, String)> {
    vec![("x-amz-target".into(), format!("Svc.{action}"))]
}

fn ecs(action: &str, body: &[u8]) -> Result<api::Response, ApiError> {
    api::call("aws.ecs", "POST", "/", Some(body), &target_header(action))
}

fn probe(r: Result<api::Response, ApiError>) -> String {
    match r {
        Ok(resp) => format!("ok:{}:{}", resp.status, String::from_utf8_lossy(&resp.body)),
        Err(e) => tag(e).to_string(),
    }
}

fn handle() -> HostHandle {
    HostHandle {
        host_ref: "ecs:c/gtc-infra-h1".into(),
        host: "h1.infra.example.com".into(),
        port: 443,
        scheme: "https".into(),
        extras: vec![],
    }
}

fn run_scenario(name: &str) -> Vec<String> {
    match name {
        "ok" => vec![probe(ecs("DescribeServices", b"{}"))],
        "undeclared-endpoint" => vec![probe(api::call("evil.exfil", "POST", "/", None, &[]))],
        "undeclared-action" => vec![probe(ecs("DeleteCluster", b"{}"))],
        "bad-header" => vec![probe(api::call(
            "aws.ecs",
            "POST",
            "/",
            None,
            &[
                ("x-amz-target".into(), "Svc.DescribeServices".into()),
                ("authorization".into(), "AWS4-HMAC-SHA256 forged".into()),
            ],
        ))],
        "path-escape" => vec![probe(api::call(
            "aws.ecs",
            "POST",
            "//evil.example.net/x",
            None,
            &target_header("DescribeServices"),
        ))],
        "oversized-request" => vec![probe(ecs("DescribeServices", &vec![b'x'; 2 * 1024 * 1024]))],
        "flood" => {
            let mut denied_at = 0u32;
            for i in 1..=400u32 {
                if matches!(ecs("DescribeServices", b"{}"), Err(ApiError::DeniedByPolicy)) {
                    denied_at = i;
                    break;
                }
            }
            vec![format!("first-denied-at:{denied_at}")]
        }
        "read-secret" => ["credential", "secret_access_key", "api-key", "session_token", "password"]
            .iter()
            .map(|k| format!("{k}:{}", target::get(k).is_some()))
            .chain([
                format!("fingerprint:{}", target::get("credential-fingerprint").is_some()),
            ])
            .collect(),
        "echo-credential" => vec![probe(api::call(
            "aws.secretsmanager",
            "POST",
            "/",
            Some(br#"{"SecretString":"${resource.credential}"}"#),
            &target_header("CreateSecret"),
        ))],
        "loop" => {
            let mut n = 0u64;
            loop {
                n = std::hint::black_box(n.wrapping_add(1));
            }
        }
        #[cfg(feature = "sleeper")]
        "sleep" => {
            std::thread::sleep(std::time::Duration::from_secs(1));
            vec!["slept".into()]
        }
        other => vec![format!("unknown-scenario:{other}")],
    }
}

impl Guest for G {
    fn describe_provider() -> ProviderDescriptor {
        ProviderDescriptor {
            id: "test_ecs".into(),
            display_name: "Test ECS".into(),
            settings_schema: r#"{"type":"object","properties":{"region":{"type":"string"}}}"#.into(),
            credential_schema: r#"{"type":"object"}"#.into(),
            endpoints: ENDPOINTS.into(),
            capabilities:
                r#"{"persistent-data":true,"public-https":true,"reachability":"public"}"#.into(),
            ref_prefix: "ecs:".into(),
        }
    }

    fn validate_settings(settings_json: String) -> Vec<Diagnostic> {
        if settings_json.contains("\"region\"") {
            Vec::new()
        } else {
            vec![Diagnostic {
                level: DiagnosticLevel::Error,
                code: "region-missing".into(),
                message: "region is required".into(),
            }]
        }
    }

    fn preflight() -> Vec<Diagnostic> {
        let ok = matches!(ecs("DescribeServices", b"{}"), Ok(r) if r.status == 200);
        vec![Diagnostic {
            level: if ok { DiagnosticLevel::Info } else { DiagnosticLevel::Error },
            code: if ok { "reachable" } else { "unreachable" }.into(),
            message: "preflight".into(),
        }]
    }

    fn supports(hosting_json: String) -> bool {
        !hosting_json.contains("\"gpu\"")
    }

    fn host_ref_for(host_id: String) -> String {
        format!("ecs:c/gtc-infra-{host_id}")
    }

    fn ensure_host(_spec: HostSpec, _host_id: String) -> Result<HostOutcome, HostError> {
        log::log(Level::Info, "ensure-host start");
        if scenario() != "lifecycle" {
            return Ok(HostOutcome::Pending);
        }
        let created = api::call(
            "aws.secretsmanager",
            "POST",
            "/",
            Some(br#"{"SecretString":"${resource.credential}","Tags":[{"Key":"fp","Value":"${resource.credential_fingerprint}"}]}"#),
            &target_header("CreateSecret"),
        );
        match created {
            Ok(r) if r.status == 200 => {}
            Ok(_) => return Err(HostError::Rejected),
            Err(_) => return Err(HostError::Unreachable),
        }
        ecs("DescribeServices", b"{}").map_err(|_| HostError::Unreachable)?;
        Ok(HostOutcome::Pending)
    }

    fn describe_host(host_ref: String) -> Result<HostOutcome, HostError> {
        if host_ref.ends_with("-h-forged") {
            return Ok(HostOutcome::Ready(HostHandle {
                host: "evil.example.net".into(),
                ..handle()
            }));
        }
        match ecs("DescribeServices", b"{}") {
            Ok(_) => Ok(HostOutcome::Ready(handle())),
            Err(_) => Err(HostError::Unreachable),
        }
    }

    fn list_owned() -> Result<Vec<String>, HostError> {
        // Results ride back as refs so they pass the host's prefix filter; the
        // trailing forged ref must NOT come back.
        let mut out: Vec<String> = run_scenario(&scenario())
            .into_iter()
            .map(|s| format!("ecs:{s}"))
            .collect();
        out.push("arn:aws:iam::1:root".into());
        Ok(out)
    }

    fn destroy(_host_ref: String, _mode: DestroyMode) -> Result<(), HostError> {
        ecs("DescribeServices", b"{}").map(|_| ()).map_err(|_| HostError::Unreachable)
    }
}

export!(G);
