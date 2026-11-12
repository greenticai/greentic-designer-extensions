//! Lifecycle value types and the checks applied to what a guest returns.
//!
//! A guest's output is untrusted input to the admin: a handle pointing at a
//! foreign host would be handed to deployed workers as "the vector store", and
//! a free-text message would end up in a row. Everything a guest returns passes
//! through here before it leaves the runtime.

use super::error::Refusal;
use super::policy::TargetPolicy;

pub(crate) const MAX_REF_BYTES: usize = 512;
const MAX_MESSAGE_BYTES: usize = 512;
const MAX_EXTRAS: usize = 16;
const MAX_OWNED: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSpec {
    pub kind: String,
    pub version: String,
    pub size: String,
    /// The validated `hosting` object of the kind.
    pub hosting_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHandle {
    pub host_ref: String,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub extras: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOutcome {
    /// Not answering yet: ask again on the next reconcile pass.
    Pending,
    Ready(HostHandle),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyMode {
    Retain,
    DestroyData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Info,
    Warning,
    Error,
}

/// A finding from `validate-settings` or `preflight`, scrubbed and truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub code: String,
    pub message: String,
}

/// Control characters removed, cut at a char boundary.
pub(crate) fn scrub_text(s: &str, max: usize) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control()).collect();
    if out.len() > max {
        let mut cut = max;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    out
}

pub(crate) fn scrub_diagnostic(level: DiagnosticLevel, code: &str, message: &str) -> Diagnostic {
    let code: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
        .take(64)
        .collect();
    Diagnostic {
        level,
        code,
        message: scrub_text(message, MAX_MESSAGE_BYTES),
    }
}

/// A host-ref is short, printable and starts with the provider's declared
/// prefix.
pub(crate) fn ref_ok(r: &str, prefix: &str) -> bool {
    r.len() <= MAX_REF_BYTES
        && r.len() > prefix.len()
        && r.starts_with(prefix)
        && !r.chars().any(char::is_control)
}

/// Is `host` equal to or a subdomain of one of the allowed ingress domains?
fn in_ingress(host: &str, domains: &[String]) -> bool {
    domains.iter().any(|d| {
        let d = d.trim_start_matches("*.");
        host == d || host.strip_suffix(d).is_some_and(|p| p.ends_with('.'))
    })
}

/// A handle is exposed to deployed workers, so it must be HTTPS, on a port, in
/// a domain the platform admin named, with a ref the provider could have made.
pub(crate) fn validate_handle(
    h: HostHandle,
    ref_prefix: &str,
    policy: &TargetPolicy,
) -> Result<HostHandle, Refusal> {
    let host_ok = super::endpoint::well_formed_host(&h.host) && !h.host.contains(':');
    let extras_ok = h.extras.len() <= MAX_EXTRAS
        && h.extras.iter().all(|(k, v)| {
            k.len() <= 64 && v.len() <= 256 && !k.chars().chain(v.chars()).any(char::is_control)
        });
    if h.scheme == "https"
        && h.port != 0
        && host_ok
        && extras_ok
        && ref_ok(&h.host_ref, ref_prefix)
        && in_ingress(&h.host, &policy.ingress_domains)
    {
        Ok(h)
    } else {
        Err(Refusal::HandleRejected)
    }
}

/// Drop refs that do not carry the provider's prefix and cap the list: a
/// fabricated ref must never reach `destroy`.
pub(crate) fn filter_owned(refs: Vec<String>, prefix: &str) -> Vec<String> {
    refs.into_iter()
        .filter(|r| ref_ok(r, prefix))
        .take(MAX_OWNED)
        .collect()
}

pub(crate) fn host_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> TargetPolicy {
        TargetPolicy::new(vec![], vec!["infra.example.com".into()])
    }

    fn handle(host: &str, scheme: &str) -> HostHandle {
        HostHandle {
            host_ref: "ecs:c/gtc-infra-h1".into(),
            host: host.into(),
            port: 443,
            scheme: scheme.into(),
            extras: vec![],
        }
    }

    #[test]
    fn a_handle_must_be_https_inside_the_ingress_domains() {
        let p = policy();
        assert!(validate_handle(handle("h1.infra.example.com", "https"), "ecs:", &p).is_ok());
        for (host, scheme) in [
            ("h1.infra.example.com", "http"),
            ("evil.example.net", "https"),
            ("h1.infra.example.com.evil.net", "https"),
            ("xinfra.example.com", "https"),
            ("10.0.0.5", "https"),
        ] {
            assert_eq!(
                validate_handle(handle(host, scheme), "ecs:", &p),
                Err(Refusal::HandleRejected),
                "{host} {scheme}"
            );
        }
        let none = TargetPolicy::new(vec![], vec![]);
        assert!(validate_handle(handle("h1.infra.example.com", "https"), "ecs:", &none).is_err());
        assert!(validate_handle(handle("h1.infra.example.com", "https"), "k8s:", &p).is_err());
    }

    #[test]
    fn fabricated_refs_are_dropped_from_the_owned_list() {
        let kept = filter_owned(
            vec![
                "ecs:a/b".into(),
                "arn:aws:iam::1:root".into(),
                "ecs:".into(),
            ],
            "ecs:",
        );
        assert_eq!(kept, vec!["ecs:a/b".to_string()]);
    }

    #[test]
    fn guest_text_is_scrubbed_and_bounded() {
        let d = scrub_diagnostic(
            DiagnosticLevel::Error,
            "iam deny!\n",
            &format!("a\u{7}b{}", "x".repeat(2000)),
        );
        assert_eq!(d.code, "iamdeny");
        assert!(d.message.starts_with("ab"));
        assert!(d.message.len() <= 512);
    }
}
