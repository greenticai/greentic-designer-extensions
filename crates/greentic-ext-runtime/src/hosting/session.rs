//! The policy engine: one [`HostingSession`] per lifecycle invocation.
//!
//! The session is what the guest's three imports (`api.call`, `target.get`,
//! `log`) are wired to. It owns the counters (calls, log lines), the
//! invocation clock, and the order in which the rules run, which IS the
//! security argument:
//!
//! 1. call budget (counted even for refused calls, so a flood of refusals is
//!    bounded too), then the invocation deadline
//! 2. the endpoint id must be declared (a guest names an id, never a host)
//! 3. method, path shape, header allow-list and request size
//! 4. the action must be one the endpoint declared
//! 5. the host is built from the endpoint's template and the target settings,
//!    then must sit inside the platform admin's `api_hosts` and must not be a
//!    private address unless the admin listed it
//! 6. only now are placeholders substituted and the port asked to carry the call
//! 7. the answer is size-checked, header-filtered and redacted before the guest
//!    sees it
//!
//! Nothing before step 6 touches a credential, and nothing after it returns one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::audit::{AuditEvent, AuditSink, Outcome};
use super::declaration::HostingDeclaration;
use super::endpoint::{
    ALLOWED_METHODS, ALLOWED_RESPONSE_HEADERS, action_allowed, derive_action, host_matches,
    is_private_host, resolve_host, validate_headers, validate_path,
};
use super::placeholder::{Substitutions, redact_bytes, redact_text};
use super::policy::TargetPolicy;
use super::port::{AuthorizedCall, HostingPort, PortError, SecretValue};

/// Who and what a session is running for. Copied into every audit record.
#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub target_id: String,
    pub extension_id: String,
    pub extension_version: String,
    pub operation: &'static str,
}

/// `api.call` failure, mirroring the WIT `api-error` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    NotDeclared,
    DeniedByPolicy,
    Timeout,
    Transport,
    TooLarge,
}

/// What the guest receives.
#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Log severity, mirroring the WIT `level` enum.
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub struct HostingSession {
    decl: Arc<HostingDeclaration>,
    port: Arc<dyn HostingPort>,
    policy: TargetPolicy,
    audit: Arc<dyn AuditSink>,
    meta: SessionMeta,
    started: Instant,
    calls: u32,
    log_lines: u32,
    credential: Option<SecretValue>,
    fingerprint: Option<String>,
    redactions: Vec<String>,
}

/// Names that look like key material are never answered by `target.get`.
const SECRETISH: &[&str] = &[
    "credential",
    "secret",
    "token",
    "password",
    "passwd",
    "private",
    "api-key",
    "api_key",
    "apikey",
    "access-key",
    "access_key",
    "bearer",
    "kubeconfig",
];

fn looks_secret(key: &str) -> bool {
    SECRETISH.iter().any(|s| key.contains(s))
}

fn clean_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
}

fn short(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(64).collect()
}

impl HostingSession {
    #[must_use]
    pub fn new(
        decl: Arc<HostingDeclaration>,
        port: Arc<dyn HostingPort>,
        mut policy: TargetPolicy,
        audit: Arc<dyn AuditSink>,
        meta: SessionMeta,
    ) -> Self {
        policy.limits = policy.limits.clamped();
        let credential = port.instance_credential();
        let ctx = port.context();
        let mut redactions: Vec<String> = port
            .redaction_values()
            .iter()
            .map(|s| s.expose().to_string())
            .collect();
        if let Some(c) = &credential {
            redactions.push(c.expose().to_string());
        }
        Self {
            decl,
            port,
            policy,
            audit,
            meta,
            started: Instant::now(),
            calls: 0,
            log_lines: 0,
            credential,
            fingerprint: ctx.credential_fingerprint,
            redactions,
        }
    }

    fn setting(&self, key: &str) -> Option<String> {
        (clean_key(key) && !looks_secret(key))
            .then(|| self.port.target_setting(key))
            .flatten()
    }

    /// `target.get`.
    #[must_use]
    pub fn target_get(&self, key: &str) -> Option<String> {
        match key {
            "installation-id" => Some(self.port.context().installation_id),
            "owner-tags" => {
                let tags: Vec<[String; 2]> = self
                    .port
                    .context()
                    .owner_tags
                    .into_iter()
                    .map(|(k, v)| [k, v])
                    .collect();
                serde_json::to_string(&tags).ok()
            }
            "credential-fingerprint" => self.fingerprint.clone(),
            _ => self.setting(key),
        }
    }

    /// `log`. Bounded, control characters removed, secrets and URL userinfo
    /// scrubbed; never an input to anything but the tracing stream.
    pub fn log(&mut self, level: LogLevel, message: &str) {
        if self.log_lines >= self.policy.limits.max_log_lines {
            return;
        }
        self.log_lines += 1;
        let mut line: String = message
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let refs: Vec<&str> = self.redactions.iter().map(String::as_str).collect();
        line = redact_text(&line, &refs);
        line = strip_userinfo(&line);
        if line.len() > self.policy.limits.max_log_bytes {
            let mut cut = self.policy.limits.max_log_bytes;
            while !line.is_char_boundary(cut) {
                cut -= 1;
            }
            line.truncate(cut);
        }
        let (ext, target) = (&self.meta.extension_id, &self.meta.target_id);
        match level {
            LogLevel::Trace => tracing::trace!(%ext, %target, "hosting guest: {line}"),
            LogLevel::Debug => tracing::debug!(%ext, %target, "hosting guest: {line}"),
            LogLevel::Info => tracing::info!(%ext, %target, "hosting guest: {line}"),
            LogLevel::Warn => tracing::warn!(%ext, %target, "hosting guest: {line}"),
            LogLevel::Error => tracing::error!(%ext, %target, "hosting guest: {line}"),
        }
    }

    /// `api.call`.
    pub fn call(
        &mut self,
        endpoint_id: &str,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        headers: Vec<(String, String)>,
    ) -> Result<ApiResponse, ApiError> {
        self.calls += 1;
        let begun = Instant::now();
        let mut rec = Record {
            index: self.calls,
            endpoint: short(endpoint_id),
            method: short(method),
            action: None,
            request_bytes: body.as_ref().map_or(0, Vec::len),
            response_bytes: 0,
        };
        let result = self.gate_and_carry(endpoint_id, method, path, body, headers, &mut rec);
        let outcome = match &result {
            Ok(r) => Outcome::Completed(r.status),
            Err(Refused::Deny(reason)) => Outcome::Denied(reason),
            Err(Refused::Api(ApiError::NotDeclared)) => Outcome::NotDeclared,
            Err(Refused::Api(ApiError::Timeout)) => Outcome::Timeout,
            Err(Refused::Api(ApiError::Transport)) => Outcome::Transport,
            Err(Refused::Api(ApiError::TooLarge)) => Outcome::TooLarge,
            Err(Refused::Api(ApiError::DeniedByPolicy)) => Outcome::Denied("policy"),
        };
        self.audit.record(AuditEvent {
            target_id: self.meta.target_id.clone(),
            extension_id: self.meta.extension_id.clone(),
            extension_version: self.meta.extension_version.clone(),
            operation: self.meta.operation,
            call_index: rec.index,
            endpoint: rec.endpoint,
            method: rec.method,
            action: rec.action,
            outcome,
            duration_ms: u64::try_from(begun.elapsed().as_millis()).unwrap_or(u64::MAX),
            request_bytes: rec.request_bytes,
            response_bytes: rec.response_bytes,
        });
        result.map_err(|r| match r {
            Refused::Deny(_) => ApiError::DeniedByPolicy,
            Refused::Api(e) => e,
        })
    }

    fn remaining(&self) -> Option<Duration> {
        self.policy
            .limits
            .invocation_timeout
            .checked_sub(self.started.elapsed())
            .filter(|d| !d.is_zero())
    }

    fn gate_and_carry(
        &self,
        endpoint_id: &str,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        headers: Vec<(String, String)>,
        rec: &mut Record,
    ) -> Result<ApiResponse, Refused> {
        let limits = self.policy.limits;
        if self.calls > limits.max_calls {
            return Err(Refused::Deny("call-budget"));
        }
        let Some(remaining) = self.remaining() else {
            return Err(Refused::Api(ApiError::Timeout));
        };
        let Some(endpoint) = self.decl.endpoint(endpoint_id) else {
            return Err(Refused::Api(ApiError::NotDeclared));
        };
        if !ALLOWED_METHODS.contains(&method) {
            return Err(Refused::Deny("method"));
        }
        let path_only = validate_path(path).map_err(Refused::Deny)?;
        validate_headers(&headers).map_err(Refused::Deny)?;
        if body
            .as_ref()
            .is_some_and(|b| b.len() > limits.max_request_bytes)
        {
            return Err(Refused::Deny("request-too-large"));
        }
        let action = derive_action(&headers, body.as_deref());
        rec.action = Some(
            action
                .clone()
                .unwrap_or_else(|| format!("{method} {}", short(path_only))),
        );
        if !action_allowed(&endpoint.actions, method, path_only, action.as_deref()) {
            return Err(Refused::Deny("action"));
        }
        let host = resolve_host(&endpoint.host, |k| self.setting(k))
            .ok_or(Refused::Deny("host-unresolved"))?;
        if !self.policy.api_hosts.iter().any(|p| host_matches(p, &host)) {
            return Err(Refused::Deny("host-not-allowed"));
        }
        if is_private_host(&host) && !self.policy.private_hosts.contains(&host) {
            return Err(Refused::Deny("private-host"));
        }

        let subs = Substitutions {
            credential: self.credential.as_ref(),
            fingerprint: self.fingerprint.as_deref(),
        };
        let headers: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k, subs.apply(&v)))
            .collect();
        let body = body.map(|b| subs.apply_body(b));
        if body
            .as_ref()
            .is_some_and(|b| b.len() > limits.max_request_bytes)
        {
            return Err(Refused::Deny("request-too-large"));
        }
        let timeout = limits.call_timeout.min(remaining);
        let call = AuthorizedCall {
            endpoint,
            host,
            method: method.to_string(),
            path: path.to_string(),
            headers,
            body,
            timeout,
            max_response_bytes: limits.max_response_bytes,
        };
        let sent = Instant::now();
        let resp = self.port.execute(&call).map_err(|e| match e {
            PortError::Timeout => Refused::Api(ApiError::Timeout),
            PortError::Transport => Refused::Api(ApiError::Transport),
            PortError::TooLarge => Refused::Api(ApiError::TooLarge),
        })?;
        // A port that ignores its deadline is still held to it.
        if sent.elapsed() > timeout {
            return Err(Refused::Api(ApiError::Timeout));
        }
        rec.response_bytes = resp.body.len();
        if resp.body.len() > limits.max_response_bytes {
            return Err(Refused::Api(ApiError::TooLarge));
        }
        let refs: Vec<&str> = self.redactions.iter().map(String::as_str).collect();
        Ok(ApiResponse {
            status: resp.status,
            headers: resp
                .headers
                .into_iter()
                .filter(|(k, _)| {
                    ALLOWED_RESPONSE_HEADERS.contains(&k.to_ascii_lowercase().as_str())
                })
                .map(|(k, v)| (k, redact_text(&v, &refs)))
                .collect(),
            body: redact_bytes(resp.body, &refs),
        })
    }
}

struct Record {
    index: u32,
    endpoint: String,
    method: String,
    action: Option<String>,
    request_bytes: usize,
    response_bytes: usize,
}

enum Refused {
    Deny(&'static str),
    Api(ApiError),
}

/// `scheme://user:pass@host` -> `scheme://<redacted>@host`.
fn strip_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        out.push_str(&rest[..i + 3]);
        rest = &rest[i + 3..];
        let end = rest
            .find(|c: char| c == '/' || c.is_whitespace())
            .unwrap_or(rest.len());
        if let Some(at) = rest[..end].rfind('@') {
            out.push_str("<redacted>@");
            rest = &rest[at + 1..];
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
