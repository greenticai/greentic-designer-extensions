//! Request-shape rules for `api.call`: hosts, paths, methods, headers and the
//! per-endpoint action allow-list.
//!
//! Everything here is a pure function over strings so each rule can be pinned
//! by a table test. The ORDER in which `session` applies them is the security
//! argument; the rules themselves only say yes or no.

use super::error::DeclarationError;

/// Methods a provider may use. Closed.
pub const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];

/// Request header names a guest may set. Everything else, and in particular
/// anything that carries authority (`authorization`, `cookie`, `host`,
/// `x-amz-security-token`, `x-api-key`, `proxy-authorization`), is refused:
/// authority is the host's to attach.
pub const ALLOWED_REQUEST_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "x-amz-target",
    "if-match",
    "if-none-match",
    "idempotency-key",
    "x-request-id",
    "prefer",
];

/// Response headers handed back to the guest. Signing and authorisation
/// headers are never among them.
pub const ALLOWED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "etag",
    "retry-after",
    "date",
    "x-request-id",
    "x-amzn-requestid",
    "x-amz-request-id",
];

/// A request header value is a short single line.
pub const MAX_HEADER_VALUE_BYTES: usize = 1024;
pub const MAX_HEADERS: usize = 16;
pub const MAX_PATH_BYTES: usize = 2048;

/// One entry of an endpoint's `actions` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionRule {
    /// A named service action (`DescribeServices`), read from the
    /// `x-amz-target` header suffix or the `Action=` form field.
    Service(String),
    /// A REST rule: method and a path that is exact or ends in `*` (prefix).
    Rest { method: String, path: String },
}

impl ActionRule {
    /// # Errors
    ///
    /// A message naming the broken rule.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some((method, path)) = s.split_once(' ') {
            if !ALLOWED_METHODS.contains(&method) {
                return Err(format!("unknown method '{method}'"));
            }
            if !path.starts_with('/') || path.contains(char::is_whitespace) {
                return Err("a REST rule's path starts with '/' and has no spaces".into());
            }
            if path == "/*" {
                return Err("a REST rule may not allow every path".into());
            }
            if path.contains("..") || path[..path.len().saturating_sub(1)].contains('*') {
                return Err("'*' is only allowed as the last character".into());
            }
            return Ok(Self::Rest {
                method: method.to_string(),
                path: path.to_string(),
            });
        }
        let ok = !s.is_empty()
            && s.len() <= 64
            && s.starts_with(|c: char| c.is_ascii_alphabetic())
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c));
        if ok {
            Ok(Self::Service(s.to_string()))
        } else {
            Err("not a service action name".into())
        }
    }
}

/// Does any rule in `actions` allow this request? `action` is the service
/// action derived from the request, if there is one.
#[must_use]
pub fn action_allowed(
    actions: &[String],
    method: &str,
    path_only: &str,
    action: Option<&str>,
) -> bool {
    actions.iter().any(|a| match ActionRule::parse(a) {
        Ok(ActionRule::Service(name)) => action == Some(name.as_str()),
        Ok(ActionRule::Rest { method: m, path }) => {
            m == method
                && match path.strip_suffix('*') {
                    Some(prefix) => path_only.starts_with(prefix),
                    None => path_only == path,
                }
        }
        Err(_) => false,
    })
}

/// The service action a request names, from the places the AWS protocols put
/// it: the `x-amz-target` header (`Svc.Action`) or an `Action=` field of a
/// form-encoded body (Query protocol). `None` when neither is present.
#[must_use]
pub fn derive_action(headers: &[(String, String)], body: Option<&[u8]>) -> Option<String> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("x-amz-target") {
            return Some(v.rsplit('.').next().unwrap_or(v).to_string());
        }
    }
    let form = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("x-www-form-urlencoded"));
    if !form {
        return None;
    }
    let text = std::str::from_utf8(body?).ok()?;
    text.split('&')
        .find_map(|pair| pair.strip_prefix("Action="))
        .map(str::to_string)
}

/// `path` is path and query only: it starts with a single `/` and cannot carry
/// an authority, a scheme, a backslash, a control character or a traversal.
///
/// # Errors
///
/// A short reason for the audit record.
pub fn validate_path(path: &str) -> Result<&str, &'static str> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err("path length");
    }
    if !path.starts_with('/') || path.starts_with("//") {
        return Err("path must start with a single '/'");
    }
    if path.chars().any(|c| c.is_control() || c == '\\' || c == '#') {
        return Err("path has a forbidden character");
    }
    let only = path.split('?').next().unwrap_or(path);
    let lowered = only.to_ascii_lowercase();
    if lowered.contains("://")
        || lowered.contains("%2e%2e")
        || lowered.contains("%2f%2f")
        || lowered.contains("%5c")
        || only.split('/').any(|seg| seg == "..")
    {
        return Err("path traversal or embedded authority");
    }
    Ok(only)
}

/// # Errors
///
/// A short reason for the audit record.
pub fn validate_headers(headers: &[(String, String)]) -> Result<(), &'static str> {
    if headers.len() > MAX_HEADERS {
        return Err("too many headers");
    }
    for (k, v) in headers {
        let name = k.to_ascii_lowercase();
        if !ALLOWED_REQUEST_HEADERS.contains(&name.as_str()) {
            return Err("header not allowed");
        }
        if v.len() > MAX_HEADER_VALUE_BYTES || v.chars().any(char::is_control) {
            return Err("header value");
        }
    }
    Ok(())
}

/// A host template: lowercase DNS characters, `{key}` placeholders, and an
/// optional `:port` — no path, userinfo, query, wildcard or whitespace.
pub(crate) fn validate_host_template(t: &str) -> Result<(), DeclarationError> {
    let bad = |m: &str| DeclarationError::new(format!("host template '{t}': {m}"));
    if t.is_empty() || t.len() > 253 {
        return Err(bad("length"));
    }
    let mut depth = 0u8;
    for c in t.chars() {
        match c {
            '{' => {
                depth += 1;
                if depth > 1 {
                    return Err(bad("nested placeholder"));
                }
            }
            '}' => {
                if depth == 0 {
                    return Err(bad("unbalanced placeholder"));
                }
                depth -= 1;
            }
            c if depth == 1 && (c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') => {}
            c if depth == 0
                && (c.is_ascii_lowercase() || c.is_ascii_digit() || "-._:".contains(c)) => {}
            _ => return Err(bad("character not allowed")),
        }
    }
    if depth != 0 {
        return Err(bad("unbalanced placeholder"));
    }
    Ok(())
}

/// Fill `{key}` placeholders from target settings. `None` when a setting is
/// missing. A value may not smuggle structure into the host: after
/// substitution the host must be a well-formed `host[:port]`.
pub(crate) fn resolve_host(
    template: &str,
    setting: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let end = rest[start..].find('}')? + start;
        out.push_str(&setting(&rest[start + 1..end])?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    well_formed_host(&out).then_some(out)
}

/// `host[:port]` of DNS labels or an IPv4 literal; lowercase.
pub(crate) fn well_formed_host(h: &str) -> bool {
    let (name, port) = match h.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (h, None),
    };
    if let Some(p) = port
        && (p.is_empty() || p.len() > 5 || !p.chars().all(|c| c.is_ascii_digit()) || p == "0")
    {
        return false;
    }
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        })
}

/// The hostname without a port.
pub(crate) fn hostname(h: &str) -> &str {
    h.rsplit_once(':').map_or(h, |(n, _)| n)
}

/// `*.suffix` needs at least one label in front of the suffix; anything else
/// is an exact match. Substring and suffix-without-dot matches are refused, so
/// `evil-amazonaws.com` and `amazonaws.com.evil.net` do not match
/// `*.amazonaws.com`.
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = hostname(host);
    pattern.strip_prefix("*.").map_or_else(
        || pattern == host,
        |suffix| {
            host.len() > suffix.len() + 1
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        },
    )
}

/// Loopback, private, link-local and metadata destinations by name or literal.
/// Public-only by default: a private API host needs an explicit platform entry.
#[must_use]
pub(crate) fn is_private_host(h: &str) -> bool {
    let name = hostname(h);
    if name == "localhost"
        || name.ends_with(".localhost")
        || name.ends_with(".internal")
        || name.ends_with(".local")
        || name.ends_with(".localdomain")
        || name.ends_with(".lan")
        || !name.contains('.')
    {
        return true;
    }
    match name.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
        }
        // All-digit and hex/octal spellings that `inet_aton` would read as an
        // address are not valid DNS names we would trust either.
        Err(_) => name
            .split('.')
            .all(|l| l.chars().all(|c| c.is_ascii_digit()) || l.starts_with("0x")),
    }
}

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
