//! `${resource.credential}` substitution and response redaction.
//!
//! Substitution happens here, on the host side of the boundary, so the guest
//! can use the instance credential in a request (to store it, say, as the
//! value of a secret) without ever holding it. Redaction is the other half: an
//! API that echoes a request back must not turn the placeholder into a way to
//! READ the credential.

use super::port::SecretValue;

pub const CREDENTIAL_PLACEHOLDER: &str = "${resource.credential}";
pub const FINGERPRINT_PLACEHOLDER: &str = "${resource.credential_fingerprint}";
pub const REDACTED: &str = "[redacted]";

/// Values the placeholders stand for in one invocation.
pub struct Substitutions<'a> {
    pub credential: Option<&'a SecretValue>,
    pub fingerprint: Option<&'a str>,
}

impl Substitutions<'_> {
    /// Replace both placeholders in `text`. A placeholder with no value is left
    /// as it is, so the provider API rejects the request instead of the host
    /// silently sending an empty secret.
    #[must_use]
    pub fn apply(&self, text: &str) -> String {
        let mut out = text.to_string();
        if let Some(c) = self.credential {
            out = out.replace(CREDENTIAL_PLACEHOLDER, c.expose());
        }
        if let Some(f) = self.fingerprint {
            out = out.replace(FINGERPRINT_PLACEHOLDER, f);
        }
        out
    }

    /// Substitute in a body, only when it is UTF-8 (a binary body is sent as it
    /// is: a placeholder inside it is not a placeholder).
    #[must_use]
    pub fn apply_body(&self, body: Vec<u8>) -> Vec<u8> {
        match String::from_utf8(body) {
            Ok(text) if text.contains("${resource.") => self.apply(&text).into_bytes(),
            Ok(text) => text.into_bytes(),
            Err(e) => e.into_bytes(),
        }
    }
}

/// Replace every occurrence of every non-trivial secret in `bytes`.
///
/// Secrets shorter than 6 bytes are skipped: replacing a 2-byte "secret"
/// everywhere would corrupt responses while hiding nothing.
#[must_use]
pub fn redact_bytes(bytes: Vec<u8>, secrets: &[&str]) -> Vec<u8> {
    let mut out = bytes;
    for s in secrets {
        let needle = s.as_bytes();
        if needle.len() < 6 || out.len() < needle.len() {
            continue;
        }
        let mut next = Vec::with_capacity(out.len());
        let mut i = 0;
        while i < out.len() {
            if out[i..].starts_with(needle) {
                next.extend_from_slice(REDACTED.as_bytes());
                i += needle.len();
            } else {
                next.push(out[i]);
                i += 1;
            }
        }
        out = next;
    }
    out
}

/// The same for text (log lines, headers).
#[must_use]
pub fn redact_text(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    for s in secrets {
        if s.len() >= 6 {
            out = out.replace(s, REDACTED);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_in_text_and_utf8_bodies_only() {
        let c = SecretValue::new("s3cr3t-value");
        let subs = Substitutions {
            credential: Some(&c),
            fingerprint: Some("fp1"),
        };
        assert_eq!(
            subs.apply(
                "{\"v\":\"${resource.credential}\",\"t\":\"${resource.credential_fingerprint}\"}"
            ),
            "{\"v\":\"s3cr3t-value\",\"t\":\"fp1\"}"
        );
        assert_eq!(
            subs.apply_body(b"x=${resource.credential}".to_vec()),
            b"x=s3cr3t-value"
        );
        let binary = vec![0xff, 0xfe, b'$', b'{'];
        assert_eq!(subs.apply_body(binary.clone()), binary);
    }

    #[test]
    fn a_placeholder_without_a_value_is_left_alone() {
        let subs = Substitutions {
            credential: None,
            fingerprint: None,
        };
        assert_eq!(
            subs.apply("${resource.credential}"),
            "${resource.credential}"
        );
    }

    #[test]
    fn redaction_removes_every_occurrence_and_ignores_tiny_secrets() {
        let out = redact_bytes(b"a s3cr3t-value b s3cr3t-value".to_vec(), &["s3cr3t-value"]);
        assert_eq!(out, b"a [redacted] b [redacted]");
        assert_eq!(redact_bytes(b"abcabc".to_vec(), &["ab"]), b"abcabc");
        assert_eq!(
            redact_text("tok=s3cr3t-value", &["s3cr3t-value"]),
            "tok=[redacted]"
        );
    }

    #[test]
    fn debug_never_prints_a_secret() {
        let c = SecretValue::new("s3cr3t-value");
        assert!(!format!("{c:?}").contains("s3cr3t"));
    }
}
