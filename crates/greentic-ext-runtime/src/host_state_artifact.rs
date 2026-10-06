//! `Host` impl for the `greentic:extension-host/artifact` import.

use crate::host_bindings::design_v04::greentic::extension_host::artifact::{self, ArtifactError};
use crate::host_ports::{ArtifactPortError, ArtifactPutRequest};
use crate::host_state::HostState;

/// Largest single artifact an extension may store (spec §3.4).
pub(crate) const MAX_ARTIFACT_BYTES: usize = 10 * 1024 * 1024;
/// Longest accepted `name`, in bytes.
pub(crate) const MAX_ARTIFACT_NAME_BYTES: usize = 255;
/// Longest accepted `mime-type`, in bytes.
pub(crate) const MAX_MIME_BYTES: usize = 127;

fn invalid(field: &str, why: &str) -> ArtifactError {
    ArtifactError::InvalidInput(format!("{field}: {why}"))
}

fn check_name(name: &str) -> Result<(), ArtifactError> {
    if name.trim().is_empty() {
        return Err(invalid("name", "is blank"));
    }
    if name.len() > MAX_ARTIFACT_NAME_BYTES {
        return Err(invalid("name", "is too long"));
    }
    // The name is shown to users and used as a file name downstream: no path
    // separators and no control characters (NUL and newlines included).
    if name
        .chars()
        .any(|c| c == '/' || c == '\\' || c.is_control())
    {
        return Err(invalid(
            "name",
            "contains a path separator or control character",
        ));
    }
    Ok(())
}

fn check_mime(mime: &str) -> Result<(), ArtifactError> {
    if mime.trim().is_empty() {
        return Err(invalid("mime-type", "is blank"));
    }
    if mime.len() > MAX_MIME_BYTES {
        return Err(invalid("mime-type", "is too long"));
    }
    // A bare `type/subtype`. Parameters (`; charset=`) and whitespace are the
    // caller's to strip; the host store allow-lists on the bare type.
    if mime
        .chars()
        .any(|c| c.is_whitespace() || c == ';' || c.is_control())
        || !mime.contains('/')
    {
        return Err(invalid("mime-type", "must be a bare type/subtype"));
    }
    Ok(())
}

impl artifact::Host for HostState {
    fn put(
        &mut self,
        bytes: Vec<u8>,
        mime_type: String,
        name: String,
    ) -> Result<String, ArtifactError> {
        // 1. Tenant first: nothing is stored without one, and a port never has
        //    to defend against a blank scope.
        if self
            .call_ctx
            .tenant
            .as_deref()
            .is_none_or(|t| t.trim().is_empty())
        {
            tracing::warn!(ext = %self.extension_id, "artifact put refused: no tenant");
            return Err(ArtifactError::TenantRequired);
        }

        // 2. Shape. Caps live here, once, rather than in each port. An
        //    over-cap payload is refused and never truncated.
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::InvalidSize);
        }
        check_name(&name)?;
        check_mime(&mime_type)?;

        // 3. Port. Absent in unit tests and runtimes the host did not wire.
        let Some(port) = self.artifact_port.as_ref() else {
            return Err(ArtifactError::Unsupported);
        };

        match port.put(
            &self.extension_id,
            &self.call_ctx,
            ArtifactPutRequest {
                bytes,
                mime_type,
                name,
            },
        ) {
            Ok(id) => Ok(id),
            Err(ArtifactPortError::Unsupported) => Err(ArtifactError::Unsupported),
            Err(ArtifactPortError::InvalidMediaType) => Err(ArtifactError::UnsupportedMediaType),
            Err(ArtifactPortError::QuotaExceeded) => Err(ArtifactError::QuotaExceeded),
            Err(ArtifactPortError::Unavailable(detail)) => {
                // The detail can name an internal host or a URL: log it, never
                // return it to the guest.
                tracing::warn!(ext = %self.extension_id, error = %detail, "artifact port unavailable");
                Err(ArtifactError::Unavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_bindings::design_v04::greentic::extension_host::artifact::{
        ArtifactError, Host as ArtifactHost,
    };
    use crate::host_ports::{ArtifactPort, ArtifactPortError, ArtifactPutRequest, HostCallContext};
    use greentic_extension_sdk_contract::describe::Permissions;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Recording {
        seen: Mutex<Vec<(String, Option<String>, ArtifactPutRequest)>>,
        outcome: Mutex<Option<ArtifactPortError>>,
    }

    impl ArtifactPort for Recording {
        fn put(
            &self,
            extension_id: &str,
            ctx: &HostCallContext,
            request: ArtifactPutRequest,
        ) -> Result<String, ArtifactPortError> {
            self.seen
                .lock()
                .unwrap()
                .push((extension_id.to_string(), ctx.tenant.clone(), request));
            match self.outcome.lock().unwrap().take() {
                Some(e) => Err(e),
                None => Ok("artifact://abc".to_string()),
            }
        }
    }

    fn host(port: Option<Arc<Recording>>, tenant: Option<&str>) -> crate::HostState {
        let mut b = crate::HostState::builder("test-ext".into(), Permissions::default()).call_ctx(
            HostCallContext {
                tenant: tenant.map(str::to_string),
                user_email: Some("u@example.com".into()),
            },
        );
        if let Some(p) = port {
            b = b.artifact_port(Some(p as Arc<dyn ArtifactPort>));
        }
        b.build()
    }

    fn put(
        h: &mut crate::HostState,
        bytes: Vec<u8>,
        mime: &str,
        name: &str,
    ) -> Result<String, ArtifactError> {
        ArtifactHost::put(h, bytes, mime.to_string(), name.to_string())
    }

    #[test]
    fn put_forwards_to_the_port_with_the_calling_tenant() {
        let port = Arc::new(Recording::default());
        let mut h = host(Some(port.clone()), Some("acme"));
        let id = put(&mut h, vec![1, 2, 3], "image/png", "cat.png").unwrap();
        assert_eq!(id, "artifact://abc");
        let seen = port.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "test-ext");
        assert_eq!(seen[0].1.as_deref(), Some("acme"));
        assert_eq!(seen[0].2.bytes, vec![1, 2, 3]);
        assert_eq!(seen[0].2.name, "cat.png");
    }

    #[test]
    fn a_missing_or_blank_tenant_is_refused_before_the_port() {
        for tenant in [None, Some(""), Some("   ")] {
            let port = Arc::new(Recording::default());
            let mut h = host(Some(port.clone()), tenant);
            let err = put(&mut h, vec![1], "image/png", "a.png").unwrap_err();
            assert!(
                matches!(err, ArtifactError::TenantRequired),
                "{tenant:?} -> {err:?}"
            );
            assert!(
                port.seen.lock().unwrap().is_empty(),
                "port must not be called"
            );
        }
    }

    #[test]
    fn no_port_reports_unsupported() {
        let mut h = host(None, Some("acme"));
        let err = put(&mut h, vec![1], "image/png", "a.png").unwrap_err();
        assert!(matches!(err, ArtifactError::Unsupported), "{err:?}");
    }

    #[test]
    fn size_cap_is_exact_and_empty_is_refused() {
        let port = Arc::new(Recording::default());
        let mut h = host(Some(port.clone()), Some("acme"));
        assert!(put(&mut h, vec![0; MAX_ARTIFACT_BYTES], "image/png", "a.png").is_ok());
        let over = put(
            &mut h,
            vec![0; MAX_ARTIFACT_BYTES + 1],
            "image/png",
            "a.png",
        )
        .unwrap_err();
        assert!(matches!(over, ArtifactError::InvalidSize), "{over:?}");
        let empty = put(&mut h, vec![], "image/png", "a.png").unwrap_err();
        assert!(matches!(empty, ArtifactError::InvalidSize), "{empty:?}");
        assert_eq!(
            port.seen.lock().unwrap().len(),
            1,
            "only the exact-cap call reached the port"
        );
    }

    #[test]
    fn bad_names_and_mime_types_are_refused() {
        let port = Arc::new(Recording::default());
        let mut h = host(Some(port.clone()), Some("acme"));
        let long = "n".repeat(MAX_ARTIFACT_NAME_BYTES + 1);
        for name in [
            "",
            "  ",
            "a/b.png",
            "a\\b.png",
            "a\0b",
            "a\nb.png",
            long.as_str(),
        ] {
            let err = put(&mut h, vec![1], "image/png", name).unwrap_err();
            assert!(
                matches!(err, ArtifactError::InvalidInput(_)),
                "name {name:?} -> {err:?}"
            );
        }
        let long_mime = format!("image/{}", "x".repeat(MAX_MIME_BYTES));
        for mime in [
            "",
            " ",
            "image/png; charset=utf-8",
            "image png",
            long_mime.as_str(),
        ] {
            let err = put(&mut h, vec![1], mime, "a.png").unwrap_err();
            assert!(
                matches!(err, ArtifactError::InvalidInput(_)),
                "mime {mime:?} -> {err:?}"
            );
        }
        assert!(port.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn port_errors_map_to_typed_variants_without_leaking_detail() {
        for (port_err, check) in [
            (ArtifactPortError::Unsupported, 0),
            (ArtifactPortError::InvalidMediaType, 1),
            (ArtifactPortError::QuotaExceeded, 2),
            (
                ArtifactPortError::Unavailable("https://10.0.0.5/secret-token".into()),
                3,
            ),
        ] {
            let port = Arc::new(Recording::default());
            *port.outcome.lock().unwrap() = Some(port_err);
            let mut h = host(Some(port), Some("acme"));
            let err = put(&mut h, vec![1], "image/png", "a.png").unwrap_err();
            match (check, &err) {
                (0, ArtifactError::Unsupported)
                | (1, ArtifactError::UnsupportedMediaType)
                | (2, ArtifactError::QuotaExceeded)
                | (3, ArtifactError::Unavailable) => {}
                other => panic!("unexpected mapping: {other:?}"),
            }
            // `Unavailable` is a unit variant: there is no field the detail could ride in.
        }
    }
}
