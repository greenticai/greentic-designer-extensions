//! `Host` impl for the `greentic:extension-host/llm` import.
//!
//! Split out of [`crate::host_state_net`]: role resolution is its own concern
//! with its own permission model, and neither file needs to carry both.

use crate::host_bindings::greentic::extension_host::llm;
use crate::host_state::HostState;

impl llm::Host for HostState {
    fn complete(&mut self, request: llm::LlmRequest) -> Result<llm::LlmResponse, String> {
        // 1. Resolve the effective role from describe permissions. A `role_hint`
        //    must be one the extension declared; with no hint we allow the sole
        //    declared role and otherwise require disambiguation.
        let declared = &self.permissions.llm_roles;
        let role = match (&request.role_hint, declared.as_slice()) {
            (Some(hint), roles) if roles.iter().any(|r| r == hint) => hint.clone(),
            (Some(hint), _) => {
                tracing::warn!(ext = %self.extension_id, requested = %hint, "llm role not permitted");
                return Err(format!("llm role not permitted: {hint}"));
            }
            (None, [sole]) => sole.clone(),
            (None, []) => {
                return Err("llm role not permitted: extension declares no llm_roles".to_string());
            }
            (None, _many) => {
                return Err(
                    "llm role-hint required: extension declares multiple llm_roles".to_string(),
                );
            }
        };

        // 2. Resolve the port. Absent in unit tests and runtimes the host did
        //    not wire for LLM use — surface a clean error rather than panic.
        let Some(port) = self.llm_port.as_ref() else {
            return Err("llm not configured for this runtime".to_string());
        };

        // 3. Map the WIT request onto the host port, call, map the response.
        let port_req = crate::host_ports::LlmPortRequest {
            system_prompt: request.system_prompt,
            messages: request
                .messages
                .into_iter()
                .map(|m| (m.role, m.content))
                .collect(),
            response_format: match request.response_format {
                None | Some(llm::ResponseFormat::Text) => {
                    crate::host_ports::LlmPortResponseFormat::Text
                }
                Some(llm::ResponseFormat::Json) => crate::host_ports::LlmPortResponseFormat::Json,
                Some(llm::ResponseFormat::JsonSchema(s)) => {
                    crate::host_ports::LlmPortResponseFormat::JsonSchema(s)
                }
            },
        };
        match port.complete(&self.extension_id, &self.call_ctx, &role, port_req) {
            Ok(r) => Ok(llm::LlmResponse {
                content: r.content,
                total_tokens: r.total_tokens,
            }),
            Err(e) => {
                tracing::warn!(ext = %self.extension_id, %role, error = %e, "llm port error");
                Err(e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_bindings::greentic::extension_host::llm::Host as LlmHost;
    use crate::host_ports::{HostCallContext, LlmPort, LlmPortRequest, LlmPortResponse};
    use greentic_extension_sdk_contract::describe::Permissions;
    use std::sync::Arc;

    fn perms_with_roles(roles: &[&str]) -> Permissions {
        let mut perms = Permissions::default();
        perms
            .llm_roles
            .extend(roles.iter().map(|r| (*r).to_string()));
        perms
    }

    fn fake_llm(tenant: Option<&str>, user_email: Option<&str>) -> Arc<FakeLlm> {
        Arc::new(FakeLlm {
            expected_extension_id: "test-ext".to_string(),
            expected_tenant: tenant.map(str::to_string),
            expected_user_email: user_email.map(str::to_string),
            expected_role: "sorla_composer".to_string(),
        })
    }

    impl LlmPort for FakeLlm {
        fn complete(
            &self,
            extension_id: &str,
            ctx: &HostCallContext,
            role: &str,
            request: LlmPortRequest,
        ) -> Result<LlmPortResponse, crate::host_ports::LlmPortError> {
            assert_eq!(extension_id, self.expected_extension_id, "extension_id");
            assert_eq!(ctx.tenant, self.expected_tenant, "tenant");
            assert_eq!(ctx.user_email, self.expected_user_email, "user_email");
            assert_eq!(role, self.expected_role, "role");
            Ok(LlmPortResponse {
                content: format!("echo:{}", request.system_prompt),
                total_tokens: Some(7),
            })
        }
    }

    fn llm_request(role_hint: Option<&str>) -> llm::LlmRequest {
        llm::LlmRequest {
            role_hint: role_hint.map(str::to_string),
            system_prompt: "you are a composer".to_string(),
            messages: vec![],
            response_format: None,
        }
    }

    /// In-test [`LlmPort`] that records the `extension_id` / `ctx` / `role`
    /// it was called with and echoes the system prompt back. Asserts the host
    /// resolved the expected role and threaded the expected tenant + user email
    /// before forwarding.
    ///
    /// `expected_*` prefix is deliberate (these are the values the port asserts
    /// against, not generic data), so the shared-prefix lint is silenced here.
    #[allow(clippy::struct_field_names)]
    struct FakeLlm {
        expected_extension_id: String,
        expected_tenant: Option<String>,
        expected_user_email: Option<String>,
        expected_role: String,
    }

    #[test]
    fn llm_complete_resolves_sole_declared_role() {
        let mut h = HostState::builder(
            "test-ext".to_string(),
            perms_with_roles(&["sorla_composer"]),
        )
        .llm_port(Some(fake_llm(Some("acme"), None)))
        .call_ctx(HostCallContext {
            tenant: Some("acme".into()),
            user_email: None,
        })
        .build();

        let resp = h
            .complete(llm_request(None))
            .expect("complete should succeed");
        assert_eq!(resp.content, "echo:you are a composer");
        assert_eq!(resp.total_tokens, Some(7));
    }

    #[test]
    fn llm_complete_passes_none_tenant_by_default() {
        // No `.call_ctx(...)` in the builder chain — the host runs
        // single-tenant/dev, so the port must observe a default (all-`None`)
        // context.
        let mut h = HostState::builder(
            "test-ext".to_string(),
            perms_with_roles(&["sorla_composer"]),
        )
        .llm_port(Some(fake_llm(None, None)))
        .build();

        let resp = h
            .complete(llm_request(None))
            .expect("complete should succeed");
        assert_eq!(resp.content, "echo:you are a composer");
    }

    #[test]
    fn llm_complete_passes_user_email() {
        let mut h = HostState::builder(
            "test-ext".to_string(),
            perms_with_roles(&["sorla_composer"]),
        )
        .llm_port(Some(fake_llm(Some("acme"), Some("alice@acme.com"))))
        .call_ctx(HostCallContext {
            tenant: Some("acme".into()),
            user_email: Some("alice@acme.com".into()),
        })
        .build();

        let resp = h
            .complete(llm_request(None))
            .expect("complete should succeed");
        assert_eq!(resp.content, "echo:you are a composer");
    }

    #[test]
    fn llm_complete_rejects_undeclared_role() {
        let mut h = HostState::builder("test-ext".to_string(), Permissions::default())
            .llm_port(Some(fake_llm(None, None)))
            .build();

        let err = h.complete(llm_request(Some("sorla_composer"))).unwrap_err();
        assert!(err.contains("llm role not permitted"), "got: {err}");
    }

    #[test]
    fn llm_complete_honours_a_valid_hint_among_several_roles() {
        // The selection arm itself: with more than one role declared, the hint
        // decides. Nothing covered a hint that is actually accepted, so the
        // arm could have returned any declared role and stayed green.
        let port = Arc::new(FakeLlm {
            expected_extension_id: "test-ext".to_string(),
            expected_tenant: None,
            expected_user_email: None,
            expected_role: "reviewer".to_string(),
        });
        let mut h = HostState::builder(
            "test-ext".to_string(),
            perms_with_roles(&["composer", "reviewer"]),
        )
        .llm_port(Some(port))
        .build();

        let resp = h
            .complete(llm_request(Some("reviewer")))
            .expect("a declared role named by the hint must be accepted");
        assert_eq!(resp.content, "echo:you are a composer");
    }

    #[test]
    fn llm_complete_rejects_a_hint_that_is_not_among_the_declared_roles() {
        let mut h = HostState::builder(
            "test-ext".to_string(),
            perms_with_roles(&["composer", "reviewer"]),
        )
        .llm_port(Some(fake_llm(None, None)))
        .build();

        let err = h.complete(llm_request(Some("admin"))).unwrap_err();
        assert!(err.contains("llm role not permitted: admin"), "got: {err}");
    }

    #[test]
    fn llm_complete_without_port_errors() {
        let mut h = HostState::builder(
            "test-ext".to_string(),
            perms_with_roles(&["sorla_composer"]),
        )
        .build();
        let err = h.complete(llm_request(None)).unwrap_err();
        assert!(err.contains("llm not configured"), "got: {err}");
    }

    #[test]
    fn llm_complete_requires_hint_when_multiple_roles() {
        let mut h = HostState::builder("test-ext".to_string(), perms_with_roles(&["a", "b"]))
            .llm_port(Some(fake_llm(None, None)))
            .build();
        let err = h.complete(llm_request(None)).unwrap_err();
        assert!(err.contains("role-hint required"), "got: {err}");
    }
}
