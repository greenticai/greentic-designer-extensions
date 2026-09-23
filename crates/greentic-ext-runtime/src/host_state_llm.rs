//! `Host` impl for the `greentic:extension-host/llm` import.
//!
//! Split out of [`crate::host_state_net`]: role resolution is its own concern
//! with its own permission model, and neither file needs to carry both.

use crate::host_bindings::greentic::extension_host::llm;
use crate::host_state::HostState;

/// Most inputs one `embed` call may carry. A guest with more must split them
/// across several calls.
pub(crate) const MAX_EMBED_INPUTS: usize = 128;
/// Most input bytes one `embed` call may carry, summed across inputs.
pub(crate) const MAX_EMBED_BYTES: usize = 1024 * 1024;

impl HostState {
    /// Resolve the effective LLM role from the extension's declared
    /// permissions. Shared by `complete` and `embed`: two copies of this gate
    /// would be two places for the permission model to drift, and a drift here
    /// is an extension reaching a role it never declared.
    fn resolve_llm_role(&self, hint: Option<&str>) -> Result<String, String> {
        let declared = &self.permissions.llm_roles;
        match (hint, declared.as_slice()) {
            (Some(h), roles) if roles.iter().any(|r| r == h) => Ok(h.to_string()),
            (Some(h), _) => {
                tracing::warn!(ext = %self.extension_id, requested = %h, "llm role not permitted");
                Err(format!("llm role not permitted: {h}"))
            }
            (None, [sole]) => Ok(sole.clone()),
            (None, []) => {
                Err("llm role not permitted: extension declares no llm_roles".to_string())
            }
            (None, _many) => {
                Err("llm role-hint required: extension declares multiple llm_roles".to_string())
            }
        }
    }
}

impl llm::Host for HostState {
    fn complete(&mut self, request: llm::LlmRequest) -> Result<llm::LlmResponse, String> {
        // 1. Resolve the effective role from describe permissions. A `role_hint`
        //    must be one the extension declared; with no hint we allow the sole
        //    declared role and otherwise require disambiguation.
        let role = self.resolve_llm_role(request.role_hint.as_deref())?;

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

    fn embed(&mut self, request: llm::EmbedRequest) -> Result<llm::EmbedResponse, String> {
        let role = self.resolve_llm_role(request.role_hint.as_deref())?;

        // Caps live here, once, rather than in each port: an over-cap batch is
        // refused and NEVER truncated, because the guest correlates vectors to
        // its own chunks positionally — a short batch is wrong data, not a
        // visible failure.
        if request.inputs.is_empty() {
            return Err("embed: inputs is empty".to_string());
        }
        if request.inputs.len() > MAX_EMBED_INPUTS {
            return Err(format!(
                "embed: {} inputs exceeds the {MAX_EMBED_INPUTS} limit",
                request.inputs.len()
            ));
        }
        let total: usize = request.inputs.iter().map(String::len).sum();
        if total > MAX_EMBED_BYTES {
            return Err(format!(
                "embed: {total} bytes of input exceeds the {MAX_EMBED_BYTES} limit"
            ));
        }
        if let Some(index) = request.inputs.iter().position(|s| s.trim().is_empty()) {
            return Err(format!("embed: inputs[{index}] is empty"));
        }

        let Some(port) = self.llm_port.as_ref() else {
            return Err("llm not configured for this runtime".to_string());
        };

        let port_req = crate::host_ports::EmbedPortRequest {
            inputs: request.inputs,
        };
        match port.embed(&self.extension_id, &self.call_ctx, &role, port_req) {
            Ok(r) => Ok(llm::EmbedResponse {
                vectors: r.vectors,
                model: r.model,
            }),
            Err(e) => {
                tracing::warn!(ext = %self.extension_id, %role, error = %e, "llm embed port error");
                Err(e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_bindings::greentic::extension_host::llm::Host as LlmHost;
    use crate::host_ports::{
        EmbedPortRequest, EmbedPortResponse, HostCallContext, LlmPort, LlmPortRequest,
        LlmPortResponse,
    };
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

    /// A port that records what it was asked to embed and answers with one
    /// vector per input, so the tests can assert order and count.
    struct RecordingEmbedPort {
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl LlmPort for RecordingEmbedPort {
        fn complete(
            &self,
            _extension_id: &str,
            _ctx: &HostCallContext,
            _role: &str,
            _request: LlmPortRequest,
        ) -> Result<LlmPortResponse, crate::host_ports::LlmPortError> {
            unreachable!("these tests only embed")
        }

        fn embed(
            &self,
            _extension_id: &str,
            _ctx: &HostCallContext,
            _role: &str,
            request: EmbedPortRequest,
        ) -> Result<EmbedPortResponse, crate::host_ports::LlmPortError> {
            *self.seen.lock().unwrap() = request.inputs.clone();
            Ok(EmbedPortResponse {
                vectors: request.inputs.iter().map(|_| vec![0.5_f32]).collect(),
                model: "text-embedding-3-small".to_string(),
            })
        }
    }

    // `HostState::builder` takes the extension id and the permissions as two
    // POSITIONAL arguments — read the existing `llm_complete_resolves_sole_
    // declared_role` test at `:137` and keep this chain identical to it.
    fn embed_host(port: Arc<RecordingEmbedPort>) -> HostState {
        HostState::builder(
            "test-ext".to_string(),
            perms_with_roles(&["agentic_worker_composer"]),
        )
        .llm_port(Some(port))
        .call_ctx(HostCallContext {
            tenant: Some("acme".into()),
            ..HostCallContext::default()
        })
        .build()
    }

    #[test]
    fn embed_returns_one_vector_per_input_in_input_order() {
        let port = Arc::new(RecordingEmbedPort {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut host = embed_host(port.clone());

        let response = host
            .embed(llm::EmbedRequest {
                role_hint: None,
                inputs: vec!["alpha".to_string(), "beta".to_string()],
            })
            .expect("a sole declared role needs no hint");

        assert_eq!(response.vectors.len(), 2);
        assert_eq!(response.model, "text-embedding-3-small");
        assert_eq!(
            *port.seen.lock().unwrap(),
            vec!["alpha".to_string(), "beta".to_string()],
            "inputs must reach the port in the order the guest sent them"
        );
    }

    #[test]
    fn embed_refuses_a_role_the_extension_did_not_declare() {
        let port = Arc::new(RecordingEmbedPort {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut host = embed_host(port);

        let err = host
            .embed(llm::EmbedRequest {
                role_hint: Some("flow_editor_composer".to_string()),
                inputs: vec!["alpha".to_string()],
            })
            .expect_err("an undeclared role must be refused");

        assert_eq!(err, "llm role not permitted: flow_editor_composer");
    }

    #[test]
    fn embed_refuses_an_empty_batch() {
        let port = Arc::new(RecordingEmbedPort {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut host = embed_host(port);

        let err = host
            .embed(llm::EmbedRequest {
                role_hint: None,
                inputs: Vec::new(),
            })
            .expect_err("an empty batch is a caller bug, not an empty answer");

        assert_eq!(err, "embed: inputs is empty");
    }

    #[test]
    fn embed_refuses_more_inputs_than_the_cap() {
        let port = Arc::new(RecordingEmbedPort {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut host = embed_host(port);

        let inputs = vec!["x".to_string(); MAX_EMBED_INPUTS + 1];
        let err = host
            .embed(llm::EmbedRequest {
                role_hint: None,
                inputs,
            })
            .expect_err("over the count cap must be refused, never truncated");

        assert!(
            err.contains(&format!("exceeds the {MAX_EMBED_INPUTS} limit")),
            "error should name the cap, got {err}"
        );
    }

    #[test]
    fn embed_accepts_a_batch_exactly_at_the_cap() {
        let port = Arc::new(RecordingEmbedPort {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut host = embed_host(port);

        let inputs = vec!["x".to_string(); MAX_EMBED_INPUTS];
        let response = host
            .embed(llm::EmbedRequest {
                role_hint: None,
                inputs,
            })
            .expect("the cap is inclusive");

        assert_eq!(response.vectors.len(), MAX_EMBED_INPUTS);
    }

    #[test]
    fn embed_refuses_a_batch_over_the_byte_cap() {
        let port = Arc::new(RecordingEmbedPort {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut host = embed_host(port);

        // Two inputs whose combined length exceeds the byte cap while staying
        // under the count cap, so this test pins the byte cap and not the other.
        let half = "y".repeat(MAX_EMBED_BYTES / 2 + 1);
        let err = host
            .embed(llm::EmbedRequest {
                role_hint: None,
                inputs: vec![half.clone(), half],
            })
            .expect_err("over the byte cap must be refused");

        assert!(
            err.contains(&format!("exceeds the {MAX_EMBED_BYTES} limit")),
            "error should name the byte cap, got {err}"
        );
    }

    #[test]
    fn embed_refuses_a_blank_input_and_names_its_index() {
        let port = Arc::new(RecordingEmbedPort {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut host = embed_host(port);

        let err = host
            .embed(llm::EmbedRequest {
                role_hint: None,
                inputs: vec!["alpha".to_string(), "   ".to_string()],
            })
            .expect_err("a blank input would be a provider 400 the guest cannot act on");

        assert_eq!(err, "embed: inputs[1] is empty");
    }

    #[test]
    fn embed_reports_no_llm_port_as_not_configured() {
        let mut host = HostState::builder(
            "test-ext".to_string(),
            perms_with_roles(&["agentic_worker_composer"]),
        )
        .build();

        let err = host
            .embed(llm::EmbedRequest {
                role_hint: None,
                inputs: vec!["alpha".to_string()],
            })
            .expect_err("no port means not configured");

        assert_eq!(err, "llm not configured for this runtime");
    }
}
