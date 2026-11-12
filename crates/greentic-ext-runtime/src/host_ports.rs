//! Narrow ports the runtime depends on for host-side capabilities.
//!
//! `greentic-ext-runtime` defines these traits locally so it stays free of
//! the (large) `greentic-i18n` / `greentic-secrets` dependency trees. The
//! designer crate wires production adapters; tests use the in-crate fakes.

use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;

/// Look up i18n keys against a locale catalog set up by the host.
///
/// `t` returns the rendered string for `key` (or the key itself if no
/// translation is available — the runtime never panics on missing keys).
/// `tf` performs simple `{name}` substitution against `args`.
pub trait Translator: Send + Sync + 'static {
    fn t(&self, key: &str) -> String;
    fn tf(&self, key: &str, args: &[(&str, &str)]) -> String;
}

/// A default no-op translator. Returns each key verbatim. Used when the
/// designer is built without an i18n catalog and as a safe baseline in
/// tests that don't care about i18n behaviour.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyTranslator;

impl Translator for KeyTranslator {
    fn t(&self, key: &str) -> String {
        key.to_string()
    }
    fn tf(&self, key: &str, _args: &[(&str, &str)]) -> String {
        key.to_string()
    }
}

/// Errors the runtime surfaces when a secret lookup fails.
#[derive(Debug, Error)]
pub enum SecretsError {
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Narrow secrets port used by the `host.secrets.get` WIT host fn.
///
/// `key` is the raw URI the extension passed (e.g. `"api.openai.com/api_key"`
/// or `"secrets://team/openai/key"`). Permission gating happens in
/// `HostState::secrets::get` BEFORE this trait is called.
pub trait SecretsBackend: Send + Sync + 'static {
    fn get(&self, key: &str) -> Result<String, SecretsError>;
}

/// In-memory `SecretsBackend` used by tests and the designer's
/// `--dev-secrets-inline` mode. Thread-safe.
#[derive(Default)]
pub struct InMemorySecrets {
    map: Mutex<HashMap<String, String>>,
}

impl InMemorySecrets {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes `&self`: the map is behind a `Mutex`, so exclusive access is
    /// already enforced at runtime and requiring it statically only forced
    /// callers into a `mut` binding they had no other use for.
    pub fn insert(&self, key: &str, value: &str) {
        let mut g = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.insert(key.to_string(), value.to_string());
    }
}

impl SecretsBackend for InMemorySecrets {
    fn get(&self, key: &str) -> Result<String, SecretsError> {
        let g = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.get(key)
            .cloned()
            .ok_or_else(|| SecretsError::NotFound(key.to_string()))
    }
}

/// Chat-completion request forwarded to the host. Credential-free by design:
/// the host resolves provider/model/key from the resolved `role`.
#[derive(Debug, Clone)]
pub struct LlmPortRequest {
    pub system_prompt: String,
    /// (role, content) pairs; role is "system" | "user" | "assistant".
    pub messages: Vec<(String, String)>,
    pub response_format: LlmPortResponseFormat,
}

/// Desired shape of the completion output. `Text` is the default; `Json`
/// requests a free-form JSON object; `JsonSchema` carries a serialized JSON
/// Schema the host should constrain the model to.
#[derive(Debug, Clone, Default)]
pub enum LlmPortResponseFormat {
    #[default]
    Text,
    Json,
    JsonSchema(String),
}

/// Successful completion result returned by the host.
#[derive(Debug, Clone)]
pub struct LlmPortResponse {
    pub content: String,
    pub total_tokens: Option<u32>,
}

/// A batch embedding request forwarded to the host. Credential-free AND
/// model-free by design: the host resolves provider, model and key from the
/// resolved `role`, which is the whole point of the capability — a guest that
/// could name the model could also name a model the tenant does not pay for.
#[derive(Debug, Clone)]
pub struct EmbedPortRequest {
    /// Texts to embed. The caller (`host_state_llm`) has already enforced the
    /// count and size caps, so an implementation may assume a sane batch.
    pub inputs: Vec<String>,
}

/// Successful batch embedding result.
#[derive(Debug, Clone)]
pub struct EmbedPortResponse {
    /// One vector per input, in the SAME order as `EmbedPortRequest::inputs`.
    /// Callers correlate vectors back to their own chunks positionally, so an
    /// implementation that reorders or drops one returns silently wrong data.
    pub vectors: Vec<Vec<f32>>,
    /// The model the host resolved and used. Guests key their vector store on
    /// this: vectors from two models are not comparable.
    pub model: String,
}

/// Errors the runtime surfaces when an LLM completion fails. Mirrors
/// [`SecretsError`]'s plain-enum + `thiserror` style so `host_state` can
/// stringify the failure for the WIT `result<_, string>` boundary.
#[derive(Debug, Error)]
pub enum LlmPortError {
    /// The resolved role is not assigned to the extension (or the host has
    /// no mapping for it). Carries the offending role name.
    #[error("llm role unassigned: {0}")]
    RoleUnassigned(String),
    /// The host LLM backend failed (network, provider, quota, etc.).
    #[error("backend error: {0}")]
    Backend(String),
    /// This host wires completions but no embedder. Distinct from `Backend`:
    /// nothing failed, the capability is absent.
    #[error("embeddings not supported by this host")]
    Unsupported,
}

/// Host port for LLM completions, implemented by the embedding host
/// (designer maps it onto its per-tenant `llm_for(role, identity)` seam).
/// Synchronous on purpose: wasmtime host fns are wired with the sync linker.
pub trait LlmPort: Send + Sync {
    /// Resolve and run a completion for `extension_id` against `role`.
    ///
    /// `ctx` is the per-call [`HostCallContext`] threaded from the embedding
    /// host: it carries the caller's tenant slug and the authenticated end
    /// user's email. The designer uses `ctx.tenant` to resolve the role
    /// per-tenant (`llm_for(role, identity)`, strict, no fallback) and
    /// `ctx.user_email` to satisfy the admin's per-user identity check
    /// (`X-Greentic-User`) — without it the admin's service-key auth rejects
    /// the call with 403.
    fn complete(
        &self,
        extension_id: &str,
        ctx: &HostCallContext,
        role: &str,
        request: LlmPortRequest,
    ) -> Result<LlmPortResponse, LlmPortError>;

    /// Embed a batch of texts, resolving the role exactly as `complete` does.
    ///
    /// The default body returns [`LlmPortError::Unsupported`] so a host that
    /// has not wired an embedder keeps compiling and reports the honest reason.
    /// This is what lets the WIT change land one repo at a time.
    fn embed(
        &self,
        _extension_id: &str,
        _ctx: &HostCallContext,
        _role: &str,
        _request: EmbedPortRequest,
    ) -> Result<EmbedPortResponse, LlmPortError> {
        Err(LlmPortError::Unsupported)
    }
}

/// Per-invocation caller context threaded from the embedding host into
/// host-port calls. Extend cautiously: every field is visible to all ports.
#[derive(Debug, Clone, Default)]
pub struct HostCallContext {
    /// Tenant slug of the end caller (multi-tenant hosts); None for
    /// single-tenant/dev.
    pub tenant: Option<String>,
    /// Email of the authenticated end user on whose behalf the call runs.
    /// Hosts that validate per-user identity (e.g. the designer-admin) require
    /// it.
    pub user_email: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_translator_returns_key_for_t() {
        let t = KeyTranslator;
        assert_eq!(t.t("greentic.test.hello"), "greentic.test.hello");
    }

    #[test]
    fn key_translator_substitutes_args_for_tf() {
        let t = KeyTranslator;
        let out = t.tf("greentic.test.hello.{}", &[("name", "Bima")]);
        assert_eq!(out, "greentic.test.hello.{}");
    }

    #[test]
    fn in_memory_secrets_returns_value_when_present() {
        let s = InMemorySecrets::default();
        s.insert("api.openai.com/api_key", "sk-test");
        let v = s.get("api.openai.com/api_key").unwrap();
        assert_eq!(v, "sk-test");
    }

    #[test]
    fn in_memory_secrets_returns_not_found_when_absent() {
        let s = InMemorySecrets::default();
        let err = s.get("api.openai.com/api_key").unwrap_err();
        assert!(matches!(err, SecretsError::NotFound(_)));
    }
}

#[cfg(test)]
mod embed_default_tests {
    use super::*;

    /// A host that wires completions but no embedder must report the honest
    /// reason rather than failing to compile or panicking.
    struct CompleteOnlyPort;

    impl LlmPort for CompleteOnlyPort {
        fn complete(
            &self,
            _extension_id: &str,
            _ctx: &HostCallContext,
            _role: &str,
            _request: LlmPortRequest,
        ) -> Result<LlmPortResponse, LlmPortError> {
            Ok(LlmPortResponse {
                content: "hi".to_string(),
                total_tokens: None,
            })
        }
    }

    #[test]
    fn a_port_that_implements_only_complete_reports_embeddings_unsupported() {
        let port = CompleteOnlyPort;
        let err = port
            .embed(
                "ext.demo",
                &HostCallContext::default(),
                "agentic_worker_composer",
                EmbedPortRequest {
                    inputs: vec!["one".to_string()],
                },
            )
            .expect_err("a complete-only port must not claim to embed");
        assert!(
            matches!(err, LlmPortError::Unsupported),
            "expected Unsupported, got {err:?}"
        );
        assert_eq!(err.to_string(), "embeddings not supported by this host");
    }
}
