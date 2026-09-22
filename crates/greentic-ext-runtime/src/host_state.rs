//! Per-Store host context handed to every WIT invocation.
//!
//! This module owns the state and its builder. The `Host` trait impls that
//! back the imported interfaces live in the siblings: `host_state_ports`
//! (logging / i18n / secrets / broker), `host_state_net` (http / llm), and
//! `host_state_oauth`, so no single file carries the whole host surface.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::host_ports::{KeyTranslator, LlmPort, SecretsBackend, Translator};
use crate::url_matcher::UrlMatcher;
use greentic_extension_sdk_contract::describe::Permissions;

/// Maximum number of nested `host.broker.call-extension` hops the runtime
/// allows in a single dispatch chain. Mirrors `crate::broker::MAX_DEPTH`.
pub const MAX_BROKER_DEPTH: u32 = 8;

/// Per-Store host context. One `HostState` is built per WIT invocation —
/// the dependencies live in `Arc`s so cloning is cheap.
///
/// Every field is private or `pub(crate)`: `permissions` in particular is the
/// allow-list each host fn checks against, so it must not be reachable — let
/// alone writable — from outside the crate.
pub struct HostState {
    pub(crate) extension_id: String,
    pub(crate) permissions: Permissions,
    pub(crate) call_depth: AtomicU32,
    pub(crate) translator: Arc<dyn Translator>,
    pub(crate) secrets_backend: Arc<dyn SecretsBackend>,
    pub(crate) http_client: Option<reqwest::blocking::Client>,
    /// Ceiling on one outbound request made on the guest's behalf. The wasm
    /// deadline cannot interrupt a blocking host call, so this is the only
    /// thing bounding `host.http.fetch`.
    pub(crate) http_timeout: std::time::Duration,
    pub(crate) llm_port: Option<Arc<dyn LlmPort>>,
    /// Per-call caller context for this dispatch (tenant slug + authenticated
    /// user email), threaded from the host's
    /// [`crate::host_ports::HostCallContext`] and forwarded to host ports.
    /// `Default` (all `None`) when the host runs single-tenant/dev.
    pub(crate) call_ctx: crate::host_ports::HostCallContext,
    pub(crate) url_matcher: UrlMatcher,
    pub(crate) runtime_weak: std::sync::Weak<crate::runtime::ExtensionRuntime>,
    pub(crate) oauth_config: Option<crate::oauth::OAuthBrokerConfig>,
    /// Store-wide memory/table budget, read back by `Store::limiter`. Lives
    /// here because wasmtime resolves the limiter out of the store's data on
    /// every growth request.
    pub(crate) limits: crate::limits::PackLimits,
    // WASI state — required because cargo-component-built WASM components
    // implicitly import WASI interfaces (wasi:cli/environment etc.).
    wasi: WasiCtx,
    table: ResourceTable,
}

impl HostState {
    /// Builder used by `LoadedExtension::build_store_and_instance` to
    /// produce a `HostState` for a single dispatch.
    #[must_use]
    pub fn builder(extension_id: String, permissions: Permissions) -> HostStateBuilder {
        HostStateBuilder {
            extension_id,
            permissions,
            translator: Arc::new(KeyTranslator),
            secrets_backend: Arc::new(crate::host_ports::InMemorySecrets::new()),
            http_client: None,
            llm_port: None,
            call_ctx: crate::host_ports::HostCallContext::default(),
            url_matcher: UrlMatcher::default(),
            runtime_weak: std::sync::Weak::new(),
            call_depth_start: 0,
            oauth_config: None,
            http_timeout: crate::limits::http_timeout_for(None),
        }
    }

    #[must_use]
    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    #[must_use]
    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    #[must_use]
    pub fn translator(&self) -> &dyn Translator {
        self.translator.as_ref()
    }

    #[must_use]
    pub fn secrets_backend(&self) -> &dyn SecretsBackend {
        self.secrets_backend.as_ref()
    }

    #[must_use]
    pub fn url_matcher(&self) -> &UrlMatcher {
        &self.url_matcher
    }
}

/// Builder for [`HostState`]. Avoids a 10-positional-arg constructor.
pub struct HostStateBuilder {
    extension_id: String,
    permissions: Permissions,
    translator: Arc<dyn Translator>,
    secrets_backend: Arc<dyn SecretsBackend>,
    http_client: Option<reqwest::blocking::Client>,
    llm_port: Option<Arc<dyn LlmPort>>,
    call_ctx: crate::host_ports::HostCallContext,
    url_matcher: UrlMatcher,
    runtime_weak: std::sync::Weak<crate::runtime::ExtensionRuntime>,
    call_depth_start: u32,
    oauth_config: Option<crate::oauth::OAuthBrokerConfig>,
    http_timeout: std::time::Duration,
}

impl HostStateBuilder {
    #[must_use]
    pub fn translator(mut self, t: Arc<dyn Translator>) -> Self {
        self.translator = t;
        self
    }

    #[must_use]
    pub fn secrets_backend(mut self, s: Arc<dyn SecretsBackend>) -> Self {
        self.secrets_backend = s;
        self
    }

    /// Supply the HTTP client backing `host.http.fetch`.
    ///
    /// The client's redirect policy is part of the security boundary: the
    /// allow-list is enforced per URL, so a client that follows redirects can
    /// be walked off the allow-list by an allowed host. `host.http.fetch`
    /// re-checks the final URL and refuses a response that landed off-list, but
    /// a host that wants the request never to leave the list at all should pass
    /// a client built with `redirect::Policy::none()`.
    #[must_use]
    pub fn http_client(mut self, c: Option<reqwest::blocking::Client>) -> Self {
        self.http_client = c;
        self
    }

    /// Ceiling on a single outbound request made for the guest.
    #[must_use]
    pub fn http_timeout(mut self, t: std::time::Duration) -> Self {
        self.http_timeout = t;
        self
    }

    #[must_use]
    pub fn llm_port(mut self, p: Option<Arc<dyn LlmPort>>) -> Self {
        self.llm_port = p;
        self
    }

    /// Set the per-call caller context (tenant slug + authenticated user
    /// email) for this dispatch. Threaded into host ports (today the LLM port)
    /// so the host can resolve per-tenant and validate per-user identity.
    #[must_use]
    pub fn call_ctx(mut self, ctx: crate::host_ports::HostCallContext) -> Self {
        self.call_ctx = ctx;
        self
    }

    #[must_use]
    pub fn url_matcher(mut self, m: UrlMatcher) -> Self {
        self.url_matcher = m;
        self
    }

    #[must_use]
    pub fn runtime_weak(mut self, w: std::sync::Weak<crate::runtime::ExtensionRuntime>) -> Self {
        self.runtime_weak = w;
        self
    }

    #[must_use]
    pub fn call_depth_start(mut self, n: u32) -> Self {
        self.call_depth_start = n;
        self
    }

    #[must_use]
    pub fn oauth_config(mut self, c: Option<crate::oauth::OAuthBrokerConfig>) -> Self {
        self.oauth_config = c;
        self
    }

    #[must_use]
    pub fn build(self) -> HostState {
        HostState {
            extension_id: self.extension_id,
            permissions: self.permissions,
            call_depth: AtomicU32::new(self.call_depth_start),
            translator: self.translator,
            secrets_backend: self.secrets_backend,
            http_client: self.http_client,
            http_timeout: self.http_timeout,
            llm_port: self.llm_port,
            call_ctx: self.call_ctx,
            url_matcher: self.url_matcher,
            runtime_weak: self.runtime_weak,
            oauth_config: self.oauth_config,
            limits: crate::limits::PackLimits::new(),
            // A default WASI context grants no preopened directory, no
            // environment, and no stdio — cargo-component imports the
            // interfaces unconditionally, but nothing behind them is reachable.
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
        }
    }
}

/// Implement [`WasiView`] so that `wasmtime_wasi::p2::add_to_linker_sync` can wire
/// WASI host functions. cargo-component adds WASI imports to every component it
/// builds, even if the Rust source never calls them.
impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_deny_everything_the_host_did_not_wire() {
        let h = HostState::builder("test-ext".to_string(), Permissions::default()).build();
        assert_eq!(h.extension_id(), "test-ext");
        assert!(
            h.url_matcher().patterns().is_empty(),
            "the default matcher must be deny-all"
        );
        assert!(h.http_client.is_none(), "no ambient http client");
        assert!(h.llm_port.is_none(), "no ambient llm port");
        assert!(h.oauth_config.is_none(), "no ambient oauth broker");
    }

    #[test]
    fn host_state_carries_oauth_config() {
        use crate::oauth::OAuthBrokerConfig;
        let cfg = OAuthBrokerConfig {
            http_base_url: "https://oauth.example/".into(),
            env: "dev".into(),
            tenant: "acme".into(),
            team: None,
            shared_secret: Some("s".into()),
        };
        let h = HostState::builder("test-ext".to_string(), Permissions::default())
            .oauth_config(Some(cfg))
            .build();
        assert_eq!(
            h.oauth_config.as_ref().map(|c| c.tenant.as_str()),
            Some("acme")
        );
    }
}
