use std::path::{Path, PathBuf};
use std::sync::Arc;

use greentic_extension_sdk_contract::{DescribeJson, ExtensionKind};
use wasmtime::Store;
use wasmtime::component::{Component, HasSelf, Instance, Linker};

use crate::health::ExtensionHealth;

/// Design-side component every dual-layout pack ships at its root.
const DESIGN_WASM_NAME: &str = "extension.wasm";
use crate::host_state::HostState;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtensionId(pub String);

impl ExtensionId {
    #[must_use]
    pub fn from_describe(describe: &DescribeJson) -> Self {
        Self(describe.metadata.id.clone())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ExtensionId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ExtensionId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

pub struct LoadedExtension {
    pub id: ExtensionId,
    pub describe: Arc<DescribeJson>,
    pub kind: ExtensionKind,
    pub source_dir: PathBuf,
    pub component: Component,
    pub health: ExtensionHealth,
}

impl LoadedExtension {
    /// Instantiate from the describe the load gate already verified.
    ///
    /// Taking the describe rather than re-reading it is the point: the gate
    /// parses `describe.json`, and every field that decides *identity and
    /// authority* is read back out of it here — `metadata.id` (the registration
    /// key, and the key the publisher pin is filed under) and
    /// `runtime.permissions` (the network allow-list and the secret namespace).
    /// Re-reading the file would let a writer who lands between the two reads
    /// have the runtime verify and pin one identity while registering a
    /// different one, with wide-open permissions, from a directory the
    /// installer owns and any user process can write.
    ///
    /// The component bytes are still read from disk here; see
    /// `ExtensionRuntime::verify_dir_signature` for what that leaves open.
    pub(crate) fn from_verified(
        engine: &wasmtime::Engine,
        source_dir: &Path,
        describe: DescribeJson,
        ledger: &crate::runtime_verify::VerifiedLedger,
    ) -> anyhow::Result<Self> {
        // Every load path funnels through here, so the report fires once per
        // load — boot and hot-reload — and never per `list_tools()` call.
        crate::tool_metadata_report::report_tool_metadata_gaps(&describe);
        let id = ExtensionId::from_describe(&describe);
        let wasm_path = wasm_component_path(&describe, source_dir)?;
        // From bytes the ledger vouches for, not from a path re-read later.
        let wasm = ledger.read_verified(&wasm_path)?;
        let component = Component::from_binary(engine, &wasm)?;
        let kind = describe.kind;
        Ok(Self {
            id,
            describe: Arc::new(describe),
            kind,
            source_dir: source_dir.to_path_buf(),
            component,
            health: ExtensionHealth::Healthy,
        })
    }
}

impl LoadedExtension {
    /// Build a fresh wasmtime Store with [`HostState`] and instantiate the component.
    /// Each call creates a new instance: a `Store` is single-threaded and
    /// carries this dispatch's `HostState`, so it is never reused across calls.
    pub(crate) fn build_store_and_instance(
        &self,
        engine: &wasmtime::Engine,
        host_overrides: HostOverrides,
        ctx: &crate::host_ports::HostCallContext,
        dispatch_timeout: Option<std::time::Duration>,
    ) -> anyhow::Result<(Store<HostState>, Instance)> {
        use crate::host_bindings::greentic::extension_host::{
            broker, http, i18n, llm, logging, secrets,
        };

        let mut linker: Linker<HostState> = Linker::new(engine);

        // Wire WASI host functions. cargo-component always adds WASI imports to
        // its output even when the Rust source never calls them directly.
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;

        // HasSelf<T> wraps T and implements HasData — required for wasmtime 43 bindgen add_to_linker.
        logging::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |s| s)?;
        i18n::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |s| s)?;
        secrets::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |s| s)?;
        broker::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |s| s)?;
        http::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |s| s)?;
        llm::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |s| s)?;
        crate::host_bindings::design_v04::greentic::oauth_broker::broker_v1::add_to_linker::<
            HostState,
            HasSelf<HostState>,
        >(&mut linker, |s| s)?;

        // Per-extension network allow-list: when the extension declares
        // `runtime.permissions.network` patterns, those patterns become the
        // authoritative allow-list for this extension (replace semantics —
        // the host-level override is NOT added). When no patterns are
        // declared the host-level override is used unchanged (deny-all by
        // default). See `effective_url_matcher` for the loopback-http rule.
        let url_matcher = crate::net_permissions::effective_url_matcher(
            &self.describe.runtime.permissions.network,
            host_overrides.url_matcher,
        );

        let state = HostState::builder(
            self.id.as_str().to_string(),
            self.describe.runtime.permissions.clone(),
        )
        .translator(host_overrides.translator)
        .secrets_backend(host_overrides.secrets_backend)
        .http_client(host_overrides.http_client)
        .http_timeout(crate::limits::http_timeout_for(dispatch_timeout))
        .llm_port(host_overrides.llm_port)
        .call_ctx(ctx.clone())
        .url_matcher(url_matcher)
        .runtime_weak(host_overrides.runtime_weak)
        .call_depth_start(host_overrides.call_depth_start)
        .oauth_config(host_overrides.oauth_config.clone())
        .build();

        let mut store = Store::new(engine, state);
        // Before `instantiate`, not after. A limiter that is not installed yet
        // is never consulted, and a component's memories and tables are
        // allocated at their declared *initial* size during instantiation — so
        // applying this afterwards left the ceilings covering only
        // `memory.grow`, which a guest never has to call.
        crate::limits::apply(&mut store, dispatch_timeout);
        let instance = linker.instantiate(&mut store, &self.component)?;
        Ok((store, instance))
    }
}

/// Resolve the WASM component path for an extension's runtime component.
///
/// Extensions that use the dual-component layout ship:
/// - Root `extension.wasm` — design-side WebAssembly with metadata (channel
///   name, icon, i18n, schemas). This is what the designer loads.
/// - A runtime gtpack (e.g. `runtime/provider.gtpack`) — either a placeholder
///   text file or a real .gtpack ZIP. The real runner-host WASM lives downstream
///   and is fetched lazily there; the designer must never try to parse it.
///
/// Multiple extension kinds follow this dual-component layout:
/// - `ProviderExtension` (e.g. `greentic.provider.telegram-1.3.1-research`)
/// - `DesignExtension` (e.g. `greentic.llm-openai-1.3.1-research`) — has a
///   real 80–900 KB `extension.wasm`; `describe.json` points at
///   `runtime/component-llm-openai.gtpack` (a 929 KB .gtpack ZIP that wasmtime
///   cannot parse as a raw component).
/// - `BundleExtension` (e.g. `greentic.bundle-standard-1.3.0-research`) — has
///   a 938 KB `extension.wasm`; `describe.json` points at a `.gtxpack` that
///   may not even exist in the installed directory.
///
/// Strategy: if `<source_dir>/extension.wasm` exists, prefer it unconditionally
/// regardless of kind. Only the runner-host — which has its own separate loader
/// path — needs the runtime gtpack declared in `describe.runtime.components`.
/// Designer's boot loader only consumes design-side metadata and UI assets.
///
/// Older single-component extensions that ship no `extension.wasm` at root fall
/// back to `describe.runtime.components[X].gtpack.file` resolved relative to
/// `source_dir`, exactly as before.
///
/// v2's `runtime.components` is a map keyed by component id. ext-runtime today
/// loads a single WASM component per extension, so we require exactly one entry.
/// Multi-component dispatch (driven by `runtime_ref` on nodeTypes/tools) is a
/// follow-up — when it lands, callers will pick the component by id and this
/// helper goes away.
fn wasm_component_path(describe: &DescribeJson, source_dir: &Path) -> anyhow::Result<PathBuf> {
    // Dual-component layout: extensions that ship a design-side `extension.wasm`
    // at the source-dir root use it for designer-side loading regardless of kind.
    // The runtime gtpack declared in `describe.runtime.components` stays meaningful
    // for runner-host (flow-execution time), which has its own separate loader path.
    //
    // Provider, llm-openai (DesignExtension), and bundle-standard (BundleExtension)
    // all follow this layout. Older single-component extensions that don't ship
    // `extension.wasm` fall back to the describe.json declared path below.
    let design_wasm = source_dir.join(DESIGN_WASM_NAME);
    if design_wasm.exists() {
        return Ok(design_wasm);
    }

    // Fallback for older single-component extensions: read
    // `describe.runtime.components[X].gtpack.file` and resolve it relative to
    // `source_dir`. These kinds already point at real WASM at that path.
    let mut iter = describe.runtime.components.iter();
    let Some((id, component)) = iter.next() else {
        anyhow::bail!("describe.runtime.components must declare at least one entry");
    };
    if iter.next().is_some() {
        anyhow::bail!(
            "describe.runtime.components has more than one entry; multi-component dispatch is not yet implemented"
        );
    }
    let gtpack = component.gtpack.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "describe.runtime.components[{id:?}].gtpack must be set for source-dir loads (OCI-only deploy is not yet supported)",
        )
    })?;
    // `gtpack.file` is a publisher-controlled string that goes straight into
    // the component compiler, so it gets the same path discipline as a ledger
    // entry. `Path::join` honours an absolute path by discarding `source_dir`,
    // and `..` walks out of the pack — either would compile bytes that sit
    // outside the directory the manifest covers, which is to say bytes no
    // signature and no hash has ever seen. Constrained to the pack, the file is
    // necessarily one the ledger lists, because `verify_dir_manifest` rejects
    // any file in the directory that it does not.
    crate::runtime_verify::pack_relative_path(source_dir, gtpack.file.as_str())
        .map_err(|e| anyhow::anyhow!("describe.runtime.components[{id:?}].gtpack.file: {e}"))
}

pub type LoadedExtensionRef = Arc<LoadedExtension>;

/// Bundle of overrides every dispatch caller must supply when building a
/// `HostState`. Production code (designer) constructs adapters around
/// `greentic-i18n` + `greentic-secrets`; tests use [`HostOverrides::defaults_for_tests`].
///
/// `http_client` is `Option` because `reqwest::blocking::Client` spawns an
/// internal tokio runtime, and dropping that runtime from inside an
/// outer async context panics with "Cannot drop a runtime in a context
/// where blocking is not allowed". Tests instantiate `ExtensionRuntime`
/// inside `#[tokio::test]` bodies but never call `http::fetch`, so
/// they leave the client `None` — `host_state` will surface a clean
/// "http client not configured" error if a test ever does invoke fetch.
/// Production callers pass `Some(client)` once at startup.
#[derive(Clone)]
pub struct HostOverrides {
    pub translator: std::sync::Arc<dyn crate::host_ports::Translator>,
    pub secrets_backend: std::sync::Arc<dyn crate::host_ports::SecretsBackend>,
    pub http_client: Option<reqwest::blocking::Client>,
    pub llm_port: Option<std::sync::Arc<dyn crate::host_ports::LlmPort>>,
    pub url_matcher: crate::url_matcher::UrlMatcher,
    pub runtime_weak: std::sync::Weak<crate::runtime::ExtensionRuntime>,
    pub call_depth_start: u32,
    pub oauth_config: Option<crate::oauth::OAuthBrokerConfig>,
}

impl std::fmt::Debug for HostOverrides {
    /// Opaque debug representation: trait-object fields cannot provide
    /// structural debug output, and `reqwest::blocking::Client` does not
    /// implement `Debug`. We show field presence rather than field values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostOverrides")
            .field("translator", &"<dyn Translator>")
            .field("secrets_backend", &"<dyn SecretsBackend>")
            .field(
                "http_client",
                &self.http_client.as_ref().map(|_| "<Client>"),
            )
            .field("llm_port", &self.llm_port.as_ref().map(|_| "<dyn LlmPort>"))
            .field("url_matcher", &self.url_matcher)
            .field(
                "runtime_weak",
                &self
                    .runtime_weak
                    .upgrade()
                    .map(|_| "<Arc<ExtensionRuntime>>"),
            )
            .field("call_depth_start", &self.call_depth_start)
            .field(
                "oauth_config",
                &self.oauth_config.as_ref().map(|_| "<OAuthBrokerConfig>"),
            )
            .finish()
    }
}

impl HostOverrides {
    /// Fakes-everywhere helper. `http_client` is `None` so dropping the
    /// runtime inside an outer async context never panics; the test never
    /// hits the path that uses it. Runtime weak is left unset (`Weak::new`),
    /// so broker dispatch returns "no runtime context available" until
    /// the cross-extension dispatch cascade lands.
    #[must_use]
    pub fn defaults_for_tests() -> Self {
        Self::default()
    }
}

impl Default for HostOverrides {
    /// Production-safe defaults: key-pass-through translator (i18n key
    /// returned verbatim), empty in-memory secrets, no HTTP client (callers
    /// that need HTTP must supply `Some(client)` via
    /// `RuntimeConfig::with_host_overrides` or
    /// `ExtensionRuntime::with_host_overrides`), empty URL allow-list, and
    /// no broker-runtime weak reference (cross-extension dispatch returns
    /// "no runtime context available" until the cascade cascade lands).
    ///
    /// `http_client` is intentionally `None` rather than eagerly constructed
    /// because `reqwest::blocking::Client` spawns its own internal tokio
    /// runtime; dropping that runtime from inside an outer `#[tokio::test]`
    /// body panics with "Cannot drop a runtime in a context where blocking is
    /// not allowed". Tests leave it `None`; production callers pass
    /// `Some(client)` once at startup.
    fn default() -> Self {
        Self {
            translator: std::sync::Arc::new(crate::host_ports::KeyTranslator),
            secrets_backend: std::sync::Arc::new(crate::host_ports::InMemorySecrets::new()),
            http_client: None,
            llm_port: None,
            url_matcher: crate::url_matcher::UrlMatcher::default(),
            runtime_weak: std::sync::Weak::new(),
            call_depth_start: 0,
            oauth_config: None,
        }
    }
}
