//! Configuration for [`crate::ExtensionRuntime`].
//!
//! Split out of [`crate::runtime`] so the runtime core stays under the
//! 500-line cap; the policy knobs a host actually sets live together here.

use std::path::PathBuf;

use crate::discovery::DiscoveryPaths;
use crate::error::RuntimeError;
use crate::loaded::HostOverrides;

/// Configuration passed to [`ExtensionRuntime::new`].
///
/// Carries both the filesystem discovery paths and the [`HostOverrides`]
/// bundle that every dispatch call injects into the wasmtime `HostState`.
/// Callers that only need defaults (tests, simple CLI tools) can use
/// [`RuntimeConfig::from_paths`]; production callers that need real
/// i18n/secrets/HTTP backends chain [`RuntimeConfig::with_host_overrides`]
/// before handing the config to the runtime.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub paths: DiscoveryPaths,
    /// Host-function overrides threaded into every WASM dispatch.
    /// Defaults to [`HostOverrides::default()`] (key-translator, empty
    /// secrets, no HTTP client, empty allow-list, no broker weak ref).
    /// Production callers replace this via [`RuntimeConfig::with_host_overrides`]
    /// or the ergonomic [`ExtensionRuntime::with_host_overrides`] builder.
    pub host_overrides: HostOverrides,
    /// Wall-clock budget for a single WIT dispatch.
    ///
    /// `None` disables the deadline for hosts that supervise calls themselves.
    /// Defaults to [`crate::DEFAULT_DISPATCH_TIMEOUT`]; the per-store memory
    /// ceilings apply regardless.
    pub dispatch_timeout: Option<std::time::Duration>,
    /// Root of the TOFU publisher-key store (`<root>/trust/publishers.json`).
    /// `None` resolves as [`RuntimeConfig::resolve_trust_root`] describes —
    /// `$GREENTIC_HOME`, else `~/.greentic`. Tests point this at a temp dir.
    pub trust_root: Option<PathBuf>,
}

impl RuntimeConfig {
    /// Construct a config from discovery paths, using production-safe
    /// [`HostOverrides::default()`] (no HTTP client, empty secrets/i18n).
    #[must_use]
    pub fn from_paths(paths: DiscoveryPaths) -> Self {
        Self {
            paths,
            host_overrides: HostOverrides::default(),
            dispatch_timeout: Some(crate::limits::DEFAULT_DISPATCH_TIMEOUT),
            trust_root: None,
        }
    }

    /// Override the per-dispatch wall-clock budget. `None` disables it.
    ///
    /// Raise it for a host that legitimately runs long extension calls; lower
    /// it for one serving interactive requests. Disabling it means a runaway
    /// guest wedges the calling thread until the process ends.
    #[must_use]
    pub fn with_dispatch_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.dispatch_timeout = timeout;
        self
    }

    /// Override the TOFU trust-store root. Returns `self` for builder-style
    /// chaining. Mainly for tests — production should leave this `None` so the
    /// root resolves to the same store `gtdx` writes.
    #[must_use]
    pub fn with_trust_root(mut self, root: PathBuf) -> Self {
        self.trust_root = Some(root);
        self
    }

    /// Resolve the root under which the TOFU publisher-key store lives.
    ///
    /// Resolution order, mirroring `gtdx` exactly:
    /// 1. an explicit [`RuntimeConfig::with_trust_root`] override,
    /// 2. `$GREENTIC_HOME` (gtdx's `--home` flag reads the same var),
    /// 3. `~/.greentic`.
    ///
    /// This deliberately does **not** derive from [`DiscoveryPaths`]. The
    /// trust store keys publisher keys by extension *id*; it has no
    /// relationship to where an extension directory happens to live.
    /// `DiscoveryPaths::home()` equals `~/.greentic` only by coincidence in
    /// the default layout and diverges under either `$GREENTIC_HOME` or the
    /// runner's `GREENTIC_EXTENSIONS_DIR` override — in which case a TOFU
    /// check would silently re-pin into a *different* store instead of
    /// matching the one gtdx populated.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Io`] when no override or `$GREENTIC_HOME` is
    /// set and the platform reports no home directory. Failing closed is
    /// deliberate: any invented fallback root would pin somewhere gtdx never
    /// reads, which is the silent-mismatch failure this resolution exists to
    /// prevent.
    pub fn resolve_trust_root(&self) -> Result<PathBuf, RuntimeError> {
        if let Some(root) = &self.trust_root {
            return Ok(root.clone());
        }
        if let Some(home) = std::env::var_os("GREENTIC_HOME").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(home));
        }
        directories::BaseDirs::new()
            .map(|d| d.home_dir().join(".greentic"))
            .ok_or_else(|| {
                RuntimeError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "cannot resolve the extension trust root: no home directory on this platform \
                     and GREENTIC_HOME is unset",
                ))
            })
    }

    /// Replace the [`HostOverrides`] bundle. Returns `self` for builder-style
    /// chaining:
    ///
    /// ```ignore
    /// let config = RuntimeConfig::from_paths(paths)
    ///     .with_host_overrides(production_overrides);
    /// ```
    #[must_use]
    pub fn with_host_overrides(mut self, overrides: HostOverrides) -> Self {
        self.host_overrides = overrides;
        self
    }
}
