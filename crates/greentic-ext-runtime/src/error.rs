use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("extension '{0}' not found")]
    NotFound(String),

    #[error(
        "signature verification failed for extension '{extension_id}': {reason}\n\
         hint: reinstall a signed extension (production), or rebuild ext-runtime \
         with `--features dev-allow-unsigned` and set GREENTIC_EXT_ALLOW_UNSIGNED=1 (dev only)"
    )]
    SignatureInvalid {
        extension_id: String,
        reason: String,
    },

    #[error("wasmtime: {0}")]
    Wasmtime(#[from] anyhow::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("watcher: {0}")]
    Watcher(String),

    #[error("deploy extension error: {0}")]
    Deploy(crate::types::DeployExtensionError),

    /// A WIT-level `extension-error` returned by the extension itself.
    /// Carries the variant intact so hosts can surface a stable `code`
    /// in the response envelope — do NOT collapse into `Wasmtime`.
    #[error("extension error ({code}): {msg}", code = .0.code(), msg = .0)]
    Extension(crate::types::HostExtensionError),
}
