//! `greentic:extension-sorx` dispatch (`control` / `observe`).
//!
//! A `sorx-runtime-extension` exports `greentic:extension-sorx/control@0.1.0`
//! and `greentic:extension-sorx/observe@0.1.0`. Both calls go through
//! [`ExtensionRuntime::dispatch_instance`], the same path every other export
//! uses, so they inherit the store limiter, the epoch deadline armed from
//! `RuntimeConfig::dispatch_timeout`, and the per-extension network
//! allow-list. Do not build a store here directly: a hand-rolled
//! `build_store_and_instance` call is exactly how a dispatch ends up running
//! without the execution-limit guard.

use crate::error::RuntimeError;
use crate::runtime::ExtensionRuntime;

const CONTROL_IFACE: &str = "greentic:extension-sorx/control@0.1.0";
const OBSERVE_IFACE: &str = "greentic:extension-sorx/observe@0.1.0";

impl ExtensionRuntime {
    /// Dispatch a `SoRX` control hook to a loaded `sorx-runtime-extension`.
    ///
    /// Returns the extension's `ControlDecision` JSON on Ok. Errors (missing
    /// extension, WIT trap, extension-returned error string) surface as
    /// `RuntimeError`; `SoRX`'s caller applies the binding's fail-mode.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::NotFound`] when no extension is loaded at `ext_id`;
    /// [`RuntimeError::Wasmtime`] for a missing export, a trap (including an
    /// execution-limit trap), or an error string returned by the extension.
    pub fn control(
        &self,
        ext_id: &str,
        hook: &str,
        binding_json: &str,
        request_json: &str,
        response_json: Option<&str>,
    ) -> Result<String, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        let iface_idx = instance
            .get_export_index(&mut store, None, CONTROL_IFACE)
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "extension '{ext_id}' does not export '{CONTROL_IFACE}'"
                ))
            })?;
        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "control")
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "sorx control interface does not export 'control'"
                ))
            })?;

        let func = instance
            .get_typed_func::<(String, String, String, Option<String>), (Result<String, String>,)>(
                &mut store, &func_idx,
            )
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (result,) = func
            .call(
                &mut store,
                (
                    hook.to_string(),
                    binding_json.to_string(),
                    request_json.to_string(),
                    response_json.map(str::to_string),
                ),
            )
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        result.map_err(|msg| {
            RuntimeError::Wasmtime(anyhow::anyhow!(
                "sorx extension '{ext_id}' control error: {msg}"
            ))
        })
    }

    /// Dispatch a `SoRX` observer event to a loaded `sorx-runtime-extension`.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::control`].
    pub fn observe(
        &self,
        ext_id: &str,
        subscription: &str,
        binding_json: &str,
        event_json: &str,
    ) -> Result<(), RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        let iface_idx = instance
            .get_export_index(&mut store, None, OBSERVE_IFACE)
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "extension '{ext_id}' does not export '{OBSERVE_IFACE}'"
                ))
            })?;
        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "observe")
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "sorx observe interface does not export 'observe'"
                ))
            })?;

        let func = instance
            .get_typed_func::<(String, String, String), (Result<(), String>,)>(
                &mut store, &func_idx,
            )
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (result,) = func
            .call(
                &mut store,
                (
                    subscription.to_string(),
                    binding_json.to_string(),
                    event_json.to_string(),
                ),
            )
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        result.map_err(|msg| {
            RuntimeError::Wasmtime(anyhow::anyhow!(
                "sorx extension '{ext_id}' observe error: {msg}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::discovery::DiscoveryPaths;
    use crate::error::RuntimeError;
    use crate::runtime::ExtensionRuntime;
    use crate::runtime_config::RuntimeConfig;

    fn empty_runtime(tmp: &tempfile::TempDir) -> ExtensionRuntime {
        let config = RuntimeConfig::from_paths(DiscoveryPaths::new(tmp.path().to_path_buf()));
        ExtensionRuntime::new(config).unwrap()
    }

    #[test]
    fn control_unknown_extension_is_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err = empty_runtime(&tmp)
            .control("does.not.exist", "pre_call", "{}", "{}", None)
            .unwrap_err();
        assert!(matches!(err, RuntimeError::NotFound(id) if id == "does.not.exist"));
    }

    #[test]
    fn observe_unknown_extension_is_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err = empty_runtime(&tmp)
            .observe("does.not.exist", "post_call", "{}", "{}")
            .unwrap_err();
        assert!(matches!(err, RuntimeError::NotFound(id) if id == "does.not.exist"));
    }
}
