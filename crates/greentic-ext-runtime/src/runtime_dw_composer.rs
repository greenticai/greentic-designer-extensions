//! `greentic:dw-composer/composer` interface dispatch.
//!
//! Composer extensions export `greentic:dw-composer/composer@0.1.0` or
//! `@0.2.0` instead of the generic `greentic:extension-design/tools`
//! interface.  This module provides type-safe invoke methods that resolve the
//! composer interface directly from the component, bypassing the `invoke_tool`
//! / `tools` path that raises boot warnings for every composer extension.
//!
//! The pattern mirrors [`crate::runtime_roles`] (see `list_roles` /
//! `compile_role`): build a fresh `Store + Instance`, resolve the named
//! interface export, obtain the typed function, call it.

use crate::error::RuntimeError;
use crate::runtime::ExtensionRuntime;

/// Version resolution order for the dw-composer interface — newest first.
const COMPOSER_VERSIONS: &[&str] = &["0.2.0", "0.1.0"];
/// Base interface name without the version suffix.
const COMPOSER_IFACE_BASE: &str = "greentic:dw-composer/composer";

impl ExtensionRuntime {
    /// Call `greentic:dw-composer/composer::metadata` and return the JSON
    /// descriptor string.
    ///
    /// The designer parses the returned JSON into its own `ComposerDescriptor`
    /// type. No input argument is required — the function takes no parameters.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError::NotFound` when no extension is loaded at
    /// `ext_id`, and `RuntimeError::Wasmtime` for any host-level failure
    /// (missing interface, trap, type mismatch).
    pub fn invoke_composer_metadata(&self, ext_id: &str) -> Result<String, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        let (iface_idx, iface_name, _version) = resolve_dw_composer_iface(&mut store, &instance)?;

        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "metadata")
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "interface '{iface_name}' does not export 'metadata'"
                ))
            })?;

        let func = instance
            .get_typed_func::<(), (String,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (result,) = func
            .call(&mut store, ())
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(result)
    }

    /// Call `greentic:dw-composer/composer::compose(intent_json)` and return
    /// the rendered manifest JSON on success or a canonical
    /// [`crate::types::HostExtensionError`] on failure.
    ///
    /// `intent_json` is a JSON-serialised `ComposeIntent` whose schema is
    /// defined by the specific composer extension. The `Ok` variant carries
    /// the rendered manifest JSON; the `Err` variant carries a
    /// `HostExtensionError` (v0.1.0 bare strings map to `Internal`).
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError::NotFound` when no extension is loaded at
    /// `ext_id`, and `RuntimeError::Wasmtime` for any host-level failure
    /// (missing interface, trap, type mismatch). A business-logic failure
    /// inside the composer is NOT a `RuntimeError` — it is the
    /// `Err(HostExtensionError)` inside the returned
    /// `Ok(Result<String, HostExtensionError>)`.
    pub fn invoke_composer_compose(
        &self,
        ext_id: &str,
        intent_json: &str,
    ) -> Result<Result<String, crate::types::HostExtensionError>, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        let (iface_idx, iface_name, version) = resolve_dw_composer_iface(&mut store, &instance)?;

        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "compose")
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "interface '{iface_name}' does not export 'compose'"
                ))
            })?;

        let result: Result<String, crate::types::HostExtensionError> = if version == "0.2.0" {
            use crate::host_bindings::dw_composer_v02::greentic::extension_base0_2_0::types::ExtensionError as E2;
            let func = instance
                .get_typed_func::<(String,), (Result<String, E2>,)>(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (r,) = func
                .call(&mut store, (intent_json.to_string(),))
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map_err(crate::ext_error::from_composer_v02)
        } else {
            let func = instance
                .get_typed_func::<(String,), (Result<String, String>,)>(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (r,) = func
                .call(&mut store, (intent_json.to_string(),))
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map_err(crate::ext_error::from_composer_v01)
        };

        Ok(result)
    }

    /// Call `greentic:dw-composer/composer::validate(manifest_json)` and
    /// return the JSON validation report string.
    ///
    /// The returned string is a JSON-serialised `ValidationReport` (exact
    /// schema is defined by the composer extension — typically an array of
    /// diagnostic objects or an object with a `valid` boolean field).
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError::NotFound` when no extension is loaded at
    /// `ext_id`, and `RuntimeError::Wasmtime` for host-level failures.
    pub fn invoke_composer_validate(
        &self,
        ext_id: &str,
        manifest_json: &str,
    ) -> Result<String, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        let (iface_idx, iface_name, _version) = resolve_dw_composer_iface(&mut store, &instance)?;

        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "validate")
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "interface '{iface_name}' does not export 'validate'"
                ))
            })?;

        let func = instance
            .get_typed_func::<(String,), (String,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (result,) = func
            .call(&mut store, (manifest_json.to_string(),))
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(result)
    }

    /// Call `greentic:dw-composer/composer::templates` and return the JSON
    /// array string of `ComposerTemplate` objects.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError::NotFound` when no extension is loaded at
    /// `ext_id`, and `RuntimeError::Wasmtime` for host-level failures.
    pub fn invoke_composer_templates(&self, ext_id: &str) -> Result<String, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        let (iface_idx, iface_name, _version) = resolve_dw_composer_iface(&mut store, &instance)?;

        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "templates")
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "interface '{iface_name}' does not export 'templates'"
                ))
            })?;

        let func = instance
            .get_typed_func::<(), (String,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (result,) = func
            .call(&mut store, ())
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(result)
    }
}

/// Resolve `greentic:dw-composer/composer` from a wasmtime component instance,
/// trying `@0.2.0` first then falling back to `@0.1.0`.
///
/// Returns the `ComponentExportIndex` for the interface, the resolved
/// fully-qualified name (for use in subsequent error messages), and the bare
/// matched version string (`"0.2.0"` or `"0.1.0"`).
///
/// # Errors
///
/// Returns `RuntimeError::Wasmtime` with a descriptive message when the
/// component does not export the expected interface at any supported version.
fn resolve_dw_composer_iface(
    store: &mut wasmtime::Store<crate::host_state::HostState>,
    instance: &wasmtime::component::Instance,
) -> Result<
    (
        wasmtime::component::ComponentExportIndex,
        String,
        &'static str,
    ),
    RuntimeError,
> {
    crate::runtime::resolve_iface_versions(store, instance, COMPOSER_IFACE_BASE, COMPOSER_VERSIONS)
}
