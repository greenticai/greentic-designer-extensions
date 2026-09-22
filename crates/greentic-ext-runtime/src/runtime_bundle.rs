//! Bundle-extension dispatch: `bundling.render`.
//!
//! The in-process call site that replaced the legacy
//! `greentic-bundle ext render` subprocess pipeline (designer PR #130).

use crate::error::RuntimeError;
use crate::runtime::{BUNDLE_VERSIONS, ExtensionRuntime, resolve_func, resolve_iface_versions};
use crate::types::{BundleArtifact, BundleSession, HostExtensionError};

const BUNDLING_IFACE: &str = "greentic:extension-bundle/bundling";

impl ExtensionRuntime {
    /// Render a bundle artefact by dispatching to a loaded bundle extension's
    /// `bundling.render` export.
    ///
    /// The host passes the designer session (flow JSON, content JSON, asset
    /// blobs, capability list) and a recipe-specific config string; the
    /// extension's WASM returns the rendered bytes (typically a `.gtpack` zip)
    /// plus the canonical filename and sha256 the extension wants written.
    ///
    /// Runs the WIT call on a sync wasmtime store, so callers in async contexts
    /// should wrap this in `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// - [`RuntimeError::NotFound`] when no extension is loaded at `ext_id`.
    /// - [`RuntimeError::Wasmtime`] for host-level failures (missing interface,
    ///   trap, type mismatch).
    /// - [`RuntimeError::Extension`] for the extension's own WIT-level error
    ///   (6-variant base at `@0.2.0`, 4-variant base at `@0.1.0`).
    pub fn render_bundle(
        &self,
        ext_id: &str,
        recipe_id: &str,
        config_json: &str,
        session: BundleSession,
    ) -> Result<BundleArtifact, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name, version) =
            resolve_iface_versions(&mut store, &instance, BUNDLING_IFACE, BUNDLE_VERSIONS)?;
        let func_idx = resolve_func(&mut store, &instance, &iface_idx, &iface_name, "render")?;

        let mapped: Result<BundleArtifact, HostExtensionError> = if version == "0.2.0" {
            use crate::host_bindings::bundle_v02::exports::greentic::extension_bundle0_2_0::bundling::{
                BundleArtifact as WitBundleArtifact, DesignerSession as WitDesignerSession,
            };
            use crate::host_bindings::bundle_v02::greentic::extension_base0_2_0::types::ExtensionError as E2;
            let func = instance
                .get_typed_func::<
                    (String, String, WitDesignerSession),
                    (Result<WitBundleArtifact, E2>,),
                >(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let wit_session = WitDesignerSession {
                flows_json: session.flows_json,
                contents_json: session.contents_json,
                assets: session.assets,
                capabilities_used: session.capabilities_used,
            };
            let (r,) = func
                .call(
                    &mut store,
                    (recipe_id.to_string(), config_json.to_string(), wit_session),
                )
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map(|a| BundleArtifact {
                filename: a.filename,
                bytes: a.bytes,
                sha256: a.sha256,
            })
            .map_err(crate::ext_error::from_bundle_v02)
        } else {
            use crate::host_bindings::bundle::exports::greentic::extension_bundle0_1_0::bundling::{
                BundleArtifact as WitBundleArtifact, DesignerSession as WitDesignerSession,
            };
            use crate::host_bindings::bundle::greentic::extension_base0_1_0::types::ExtensionError as E1;
            let func = instance
                .get_typed_func::<
                    (String, String, WitDesignerSession),
                    (Result<WitBundleArtifact, E1>,),
                >(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let wit_session = WitDesignerSession {
                flows_json: session.flows_json,
                contents_json: session.contents_json,
                assets: session.assets,
                capabilities_used: session.capabilities_used,
            };
            let (r,) = func
                .call(
                    &mut store,
                    (recipe_id.to_string(), config_json.to_string(), wit_session),
                )
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map(|a| BundleArtifact {
                filename: a.filename,
                bytes: a.bytes,
                sha256: a.sha256,
            })
            .map_err(crate::ext_error::from_bundle_v01)
        };

        mapped.map_err(RuntimeError::Extension)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_bundle_reports_an_unknown_extension_as_not_found() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        match rt.render_bundle(
            "greentic.absent",
            "standard",
            "{}",
            BundleSession::default(),
        ) {
            Err(RuntimeError::NotFound(id)) => assert_eq!(id, "greentic.absent"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
