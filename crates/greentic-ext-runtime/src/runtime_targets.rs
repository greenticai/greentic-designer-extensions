//! `targets` interface dispatch for deploy extensions.
//!
//! The credential + target-enumeration half of the deploy world; the
//! `deployment` half lives in [`crate::runtime_deploy`].

use crate::error::RuntimeError;
use crate::runtime::{DEPLOY_VERSIONS, ExtensionRuntime, resolve_func, resolve_iface_versions};
use crate::types::{Diagnostic, HostExtensionError, Severity, TargetSummary};

const TARGETS_IFACE: &str = "greentic:extension-deploy/targets";

impl ExtensionRuntime {
    /// Ask a deploy extension to validate a credentials JSON payload for the
    /// given target. Returns diagnostics; an empty vec means valid.
    pub fn validate_credentials(
        &self,
        ext_id: &str,
        target_id: &str,
        credentials_json: &str,
    ) -> Result<Vec<Diagnostic>, RuntimeError> {
        use crate::host_bindings::deploy::exports::greentic::extension_deploy0_1_0::targets::Diagnostic as WitDiagnostic;

        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name, _version) =
            resolve_iface_versions(&mut store, &instance, TARGETS_IFACE, DEPLOY_VERSIONS)?;
        let func_idx = resolve_func(
            &mut store,
            &instance,
            &iface_idx,
            &iface_name,
            "validate-credentials",
        )?;

        let func = instance
            .get_typed_func::<(String, String), (Vec<WitDiagnostic>,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (result,) = func
            .call(
                &mut store,
                (target_id.to_string(), credentials_json.to_string()),
            )
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(result
            .into_iter()
            .map(|d| Diagnostic {
                severity: severity_from_wit(d.severity),
                code: d.code,
                message: d.message,
                path: d.path,
            })
            .collect())
    }

    /// Return the JSON Schema (as a string) describing credentials required
    /// by the given deploy target.
    pub fn credential_schema(&self, ext_id: &str, target_id: &str) -> Result<String, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name, version) =
            resolve_iface_versions(&mut store, &instance, TARGETS_IFACE, DEPLOY_VERSIONS)?;
        let func_idx = resolve_func(
            &mut store,
            &instance,
            &iface_idx,
            &iface_name,
            "credential-schema",
        )?;

        let call_args = (target_id.to_string(),);
        let mapped: Result<String, HostExtensionError> = if version == "0.2.0" {
            use crate::host_bindings::deploy_v02::greentic::extension_base0_2_0::types::ExtensionError as E2;
            let func = instance
                .get_typed_func::<(String,), (Result<String, E2>,)>(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (r,) = func
                .call(&mut store, call_args)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map_err(crate::ext_error::from_deploy_v02)
        } else {
            use crate::host_bindings::deploy::greentic::extension_base0_1_0::types::ExtensionError as E1;
            let func = instance
                .get_typed_func::<(String,), (Result<String, E1>,)>(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (r,) = func
                .call(&mut store, call_args)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map_err(crate::ext_error::from_deploy_v01)
        };

        mapped.map_err(RuntimeError::Extension)
    }

    /// Enumerate targets exported by a loaded deploy extension.
    pub fn list_targets(&self, ext_id: &str) -> Result<Vec<TargetSummary>, RuntimeError> {
        use crate::host_bindings::deploy::exports::greentic::extension_deploy0_1_0::targets::TargetSummary as WitTargetSummary;

        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name, _version) =
            resolve_iface_versions(&mut store, &instance, TARGETS_IFACE, DEPLOY_VERSIONS)?;
        let func_idx = resolve_func(
            &mut store,
            &instance,
            &iface_idx,
            &iface_name,
            "list-targets",
        )?;

        let func = instance
            .get_typed_func::<(), (Vec<WitTargetSummary>,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (result,) = func
            .call(&mut store, ())
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(result
            .into_iter()
            .map(|t| TargetSummary {
                id: t.id,
                display_name: t.display_name,
                description: t.description,
                icon_path: t.icon_path,
                supports_rollback: t.supports_rollback,
            })
            .collect())
    }
}

/// The deploy world re-exports the base-types `severity` under its own path, so
/// it needs its own mapper even though the variants match
/// [`crate::runtime_design::severity_from_wit`] exactly.
fn severity_from_wit(
    s: crate::host_bindings::deploy::greentic::extension_base0_1_0::types::Severity,
) -> Severity {
    use crate::host_bindings::deploy::greentic::extension_base0_1_0::types::Severity as Wit;
    match s {
        Wit::Error => Severity::Error,
        Wit::Warning => Severity::Warning,
        Wit::Info => Severity::Info,
        Wit::Hint => Severity::Hint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_targets_returns_error_for_unknown_extension() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        match rt.list_targets("does-not-exist") {
            Err(RuntimeError::NotFound(id)) => assert_eq!(id, "does-not-exist"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn credential_schema_returns_error_for_unknown_extension() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        assert!(matches!(
            rt.credential_schema("does-not-exist", "some-target"),
            Err(RuntimeError::NotFound(_))
        ));
    }

    #[test]
    fn validate_credentials_returns_error_for_unknown_extension() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        assert!(matches!(
            rt.validate_credentials("does-not-exist", "target", "{}"),
            Err(RuntimeError::NotFound(_))
        ));
    }
}
