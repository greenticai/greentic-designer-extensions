//! `deployment` interface dispatch for deploy extensions (Mode B).
//!
//! Sibling of [`crate::runtime_targets`], which carries the `targets` surface
//! of the same world. First consumer: the designer's wizard deploy step
//! driving `greentic.deploy-github`.

use crate::error::RuntimeError;
use crate::runtime::{DEPLOY_VERSIONS, ExtensionRuntime, resolve_func, resolve_iface_versions};
use crate::types::{DeployExtensionError, DeployJob, DeployRequest, DeployStatus};

use crate::host_bindings::deploy::exports::greentic::extension_deploy0_1_0::deployment::{
    DeployJob as WitDeployJob, DeployRequest as WitDeployRequest, DeployStatus as WitDeployStatus,
};
use crate::host_bindings::deploy::greentic::extension_base0_1_0::types::ExtensionError as WitExtensionError;
use crate::host_bindings::deploy_v02::exports::greentic::extension_deploy0_2_0::deployment::{
    DeployJob as WitDeployJobV2, DeployRequest as WitDeployRequestV2,
    DeployStatus as WitDeployStatusV2,
};
use crate::host_bindings::deploy_v02::greentic::extension_base0_2_0::types::ExtensionError as WitExtensionErrorV2;

const DEPLOYMENT_IFACE: &str = "greentic:extension-deploy/deployment";

/// A resolved `deployment` call site: an open store + instance, the export
/// index of the requested function, and the interface version that matched.
struct DeploymentCall {
    store: wasmtime::Store<crate::host_state::HostState>,
    instance: wasmtime::component::Instance,
    func_idx: wasmtime::component::ComponentExportIndex,
    version: &'static str,
}

impl ExtensionRuntime {
    /// Start a deployment inside the extension. Returns the initial job.
    ///
    /// Calls `greentic:extension-deploy/deployment::deploy`, resolving the
    /// interface newest-first across `@0.2.0`/`@0.1.0`. The matched version
    /// selects the `extension-error` ABI (6-variant base at `@0.2.0`,
    /// 4-variant base at `@0.1.0`). The call is synchronous and may take up
    /// to ~2 minutes for network-bound extensions (artifact upload); run it
    /// on a blocking thread.
    pub fn deploy(&self, ext_id: &str, req: DeployRequest) -> Result<DeployJob, RuntimeError> {
        let DeploymentCall {
            mut store,
            instance,
            func_idx,
            version,
        } = self.deployment_call(ext_id, "deploy")?;

        if version == "0.2.0" {
            let func = instance
                .get_typed_func::<(WitDeployRequestV2,), (Result<WitDeployJobV2, WitExtensionErrorV2>,)>(
                    &mut store, &func_idx,
                )
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let wit_req = WitDeployRequestV2 {
                target_id: req.target_id,
                artifact_bytes: req.artifact_bytes,
                credentials_json: req.credentials_json,
                config_json: req.config_json,
                deployment_name: req.deployment_name,
            };
            let (result,) = func
                .call(&mut store, (wit_req,))
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            result
                .map(job_to_host_v2)
                .map_err(|e| RuntimeError::Deploy(err_to_host_v2(e)))
        } else {
            let func = instance
                .get_typed_func::<(WitDeployRequest,), (Result<WitDeployJob, WitExtensionError>,)>(
                    &mut store, &func_idx,
                )
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let wit_req = WitDeployRequest {
                target_id: req.target_id,
                artifact_bytes: req.artifact_bytes,
                credentials_json: req.credentials_json,
                config_json: req.config_json,
                deployment_name: req.deployment_name,
            };
            let (result,) = func
                .call(&mut store, (wit_req,))
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            result
                .map(job_to_host)
                .map_err(|e| RuntimeError::Deploy(err_to_host(e)))
        }
    }

    /// Poll a previously started deployment job.
    pub fn deploy_poll(&self, ext_id: &str, job_id: &str) -> Result<DeployJob, RuntimeError> {
        let DeploymentCall {
            mut store,
            instance,
            func_idx,
            version,
        } = self.deployment_call(ext_id, "poll")?;

        if version == "0.2.0" {
            let func = instance
                .get_typed_func::<(String,), (Result<WitDeployJobV2, WitExtensionErrorV2>,)>(
                    &mut store, &func_idx,
                )
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (result,) = func
                .call(&mut store, (job_id.to_string(),))
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            result
                .map(job_to_host_v2)
                .map_err(|e| RuntimeError::Deploy(err_to_host_v2(e)))
        } else {
            let func = instance
                .get_typed_func::<(String,), (Result<WitDeployJob, WitExtensionError>,)>(
                    &mut store, &func_idx,
                )
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (result,) = func
                .call(&mut store, (job_id.to_string(),))
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            result
                .map(job_to_host)
                .map_err(|e| RuntimeError::Deploy(err_to_host(e)))
        }
    }

    /// Roll back a previously started deployment job.
    pub fn deploy_rollback(&self, ext_id: &str, job_id: &str) -> Result<(), RuntimeError> {
        let DeploymentCall {
            mut store,
            instance,
            func_idx,
            version,
        } = self.deployment_call(ext_id, "rollback")?;

        if version == "0.2.0" {
            let func = instance
                .get_typed_func::<(String,), (Result<(), WitExtensionErrorV2>,)>(
                    &mut store, &func_idx,
                )
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (result,) = func
                .call(&mut store, (job_id.to_string(),))
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            result.map_err(|e| RuntimeError::Deploy(err_to_host_v2(e)))
        } else {
            let func = instance
                .get_typed_func::<(String,), (Result<(), WitExtensionError>,)>(
                    &mut store, &func_idx,
                )
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (result,) = func
                .call(&mut store, (job_id.to_string(),))
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            result.map_err(|e| RuntimeError::Deploy(err_to_host(e)))
        }
    }

    /// Resolve one `deployment` function into an open call site.
    ///
    /// All three entry points above open identically; factoring it keeps the
    /// version-resolution order from drifting between them.
    fn deployment_call(&self, ext_id: &str, func: &str) -> Result<DeploymentCall, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name, version) =
            resolve_iface_versions(&mut store, &instance, DEPLOYMENT_IFACE, DEPLOY_VERSIONS)?;
        let func_idx = resolve_func(&mut store, &instance, &iface_idx, &iface_name, func)?;
        Ok(DeploymentCall {
            store,
            instance,
            func_idx,
            version,
        })
    }
}

fn job_to_host(j: WitDeployJob) -> DeployJob {
    DeployJob {
        id: j.id,
        status: match j.status {
            WitDeployStatus::Pending => DeployStatus::Pending,
            WitDeployStatus::Provisioning => DeployStatus::Provisioning,
            WitDeployStatus::Configuring => DeployStatus::Configuring,
            WitDeployStatus::Starting => DeployStatus::Starting,
            WitDeployStatus::Running => DeployStatus::Running,
            WitDeployStatus::Failed => DeployStatus::Failed,
            WitDeployStatus::RolledBack => DeployStatus::RolledBack,
        },
        message: j.message,
        endpoints: j.endpoints,
    }
}

fn err_to_host(e: WitExtensionError) -> DeployExtensionError {
    match e {
        WitExtensionError::InvalidInput(m) => DeployExtensionError::InvalidInput(m),
        WitExtensionError::MissingCapability(m) => DeployExtensionError::MissingCapability(m),
        WitExtensionError::PermissionDenied(m) => DeployExtensionError::PermissionDenied(m),
        WitExtensionError::Internal(m) => DeployExtensionError::Internal(m),
    }
}

fn job_to_host_v2(j: WitDeployJobV2) -> DeployJob {
    DeployJob {
        id: j.id,
        status: match j.status {
            WitDeployStatusV2::Pending => DeployStatus::Pending,
            WitDeployStatusV2::Provisioning => DeployStatus::Provisioning,
            WitDeployStatusV2::Configuring => DeployStatus::Configuring,
            WitDeployStatusV2::Starting => DeployStatus::Starting,
            WitDeployStatusV2::Running => DeployStatus::Running,
            WitDeployStatusV2::Failed => DeployStatus::Failed,
            WitDeployStatusV2::RolledBack => DeployStatus::RolledBack,
        },
        message: j.message,
        endpoints: j.endpoints,
    }
}

fn err_to_host_v2(e: WitExtensionErrorV2) -> DeployExtensionError {
    match e {
        WitExtensionErrorV2::InvalidInput(m) => DeployExtensionError::InvalidInput(m),
        WitExtensionErrorV2::MissingCapability(m) => DeployExtensionError::MissingCapability(m),
        WitExtensionErrorV2::PermissionDenied(m) => DeployExtensionError::PermissionDenied(m),
        WitExtensionErrorV2::NotFound(m) => DeployExtensionError::NotFound(m),
        WitExtensionErrorV2::SchemaInvalid(m) => DeployExtensionError::SchemaInvalid(m),
        WitExtensionErrorV2::Internal(m) => DeployExtensionError::Internal(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_returns_not_found_for_unknown_extension() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        let req = DeployRequest {
            target_id: "github-repo".into(),
            artifact_bytes: vec![1, 2, 3],
            credentials_json: "{}".into(),
            config_json: "{}".into(),
            deployment_name: "demo".into(),
        };
        match rt.deploy("greentic.deploy-github", req) {
            Err(RuntimeError::NotFound(id)) => assert_eq!(id, "greentic.deploy-github"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn deploy_poll_returns_not_found_for_unknown_extension() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        match rt.deploy_poll("greentic.deploy-github", "job-1") {
            Err(RuntimeError::NotFound(id)) => assert_eq!(id, "greentic.deploy-github"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn deploy_rollback_returns_not_found_for_unknown_extension() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        match rt.deploy_rollback("greentic.deploy-github", "job-1") {
            Err(RuntimeError::NotFound(id)) => assert_eq!(id, "greentic.deploy-github"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
