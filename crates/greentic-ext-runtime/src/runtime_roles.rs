//! `roles` interface dispatch for design extensions.
//!
//! Mirrors the export-walking pattern of the sibling dispatch modules
//! ([`crate::runtime_design`], [`crate::runtime_bundle`]): resolve a fresh
//! store + instance, resolve the interface newest-first, call the typed
//! signature, map the WIT error onto a host type.
//!
//! `roles` keeps its own version table rather than reusing `DESIGN_VERSIONS`:
//! the interface never existed at `@0.1.0`, so falling back that far would
//! look for an interface that cannot be there.

use crate::error::RuntimeError;
use crate::runtime::ExtensionRuntime;
use crate::types::{
    CompileContext, Diagnostic, HostExtensionError, RoleError, RoleSpec, Severity, TargetKind,
};

/// Base interface name without version suffix.
const IFACE_BASE: &str = "greentic:extension-design/roles";
/// Version resolution order — newest first.
const ROLES_VERSIONS: &[&str] = &["0.3.0", "0.2.0"];

impl ExtensionRuntime {
    /// List all roles exposed by a loaded design extension.
    ///
    /// Calls `greentic:extension-design/roles::list-roles` (resolved against
    /// `@0.3.0` first, then `@0.2.0`).
    /// Returns an empty vec when the extension does not export the
    /// `roles` interface (older 0.1.0 extensions, for example) so
    /// callers can treat it as "no roles published" without reaching
    /// for `RuntimeError::Wasmtime`.
    pub fn list_roles(&self, ext_id: &str) -> Result<Vec<RoleSpec>, RuntimeError> {
        use crate::host_bindings::exports::greentic::extension_design0_2_0::roles::RoleSpec as WitRoleSpec;

        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        // Try newest first; fall back gracefully to empty if neither version
        // is exported (older extensions that pre-date roles entirely).
        let iface_idx = {
            let mut found = None;
            for &v in ROLES_VERSIONS {
                let name = format!("{IFACE_BASE}@{v}");
                if let Some(idx) = instance.get_export_index(&mut store, None, &name) {
                    found = Some(idx);
                    break;
                }
            }
            match found {
                Some(idx) => idx,
                None => return Ok(Vec::new()),
            }
        };

        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "list-roles")
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "interface '{IFACE_BASE}' does not export 'list-roles'"
                ))
            })?;

        let func = instance
            .get_typed_func::<(), (Vec<WitRoleSpec>,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (roles,) = func
            .call(&mut store, ())
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(roles.into_iter().map(wit_role_spec_to_host).collect())
    }

    /// Run the cheap-path validator for a role's DSL entry.
    ///
    /// Calls `greentic:extension-design/roles::validate-role` (resolved
    /// against `@0.3.0` first, then `@0.2.0`).
    /// Returns the diagnostic list verbatim (empty = valid, mirrors the
    /// WIT contract). `RuntimeError` is reserved for host failures —
    /// missing extension, missing interface, wasmtime trap.
    pub fn validate_role(
        &self,
        ext_id: &str,
        name: &str,
        entry_json: &str,
    ) -> Result<Vec<Diagnostic>, RuntimeError> {
        use crate::host_bindings::exports::greentic::extension_design0_2_0::roles::Diagnostic as WitDiagnostic;

        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        let (iface_idx, iface_name, _version) = crate::runtime::resolve_iface_versions(
            &mut store,
            &instance,
            IFACE_BASE,
            ROLES_VERSIONS,
        )?;

        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "validate-role")
            .ok_or_else(|| {
                RuntimeError::Wasmtime(anyhow::anyhow!(
                    "interface '{iface_name}' does not export 'validate-role'"
                ))
            })?;

        let func = instance
            .get_typed_func::<(String, String), (Vec<WitDiagnostic>,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (diags,) = func
            .call(&mut store, (name.to_string(), entry_json.to_string()))
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(diags.into_iter().map(wit_diagnostic_to_host).collect())
    }

    /// Compile a single DSL entry to its target representation.
    ///
    /// Calls `greentic:extension-design/roles::compile-role` (resolved against
    /// `@0.3.0` first, then `@0.2.0`). A missing extension surfaces as
    /// `RoleError::UnknownRole(ext_id)` (the registry can't tell "no
    /// extension" apart from "no role" from the LLM's perspective and both
    /// should retry with a hint). Host failures (wasmtime trap, missing
    /// interface) surface as `RoleError::Host(HostExtensionError::Internal(_))`
    /// so the caller can match exhaustively without juggling two error types.
    pub fn compile_role(
        &self,
        ext_id: &str,
        name: &str,
        target: TargetKind,
        entry_json: &str,
        ctx: Option<&CompileContext>,
    ) -> Result<String, RoleError> {
        // A missing extension surfaces as `UnknownRole`, not `NotFound`: from
        // the LLM's point of view "no such extension" and "no such role" call
        // for the same retry, so `compile_role` collapses them deliberately.
        let (mut store, instance) = self.dispatch_instance(ext_id).map_err(|e| match e {
            RuntimeError::NotFound(id) => RoleError::UnknownRole(id),
            other => RoleError::Host(HostExtensionError::Internal(format!(
                "instantiate '{ext_id}': {other}"
            ))),
        })?;

        let (iface_idx, iface_name, version) = crate::runtime::resolve_iface_versions(
            &mut store,
            &instance,
            IFACE_BASE,
            ROLES_VERSIONS,
        )
        .map_err(|e| {
            RoleError::Host(HostExtensionError::Internal(format!(
                "extension '{ext_id}' does not export '{IFACE_BASE}': {e}"
            )))
        })?;

        let func_idx = instance
            .get_export_index(&mut store, Some(&iface_idx), "compile-role")
            .ok_or_else(|| {
                RoleError::Host(HostExtensionError::Internal(format!(
                    "interface '{iface_name}' does not export 'compile-role'"
                )))
            })?;

        if version == "0.3.0" {
            use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::{
                CompileContext as WitCompileContext, RoleError as WitRoleError,
                TargetKind as WitTargetKind,
            };

            let func = instance
                .get_typed_func::<
                    (String, WitTargetKind, String, Option<WitCompileContext>),
                    (Result<String, WitRoleError>,),
                >(&mut store, &func_idx)
                .map_err(|e| RoleError::Host(HostExtensionError::Internal(e.to_string())))?;

            let wit_ctx = ctx.cloned().map(|c| WitCompileContext {
                flow_entries_json: c.flow_entries_json,
                flow_id: c.flow_id,
                locale: c.locale,
            });

            let (result,) = func
                .call(
                    &mut store,
                    (
                        name.to_string(),
                        target_to_wit_v03(target),
                        entry_json.to_string(),
                        wit_ctx,
                    ),
                )
                .map_err(|e| RoleError::Host(HostExtensionError::Internal(e.to_string())))?;

            result.map_err(wit_role_error_to_host_v03)
        } else {
            use crate::host_bindings::exports::greentic::extension_design0_2_0::roles::{
                CompileContext as WitCompileContext, RoleError as WitRoleError,
                TargetKind as WitTargetKind,
            };

            let func = instance
                .get_typed_func::<
                    (String, WitTargetKind, String, Option<WitCompileContext>),
                    (Result<String, WitRoleError>,),
                >(&mut store, &func_idx)
                .map_err(|e| RoleError::Host(HostExtensionError::Internal(e.to_string())))?;

            let wit_ctx = ctx.cloned().map(|c| WitCompileContext {
                flow_entries_json: c.flow_entries_json,
                flow_id: c.flow_id,
                locale: c.locale,
            });

            let (result,) = func
                .call(
                    &mut store,
                    (
                        name.to_string(),
                        target_to_wit(target),
                        entry_json.to_string(),
                        wit_ctx,
                    ),
                )
                .map_err(|e| RoleError::Host(HostExtensionError::Internal(e.to_string())))?;

            result.map_err(wit_role_error_to_host)
        }
    }
}

fn wit_role_spec_to_host(
    s: crate::host_bindings::exports::greentic::extension_design0_2_0::roles::RoleSpec,
) -> RoleSpec {
    RoleSpec {
        name: s.name,
        description: s.description,
        json_schema: s.json_schema,
        target: target_from_wit(s.target),
        schema_version: s.schema_version,
        context_aware: s.context_aware,
    }
}

fn wit_diagnostic_to_host(
    d: crate::host_bindings::exports::greentic::extension_design0_2_0::roles::Diagnostic,
) -> Diagnostic {
    use crate::host_bindings::greentic::extension_base0_1_0::types::Severity as WitSeverity;
    Diagnostic {
        severity: match d.severity {
            WitSeverity::Error => Severity::Error,
            WitSeverity::Warning => Severity::Warning,
            WitSeverity::Info => Severity::Info,
            WitSeverity::Hint => Severity::Hint,
        },
        code: d.code,
        message: d.message,
        path: d.path,
    }
}

// ---------------------------------------------------------------------------
// v0.2.0 error mapping helpers
// ---------------------------------------------------------------------------

fn wit_role_error_to_host(
    e: crate::host_bindings::exports::greentic::extension_design0_2_0::roles::RoleError,
) -> RoleError {
    use crate::host_bindings::exports::greentic::extension_design0_2_0::roles::RoleError as WitRoleError;
    match e {
        WitRoleError::UnknownRole(s) => RoleError::UnknownRole(s),
        WitRoleError::InvalidInput(diags) => {
            RoleError::InvalidInput(diags.into_iter().map(wit_diagnostic_to_host).collect())
        }
        WitRoleError::CompileFailed(s) => RoleError::CompileFailed(s),
        WitRoleError::TargetNotSupported(t) => RoleError::TargetNotSupported(target_from_wit(t)),
        WitRoleError::VersionNotSupported(v) => RoleError::VersionNotSupported(v),
        WitRoleError::Host(ee) => RoleError::Host(wit_extension_error_to_host(ee)),
    }
}

fn wit_extension_error_to_host(
    e: crate::host_bindings::exports::greentic::extension_design0_2_0::roles::ExtensionError,
) -> HostExtensionError {
    use crate::host_bindings::exports::greentic::extension_design0_2_0::roles::ExtensionError as WitErr;
    match e {
        WitErr::InvalidInput(s) => HostExtensionError::InvalidInput(s),
        WitErr::MissingCapability(s) => HostExtensionError::MissingCapability(s),
        WitErr::PermissionDenied(s) => HostExtensionError::PermissionDenied(s),
        WitErr::Internal(s) => HostExtensionError::Internal(s),
    }
}

fn target_to_wit(
    t: TargetKind,
) -> crate::host_bindings::exports::greentic::extension_design0_2_0::roles::TargetKind {
    use crate::host_bindings::exports::greentic::extension_design0_2_0::roles::TargetKind as Wit;
    match t {
        TargetKind::AdaptiveCard => Wit::AdaptiveCard,
        TargetKind::SlackBlockKit => Wit::SlackBlockKit,
        TargetKind::TeamsCard => Wit::TeamsCard,
        TargetKind::PlainText => Wit::PlainText,
    }
}

fn target_from_wit(
    t: crate::host_bindings::exports::greentic::extension_design0_2_0::roles::TargetKind,
) -> TargetKind {
    use crate::host_bindings::exports::greentic::extension_design0_2_0::roles::TargetKind as Wit;
    match t {
        Wit::AdaptiveCard => TargetKind::AdaptiveCard,
        Wit::SlackBlockKit => TargetKind::SlackBlockKit,
        Wit::TeamsCard => TargetKind::TeamsCard,
        Wit::PlainText => TargetKind::PlainText,
    }
}

// ---------------------------------------------------------------------------
// v0.3.0 error mapping helpers
// ---------------------------------------------------------------------------

fn wit_role_error_to_host_v03(
    e: crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::RoleError,
) -> RoleError {
    use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::RoleError as WitRoleError;
    match e {
        WitRoleError::UnknownRole(s) => RoleError::UnknownRole(s),
        WitRoleError::InvalidInput(diags) => {
            RoleError::InvalidInput(diags.into_iter().map(wit_diagnostic_to_host_v03).collect())
        }
        WitRoleError::CompileFailed(s) => RoleError::CompileFailed(s),
        WitRoleError::TargetNotSupported(t) => {
            RoleError::TargetNotSupported(target_from_wit_v03(t))
        }
        WitRoleError::VersionNotSupported(v) => RoleError::VersionNotSupported(v),
        WitRoleError::Host(ee) => RoleError::Host(wit_extension_error_to_host_v03(ee)),
    }
}

/// Map the 6-variant `extension-error` from the `design_v03` roles re-export.
///
/// This is structurally identical to `crate::ext_error::from_design_v03` but
/// takes the distinct re-exported type generated under the roles interface
/// path rather than the base-types path.
fn wit_extension_error_to_host_v03(
    e: crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::ExtensionError,
) -> HostExtensionError {
    use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::ExtensionError as WitErr;
    match e {
        WitErr::InvalidInput(s) => HostExtensionError::InvalidInput(s),
        WitErr::MissingCapability(s) => HostExtensionError::MissingCapability(s),
        WitErr::PermissionDenied(s) => HostExtensionError::PermissionDenied(s),
        WitErr::NotFound(s) => HostExtensionError::NotFound(s),
        WitErr::SchemaInvalid(s) => HostExtensionError::SchemaInvalid(s),
        WitErr::Internal(s) => HostExtensionError::Internal(s),
    }
}

fn wit_diagnostic_to_host_v03(
    d: crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::Diagnostic,
) -> Diagnostic {
    use crate::host_bindings::design_v03::greentic::extension_base0_2_0::types::Severity as WitSeverity;
    Diagnostic {
        severity: match d.severity {
            WitSeverity::Error => Severity::Error,
            WitSeverity::Warning => Severity::Warning,
            WitSeverity::Info => Severity::Info,
            WitSeverity::Hint => Severity::Hint,
        },
        code: d.code,
        message: d.message,
        path: d.path,
    }
}

fn target_to_wit_v03(
    t: TargetKind,
) -> crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::TargetKind {
    use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::TargetKind as Wit;
    match t {
        TargetKind::AdaptiveCard => Wit::AdaptiveCard,
        TargetKind::SlackBlockKit => Wit::SlackBlockKit,
        TargetKind::TeamsCard => Wit::TeamsCard,
        TargetKind::PlainText => Wit::PlainText,
    }
}

fn target_from_wit_v03(
    t: crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::TargetKind,
) -> TargetKind {
    use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::roles::TargetKind as Wit;
    match t {
        Wit::AdaptiveCard => TargetKind::AdaptiveCard,
        Wit::SlackBlockKit => TargetKind::SlackBlockKit,
        Wit::TeamsCard => TargetKind::TeamsCard,
        Wit::PlainText => TargetKind::PlainText,
    }
}
