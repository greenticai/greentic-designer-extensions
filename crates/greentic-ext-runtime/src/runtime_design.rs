//! Design-extension dispatch: `tools`, `validation`, and `guardrail`.
//!
//! Mirrors the export-walking pattern used by every sibling dispatch module —
//! [`ExtensionRuntime::dispatch_instance`], resolve the interface newest-first,
//! resolve the function, call the typed signature, map the WIT error onto
//! [`crate::types::HostExtensionError`].

use crate::error::RuntimeError;
use crate::host_ports::HostCallContext;
use crate::runtime::{
    DESIGN_VERSIONS, ExtensionRuntime, GUARDRAIL_VERSIONS, resolve_design_iface, resolve_func,
    resolve_iface_versions, warn_if_legacy_contract,
};
use crate::types::{Diagnostic, HostExtensionError, Severity, ToolDefinition, ValidateResult};

/// The contract version under which `describe.json` is the sole source of tool
/// metadata. Mirrors the check in [`crate::tool_metadata_report`].
const V2_API_VERSION: &str = "greentic.ai/v2";

const TOOLS_IFACE: &str = "greentic:extension-design/tools";
const VALIDATION_IFACE: &str = "greentic:extension-design/validation";
const GUARDRAIL_IFACE: &str = "greentic:extension-design/guardrail";

impl ExtensionRuntime {
    /// Invoke a named tool on a loaded extension.
    ///
    /// Builds a fresh wasmtime Store + Instance, calls
    /// `greentic:extension-design/tools::invoke-tool` (resolved newest-first
    /// across 0.3.0/0.2.0/0.1.0; WIT errors surface as
    /// [`RuntimeError::Extension`]), and returns the JSON result string.
    pub fn invoke_tool(
        &self,
        ext_id: &str,
        tool_name: &str,
        args_json: &str,
    ) -> Result<String, RuntimeError> {
        self.invoke_tool_ctx(ext_id, tool_name, args_json, &HostCallContext::default())
    }

    /// Like [`Self::invoke_tool`] but threads a per-call [`HostCallContext`]
    /// (e.g. the caller's tenant slug) into the host ports for this dispatch.
    /// Multi-tenant hosts (the designer) use this so the LLM port can resolve
    /// roles per tenant.
    pub fn invoke_tool_ctx(
        &self,
        ext_id: &str,
        tool_name: &str,
        args_json: &str,
        ctx: &HostCallContext,
    ) -> Result<String, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance_ctx(ext_id, ctx)?;

        // The interface is resolved newest-first across the design version
        // table; the matched version selects which `extension-error` ABI to
        // deserialize (6-variant base at 0.3.0, 4-variant base at 0.2.0/0.1.0).
        // The invoke-tool signature is identical across versions — only the
        // error variant set differs.
        let (iface_idx, iface_name, version) =
            resolve_iface_versions(&mut store, &instance, TOOLS_IFACE, DESIGN_VERSIONS)?;
        warn_if_legacy_contract(ext_id, version, DESIGN_VERSIONS[0]);
        let func_idx = resolve_func(
            &mut store,
            &instance,
            &iface_idx,
            &iface_name,
            "invoke-tool",
        )?;

        let call_args = (tool_name.to_string(), args_json.to_string());
        let mapped: Result<String, HostExtensionError> = if version == "0.3.0" {
            use crate::host_bindings::design_v03::greentic::extension_base0_2_0::types::ExtensionError as E2;
            let func = instance
                .get_typed_func::<(String, String), (Result<String, E2>,)>(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (r,) = func
                .call(&mut store, call_args)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map_err(crate::ext_error::from_design_v03)
        } else {
            use crate::host_bindings::greentic::extension_base0_1_0::types::ExtensionError as E1;
            let func = instance
                .get_typed_func::<(String, String), (Result<String, E1>,)>(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (r,) = func
                .call(&mut store, call_args)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map_err(crate::ext_error::from_design_v01)
        };

        mapped.map_err(RuntimeError::Extension)
    }

    /// List all tools exposed by a loaded design extension.
    ///
    /// Calls `greentic:extension-design/tools::list-tools` for v1-contract
    /// extensions. **v2 contract** (`apiVersion == "greentic.ai/v2"`) reads the
    /// tools from `describe.contributions.tools[]` — the runtime WIT no longer
    /// exports `list-tools` in that contract. Everything a v2 tool exposes —
    /// description, schemas, capabilities, agentic-worker metadata — must
    /// therefore be declared in `describe.json`; the WIT export is never
    /// consulted on that path.
    pub fn list_tools(&self, ext_id: &str) -> Result<Vec<ToolDefinition>, RuntimeError> {
        use crate::host_bindings::exports::greentic::extension_design0_2_0::tools::ToolDefinition as WitToolDef;

        let loaded = self.lookup(ext_id)?;

        // v2 declarative path: tools live in describe.json, not in WIT.
        if loaded.describe.api_version == V2_API_VERSION {
            return Ok(loaded
                .describe
                .contributions
                .tools
                .iter()
                .map(contribution_tool_to_definition)
                .collect());
        }

        // v1 WIT-call path.
        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name) = resolve_design_iface(&mut store, &instance, TOOLS_IFACE)?;
        let func_idx = resolve_func(&mut store, &instance, &iface_idx, &iface_name, "list-tools")?;

        let func = instance
            .get_typed_func::<(), (Vec<WitToolDef>,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (defs,) = func
            .call(&mut store, ())
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(defs
            .into_iter()
            .map(|d| ToolDefinition {
                name: d.name,
                description: d.description,
                input_schema_json: d.input_schema_json,
                output_schema_json: d.output_schema_json,
                capabilities: d.capabilities,
                agentic_worker_metadata: d.agentic_worker_metadata,
                // v1 WIT has no per-tool secret declaration; the field exists
                // only for the v2 declarative path above.
                secret_requirements: Vec::new(),
            })
            .collect())
    }

    /// Validate extension-specific content against the extension's schema.
    ///
    /// `content_type` is an extension-defined label (e.g. `"AdaptiveCard"` for
    /// the adaptive-cards extension); `content_json` is the content payload as
    /// a JSON string.
    ///
    /// Returns a [`ValidateResult`] with a `valid` flag and a list of
    /// diagnostics. Extensions that don't export this interface surface a
    /// [`RuntimeError::Wasmtime`] — callers that want graceful degradation
    /// should treat "interface not exported" as "no validation available"
    /// rather than a hard failure.
    pub fn validate_content(
        &self,
        ext_id: &str,
        content_type: &str,
        content_json: &str,
    ) -> Result<ValidateResult, RuntimeError> {
        use crate::host_bindings::exports::greentic::extension_design0_2_0::validation::ValidateResult as WitValidateResult;

        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name) =
            resolve_design_iface(&mut store, &instance, VALIDATION_IFACE)?;
        let func_idx = resolve_func(
            &mut store,
            &instance,
            &iface_idx,
            &iface_name,
            "validate-content",
        )?;

        let func = instance
            .get_typed_func::<(String, String), (WitValidateResult,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (result,) = func
            .call(
                &mut store,
                (content_type.to_string(), content_json.to_string()),
            )
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(ValidateResult {
            valid: result.valid,
            diagnostics: result
                .diagnostics
                .into_iter()
                .map(|d| Diagnostic {
                    severity: severity_from_wit(d.severity),
                    code: d.code,
                    message: d.message,
                    path: d.path,
                })
                .collect(),
        })
    }

    /// Evaluate a guardrail extension against `input_json` and return the
    /// verdict as a JSON string.
    ///
    /// `input_json` must be a JSON object matching the WIT `guardrail-input`
    /// record:
    ///
    /// ```json
    /// {
    ///   "direction": "inbound",
    ///   "content": "…",
    ///   "agent_id": "…",
    ///   "session_id": "…",
    ///   "tenant_id": "…",
    ///   "env_id": "…",
    ///   "context": null
    /// }
    /// ```
    ///
    /// Returns the verdict as JSON, e.g. `{"kind":"accept"}` or
    /// `{"kind":"deny","code":"…","message":"…","details":null}`.
    ///
    /// # Errors
    ///
    /// - [`RuntimeError::NotFound`] when no extension is loaded at `ext_id`.
    /// - [`RuntimeError::Wasmtime`] when store/instance construction fails, the
    ///   interface is not exported, the typed-func call fails, or `input_json`
    ///   cannot be deserialised.
    pub fn evaluate_guardrail(
        &self,
        ext_id: &str,
        input_json: &str,
    ) -> Result<String, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;

        // Guardrail interface only exists at 0.3.0 — a single-version table.
        let (iface_idx, iface_name, _version) =
            resolve_iface_versions(&mut store, &instance, GUARDRAIL_IFACE, GUARDRAIL_VERSIONS)?;
        let func_idx = resolve_func(&mut store, &instance, &iface_idx, &iface_name, "evaluate")?;

        let wire =
            crate::guardrail_map::call_evaluate(&mut store, &instance, &func_idx, input_json)?;
        serde_json::to_string(&wire).map_err(|e| RuntimeError::Wasmtime(e.into()))
    }
}

/// Map a v2 describe `Tool` contribution to a host-side [`ToolDefinition`].
///
/// Every field comes from the declarative `describe.json` tool entry — for a
/// v2 extension this is the ONLY source, since [`ExtensionRuntime::list_tools`]
/// never calls the wasm's `list-tools` export for that contract. A field the
/// describe omits is therefore not "filled in from WIT later"; it is simply
/// absent for the tool's whole life.
///
/// Omissions are not errors, so that a partially-declared tool is still
/// offered rather than disappearing — but each one degrades the tool, and the
/// symptom is otherwise silence: an LLM that cannot infer arguments, or a
/// planner with no side-effect signal, and nothing anywhere saying why. This
/// mapper is a pure function and reports nothing; the omissions are reported
/// once per extension when the artifact is loaded, by
/// `tool_metadata_report::report_tool_metadata_gaps`. Reporting from here
/// instead would repeat the whole burst on every `list_tools` call, which is a
/// per-request path.
#[must_use]
pub fn contribution_tool_to_definition(
    t: &greentic_extension_sdk_contract::describe::contributions::Tool,
) -> ToolDefinition {
    ToolDefinition {
        name: t.name.clone(),
        description: t.description.clone().unwrap_or_default(),
        input_schema_json: t.input_schema.clone().unwrap_or_default(),
        output_schema_json: t.output_schema.clone(),
        capabilities: t.capabilities.clone(),
        agentic_worker_metadata: t.agentic_worker_metadata.clone(),
        secret_requirements: t.secret_requirements.clone(),
    }
}

/// Shared severity mapping for the `@0.1.0` base-types enum that both the
/// design and deploy worlds re-export.
pub(crate) fn severity_from_wit(
    s: crate::host_bindings::greentic::extension_base0_1_0::types::Severity,
) -> Severity {
    use crate::host_bindings::greentic::extension_base0_1_0::types::Severity as Wit;
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
    fn invoke_tool_reports_an_unknown_extension_as_not_found() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        match rt.invoke_tool("greentic.absent", "do_thing", "{}") {
            Err(RuntimeError::NotFound(id)) => assert_eq!(id, "greentic.absent"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn list_tools_reports_an_unknown_extension_as_not_found() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        assert!(matches!(
            rt.list_tools("greentic.absent"),
            Err(RuntimeError::NotFound(_))
        ));
    }

    #[test]
    fn validate_content_reports_an_unknown_extension_as_not_found() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        assert!(matches!(
            rt.validate_content("greentic.absent", "AdaptiveCard", "{}"),
            Err(RuntimeError::NotFound(_))
        ));
    }

    #[test]
    fn evaluate_guardrail_reports_an_unknown_extension_as_not_found() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        assert!(matches!(
            rt.evaluate_guardrail("greentic.absent", "{}"),
            Err(RuntimeError::NotFound(_))
        ));
    }
}
