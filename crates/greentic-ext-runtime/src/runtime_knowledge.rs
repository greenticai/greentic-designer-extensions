//! Design-extension dispatch: `prompting` and `knowledge`.
//!
//! Sibling of [`crate::runtime_design`] — same export-walking pattern, split
//! off so neither file has to carry the whole design surface.

use crate::error::RuntimeError;
use crate::runtime::{
    DESIGN_VERSIONS, ExtensionRuntime, resolve_design_iface, resolve_func, resolve_iface_versions,
};
use crate::types::{HostExtensionError, KnowledgeEntry, KnowledgeEntrySummary, PromptFragment};

const PROMPTING_IFACE: &str = "greentic:extension-design/prompting";
const KNOWLEDGE_IFACE: &str = "greentic:extension-design/knowledge";

impl ExtensionRuntime {
    /// Retrieve system prompt fragments from a loaded design extension.
    ///
    /// Calls `greentic:extension-design/prompting::system-prompt-fragments`,
    /// resolving the interface newest-first across the design version table.
    pub fn prompt_fragments(&self, ext_id: &str) -> Result<Vec<PromptFragment>, RuntimeError> {
        use crate::host_bindings::exports::greentic::extension_design0_2_0::prompting::PromptFragment as WitFrag;

        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name) = resolve_design_iface(&mut store, &instance, PROMPTING_IFACE)?;
        let func_idx = resolve_func(
            &mut store,
            &instance,
            &iface_idx,
            &iface_name,
            "system-prompt-fragments",
        )?;

        let func = instance
            .get_typed_func::<(), (Vec<WitFrag>,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (frags,) = func
            .call(&mut store, ())
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(frags
            .into_iter()
            .map(|f| PromptFragment {
                section: f.section,
                content_markdown: f.content_markdown,
                priority: f.priority,
            })
            .collect())
    }

    /// List knowledge entries, optionally filtered by category.
    pub fn knowledge_list(
        &self,
        ext_id: &str,
        category_filter: Option<&str>,
    ) -> Result<Vec<KnowledgeEntrySummary>, RuntimeError> {
        use crate::host_bindings::exports::greentic::extension_design0_2_0::knowledge::EntrySummary as WitSummary;

        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name) = resolve_design_iface(&mut store, &instance, KNOWLEDGE_IFACE)?;
        let func_idx = resolve_func(
            &mut store,
            &instance,
            &iface_idx,
            &iface_name,
            "list-entries",
        )?;

        let func = instance
            .get_typed_func::<(Option<String>,), (Vec<WitSummary>,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (entries,) = func
            .call(&mut store, (category_filter.map(String::from),))
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(entries.into_iter().map(wit_summary_to_host).collect())
    }

    /// Retrieve a single knowledge entry by ID.
    ///
    /// The matched interface version selects which `extension-error` ABI to
    /// deserialize (6-variant base at `@0.3.0`, 4-variant base at
    /// `@0.2.0`/`@0.1.0`); WIT errors surface as [`RuntimeError::Extension`].
    pub fn knowledge_get(
        &self,
        ext_id: &str,
        entry_id: &str,
    ) -> Result<KnowledgeEntry, RuntimeError> {
        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name, version) =
            resolve_iface_versions(&mut store, &instance, KNOWLEDGE_IFACE, DESIGN_VERSIONS)?;
        let func_idx = resolve_func(&mut store, &instance, &iface_idx, &iface_name, "get-entry")?;

        let call_args = (entry_id.to_string(),);
        let mapped: Result<KnowledgeEntry, HostExtensionError> = if version == "0.3.0" {
            use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::knowledge::{
                Entry as WitEntry, ExtensionError as E2,
            };
            let func = instance
                .get_typed_func::<(String,), (Result<WitEntry, E2>,)>(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (r,) = func
                .call(&mut store, call_args)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map(|e| KnowledgeEntry {
                id: e.id,
                title: e.title,
                category: e.category,
                tags: e.tags,
                content_json: e.content_json,
            })
            .map_err(crate::ext_error::from_design_v03)
        } else {
            use crate::host_bindings::exports::greentic::extension_design0_2_0::knowledge::{
                Entry as WitEntry, ExtensionError as E1,
            };
            let func = instance
                .get_typed_func::<(String,), (Result<WitEntry, E1>,)>(&mut store, &func_idx)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            let (r,) = func
                .call(&mut store, call_args)
                .map_err(|e| RuntimeError::Wasmtime(e.into()))?;
            r.map(|e| KnowledgeEntry {
                id: e.id,
                title: e.title,
                category: e.category,
                tags: e.tags,
                content_json: e.content_json,
            })
            .map_err(crate::ext_error::from_design_v01)
        };

        mapped.map_err(RuntimeError::Extension)
    }

    /// Suggest knowledge entries matching a query.
    pub fn knowledge_suggest(
        &self,
        ext_id: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<KnowledgeEntrySummary>, RuntimeError> {
        use crate::host_bindings::exports::greentic::extension_design0_2_0::knowledge::EntrySummary as WitSummary;

        let (mut store, instance) = self.dispatch_instance(ext_id)?;
        let (iface_idx, iface_name) = resolve_design_iface(&mut store, &instance, KNOWLEDGE_IFACE)?;
        let func_idx = resolve_func(
            &mut store,
            &instance,
            &iface_idx,
            &iface_name,
            "suggest-entries",
        )?;

        let func = instance
            .get_typed_func::<(String, u32), (Vec<WitSummary>,)>(&mut store, &func_idx)
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        let (entries,) = func
            .call(&mut store, (query.to_string(), limit))
            .map_err(|e| RuntimeError::Wasmtime(e.into()))?;

        Ok(entries.into_iter().map(wit_summary_to_host).collect())
    }
}

/// Convert a bindgen `EntrySummary` to the host-side type.
fn wit_summary_to_host(
    s: crate::host_bindings::exports::greentic::extension_design0_2_0::knowledge::EntrySummary,
) -> KnowledgeEntrySummary {
    KnowledgeEntrySummary {
        id: s.id,
        title: s.title,
        category: s.category,
        tags: s.tags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_fragments_reports_an_unknown_extension_as_not_found() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        assert!(matches!(
            rt.prompt_fragments("greentic.absent"),
            Err(RuntimeError::NotFound(_))
        ));
    }

    #[test]
    fn knowledge_calls_report_an_unknown_extension_as_not_found() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        assert!(matches!(
            rt.knowledge_list("greentic.absent", None),
            Err(RuntimeError::NotFound(_))
        ));
        assert!(matches!(
            rt.knowledge_get("greentic.absent", "entry-1"),
            Err(RuntimeError::NotFound(_))
        ));
        assert!(matches!(
            rt.knowledge_suggest("greentic.absent", "query", 5),
            Err(RuntimeError::NotFound(_))
        ));
    }
}
