//! `contributions.views[]`: the UI pages an extension declares for a host
//! surface (Designer, Admin).
//!
//! There is no WIT counterpart to mirror here, unlike every other dispatch
//! module in this crate. A view is a static HTML/JS/CSS bundle shipped under
//! `assets/views/<id>/` inside the pack — declaration-only, the same way
//! [`crate::runtime_design::list_tools`]'s v2 path reads
//! `describe.contributions.tools[]` without ever calling into WASM. The
//! difference from that v2 tool path is that views have **no v1 fallback
//! either**: the runtime WIT has never exported a `list-views` interface, at
//! any contract version, because there is nothing a WASM guest could compute
//! here that isn't already fully expressed by the signed `describe.json`. So
//! where [`ExtensionRuntime::list_tools`] branches on `api_version` to choose
//! between the declarative path and a WIT call, [`ExtensionRuntime::list_views`]
//! has no such branch — not an oversight, just nothing to branch on.

use std::path::{Path, PathBuf};

use greentic_extension_sdk_contract::describe::contributions::View;

use crate::error::RuntimeError;
use crate::runtime::ExtensionRuntime;
use crate::types::ViewDefinition;

impl ExtensionRuntime {
    /// List every UI view a loaded extension contributes.
    ///
    /// Declaration-only: reads `describe.contributions.views[]` and resolves
    /// each view's on-disk asset location under the extension's
    /// `source_dir`. Does not read, verify, or serve any file the view
    /// declares — that is a host's job once it has the [`ViewDefinition`].
    ///
    /// # Errors
    ///
    /// - [`RuntimeError::NotFound`] when no extension is loaded at `ext_id`.
    /// - [`RuntimeError::Wasmtime`] (used here as the crate's general
    ///   internal-error carrier, matching e.g. `rebuild_registry`'s bad-semver
    ///   case in `runtime_registry.rs`) when a view's `id` or `entry` would
    ///   resolve outside the extension's directory. Unlike a missing tool
    ///   description, which is metadata quality that degrades gracefully, a
    ///   `..`-laden `entry` is a real path-traversal attempt against a
    ///   filesystem path this function hands back to the host — so the whole
    ///   call fails loudly rather than silently omitting the offending view.
    pub fn list_views(&self, ext_id: &str) -> Result<Vec<ViewDefinition>, RuntimeError> {
        let loaded = self.lookup(ext_id)?;
        loaded
            .describe
            .contributions
            .views
            .iter()
            .map(|v| view_to_definition(v, &loaded.source_dir))
            .collect()
    }
}

/// Map a v2 describe `View` contribution to a host-side [`ViewDefinition`],
/// resolving its asset directory and entry file against `source_dir`.
///
/// `source_dir` is the extension's verified installation directory
/// ([`crate::loaded::LoadedExtension::source_dir`]); `v.id` and `v.entry` are
/// publisher-controlled strings from a signed `describe.json`. Both get the
/// same path-traversal check [`crate::runtime_verify::pack_relative_path`]
/// applies to `gtpack.file` in `crate::loaded::wasm_component_path` — an
/// absolute path or a `..` segment in either field would otherwise resolve
/// to bytes outside the directory the manifest ledger covers.
#[must_use = "resolves paths against source_dir; the Result must be checked for traversal errors"]
pub fn view_to_definition(v: &View, source_dir: &Path) -> Result<ViewDefinition, RuntimeError> {
    let asset_dir = pack_relative(source_dir, &format!("assets/views/{}", v.id))
        .map_err(|e| RuntimeError::Wasmtime(anyhow::anyhow!("view {:?} asset dir: {e}", v.id)))?;
    let entry_path = pack_relative(&asset_dir, &v.entry)
        .map_err(|e| RuntimeError::Wasmtime(anyhow::anyhow!("view {:?} entry: {e}", v.id)))?;

    Ok(ViewDefinition {
        id: v.id.clone(),
        surface: v.surface,
        title_key: v.title_key.clone(),
        title_fallback: v.title_fallback.clone(),
        icon: v.icon.clone(),
        entry: v.entry.clone(),
        placement: v.placement.clone(),
        min_visibility: v.min_visibility,
        tools: v.tools.clone(),
        asset_dir,
        entry_path,
    })
}

/// Thin wrapper over [`crate::runtime_verify::pack_relative_path`] that turns
/// its `String` error into something callers can `?`-propagate without
/// hand-rolling the conversion at every call site.
fn pack_relative(dir: &Path, rel: &str) -> Result<PathBuf, String> {
    crate::runtime_verify::pack_relative_path(dir, rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_views_reports_an_unknown_extension_as_not_found() {
        let rt = ExtensionRuntime::for_test().expect("engine construction");
        assert!(matches!(
            rt.list_views("greentic.absent"),
            Err(RuntimeError::NotFound(_))
        ));
    }
}
