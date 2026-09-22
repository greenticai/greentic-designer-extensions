//! Registration, capability-registry derivation, and the hot-reload watcher.
//!
//! Split out of [`crate::runtime`] so the mutation paths for `loaded` live
//! together: every one of them must rebuild the capability registry wholesale
//! (see [`ExtensionRuntime::rebuild_registry`]), and keeping them in one file
//! is what makes a new mutation path that forgets to obvious on review.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::capability::{CapabilityRegistry, OfferedBinding};
use crate::error::RuntimeError;
use crate::loaded::{ExtensionId, LoadedExtension, LoadedExtensionRef};
use crate::runtime::{ExtensionRuntime, RuntimeEvent};

impl ExtensionRuntime {
    /// Verify, load, and register the extension in `dir`.
    ///
    /// The signature gate runs first and unconditionally — see
    /// [`crate::runtime_verify`].
    pub fn register_loaded_from_dir(&mut self, dir: &Path) -> Result<(), RuntimeError> {
        let (describe, ledger) = self.verify_dir_signature(dir)?;
        let loaded = LoadedExtension::from_verified(self.engine(), dir, describe, &ledger)?;
        let id = loaded.id.clone();

        self.mutate_loaded(|map| map.insert(id.clone(), Arc::new(loaded)))?;

        self.emit(RuntimeEvent::ExtensionInstalled(id));
        Ok(())
    }

    /// Derive the capability registry from the loaded set.
    ///
    /// The registry holds nothing that is not already derivable from the
    /// loaded describes, so it is rebuilt wholesale rather than patched
    /// incrementally at each call site. That is what makes eviction correct by
    /// construction: a capability dropped from a describe, an extension that
    /// was removed, and a re-registered dir all fall out of the new map
    /// automatically instead of each needing its own fix. The previous
    /// clone-forward-then-append approach got all three wrong.
    pub(crate) fn rebuild_registry(
        loaded: &HashMap<ExtensionId, LoadedExtensionRef>,
    ) -> Result<CapabilityRegistry, RuntimeError> {
        let mut registry = CapabilityRegistry::new();
        for (id, ext) in loaded {
            for cap in &ext.describe.capabilities.offered {
                let version: semver::Version =
                    cap.version.parse().map_err(|e: semver::Error| {
                        RuntimeError::Wasmtime(anyhow::anyhow!("bad offered version: {e}"))
                    })?;
                registry.add_offering(OfferedBinding {
                    extension_id: id.as_str().to_string(),
                    cap_id: cap.id.clone(),
                    version,
                    kind: ext.kind,
                    // Source-dir registration has no export path; preserved
                    // from the original behaviour.
                    export_path: String::new(),
                });
            }
        }
        Ok(registry)
    }

    /// Drop the extension loaded from `dir`, addressed by its source path.
    ///
    /// The watcher no longer routes through here — it goes through
    /// [`Self::evict_vanished_extensions`], which asks the filesystem rather
    /// than trusting the removed path. This remains as the by-path entry point
    /// for tests that want to evict one specific directory without staging a
    /// real uninstall, and for an embedder that already knows which directory
    /// went away.
    ///
    /// `#[doc(hidden)] pub` rather than private so the watcher-path tests can
    /// reach it; not part of the supported API.
    #[doc(hidden)]
    pub fn handle_removal(&self, dir: &Path) {
        // The lookup happens inside the edit so it sees the same map the
        // removal is applied to; resolving the id outside would reintroduce the
        // race the lock exists to close.
        let found = self.mutate_loaded(|map| {
            let id = map
                .iter()
                .find(|(_, v)| v.source_dir == dir)
                .map(|(id, _)| id.clone())?;
            map.remove(&id);
            Some(id)
        });
        self.report_eviction(&dir.display().to_string(), found);
    }

    /// Drop one extension by id.
    pub(crate) fn evict(&self, id: &ExtensionId) {
        let found = self.mutate_loaded(|map| map.remove(id).map(|_| id.clone()));
        self.report_eviction(id.as_str(), found);
    }

    /// Announce an eviction, or record why one did not happen.
    ///
    /// Rebuilding drops the evicted extension's offerings. Leaving them
    /// advertised is the false positive that lets a preflight check pass a
    /// policy the runtime then fails closed on.
    fn report_eviction(&self, subject: &str, found: Result<Option<ExtensionId>, RuntimeError>) {
        match found {
            Ok(Some(id)) => self.emit(RuntimeEvent::ExtensionRemoved(id)),
            Ok(None) => {}
            // Unreachable in practice: an extension whose offered version does
            // not parse never enters `loaded` (every insert rebuilds before
            // storing and bails on error), so a rebuild over a subset of
            // `loaded` cannot fail. Eviction returns no error, so rather than
            // strand the runtime in a half-applied state we keep both the map
            // and the registry as they were and make the anomaly auditable.
            Err(e) => tracing::error!(
                subject,
                error = %e,
                "capability registry rebuild failed on eviction; extension left loaded"
            ),
        }
    }

    /// Hot-reload entry point for an added or modified extension directory.
    ///
    /// `#[doc(hidden)] pub` rather than private so the watcher-path tests can
    /// exercise the signature gate directly — driving a real filesystem
    /// watcher from a test would be slow and racy. Not part of the supported
    /// API: callers should use [`ExtensionRuntime::register_loaded_from_dir`].
    #[doc(hidden)]
    pub fn handle_added_or_modified(&self, dir: &Path) -> Result<(), RuntimeError> {
        // The same gate as `register_loaded_from_dir`, no exceptions. Without
        // this, anyone able to write to a watched extension directory got code
        // execution with no signature check at all — and did not even need to
        // re-sign, since this path previously verified nothing.
        let (describe, ledger) = self.verify_dir_signature(dir)?;
        let loaded = LoadedExtension::from_verified(self.engine(), dir, describe, &ledger)?;
        let id = loaded.id.clone();
        let new_version = loaded.describe.metadata.version.clone();

        // Refuse a downgrade. TOFU pins a publisher *key*, never a version
        // floor, so a correctly-signed older pack verifies perfectly — which
        // means anyone who can write the extensions directory, or replay a
        // stale artifact the publisher really did sign, can roll a patched
        // extension back to a vulnerable one and the gate applauds.
        let outcome = self.mutate_loaded(|map| {
            let prev = map.get(&id).map(|e| e.describe.metadata.version.clone());
            if let Some(prev) = &prev
                && is_downgrade(prev, &new_version)
            {
                return Reload::RefusedDowngrade(prev.clone());
            }
            map.insert(id.clone(), Arc::new(loaded));
            match prev {
                Some(prev) => Reload::Updated(prev),
                None => Reload::Installed,
            }
        })?;

        let event = match outcome {
            Reload::Updated(prev_version) => RuntimeEvent::ExtensionUpdated { id, prev_version },
            Reload::Installed => RuntimeEvent::ExtensionInstalled(id),
            Reload::RefusedDowngrade(prev) => {
                return Err(RuntimeError::SignatureInvalid {
                    extension_id: id.as_str().to_string(),
                    reason: format!(
                        "refusing to replace version {prev} with the older {new_version}: a \
                         correctly-signed older pack is still a downgrade"
                    ),
                });
            }
        };
        self.emit(event);
        Ok(())
    }
}

/// What a reload did to the loaded map.
enum Reload {
    Installed,
    Updated(String),
    RefusedDowngrade(String),
}

/// Is `candidate` an older release than `current`?
///
/// Both must parse as semver for the comparison to mean anything; an
/// unparseable version on either side is not treated as a downgrade, because
/// refusing loads over a version string we cannot read would break packs that
/// verify fine. Equal versions are allowed through — re-registering the same
/// version is how a repaired pack is reloaded.
fn is_downgrade(current: &str, candidate: &str) -> bool {
    match (
        semver::Version::parse(current),
        semver::Version::parse(candidate),
    ) {
        (Ok(current), Ok(candidate)) => candidate < current,
        _ => false,
    }
}
