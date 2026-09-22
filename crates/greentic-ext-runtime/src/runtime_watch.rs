//! The hot-reload watcher: filesystem events in, load and eviction out.
//!
//! Split from [`crate::runtime_registry`], which owns the mutation paths this
//! calls into. The two halves answer different questions — *what a change to
//! the tree means* lives here, *how the loaded map changes* lives there.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::RuntimeError;
use crate::loaded::ExtensionId;
use crate::runtime::{ExtensionRuntime, RuntimeEvent, WatcherGuard};

/// Filename of the persistent enable/disable state document, located at
/// `<home>/extensions-state.json`. Kept in sync with the constant of the
/// same name in `greentic-ext-state` (single source of truth lives there;
/// this duplicate exists only because the runtime intentionally does not
/// depend on `greentic-ext-state` to avoid a circular crate dependency).
const STATE_FILENAME: &str = "extensions-state.json";

/// How long the watcher thread waits on the event channel before re-checking
/// its stop signal. Bounds shutdown latency; `WatcherGuard::drop` documents it.
const WATCH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

impl ExtensionRuntime {
    /// Spawns a watcher background thread. Events trigger reload of the
    /// affected extension's directory. The returned guard stops the thread
    /// when dropped.
    pub fn start_watcher(self: Arc<Self>) -> Result<WatcherGuard, RuntimeError> {
        let mut paths: Vec<PathBuf> = self.config().paths.all().into_iter().cloned().collect();
        // Also watch the parent of the extensions root so we receive events
        // for `<home>/extensions-state.json`. Best-effort: if the home dir
        // doesn't exist or has no parent we skip it — the kind dirs are still
        // watched, so hot reload keeps working; only the state-file signal is
        // lost, and `crate::watcher::watch` logs the paths it could not take.
        if let Some(home) = self.config().paths.home()
            && home.exists()
            && !paths.iter().any(|p| p == home)
        {
            paths.push(home.to_path_buf());
        }
        let (rx, watch_handle) = crate::watcher::watch(&paths)?;
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let this = self.clone();
        let join = std::thread::spawn(move || {
            // Own the watch_handle here — dropping it closes the fs watcher
            // and the tx side of the FsEvent channel when this thread exits.
            let _watch_handle = watch_handle;
            loop {
                // Check stop signal (Ok = message received, Disconnected = sender dropped).
                match stop_rx.try_recv() {
                    Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
                match rx.recv_timeout(WATCH_POLL_INTERVAL) {
                    Ok(event) => {
                        if let Err(e) = this.handle_fs_event(&event) {
                            tracing::warn!(error = %e, "hot reload failed");
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        Ok(WatcherGuard::new(stop_tx, join))
    }

    /// Drive one filesystem event through the classifier.
    ///
    /// `#[doc(hidden)] pub` for the same reason as [`Self::handle_removal`]:
    /// the classification itself — which events evict and which reload — is
    /// what the watcher tests need to pin, and driving a real filesystem
    /// watcher to reach it would be slow and racy. Not part of the supported
    /// API.
    #[doc(hidden)]
    pub fn handle_fs_event_for_test(
        &self,
        event: &crate::watcher::FsEvent,
    ) -> Result<(), RuntimeError> {
        self.handle_fs_event(event)
    }

    fn handle_fs_event(&self, event: &crate::watcher::FsEvent) -> Result<(), RuntimeError> {
        use crate::watcher::FsEvent;
        let path = match event {
            FsEvent::Added(p) | FsEvent::Modified(p) | FsEvent::Removed(p) => p.clone(),
        };

        // Classify state file events first. The state file lives at exactly
        // `<home>/extensions-state.json`. Match the whole path, not the
        // basename: the home dir is watched recursively, so a basename match
        // also fired for any pack shipping a file of that name — which both
        // emitted spurious `StateFileChanged` and, worse, returned early and
        // skipped re-verifying the pack that file belonged to.
        let is_state_file = self
            .config()
            .paths
            .home()
            .is_some_and(|home| path == home.join(STATE_FILENAME));
        if is_state_file {
            self.emit(RuntimeEvent::StateFileChanged);
            return Ok(());
        }

        match event {
            // Removal cannot go through `find_extension_dir`: that resolves a
            // path by looking for a `describe.json` beside it, and after an
            // uninstall there is no describe.json to find — so the event was
            // dropped and the extension stayed loaded and dispatchable until
            // the process restarted. Match against what is loaded instead, and
            // let the filesystem confirm which of those are actually gone.
            FsEvent::Removed(_) => self.evict_vanished_extensions(),
            FsEvent::Added(_) | FsEvent::Modified(_) => {
                let roots = self.config().paths.all();
                if let Some(dir) = find_extension_dir(&roots, &path) {
                    self.handle_added_or_modified(&dir)?;
                }
            }
        }
        Ok(())
    }

    /// Drop every loaded extension whose source directory no longer exists.
    ///
    /// Driven by the removal event rather than by the removed path: an
    /// uninstall can arrive as one event for the directory, or as a burst of
    /// per-file events in whatever order the debouncer coalesced them, and
    /// asking the filesystem which extensions are still there answers all of
    /// those the same way. Deleting a single asset out of a pack leaves its
    /// directory in place and so does not evict — the compiled component is
    /// already in memory, and a re-verify would only reject the pack without
    /// unloading it.
    fn evict_vanished_extensions(&self) {
        let vanished: Vec<ExtensionId> = self
            .loaded()
            .iter()
            .filter(|(_, ext)| has_vanished(&ext.source_dir))
            .map(|(id, _)| id.clone())
            .collect();

        for id in vanished {
            self.evict(&id);
        }
    }
}

/// Resolve a changed path to the extension directory that owns it, if any.
///
/// An extension directory is `<root>/<kind>/<name>` — exactly what
/// [`crate::discovery::scan_kind_dir`] enumerates. This walks up from `p` only
/// as far as that shape allows, and requires the result to sit directly under
/// a kind directory of one of the configured `roots`.
///
/// The bound is the point. Walking up to the filesystem root and taking the
/// first `describe.json` found meant any nested or dot-prefixed directory
/// anywhere under the watched tree — places discovery would never enumerate —
/// got a load attempt, and on success a first-use publisher pin under an
/// extension id of the writer's choosing. That pin is a write into the store
/// shared with `gtdx`, so it permanently blocks the genuine publisher for that
/// id. Making the two enumerators agree on what an extension directory is
/// closes that door.
fn find_extension_dir(roots: &[&PathBuf], p: &Path) -> Option<PathBuf> {
    let mut cur = p;
    loop {
        if cur
            .join(greentic_extension_sdk_contract::DESCRIBE_ENTRY_NAME)
            .exists()
            && is_extension_dir(roots, cur)
        {
            return Some(cur.to_path_buf());
        }
        cur = cur.parent()?;
    }
}

/// Has `dir` actually been removed, as opposed to merely being unreadable?
///
/// `Path::exists` answers `false` for *any* stat error, permission denied
/// included — so a parent directory whose mode changed would read as a mass
/// uninstall and silently unload every extension under it. Only `NotFound`
/// means gone; anything else is logged and the extension is left alone, which
/// is the conservative direction here (a stale load is recoverable, a
/// spontaneous unload of a working install is not obviously so).
fn has_vanished(dir: &Path) -> bool {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "cannot tell whether an extension directory still exists; leaving it loaded"
            );
            false
        }
    }
}

/// Is `dir` a `<root>/<kind>/<name>` directory for one of `roots`?
///
/// Both halves matter. Checking only the depth left any two-deep directory
/// under a watched root loadable — `<root>/.stash/anything/` included, which
/// `scan_kind_dir` never lists — and a successful load writes a first-use
/// publisher pin into the store `gtdx` shares, under whatever extension id the
/// pack claims. Requiring `<kind>` to be a real `ExtensionKind::dir_name` is
/// what makes the watcher and the enumerator agree on what an extension
/// directory is.
fn is_extension_dir(roots: &[&PathBuf], dir: &Path) -> bool {
    let Some(kind_dir) = dir.parent() else {
        return false;
    };
    let Some(root) = kind_dir.parent() else {
        return false;
    };
    if !roots.iter().any(|r| r.as_path() == root) {
        return false;
    }
    kind_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_known_kind_dir)
}

/// Does `name` spell one of the per-kind directories the layout defines?
fn is_known_kind_dir(name: &str) -> bool {
    use greentic_extension_sdk_contract::ExtensionKind;
    // `ALL`, not a hand-written literal: a literal here previously omitted
    // `WasixMcpRouter`, so the watcher silently ignored `<root>/mcp/<name>/`
    // and never picked up an installed or changed `mcp` extension. `ALL` is
    // the same fix `gtdx uninstall` needed after it once hand-listed kinds
    // and dropped `Provider` — see `ExtensionKind::ALL`'s doc comment.
    ExtensionKind::ALL.iter().any(|k| k.dir_name() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `<root>/<kind>/<name>/describe.json`, the shape `scan_kind_dir` finds.
    fn extension_at(root: &Path, kind: &str, name: &str) -> PathBuf {
        let dir = root.join(kind).join(name);
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("describe.json"), b"{}").unwrap();
        dir
    }

    #[test]
    fn find_extension_dir_walks_up_to_the_owning_extension() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let ext = extension_at(&root, "design", "greentic.demo");

        let touched = ext.join("assets").join("icon.svg");
        assert_eq!(find_extension_dir(&[&root], &touched), Some(ext));
    }

    #[test]
    fn find_extension_dir_gives_up_outside_an_extension() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let stray = root.join("not-an-extension.txt");
        std::fs::write(&stray, b"x").unwrap();
        assert_eq!(find_extension_dir(&[&root], &stray), None);
    }

    #[test]
    fn a_describe_nested_below_the_expected_depth_is_not_an_extension() {
        // A `describe.json` smuggled one level deeper than `<root>/<kind>/<name>`
        // is somewhere `scan_kind_dir` would never look. Loading it would hand
        // whoever wrote it a first-use publisher pin under an id of their
        // choosing, in the trust store gtdx shares.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let nested = root.join("design").join("greentic.demo").join("smuggled");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("describe.json"), b"{}").unwrap();

        // It resolves to the real extension above it, never to the nested dir.
        assert_eq!(
            find_extension_dir(&[&root], &nested.join("describe.json")),
            None,
            "the enclosing directory has no describe.json of its own here"
        );
    }

    #[test]
    fn a_two_deep_directory_under_a_non_kind_folder_is_not_an_extension() {
        // The bound used to check depth only, so `<root>/.stash/anything/`
        // loaded — a place `scan_kind_dir` never lists. A successful load
        // writes a first-use publisher pin into the store gtdx shares, under
        // whatever id the pack claims, which permanently blocks the real
        // publisher for that id.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let stash = extension_at(&root, ".stash", "greentic.squatter");

        assert_eq!(
            find_extension_dir(&[&root], &stash.join("describe.json")),
            None,
            "the middle component must be a real ExtensionKind dir_name"
        );

        // The same pack under a real kind directory is fine.
        let genuine = extension_at(&root, "design", "greentic.real");
        assert_eq!(
            find_extension_dir(&[&root], &genuine.join("describe.json")),
            Some(genuine)
        );
    }

    #[test]
    fn is_known_kind_dir_accepts_every_extension_kind() {
        // Widens on its own when the contract gains a kind — `ExtensionKind::ALL`
        // is what `is_known_kind_dir` is built from, so this would have caught
        // the watcher silently ignoring `mcp/` before the fix: a hand-listed
        // literal array here would have passed alongside a hand-listed literal
        // in the implementation.
        use greentic_extension_sdk_contract::ExtensionKind;
        for kind in ExtensionKind::ALL {
            assert!(
                is_known_kind_dir(kind.dir_name()),
                "is_known_kind_dir must accept {:?}'s dir_name {:?}",
                kind,
                kind.dir_name()
            );
        }
    }

    #[test]
    fn a_describe_outside_every_configured_root_is_ignored() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("configured");
        std::fs::create_dir_all(&root).unwrap();
        let elsewhere = extension_at(&tmp.path().join("elsewhere"), "design", "greentic.rogue");

        assert_eq!(
            find_extension_dir(&[&root], &elsewhere.join("describe.json")),
            None
        );
    }
}
