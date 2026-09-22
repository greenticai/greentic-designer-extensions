use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use notify::RecommendedWatcher;
use notify::RecursiveMode;
use notify_debouncer_full::{DebounceEventResult, Debouncer, RecommendedCache, new_debouncer};

use crate::error::RuntimeError;

/// How long the debouncer coalesces filesystem events before emitting them.
/// An editor writing a file produces a burst; without this the runtime would
/// re-verify and re-instantiate an extension several times per save.
const DEBOUNCE_WINDOW: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub enum FsEvent {
    Added(PathBuf),
    Modified(PathBuf),
    Removed(PathBuf),
}

/// RAII handle that keeps the debouncer alive. Drop this to stop watching.
pub struct WatchHandle {
    _debouncer: Debouncer<RecommendedWatcher, RecommendedCache>,
}

/// Start watching `paths` recursively. Returns a channel receiver emitting
/// coalesced FS events and a `WatchHandle` that owns the debouncer — drop
/// the handle to stop watching and close the channel.
///
/// Paths that do not exist are skipped rather than failing the whole watcher:
/// a designer install legitimately has no `project` extensions dir until the
/// user creates one. Every skip is logged, because a silently unwatched path
/// looks exactly like "hot reload is broken" from the outside.
pub fn watch(paths: &[PathBuf]) -> Result<(mpsc::Receiver<FsEvent>, WatchHandle), RuntimeError> {
    let (tx, rx) = mpsc::channel();
    let mut debouncer = new_debouncer(DEBOUNCE_WINDOW, None, move |res: DebounceEventResult| {
        let events = match res {
            Ok(events) => events,
            Err(errors) => {
                // Backend errors mean events were dropped — an overflowed
                // inotify queue, a vanished watch descriptor. Hot reload is
                // now missing changes, so this must never be swallowed.
                for e in errors {
                    tracing::warn!(
                        error = %e,
                        "filesystem watcher reported an error; some change events were lost"
                    );
                }
                return;
            }
        };
        for ev in events {
            for p in &ev.event.paths {
                let out = match ev.event.kind {
                    notify::EventKind::Create(_) => FsEvent::Added(p.clone()),
                    notify::EventKind::Modify(_) => FsEvent::Modified(p.clone()),
                    notify::EventKind::Remove(_) => FsEvent::Removed(p.clone()),
                    _ => continue,
                };
                // A send failure means the runtime dropped its receiver and
                // is shutting down; the thread exits on its own next loop.
                if tx.send(out).is_err() {
                    return;
                }
            }
        }
    })
    .map_err(|e| RuntimeError::Watcher(e.to_string()))?;

    for p in paths {
        if !p.exists() {
            tracing::debug!(
                path = %p.display(),
                "extension watch path does not exist yet; not watching it"
            );
            continue;
        }
        debouncer
            .watch(p, RecursiveMode::Recursive)
            .map_err(|e| RuntimeError::Watcher(e.to_string()))?;
    }
    Ok((
        rx,
        WatchHandle {
            _debouncer: debouncer,
        },
    ))
}
