//! Execution limits applied to every wasmtime `Store`.
//!
//! An extension is trusted only as far as the load gate goes, and TOFU means
//! "signed" is "signed by the first key we ever saw for this id". Nothing about
//! that stops a loaded extension from exporting a tool whose body is
//! `loop { v.push(0) }`. Without a limit, `func.call(...)` never returns and
//! cannot be interrupted; the designer runs these under `spawn_blocking`, so a
//! handful of such calls exhausts the blocking pool and the process stops
//! serving. Linear memory was likewise bounded only by the wasm32 4 GiB ceiling.
//!
//! Two mechanisms, because they catch different things:
//!
//! - **Epoch interruption** bounds *wall-clock* time spent **executing wasm**.
//!   A ticker thread bumps the engine's epoch; wasm checks it at loop backedges
//!   and function entries and traps once the store's deadline passes.
//! - **[`PackLimits`]** bounds memory and table growth, which epochs cannot see
//!   at all: a guest can exhaust host memory without ever failing to make
//!   progress.
//!
//! # What the deadline does NOT cover
//!
//! An earlier version of this doc claimed "time spent inside a host call
//! counts". **It does not.** The epoch is only ever evaluated by running wasm,
//! so while the thread is parked in a blocking host call no check happens and
//! the trap cannot fire. Two consequences worth stating plainly:
//!
//! - Every host call the runtime makes on a guest's behalf needs its own
//!   timeout. `host.http.fetch` and the OAuth broker client get theirs from
//!   [`http_timeout_for`], derived from the same dispatch budget.
//! - `wasmtime_wasi::p2::add_to_linker_sync` gives every component
//!   `wasi:io/poll`, and in the *sync* linker `poll` blocks the OS thread. A
//!   guest needs no declared permission to sleep there, and this deadline
//!   cannot interrupt it. Closing that needs async wasmtime with the call
//!   wrapped in a host-side timeout — a larger change than this module, and
//!   deliberately not pretended away here.
//!
//! Fuel would be the third option and is deliberately not used: it meters
//! instructions rather than time, costs roughly 2x throughput, and gives a
//! budget nobody can reason about from the outside.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use wasmtime::{Engine, ResourceLimiter, Store};

/// Wall-clock budget for a single dispatch, when the host does not set one.
///
/// Generous on purpose. `deploy` is documented as taking up to ~2 minutes for
/// network-bound extensions and `render_bundle` is not fast either, so the
/// default has to clear a legitimate slow call by a wide margin. It is not
/// trying to be a tight SLA — it is the difference between a wedged worker
/// thread and a trapped call.
pub const DEFAULT_DISPATCH_TIMEOUT: Duration = Duration::from_mins(5);

/// How often the ticker bumps the engine epoch. Also the granularity of the
/// deadline: a 1 s tick means a 300 s budget expires somewhere in [300, 301).
const EPOCH_TICK: Duration = Duration::from_secs(1);

/// Linear memory one dispatch may hold **in total, across every memory**.
///
/// Store-wide on purpose. `StoreLimits::memory_size` applies per linear memory,
/// and a component is many core instances each free to declare its own — so a
/// 512 MiB per-memory ceiling with 64 memories allowed is a 32 GiB store, with
/// every ceiling reporting as enforced. Summing is the only phrasing of this
/// limit that means what it says.
const MAX_MEMORY_BYTES: usize = 512 * 1024 * 1024;

/// Table entries one dispatch may hold in total, across every table.
const MAX_TABLE_ELEMENTS: usize = 100_000;

/// Concurrent instances, memories, and tables within one store. Runaway guards
/// on top of the two totals above, not budgets in their own right.
const MAX_INSTANCES: usize = 64;
const MAX_MEMORIES: usize = 64;
const MAX_TABLES: usize = 64;

/// Ceiling on how long a single host call made on the guest's behalf may take.
///
/// The wasm deadline cannot interrupt a blocking host call, so each one needs
/// its own bound. Derived from the dispatch budget so the two cannot drift, and
/// clamped: a host that disables the dispatch deadline still does not get
/// unbounded outbound requests, because "no wasm deadline" is a statement about
/// supervision, not an invitation to hang on a socket forever.
const MAX_HOST_CALL_TIMEOUT: Duration = Duration::from_mins(2);

/// The timeout to put on one outbound host request under `dispatch_timeout`.
///
/// `None` dispatch budget still yields a bound — see [`MAX_HOST_CALL_TIMEOUT`].
#[must_use]
pub fn http_timeout_for(dispatch_timeout: Option<Duration>) -> Duration {
    dispatch_timeout.map_or(MAX_HOST_CALL_TIMEOUT, |d| d.min(MAX_HOST_CALL_TIMEOUT))
}

/// Store-wide resource budget.
///
/// Tracks the running total each `*_growing` callback has already approved, so
/// the ceiling covers the whole store rather than each memory separately.
/// Growth requests are only counted when granted, so a refusal does not consume
/// budget a later, smaller request could have used.
#[derive(Debug)]
pub struct PackLimits {
    memory_bytes: usize,
    table_elements: usize,
}

impl PackLimits {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            memory_bytes: 0,
            table_elements: 0,
        }
    }
}

impl Default for PackLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Add `desired - current` to `running`, refusing if the total would pass `cap`.
fn admit(running: &mut usize, current: usize, desired: usize, cap: usize) -> bool {
    let delta = desired.saturating_sub(current);
    let Some(total) = running.checked_add(delta) else {
        return false;
    };
    if total > cap {
        return false;
    }
    *running = total;
    true
}

impl ResourceLimiter for PackLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(admit(
            &mut self.memory_bytes,
            current,
            desired,
            MAX_MEMORY_BYTES,
        ))
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(admit(
            &mut self.table_elements,
            current,
            desired,
            MAX_TABLE_ELEMENTS,
        ))
    }

    fn instances(&self) -> usize {
        MAX_INSTANCES
    }

    fn memories(&self) -> usize {
        MAX_MEMORIES
    }

    fn tables(&self) -> usize {
        MAX_TABLES
    }
}

/// Background ticker that advances an [`Engine`]'s epoch.
///
/// Held by the runtime for its whole life; dropping it stops the thread. One
/// ticker per engine is enough — every store built from that engine reads the
/// same counter.
pub struct EpochTicker {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    /// Spawn the ticker for `engine`.
    ///
    /// Holds a `Weak`, not a clone: an `Engine` clone would keep the engine —
    /// and its compiled modules — alive for as long as the thread, which is
    /// exactly the leak a "just keep it simple" version introduces.
    pub fn spawn(engine: &Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let weak = engine.weak();
        let flag = stop.clone();
        let spawned = std::thread::Builder::new()
            .name("greentic-ext-epoch".to_string())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_TICK);
                    // The engine outliving this thread is the normal case; the
                    // reverse means the runtime is gone and so is the reason to
                    // keep ticking.
                    let Some(engine) = weak.upgrade() else {
                        return;
                    };
                    engine.increment_epoch();
                }
            });

        // Without this thread the epoch never advances, so every dispatch
        // deadline is unreachable and the runaway-guest guard is off — the one
        // failure here that must not pass in silence, because everything
        // downstream keeps working exactly as if it were armed.
        let join = match spawned {
            Ok(handle) => Some(handle),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "could not start the epoch ticker; extension dispatch deadlines will NOT fire"
                );
                None
            }
        };
        Self { stop, join }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // The thread wakes at most `EPOCH_TICK` from now and exits. Detach
        // rather than join: a `Drop` that blocks up to a second on a background
        // ticker is a worse trade than letting it finish on its own.
        drop(self.join.take());
    }
}

/// Apply the store-wide ceilings and the wall-clock deadline to `store`.
///
/// **Must run before `Linker::instantiate`.** A `ResourceLimiter` that is not
/// installed yet is never consulted, and memories and tables declared with a
/// large *initial* size are allocated during instantiation — so applying this
/// afterwards left the ceilings covering only `memory.grow`, which a guest
/// simply never has to call. The epoch deadline has the mirror-image problem:
/// wasmtime's default is `0`, so any wasm run during instantiation traps at
/// once unless a deadline is set first.
///
/// `timeout` of `None` means the host supervises dispatch itself. It still gets
/// an explicit effectively-unreachable deadline rather than the default `0`,
/// and the memory ceilings apply either way — there is no reason to want those
/// unbounded.
pub fn apply(store: &mut Store<crate::host_state::HostState>, timeout: Option<Duration>) {
    store.limiter(|state| &mut state.limits);
    store.set_epoch_deadline(timeout.map_or(u64::MAX, deadline_ticks));
}

/// How many epoch ticks `timeout` is worth, as at least one.
///
/// Integer nanoseconds throughout: a float round-trip would need a lossy cast
/// back to `u64` at the end, and rounding *down* there is the one direction
/// that matters — a deadline of zero traps the call immediately. Rounds up, so
/// a sub-tick timeout still gets one whole tick, and saturates rather than
/// wrapping if a host configures an absurd duration.
fn deadline_ticks(timeout: Duration) -> u64 {
    let per_tick = EPOCH_TICK.as_nanos().max(1);
    let ticks = timeout.as_nanos().div_ceil(per_tick).max(1);
    u64::try_from(ticks).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sub_tick_timeout_still_gets_a_whole_tick() {
        // Rounding down here would produce a deadline of zero, which traps the
        // call before it runs a single instruction.
        assert_eq!(deadline_ticks(Duration::from_millis(1)), 1);
        assert_eq!(deadline_ticks(Duration::ZERO), 1);
    }

    #[test]
    fn a_whole_number_of_ticks_is_not_rounded_up() {
        assert_eq!(deadline_ticks(EPOCH_TICK), 1);
        assert_eq!(deadline_ticks(EPOCH_TICK * 5), 5);
    }

    #[test]
    fn a_partial_tick_rounds_up() {
        assert_eq!(deadline_ticks(EPOCH_TICK * 5 + Duration::from_nanos(1)), 6);
    }

    #[test]
    fn the_default_budget_clears_a_slow_deploy_by_a_wide_margin() {
        // `deploy` is documented as taking up to ~2 minutes for network-bound
        // extensions; the default has to be comfortably above that or it turns
        // a slow success into a trap.
        assert!(DEFAULT_DISPATCH_TIMEOUT >= Duration::from_mins(4));
    }

    #[test]
    fn an_absurd_timeout_saturates_instead_of_wrapping() {
        assert_eq!(deadline_ticks(Duration::MAX), u64::MAX);
    }

    #[test]
    fn the_memory_budget_is_store_wide_not_per_memory() {
        // The bug this pins: `StoreLimits::memory_size` applies per linear
        // memory, and a component is many core instances each free to declare
        // one. Sixty-four memories each exactly at a 512 MiB "ceiling" is a
        // 32 GiB store with every ceiling reporting as enforced.
        let mut limits = PackLimits::new();
        assert!(
            limits
                .memory_growing(0, MAX_MEMORY_BYTES, None)
                .expect("first memory fits"),
            "one memory at the ceiling is fine"
        );
        assert!(
            !limits
                .memory_growing(0, 1, None)
                .expect("second memory is refused, not errored"),
            "a second memory must draw on the same budget, not a fresh one"
        );
    }

    #[test]
    fn a_refused_growth_does_not_consume_budget() {
        let mut limits = PackLimits::new();
        assert!(
            !limits
                .memory_growing(0, MAX_MEMORY_BYTES + 1, None)
                .unwrap()
        );
        assert!(
            limits.memory_growing(0, MAX_MEMORY_BYTES, None).unwrap(),
            "the refused request must not have spent any of the budget"
        );
    }

    #[test]
    fn growth_is_charged_by_delta_not_by_target() {
        // `memory_growing` reports (current, desired); charging `desired` would
        // bill every incremental grow for the whole memory all over again.
        let mut limits = PackLimits::new();
        let half = MAX_MEMORY_BYTES / 2;
        assert!(limits.memory_growing(0, half, None).unwrap());
        assert!(
            limits.memory_growing(half, MAX_MEMORY_BYTES, None).unwrap(),
            "growing the same memory to the ceiling must be charged the delta"
        );
    }

    #[test]
    fn tables_have_their_own_store_wide_budget() {
        let mut limits = PackLimits::new();
        assert!(limits.table_growing(0, MAX_TABLE_ELEMENTS, None).unwrap());
        assert!(!limits.table_growing(0, 1, None).unwrap());
    }

    #[test]
    fn a_host_call_is_bounded_even_when_dispatch_is_not() {
        // "No wasm deadline" is a statement about host supervision, not an
        // invitation to hang on a socket forever — and the wasm deadline could
        // not interrupt that call anyway.
        assert_eq!(http_timeout_for(None), MAX_HOST_CALL_TIMEOUT);
        assert_eq!(
            http_timeout_for(Some(Duration::from_secs(9))),
            Duration::from_secs(9),
            "a tighter dispatch budget tightens the host call with it"
        );
        assert_eq!(
            http_timeout_for(Some(Duration::from_mins(30))),
            MAX_HOST_CALL_TIMEOUT,
            "a looser one is still clamped"
        );
    }
}
