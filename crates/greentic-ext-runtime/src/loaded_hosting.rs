//! The store and linker a hosting-provider invocation runs in.
//!
//! This is NOT `add_host_interfaces` plus a few more. A hosting extension gets
//! a linker built from scratch that contains:
//!
//! * the three hosting imports (`log`, `target`, `api`), and
//! * the WASI interfaces a `std` guest cannot be built without — `cli`
//!   (environment, exit, stdio, terminals) and `io` (error, poll, streams) —
//!
//! and nothing else. In particular it has no `greentic:extension-host/secrets`,
//! `http`, `broker`, `llm` or `artifact`, no OAuth broker, no WASI filesystem,
//! sockets, random, or **clocks**. A component that imports any of them fails
//! at instantiation, which is how "the hosting world does not import secrets,
//! a generic fetch, or any way to wait" is enforced rather than hoped for.
//!
//! Without a clock there is no timer pollable, so `wasi:io/poll` can only wait
//! on streams (stdin is empty), and the one thing the epoch deadline cannot
//! interrupt — a guest sleeping inside a blocking host call — has no way to
//! start.

use std::time::Duration;

use wasmtime::Store;
use wasmtime::component::{HasData, Instance, Linker, ResourceTable};
use wasmtime_wasi::WasiView;
use wasmtime_wasi::cli::{WasiCli, WasiCliView};
use wasmtime_wasi::p2::bindings::{cli, sync};

use crate::host_state::HostState;
use crate::hosting::session::HostingSession;
use crate::loaded::LoadedExtension;

struct HasIo;

impl HasData for HasIo {
    type Data<'a> = &'a mut ResourceTable;
}

/// The WASI surface a hosting guest gets. See the module doc for what is left out.
fn add_restricted_wasi<T: WasiView>(linker: &mut Linker<T>) -> anyhow::Result<()> {
    wasmtime_wasi_io::bindings::wasi::io::error::add_to_linker::<T, HasIo>(linker, |t| {
        t.ctx().table
    })?;
    sync::io::poll::add_to_linker::<T, HasIo>(linker, |t| t.ctx().table)?;
    sync::io::streams::add_to_linker::<T, HasIo>(linker, |t| t.ctx().table)?;
    cli::exit::add_to_linker::<T, WasiCli>(linker, &cli::exit::LinkOptions::default(), T::cli)?;
    cli::environment::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    cli::stdin::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    cli::stdout::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    cli::stderr::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    cli::terminal_input::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    cli::terminal_output::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    cli::terminal_stdin::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    cli::terminal_stdout::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    cli::terminal_stderr::add_to_linker::<T, WasiCli>(linker, T::cli)?;
    Ok(())
}

/// Register the three hosting imports.
fn add_hosting_interfaces(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    use crate::host_bindings::hosting::greentic::extension_hosting::{api, log, target};
    use wasmtime::component::HasSelf;
    log::add_to_linker::<HostState, HasSelf<HostState>>(linker, |s| s)?;
    target::add_to_linker::<HostState, HasSelf<HostState>>(linker, |s| s)?;
    api::add_to_linker::<HostState, HasSelf<HostState>>(linker, |s| s)?;
    Ok(())
}

impl LoadedExtension {
    /// Build a store and instance for one hosting invocation.
    ///
    /// `deadline` is the wall-clock budget for the guest's own execution; the
    /// caller passes the smaller of the runtime's dispatch timeout and the
    /// target's per-invocation limit.
    pub(crate) fn build_hosting_store_and_instance(
        &self,
        engine: &wasmtime::Engine,
        session: HostingSession,
        deadline: Option<Duration>,
    ) -> anyhow::Result<(Store<HostState>, Instance)> {
        let mut linker: Linker<HostState> = Linker::new(engine);
        add_restricted_wasi(&mut linker)?;
        add_hosting_interfaces(&mut linker)?;

        let state = HostState::builder(
            self.id.as_str().to_string(),
            self.describe.runtime.permissions.clone(),
        )
        .hosting(Some(session))
        .build();
        let mut store = Store::new(engine, state);
        // Before `instantiate`, for the reason documented on `limits::apply`.
        crate::limits::apply(&mut store, deadline);
        let instance = linker.instantiate(&mut store, &self.component)?;
        Ok((store, instance))
    }
}
