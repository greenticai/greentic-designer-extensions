//! Hosting-provider dispatch: the lifecycle of `greentic:extension-hosting`.
//!
//! [`ExtensionRuntime::hosting_provider`] checks that an extension really is a
//! hosting provider, reads its declaration through the pure `describe-provider`
//! export, and returns a [`HostingProvider`] whose methods are the six
//! `HostAdapter` operations plus the two pure helpers. Each call gets its own
//! store, its own [`HostingSession`] (counters, deadline, audit) and the
//! restricted hosting linker; nothing carries over between calls.
//!
//! Callers in async contexts wrap these in `spawn_blocking`, like every other
//! dispatch here: the guest runs on a sync wasmtime store.

use std::sync::Arc;

use greentic_extension_sdk_contract::ExtensionKind;

use crate::error::RuntimeError;
use crate::host_bindings::hosting as wit;
use crate::host_bindings::hosting::exports::greentic::extension_hosting::provider as p;
use crate::host_state::HostState;
use crate::hosting::audit::AuditSink;
use crate::hosting::lifecycle::{
    MAX_REF_BYTES, filter_owned, host_id_ok, ref_ok, scrub_diagnostic, scrub_text, validate_handle,
};
use crate::hosting::port::NullPort;
use crate::hosting::session::{HostingSession, SessionMeta};
use crate::hosting::{
    DestroyMode, Diagnostic, DiagnosticLevel, HOSTING_PROVIDER_CAPABILITY, HostError, HostHandle,
    HostOutcome, HostSpec, HostingDeclaration, HostingError, HostingPort, RawDescriptor, Refusal,
    TargetPolicy,
};
use crate::runtime::ExtensionRuntime;

/// Everything about one hosting target that the runtime needs to run a call.
#[derive(Clone)]
pub struct HostingContext {
    /// The platform target this call runs for. Appears in every audit record.
    pub target_id: String,
    /// Holds the credentials and carries the approved calls.
    pub port: Arc<dyn HostingPort>,
    /// What the platform admin confirmed for this target.
    pub policy: TargetPolicy,
    pub audit: Arc<dyn AuditSink>,
}

/// A loaded hosting extension bound to one target.
pub struct HostingProvider<'a> {
    rt: &'a ExtensionRuntime,
    ext_id: String,
    version: String,
    ctx: HostingContext,
    declaration: Arc<HostingDeclaration>,
    capability_hash: String,
}

impl ExtensionRuntime {
    /// Bind a loaded hosting extension to a target.
    ///
    /// # Errors
    ///
    /// [`HostingError::NotAProvider`] unless the extension is a
    /// `DeployExtension` offering `greentic:hosting/provider`;
    /// [`HostingError::Declaration`] when its declaration is invalid;
    /// [`HostingError::Deadline`] / [`HostingError::Trapped`] if the pure
    /// `describe-provider` export does not return.
    pub fn hosting_provider(
        &self,
        ext_id: &str,
        ctx: HostingContext,
    ) -> Result<HostingProvider<'_>, HostingError> {
        let loaded = self.lookup(ext_id)?;
        let offers = loaded
            .describe
            .capabilities
            .offered
            .iter()
            .any(|c| c.id.as_str() == HOSTING_PROVIDER_CAPABILITY);
        if loaded.kind != ExtensionKind::Deploy || !offers {
            return Err(HostingError::NotAProvider(format!(
                "'{ext_id}' must be a DeployExtension offering {HOSTING_PROVIDER_CAPABILITY}"
            )));
        }
        let version = loaded.describe.metadata.version.clone();
        let mut provider = HostingProvider {
            rt: self,
            ext_id: ext_id.to_string(),
            version,
            ctx,
            declaration: Arc::new(placeholder_declaration()),
            capability_hash: String::new(),
        };
        let raw = provider.invoke_pure("describe-provider", |g, s| {
            g.call_describe_provider(s).map(|d| RawDescriptor {
                id: d.id,
                display_name: d.display_name,
                settings_schema: d.settings_schema,
                credential_schema: d.credential_schema,
                endpoints: d.endpoints,
                capabilities: d.capabilities,
                ref_prefix: d.ref_prefix,
            })
        })?;
        let decl = HostingDeclaration::parse(&raw)?;
        provider.capability_hash = decl.capability_hash();
        provider.declaration = Arc::new(decl);
        Ok(provider)
    }
}

fn placeholder_declaration() -> HostingDeclaration {
    HostingDeclaration {
        provider_id: String::new(),
        display_name: String::new(),
        ref_prefix: String::new(),
        endpoints: Vec::new(),
        capabilities: crate::hosting::ProviderCapabilities {
            persistent_data: false,
            public_https: false,
            reachability: "public".into(),
        },
        settings_schema: serde_json::Value::Null,
        credential_schema: serde_json::Value::Null,
    }
}

type Guest<'g> = &'g p::Guest;

impl HostingProvider<'_> {
    /// The validated declaration (endpoints, actions, capabilities).
    #[must_use]
    pub fn declaration(&self) -> &HostingDeclaration {
        &self.declaration
    }

    /// The hash an admin approval is bound to.
    #[must_use]
    pub fn capability_hash(&self) -> &str {
        &self.capability_hash
    }

    fn classify(e: &wasmtime::Error) -> HostingError {
        Self::trap(
            matches!(
                e.downcast_ref::<wasmtime::Trap>(),
                Some(wasmtime::Trap::Interrupt)
            ),
            &format!("{e:#}"),
        )
    }

    fn trap(interrupted: bool, text: &str) -> HostingError {
        if interrupted {
            HostingError::Deadline
        } else {
            HostingError::Trapped(scrub_text(text, 300))
        }
    }

    fn session(&self, operation: &'static str, pure: bool) -> HostingSession {
        let meta = SessionMeta {
            target_id: self.ctx.target_id.clone(),
            extension_id: self.ext_id.clone(),
            extension_version: self.version.clone(),
            operation,
        };
        if pure {
            // No allowed host, no port: a pure export cannot reach anything.
            HostingSession::new(
                self.declaration.clone(),
                Arc::new(NullPort),
                TargetPolicy::new(Vec::new(), Vec::new()),
                self.ctx.audit.clone(),
                meta,
            )
        } else {
            HostingSession::new(
                self.declaration.clone(),
                self.ctx.port.clone(),
                self.ctx.policy.clone(),
                self.ctx.audit.clone(),
                meta,
            )
        }
    }

    fn invoke_with<T>(
        &self,
        session: HostingSession,
        f: impl FnOnce(Guest<'_>, &mut wasmtime::Store<HostState>) -> wasmtime::Result<T>,
    ) -> Result<T, HostingError> {
        let limits = self.ctx.policy.limits.clamped();
        let (mut store, instance) =
            self.rt
                .dispatch_hosting(&self.ext_id, session, limits.invocation_timeout)?;
        let world =
            wit::HostingExtension::new(&mut store, &instance).map_err(|e| Self::classify(&e))?;
        f(world.greentic_extension_hosting_provider(), &mut store).map_err(|e| Self::classify(&e))
    }

    fn invoke_pure<T>(
        &self,
        op: &'static str,
        f: impl FnOnce(Guest<'_>, &mut wasmtime::Store<HostState>) -> wasmtime::Result<T>,
    ) -> Result<T, HostingError> {
        self.invoke_with(self.session(op, true), f)
    }

    fn invoke<T>(
        &self,
        op: &'static str,
        f: impl FnOnce(Guest<'_>, &mut wasmtime::Store<HostState>) -> wasmtime::Result<T>,
    ) -> Result<T, HostingError> {
        self.invoke_with(self.session(op, false), f)
    }

    /// Creating a host needs an enabled, unfrozen target and an approval of
    /// exactly this declaration. Reads and deletes never do: an upgrade or an
    /// incident must not orphan hosts that already exist.
    fn gate_create(&self) -> Result<(), Refusal> {
        let policy = &self.ctx.policy;
        if !policy.enabled {
            return Err(Refusal::TargetDisabled);
        }
        if policy.frozen {
            return Err(Refusal::Frozen);
        }
        match policy.approved_capability_hash.as_deref() {
            None => Err(Refusal::NotApproved),
            Some(h) if h != self.capability_hash => Err(Refusal::NeedsReapproval),
            Some(_) => Ok(()),
        }
    }

    fn diagnostics(list: Vec<p::Diagnostic>) -> Vec<Diagnostic> {
        list.into_iter()
            .take(100)
            .map(|d| {
                let level = match d.level {
                    p::DiagnosticLevel::Info => DiagnosticLevel::Info,
                    p::DiagnosticLevel::Warning => DiagnosticLevel::Warning,
                    p::DiagnosticLevel::Error => DiagnosticLevel::Error,
                };
                scrub_diagnostic(level, &d.code, &d.message)
            })
            .collect()
    }

    fn host_error(e: p::HostError) -> HostingError {
        HostingError::Provider(match e {
            p::HostError::UnsupportedKind => HostError::UnsupportedKind,
            p::HostError::NotConfigured => HostError::NotConfigured,
            p::HostError::NotOwned => HostError::NotOwned,
            p::HostError::AtCapacity => HostError::AtCapacity,
            p::HostError::Rejected => HostError::Rejected,
            p::HostError::Unreachable => HostError::Unreachable,
            p::HostError::Quota => HostError::Quota,
        })
    }

    fn outcome(&self, o: p::HostOutcome) -> Result<HostOutcome, HostingError> {
        match o {
            p::HostOutcome::Pending => Ok(HostOutcome::Pending),
            p::HostOutcome::Ready(h) => validate_handle(
                HostHandle {
                    host_ref: h.host_ref,
                    host: h.host,
                    port: h.port,
                    scheme: h.scheme,
                    extras: h.extras,
                },
                &self.declaration.ref_prefix,
                &self.ctx.policy,
            )
            .map(HostOutcome::Ready)
            .map_err(HostingError::Refused),
        }
    }

    /// Settings findings, from the pure `validate-settings` export.
    pub fn validate_settings(&self, settings_json: &str) -> Result<Vec<Diagnostic>, HostingError> {
        self.invoke_pure("validate-settings", |g, s| {
            g.call_validate_settings(s, settings_json)
        })
        .map(Self::diagnostics)
    }

    /// Read-only checks of the target's credential. Runs against the real port
    /// and policy, so it needs `api_hosts` set but not an approval.
    pub fn preflight(&self) -> Result<Vec<Diagnostic>, HostingError> {
        self.invoke("preflight", |g, s| g.call_preflight(s))
            .map(Self::diagnostics)
    }

    /// Can this provider run this kind? Pure.
    pub fn supports(&self, hosting_json: &str) -> Result<bool, HostingError> {
        self.invoke_pure("supports", |g, s| g.call_supports(s, hosting_json))
    }

    /// The ref a host will have, before it exists. Pure; must carry the
    /// declared prefix.
    pub fn host_ref_for(&self, host_id: &str) -> Result<String, HostingError> {
        if !host_id_ok(host_id) {
            return Err(HostingError::Provider(HostError::Rejected));
        }
        let r = self.invoke_pure("host-ref-for", |g, s| g.call_host_ref_for(s, host_id))?;
        if ref_ok(&r, &self.declaration.ref_prefix) {
            Ok(r)
        } else {
            Err(HostingError::Refused(Refusal::HandleRejected))
        }
    }

    /// Create the host if it does not exist. Idempotent per `host_id`.
    pub fn ensure_host(&self, spec: &HostSpec, host_id: &str) -> Result<HostOutcome, HostingError> {
        self.gate_create().map_err(HostingError::Refused)?;
        if !host_id_ok(host_id) || spec.hosting_json.len() > 64 * 1024 {
            return Err(HostingError::Provider(HostError::Rejected));
        }
        let wit_spec = p::HostSpec {
            kind: spec.kind.clone(),
            version: spec.version.clone(),
            size: spec.size.clone(),
            hosting_json: spec.hosting_json.clone(),
        };
        self.invoke("ensure-host", |g, s| {
            g.call_ensure_host(s, &wit_spec, host_id)
        })?
        .map_err(Self::host_error)
        .and_then(|o| self.outcome(o))
    }

    /// Current state of a host.
    pub fn describe_host(&self, host_ref: &str) -> Result<HostOutcome, HostingError> {
        self.check_ref(host_ref)?;
        self.invoke("describe-host", |g, s| g.call_describe_host(s, host_ref))?
            .map_err(Self::host_error)
            .and_then(|o| self.outcome(o))
    }

    /// Every host this installation owns on the target, by ref. Refs that do
    /// not carry the declared prefix are dropped.
    pub fn list_owned(&self) -> Result<Vec<String>, HostingError> {
        self.invoke("list-owned", |g, s| g.call_list_owned(s))?
            .map_err(Self::host_error)
            .map(|refs| filter_owned(refs, &self.declaration.ref_prefix))
    }

    /// Remove a host. Idempotent. Allowed on a disabled, frozen or unapproved
    /// target: deleting is never what an incident freezes.
    pub fn destroy(&self, host_ref: &str, mode: DestroyMode) -> Result<(), HostingError> {
        self.check_ref(host_ref)?;
        let mode = match mode {
            DestroyMode::Retain => p::DestroyMode::Retain,
            DestroyMode::DestroyData => p::DestroyMode::DestroyData,
        };
        self.invoke("destroy", |g, s| g.call_destroy(s, host_ref, mode))?
            .map_err(Self::host_error)
    }

    fn check_ref(&self, host_ref: &str) -> Result<(), HostingError> {
        if ref_ok(host_ref, &self.declaration.ref_prefix) && host_ref.len() <= MAX_REF_BYTES {
            Ok(())
        } else {
            Err(HostingError::Provider(HostError::Rejected))
        }
    }
}

impl From<RuntimeError> for HostingError {
    fn from(e: RuntimeError) -> Self {
        match e {
            RuntimeError::Wasmtime(err) => HostingProvider::trap(
                matches!(
                    err.downcast_ref::<wasmtime::Trap>(),
                    Some(wasmtime::Trap::Interrupt)
                ),
                &format!("{err:#}"),
            ),
            other => Self::Runtime(other),
        }
    }
}
