//! What the platform admin may set per target.
//!
//! The admin can only NARROW what an extension declared: every knob here
//! either removes something the extension asked for or caps it. Nothing here
//! can add an endpoint, an action or an auth profile.

use std::time::Duration;

/// Hard ceilings no target configuration can raise.
pub mod platform_max {
    use std::time::Duration;
    pub const REQUEST_BYTES: usize = 4 * 1024 * 1024;
    pub const RESPONSE_BYTES: usize = 32 * 1024 * 1024;
    pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);
    pub const INVOCATION_TIMEOUT: Duration = Duration::from_secs(600);
    pub const CALLS: u32 = 1000;
    pub const LOG_LINES: u32 = 500;
}

/// Per-call and per-invocation budgets. Defaults are the design's: request
/// 1 MiB, response 8 MiB, 30 s per call, 150 calls and 120 s per invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostingLimits {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub call_timeout: Duration,
    pub invocation_timeout: Duration,
    pub max_calls: u32,
    pub max_log_lines: u32,
    pub max_log_bytes: usize,
}

impl Default for HostingLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 8 * 1024 * 1024,
            call_timeout: Duration::from_secs(30),
            invocation_timeout: Duration::from_secs(120),
            max_calls: 150,
            max_log_lines: 100,
            max_log_bytes: 512,
        }
    }
}

impl HostingLimits {
    /// The same limits with every value capped at [`platform_max`], and none
    /// zero (a zero timeout or call budget would make every operation fail in
    /// a way that reads as the provider's fault).
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            max_request_bytes: self.max_request_bytes.clamp(1, platform_max::REQUEST_BYTES),
            max_response_bytes: self
                .max_response_bytes
                .clamp(1, platform_max::RESPONSE_BYTES),
            call_timeout: self
                .call_timeout
                .clamp(Duration::from_millis(1), platform_max::CALL_TIMEOUT),
            invocation_timeout: self
                .invocation_timeout
                .clamp(Duration::from_millis(1), platform_max::INVOCATION_TIMEOUT),
            max_calls: self.max_calls.clamp(1, platform_max::CALLS),
            max_log_lines: self.max_log_lines.min(platform_max::LOG_LINES),
            max_log_bytes: self.max_log_bytes.clamp(16, 4096),
        }
    }
}

/// Policy for one hosting target, as confirmed by the platform admin.
#[derive(Debug, Clone)]
pub struct TargetPolicy {
    /// Hosts a credential may be sent to (`*.amazonaws.com`, an exact API
    /// server). EMPTY means no call is allowed: the platform admin confirms the
    /// list when enabling the target, it is never inferred from the extension.
    pub api_hosts: Vec<String>,
    /// Private or loopback API hosts that are allowed anyway (an in-VPC
    /// Kubernetes API server). Exact `host` or `host:port` entries only, set by
    /// a platform admin and never reachable from an extension declaration.
    pub private_hosts: Vec<String>,
    /// Domains a returned host handle must sit in. EMPTY means no handle is
    /// accepted.
    pub ingress_domains: Vec<String>,
    pub limits: HostingLimits,
    /// Capability hash the admin approved (`HostingDeclaration::capability_hash`).
    /// `None` means nothing is approved yet: reads run, `ensure-host` is refused.
    pub approved_capability_hash: Option<String>,
    /// Disabling a target stops new hosts; existing ones stay describable and
    /// destroyable.
    pub enabled: bool,
    /// Incident switch with the same effect as `enabled = false`.
    pub frozen: bool,
}

impl TargetPolicy {
    /// A policy that allows calls to `api_hosts` and nothing else; not yet
    /// approved, so it cannot create hosts.
    #[must_use]
    pub fn new(api_hosts: Vec<String>, ingress_domains: Vec<String>) -> Self {
        Self {
            api_hosts,
            private_hosts: Vec::new(),
            ingress_domains,
            limits: HostingLimits::default(),
            approved_capability_hash: None,
            enabled: true,
            frozen: false,
        }
    }

    /// Approve exactly this capability hash.
    #[must_use]
    pub fn approved(mut self, hash: impl Into<String>) -> Self {
        self.approved_capability_hash = Some(hash.into());
        self
    }

    #[must_use]
    pub fn with_limits(mut self, limits: HostingLimits) -> Self {
        self.limits = limits;
        self
    }
}
