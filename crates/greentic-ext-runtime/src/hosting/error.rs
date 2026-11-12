//! Errors of the hosting subsystem.

use thiserror::Error;

/// A hosting declaration that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid hosting declaration: {0}")]
pub struct DeclarationError(String);

impl DeclarationError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// The provider's own verdict, from the closed `host-error` enum. Each variant
/// maps to one fixed phrase on the admin side; no guest text rides with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HostError {
    #[error("the provider cannot run this kind")]
    UnsupportedKind,
    #[error("the target is not configured")]
    NotConfigured,
    #[error("an object with the expected name is not owned by this installation")]
    NotOwned,
    #[error("the target is at capacity")]
    AtCapacity,
    #[error("the provider rejected the request")]
    Rejected,
    #[error("the provider could not be reached")]
    Unreachable,
    #[error("a quota was exceeded")]
    Quota,
}

/// Why a hosting lifecycle call did not produce a provider answer.
#[derive(Debug, Error)]
pub enum HostingError {
    /// The provider answered with one of its closed errors.
    #[error("provider error: {0}")]
    Provider(HostError),
    /// The host refused to run the operation at all (policy), before or after
    /// the guest ran.
    #[error("refused by policy: {0}")]
    Refused(Refusal),
    /// The guest ran past its wall-clock budget and was interrupted.
    #[error("the extension exceeded its execution deadline")]
    Deadline,
    /// The guest trapped or could not be instantiated. The text is the
    /// runtime's, never guest-controlled.
    #[error("the extension failed: {0}")]
    Trapped(String),
    /// The extension is not a usable hosting provider.
    #[error("not a hosting provider: {0}")]
    NotAProvider(String),
    #[error(transparent)]
    Declaration(#[from] DeclarationError),
    #[error(transparent)]
    Runtime(crate::error::RuntimeError),
}

impl HostingError {
    /// The closed error the admin's reconcile loop should record for this
    /// failure: a deadline or a trap reads as `unreachable`, a policy refusal
    /// as `rejected`. Guest text never travels.
    #[must_use]
    pub fn to_host_error(&self) -> HostError {
        match self {
            Self::Provider(e) => *e,
            Self::Deadline | Self::Trapped(_) => HostError::Unreachable,
            Self::Refused(_)
            | Self::NotAProvider(_)
            | Self::Declaration(_)
            | Self::Runtime(_) => HostError::Rejected,
        }
    }
}

/// A host-side refusal to run a lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Refusal {
    #[error("hosting is disabled for this target")]
    TargetDisabled,
    #[error("the target is frozen: new hosts are refused")]
    Frozen,
    #[error("the extension version has not been approved for this target")]
    NotApproved,
    #[error("the extension's declared capabilities changed since approval")]
    NeedsReapproval,
    #[error("the extension returned a host handle the target does not allow")]
    HandleRejected,
}
