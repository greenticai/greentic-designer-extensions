//! Hosting providers: the host side of `greentic:extension-hosting`.
//!
//! A hosting extension holds the provider logic (how to start a container on
//! ECS, Cloud Run, Kubernetes ...). This module holds everything that must NOT
//! be left to it: which endpoints and actions it may call, where credentials
//! may be sent, how long and how often it may call, what it may learn, and the
//! audit trail of what it did. See `docs/hosting-provider-world.md`.

mod declaration;
mod endpoint;
mod error;
pub(crate) mod lifecycle;
mod policy;
pub(crate) mod port;

pub mod audit;
pub mod mock;
pub mod placeholder;
pub mod session;

pub use declaration::{
    EndpointDecl, HOSTING_PROVIDER_CAPABILITY, HostingDeclaration, KNOWN_PROFILES, ProfileRef,
    ProviderCapabilities, RawDescriptor,
};
pub use endpoint::{
    ALLOWED_METHODS, ALLOWED_REQUEST_HEADERS, ALLOWED_RESPONSE_HEADERS, ActionRule, host_matches,
};
pub use error::{DeclarationError, HostError, HostingError, Refusal};
pub use lifecycle::{DestroyMode, Diagnostic, DiagnosticLevel, HostHandle, HostOutcome, HostSpec};
pub use policy::{HostingLimits, TargetPolicy, platform_max};
pub use port::{AuthorizedCall, HostingPort, PortError, PortResponse, SecretValue, TargetContext};
