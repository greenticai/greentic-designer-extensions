//! Wasmtime-based runtime for Greentic Designer Extensions.
#![forbid(unsafe_code)]

pub mod broker;
pub mod capability;
pub mod discovery;
mod error;
mod ext_error;
pub mod guardrail_map;
mod health;
pub mod host_bindings;
pub mod host_ports;
mod host_state;
mod host_state_llm;
mod host_state_net;
mod host_state_oauth;
mod host_state_ports;
mod http_scheme_policy;
mod limits;
mod loaded;
mod net_permissions;
pub mod oauth;
mod runtime;
mod runtime_bundle;
mod runtime_config;
mod runtime_deploy;
mod runtime_design;
mod runtime_dw_composer;
mod runtime_knowledge;
mod runtime_registry;
mod runtime_roles;
mod runtime_sorx;
mod runtime_targets;
mod runtime_verify;
mod runtime_views;
mod runtime_watch;
mod tool_metadata_report;
pub mod types;
pub mod url_matcher;
pub mod watcher;

pub use self::broker::{Broker, BrokerError, BrokerResult};
pub use self::capability::{CapabilityRegistry, OfferedBinding, ResolutionPlan};
pub use self::discovery::DiscoveryPaths;
pub use self::error::RuntimeError;
pub use self::guardrail_map::GuardrailVerdictWire;
pub use self::health::{ExtensionHealth, HealthReason};
pub use self::host_ports::{
    InMemorySecrets, KeyTranslator, SecretsBackend, SecretsError, Translator,
};
pub use self::host_state::HostState;
pub use self::limits::DEFAULT_DISPATCH_TIMEOUT;
pub use self::loaded::{ExtensionId, HostOverrides, LoadedExtension, LoadedExtensionRef};
pub use self::runtime::{ExtensionRuntime, RuntimeEvent, WatcherGuard};
pub use self::runtime_config::RuntimeConfig;
pub use self::runtime_design::contribution_tool_to_definition;
pub use self::runtime_views::view_to_definition;
pub use self::types::{
    BundleArtifact, BundleSession, CompileContext, DeployExtensionError, DeployJob, DeployRequest,
    DeployStatus, Diagnostic, HostExtensionError, KnowledgeEntry, KnowledgeEntrySummary,
    PromptFragment, RoleError, RoleSpec, Severity, TargetKind, TargetSummary, ToolDefinition,
    ValidateResult, ViewDefinition,
};
pub use self::url_matcher::UrlMatcher;

/// Re-export `reqwest` so consumers wiring `HostOverrides::http_client`
/// always construct the `Client` against the same crate version this
/// crate compiles against. Without this, a downstream crate that pulls
/// `reqwest` at a different semver (e.g. 0.13 vs the 0.12 we depend on)
/// produces two distinct `reqwest::blocking::Client` types and the
/// `http_client: Some(client)` assignment fails with a confusing
/// `expected reqwest::blocking::Client, found reqwest::blocking::Client`.
pub use reqwest;
