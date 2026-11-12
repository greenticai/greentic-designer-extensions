//! The seam between the policy engine and whoever holds the credentials.
//!
//! The runtime decides WHETHER a call may happen; the embedder's
//! [`HostingPort`] decides HOW it is authorised and carried (`SigV4` signing,
//! a bearer header, a kubeconfig token) and holds every secret. The port never
//! sees a request the policy refused, and the guest never sees anything the
//! port holds.

use std::fmt;
use std::time::Duration;

use super::declaration::EndpointDecl;

/// A secret value. `Debug` and `Display` print a fixed mask, there is no
/// `Clone`, and the only way to read it is [`SecretValue::expose`], which the
/// runtime calls for exactly two things: placeholder substitution into an
/// outbound request and response redaction.
pub struct SecretValue(String);

impl SecretValue {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value. Never pass the result to a log, an error or the guest.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// Per-call facts the guest may learn through `target.get`.
#[derive(Debug, Clone, Default)]
pub struct TargetContext {
    pub installation_id: String,
    /// The ownership tags every created object must carry.
    pub owner_tags: Vec<(String, String)>,
    /// HMAC of the resource's instance credential. Not the credential.
    pub credential_fingerprint: Option<String>,
}

/// A request the policy approved. The body and header values may contain
/// secrets (placeholders are already substituted), so [`fmt::Debug`] prints
/// neither.
pub struct AuthorizedCall<'a> {
    pub endpoint: &'a EndpointDecl,
    /// The resolved host, already checked against the target's allow-list.
    pub host: String,
    pub method: String,
    /// Path and query.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// Hard ceiling for this call. The port MUST enforce it: the guest's epoch
    /// deadline cannot interrupt a blocking host call.
    pub timeout: Duration,
    /// The port should stop reading past this many body bytes.
    pub max_response_bytes: usize,
}

impl fmt::Debug for AuthorizedCall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedCall")
            .field("endpoint", &self.endpoint.id)
            .field("host", &self.host)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// The provider API's answer. Redirects are never followed: a port returns a
/// `3xx` as it is.
#[derive(Debug, Clone)]
pub struct PortResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// How a call can fail below the policy engine. Closed, like `api-error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    Timeout,
    Transport,
    TooLarge,
}

/// Implemented by the embedder (the admin, over its `SigV4` client; the mock in
/// [`super::mock`]).
pub trait HostingPort: Send + Sync {
    /// A NON-SECRET setting of the target (`region`, `cluster`, ...). The
    /// runtime refuses key-material-looking names before asking.
    fn target_setting(&self, key: &str) -> Option<String>;

    /// Facts for the reserved `target.get` keys.
    fn context(&self) -> TargetContext;

    /// The resource's instance credential, used ONLY for `${resource.credential}`
    /// substitution into outbound requests and for response redaction.
    fn instance_credential(&self) -> Option<SecretValue>;

    /// Further values that must never reach a log or the guest if an API
    /// echoes them (an access key id, a token the port minted).
    fn redaction_values(&self) -> Vec<SecretValue> {
        Vec::new()
    }

    /// Authorise and carry one approved call.
    ///
    /// # Errors
    ///
    /// [`PortError`], never a free-form string: the guest sees only the closed
    /// `api-error`.
    fn execute(&self, call: &AuthorizedCall<'_>) -> Result<PortResponse, PortError>;
}

/// A port that holds nothing and carries nothing. Used for the pure exports
/// (`describe-provider`, `supports`, `host-ref-for`, `validate-settings`),
/// which must not be able to reach a provider at all.
#[derive(Debug, Default)]
pub(crate) struct NullPort;

impl HostingPort for NullPort {
    fn target_setting(&self, _key: &str) -> Option<String> {
        None
    }
    fn context(&self) -> TargetContext {
        TargetContext::default()
    }
    fn instance_credential(&self) -> Option<SecretValue> {
        None
    }
    fn execute(&self, _call: &AuthorizedCall<'_>) -> Result<PortResponse, PortError> {
        Err(PortError::Transport)
    }
}
