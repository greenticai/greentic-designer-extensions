//! A scripted [`HostingPort`] for tests of the policy engine, of the runtime
//! wiring and of hosting extensions themselves.
//!
//! It records every call it is asked to carry, AFTER placeholder substitution,
//! so a test can assert what a provider API would have received.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use super::port::{
    AuthorizedCall, HostingPort, PortError, PortResponse, SecretValue, TargetContext,
};

/// What the mock saw. The body is the post-substitution bytes.
#[derive(Debug, Clone)]
pub struct SeenCall {
    pub endpoint: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

type Responder = Box<dyn Fn(&SeenCall) -> Result<PortResponse, PortError> + Send + Sync>;

#[derive(Default)]
pub struct MockHostingPort {
    settings: BTreeMap<String, String>,
    context: TargetContext,
    credential: Option<String>,
    extra_redactions: Vec<String>,
    responder: Option<Responder>,
    delay: Duration,
    seen: Mutex<Vec<SeenCall>>,
}

impl MockHostingPort {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn setting(mut self, key: &str, value: &str) -> Self {
        self.settings.insert(key.to_string(), value.to_string());
        self
    }

    #[must_use]
    pub fn context(mut self, ctx: TargetContext) -> Self {
        self.context = ctx;
        self
    }

    /// The resource's instance credential.
    #[must_use]
    pub fn credential(mut self, value: &str) -> Self {
        self.credential = Some(value.to_string());
        self
    }

    /// A value the port itself holds (a signing key id) that must be redacted.
    #[must_use]
    pub fn also_redact(mut self, value: &str) -> Self {
        self.extra_redactions.push(value.to_string());
        self
    }

    /// Answer every call with `f`.
    #[must_use]
    pub fn respond(
        mut self,
        f: impl Fn(&SeenCall) -> Result<PortResponse, PortError> + Send + Sync + 'static,
    ) -> Self {
        self.responder = Some(Box::new(f));
        self
    }

    /// Sleep this long before answering, to exercise the deadline.
    #[must_use]
    pub fn delay(mut self, d: Duration) -> Self {
        self.delay = d;
        self
    }

    /// The calls carried so far.
    #[must_use]
    pub fn seen(&self) -> Vec<SeenCall> {
        self.seen
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
    }
}

impl HostingPort for MockHostingPort {
    fn target_setting(&self, key: &str) -> Option<String> {
        self.settings.get(key).cloned()
    }

    fn context(&self) -> TargetContext {
        self.context.clone()
    }

    fn instance_credential(&self) -> Option<SecretValue> {
        self.credential.clone().map(SecretValue::new)
    }

    fn redaction_values(&self) -> Vec<SecretValue> {
        self.extra_redactions
            .iter()
            .cloned()
            .map(SecretValue::new)
            .collect()
    }

    fn execute(&self, call: &AuthorizedCall<'_>) -> Result<PortResponse, PortError> {
        let seen = SeenCall {
            endpoint: call.endpoint.id.clone(),
            host: call.host.clone(),
            method: call.method.clone(),
            path: call.path.clone(),
            headers: call.headers.clone(),
            body: call.body.clone(),
            timeout: call.timeout,
        };
        match self.seen.lock() {
            Ok(mut g) => g.push(seen.clone()),
            Err(p) => p.into_inner().push(seen.clone()),
        }
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        self.responder.as_ref().map_or_else(
            || {
                Ok(PortResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                })
            },
            |f| f(&seen),
        )
    }
}
