//! One structured audit record per `api.call`, allowed or not.
//!
//! A record names the target, the extension version, the endpoint, the action,
//! the outcome and the duration. It never carries a request or response body,
//! a header value or a path query: the audit stream is read by the people who
//! must be able to see what a hosting extension did without being handed what
//! it was holding.

use std::sync::Mutex;

/// How a call ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The provider answered; the HTTP status.
    Completed(u16),
    /// The endpoint id is not declared.
    NotDeclared,
    /// Refused by policy; a fixed reason token.
    Denied(&'static str),
    Timeout,
    Transport,
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub target_id: String,
    pub extension_id: String,
    pub extension_version: String,
    /// Lifecycle operation the call ran inside (`ensure-host`, ...).
    pub operation: &'static str,
    /// 1-based position within the invocation.
    pub call_index: u32,
    pub endpoint: String,
    pub method: String,
    /// Service action name or REST path without its query; `None` when the
    /// request named none.
    pub action: Option<String>,
    pub outcome: Outcome,
    pub duration_ms: u64,
    pub request_bytes: usize,
    pub response_bytes: usize,
}

/// Receives audit records. Must not block: it runs inside a host call.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
}

/// Writes records to `tracing` under the `greentic_ext_runtime::hosting::audit`
/// target.
#[derive(Debug, Default)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, e: AuditEvent) {
        tracing::info!(
            target: "greentic_ext_runtime::hosting::audit",
            target_id = %e.target_id,
            extension = %e.extension_id,
            version = %e.extension_version,
            operation = e.operation,
            call = e.call_index,
            endpoint = %e.endpoint,
            method = %e.method,
            action = e.action.as_deref().unwrap_or(""),
            outcome = ?e.outcome,
            duration_ms = e.duration_ms,
            request_bytes = e.request_bytes,
            response_bytes = e.response_bytes,
            "hosting api call"
        );
    }
}

/// Keeps records in memory; for tests and for embedders that forward in batches.
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAuditSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of the records so far.
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        match self.events.lock() {
            Ok(mut g) => g.push(event),
            Err(p) => p.into_inner().push(event),
        }
    }
}
