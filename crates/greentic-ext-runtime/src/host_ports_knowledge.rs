//! The knowledge host port: lets an extension write to the caller's knowledge
//! library (create, read, list, remove) through the
//! `greentic:extension-host/knowledge` import.
//!
//! Re-exported from [`crate::host_ports`]; it lives in its own file only to
//! keep that module under the size cap.

use crate::host_ports::HostCallContext;

/// A document an extension asks the host to create in a knowledge base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeCreateRequest {
    /// The base's NAME, as an operator sees it. The host resolves it inside
    /// the scope of the call; a guest never names a tenant or a team.
    pub knowledge_base: String,
    /// Display name of the new document.
    pub name: String,
    /// The document's text (UTF-8).
    pub text: String,
}

/// Result of a successful [`KnowledgePort::create`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeCreated {
    pub document_id: String,
    /// `false` when an identical document already existed and was reused.
    pub created: bool,
}

/// One document read back with [`KnowledgePort::read`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeDocument {
    pub name: String,
    pub text: String,
    /// `true` when the host returned only a prefix of the text.
    pub truncated: bool,
}

/// One row of [`KnowledgePort::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeDocumentInfo {
    pub document_id: String,
    pub name: String,
    pub size_chars: u64,
}

/// Why a knowledge port call failed. The variants map one-to-one onto the WIT
/// `knowledge-error`. None of them may carry document text; `Unavailable`'s
/// detail is logged host-side and never returned to the guest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KnowledgePortError {
    /// The caller may not use this base (or it does not exist: the two must
    /// read the same, so the port is not an existence oracle).
    #[error("knowledge operation not allowed")]
    NotAllowed,
    /// No such document in that base.
    #[error("knowledge document not found")]
    NotFound,
    /// The text or the name is over the host's cap.
    #[error("knowledge document too large")]
    TooLarge,
    /// The content is not a text kind the host accepts.
    #[error("knowledge media type not accepted")]
    InvalidMediaType,
    /// The tenant's knowledge quota is exhausted.
    #[error("knowledge quota exceeded")]
    QuotaExceeded,
    /// The store failed or is unreachable. Logged, never returned to the guest.
    #[error("knowledge store unavailable: {0}")]
    Unavailable(String),
}

/// Host port for the knowledge library, implemented by the embedding host (the
/// designer maps it onto its per-tenant, per-team knowledge store).
///
/// Synchronous on purpose: wasmtime host fns are wired with the sync linker.
/// The host applies no timeout to a port call and the wasm epoch deadline
/// cannot interrupt it, so a port must bound its own work.
///
/// The runtime has already checked, before any method is called, that the
/// extension declared the operation (`knowledge://<op>` in
/// `runtime.permissions.network`) and that `ctx.tenant` is non-blank. A port
/// must still resolve the base inside the scope `ctx` names (tenant, team,
/// session) and never widen it.
pub trait KnowledgePort: Send + Sync {
    /// Create a document in `request.knowledge_base`.
    fn create(
        &self,
        extension_id: &str,
        ctx: &HostCallContext,
        request: KnowledgeCreateRequest,
    ) -> Result<KnowledgeCreated, KnowledgePortError>;

    /// Read one document of `knowledge_base`.
    fn read(
        &self,
        extension_id: &str,
        ctx: &HostCallContext,
        knowledge_base: &str,
        document_id: &str,
    ) -> Result<KnowledgeDocument, KnowledgePortError>;

    /// List the documents of `knowledge_base`.
    fn list(
        &self,
        extension_id: &str,
        ctx: &HostCallContext,
        knowledge_base: &str,
    ) -> Result<Vec<KnowledgeDocumentInfo>, KnowledgePortError>;

    /// Remove `document_id` from `knowledge_base` (membership only; the
    /// library document is kept). `Ok(false)` when it was not a member.
    fn remove(
        &self,
        extension_id: &str,
        ctx: &HostCallContext,
        knowledge_base: &str,
        document_id: &str,
    ) -> Result<bool, KnowledgePortError>;
}
