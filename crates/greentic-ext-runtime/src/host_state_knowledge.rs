//! `Host` impl for the `greentic:extension-host/knowledge` import.
//!
//! Every call is checked here, once, before the port sees it: the operation
//! must be declared (`knowledge://<op>` in `runtime.permissions.network`), the
//! call must carry a tenant, and the arguments must fit the host's caps. A
//! refusal never names a base or echoes document text.

use crate::host_bindings::design_v04::greentic::extension_host::knowledge::{
    self, BaseInfo, Created, Document, DocumentInfo, KnowledgeError, SearchHit, Updated,
};
use crate::host_ports::{
    KnowledgeCreateRequest, KnowledgePortError, KnowledgeSearchRequest, KnowledgeUpdateRequest,
};
use crate::host_state::HostState;
use crate::knowledge_grant::{KnowledgeOp, declares};

/// Largest document text an extension may write, in bytes. The embedding host
/// may apply a tighter cap of its own and answer `too-large`.
pub(crate) const MAX_KNOWLEDGE_TEXT_BYTES: usize = 10 * 1024 * 1024;
/// Longest accepted knowledge-base name or document id, in bytes.
pub(crate) const MAX_KNOWLEDGE_REF_BYTES: usize = 255;
/// Most hits a search returns; a larger `limit` is clamped, `0` reads as 1.
pub(crate) const MAX_SEARCH_LIMIT: u32 = 20;
/// Longest accepted search query, in bytes.
pub(crate) const MAX_SEARCH_QUERY_BYTES: usize = 4096;

fn map_port_error(ext: &str, op: KnowledgeOp, err: KnowledgePortError) -> KnowledgeError {
    match err {
        KnowledgePortError::NotAllowed => KnowledgeError::NotAllowed,
        KnowledgePortError::NotFound => KnowledgeError::NotFound,
        KnowledgePortError::TooLarge => KnowledgeError::TooLarge,
        KnowledgePortError::InvalidMediaType => KnowledgeError::InvalidMediaType,
        KnowledgePortError::QuotaExceeded => KnowledgeError::QuotaExceeded,
        KnowledgePortError::Unavailable(detail) => {
            // The detail can name an internal host: log it, never return it.
            tracing::warn!(ext = %ext, op = op.as_str(), error = %detail, "knowledge port unavailable");
            KnowledgeError::Unavailable
        }
    }
}

/// A base name the host can never resolve. Reads like a forbidden base, so the
/// interface is not an existence oracle.
fn bad_base(base: &str) -> bool {
    base.trim().is_empty()
        || base.len() > MAX_KNOWLEDGE_REF_BYTES
        || base.chars().any(char::is_control)
}

/// A document id that can never name a document.
fn bad_document_id(id: &str) -> bool {
    id.trim().is_empty() || id.len() > MAX_KNOWLEDGE_REF_BYTES || id.chars().any(char::is_control)
}

impl HostState {
    /// Permission, tenant and port, in that order. Returns the port to call.
    fn knowledge_gate(
        &self,
        op: KnowledgeOp,
        base: Option<&str>,
    ) -> Result<std::sync::Arc<dyn crate::host_ports::KnowledgePort>, KnowledgeError> {
        if !declares(&self.permissions.network, op) {
            tracing::warn!(ext = %self.extension_id, op = op.as_str(), "knowledge call refused: operation not declared");
            return Err(KnowledgeError::NotAllowed);
        }
        if self
            .call_ctx
            .tenant
            .as_deref()
            .is_none_or(|t| t.trim().is_empty())
        {
            tracing::warn!(ext = %self.extension_id, op = op.as_str(), "knowledge call refused: no tenant");
            return Err(KnowledgeError::NotAllowed);
        }
        if base.is_some_and(bad_base) {
            return Err(KnowledgeError::NotAllowed);
        }
        if let Some(port) = self.knowledge_port.as_ref() {
            return Ok(port.clone());
        }
        tracing::debug!(ext = %self.extension_id, "knowledge call refused: host wires no knowledge port");
        Err(KnowledgeError::Unavailable)
    }
}

impl knowledge::Host for HostState {
    fn create(
        &mut self,
        knowledge_base: String,
        name: String,
        text: String,
    ) -> Result<Created, KnowledgeError> {
        let op = KnowledgeOp::Create;
        let port = self.knowledge_gate(op, Some(&knowledge_base))?;
        // Caps live here once. Over-cap input is refused, never truncated.
        if text.len() > MAX_KNOWLEDGE_TEXT_BYTES {
            return Err(KnowledgeError::TooLarge);
        }
        match crate::host_state_artifact::name_problem(&name) {
            None => {}
            Some(_) if name.len() > crate::host_state_artifact::MAX_ARTIFACT_NAME_BYTES => {
                return Err(KnowledgeError::TooLarge);
            }
            Some(_) => return Err(KnowledgeError::NotAllowed),
        }
        let created = port
            .create(
                &self.extension_id,
                &self.call_ctx,
                KnowledgeCreateRequest {
                    knowledge_base,
                    name,
                    text,
                },
            )
            .map_err(|e| map_port_error(&self.extension_id, op, e))?;
        if created.document_id.trim().is_empty() {
            tracing::warn!(ext = %self.extension_id, "knowledge port returned a blank document id");
            return Err(KnowledgeError::Unavailable);
        }
        Ok(Created {
            document_id: created.document_id,
            created: created.created,
        })
    }

    fn read(
        &mut self,
        knowledge_base: String,
        document_id: String,
    ) -> Result<Document, KnowledgeError> {
        let op = KnowledgeOp::Read;
        let port = self.knowledge_gate(op, Some(&knowledge_base))?;
        if bad_document_id(&document_id) {
            return Err(KnowledgeError::NotFound);
        }
        let doc = port
            .read(
                &self.extension_id,
                &self.call_ctx,
                &knowledge_base,
                &document_id,
            )
            .map_err(|e| map_port_error(&self.extension_id, op, e))?;
        Ok(Document {
            name: doc.name,
            text: doc.text,
            truncated: doc.truncated,
        })
    }

    fn list(&mut self, knowledge_base: String) -> Result<Vec<DocumentInfo>, KnowledgeError> {
        let op = KnowledgeOp::List;
        let port = self.knowledge_gate(op, Some(&knowledge_base))?;
        let rows = port
            .list(&self.extension_id, &self.call_ctx, &knowledge_base)
            .map_err(|e| map_port_error(&self.extension_id, op, e))?;
        Ok(rows
            .into_iter()
            .map(|r| DocumentInfo {
                document_id: r.document_id,
                name: r.name,
                size_chars: r.size_chars,
            })
            .collect())
    }

    fn remove(
        &mut self,
        knowledge_base: String,
        document_id: String,
    ) -> Result<bool, KnowledgeError> {
        let op = KnowledgeOp::Remove;
        let port = self.knowledge_gate(op, Some(&knowledge_base))?;
        if bad_document_id(&document_id) {
            return Err(KnowledgeError::NotFound);
        }
        port.remove(
            &self.extension_id,
            &self.call_ctx,
            &knowledge_base,
            &document_id,
        )
        .map_err(|e| map_port_error(&self.extension_id, op, e))
    }

    fn list_bases(&mut self) -> Result<Vec<BaseInfo>, KnowledgeError> {
        let op = KnowledgeOp::ListBases;
        let port = self.knowledge_gate(op, None)?;
        let bases = port
            .list_bases(&self.extension_id, &self.call_ctx)
            .map_err(|e| map_port_error(&self.extension_id, op, e))?;
        Ok(bases
            .into_iter()
            .map(|b| BaseInfo {
                name: b.name,
                description: b.description,
                document_count: b.document_count,
            })
            .collect())
    }

    fn search(
        &mut self,
        knowledge_base: String,
        query: String,
        limit: u32,
    ) -> Result<Vec<SearchHit>, KnowledgeError> {
        let op = KnowledgeOp::Search;
        let port = self.knowledge_gate(op, Some(&knowledge_base))?;
        if query.len() > MAX_SEARCH_QUERY_BYTES {
            return Err(KnowledgeError::TooLarge);
        }
        // A blank query matches nothing; the port is not asked.
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let limit = limit.clamp(1, MAX_SEARCH_LIMIT);
        let hits = port
            .search(
                &self.extension_id,
                &self.call_ctx,
                KnowledgeSearchRequest {
                    knowledge_base,
                    query,
                    limit,
                },
            )
            .map_err(|e| map_port_error(&self.extension_id, op, e))?;
        Ok(hits
            .into_iter()
            .take(limit as usize)
            .map(|h| SearchHit {
                document_id: h.document_id,
                name: h.name,
                passage: h.passage,
                score: h.score,
            })
            .collect())
    }

    fn update(
        &mut self,
        knowledge_base: String,
        document_id: String,
        text: String,
    ) -> Result<Updated, KnowledgeError> {
        let op = KnowledgeOp::Update;
        let port = self.knowledge_gate(op, Some(&knowledge_base))?;
        if bad_document_id(&document_id) {
            return Err(KnowledgeError::NotFound);
        }
        if text.len() > MAX_KNOWLEDGE_TEXT_BYTES {
            return Err(KnowledgeError::TooLarge);
        }
        let updated = port
            .update(
                &self.extension_id,
                &self.call_ctx,
                KnowledgeUpdateRequest {
                    knowledge_base,
                    document_id,
                    text,
                },
            )
            .map_err(|e| map_port_error(&self.extension_id, op, e))?;
        if updated.document_id.trim().is_empty() {
            tracing::warn!(ext = %self.extension_id, "knowledge port returned a blank document id");
            return Err(KnowledgeError::Unavailable);
        }
        Ok(Updated {
            document_id: updated.document_id,
        })
    }
}

#[cfg(test)]
#[path = "host_state_knowledge_tests.rs"]
mod tests;
