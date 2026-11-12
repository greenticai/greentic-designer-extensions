//! Which `greentic:extension-host/knowledge` operations an extension declared.
//!
//! An extension lists `knowledge://<op>` tokens, one per operation it uses
//! (`create`, `read`, `list`, `remove`), in its existing
//! `runtime.permissions.network`. No new `describe.json` key exists: the
//! contract's `Permissions` is `deny_unknown_fields`, so a new key would make
//! every designer that predates it refuse the whole describe. This is the
//! same route `infra://` grants took.
//!
//! The tokens are not URLs. [`without_knowledge_tokens`] strips them before
//! the network allow-list is built, so they can never widen it, and
//! [`declared_ops`] reads them back for the per-call check. A token naming an
//! unknown operation grants nothing.

const SCHEME: &str = "knowledge://";

/// One operation of the knowledge interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnowledgeOp {
    Create,
    Read,
    List,
    Remove,
}

impl KnowledgeOp {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::List => "list",
            Self::Remove => "remove",
        }
    }

    fn parse(op: &str) -> Option<Self> {
        match op {
            "create" => Some(Self::Create),
            "read" => Some(Self::Read),
            "list" => Some(Self::List),
            "remove" => Some(Self::Remove),
            _ => None,
        }
    }
}

fn is_token(pattern: &str) -> bool {
    pattern.starts_with(SCHEME)
}

/// Whether `network` declares `op`. Exact match only: no wildcard, no case
/// folding, so a declaration reads exactly as it is written.
pub(crate) fn declares(network: &[String], op: KnowledgeOp) -> bool {
    network
        .iter()
        .filter_map(|p| p.strip_prefix(SCHEME))
        .filter_map(KnowledgeOp::parse)
        .any(|declared| declared == op)
}

/// Every operation `network` declares, in a stable order.
#[cfg(test)]
pub(crate) fn declared_ops(network: &[String]) -> Vec<KnowledgeOp> {
    [
        KnowledgeOp::Create,
        KnowledgeOp::Read,
        KnowledgeOp::List,
        KnowledgeOp::Remove,
    ]
    .into_iter()
    .filter(|op| declares(network, *op))
    .collect()
}

/// `network` without its `knowledge://` tokens, for the URL allow-list.
pub(crate) fn without_knowledge_tokens(network: &[String]) -> Vec<String> {
    network
        .iter()
        .filter(|p| {
            if !is_token(p) {
                return true;
            }
            if p.strip_prefix(SCHEME)
                .and_then(KnowledgeOp::parse)
                .is_none()
            {
                tracing::warn!(token = %p, "ignoring a knowledge token naming no known operation");
            }
            false
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn declared_ops_reads_exactly_the_listed_operations() {
        let net = s(&[
            "knowledge://create",
            "https://api.example.com/*",
            "knowledge://list",
        ]);
        assert_eq!(
            declared_ops(&net),
            vec![KnowledgeOp::Create, KnowledgeOp::List]
        );
        assert!(declares(&net, KnowledgeOp::Create));
        assert!(!declares(&net, KnowledgeOp::Remove));
    }

    #[test]
    fn unknown_wildcard_or_differently_cased_tokens_grant_nothing() {
        let net = s(&[
            "knowledge://*",
            "knowledge://Create",
            "knowledge://",
            "knowledge://delete",
        ]);
        assert!(declared_ops(&net).is_empty());
    }

    #[test]
    fn nothing_declared_means_nothing_allowed() {
        assert!(declared_ops(&[]).is_empty());
    }

    #[test]
    fn tokens_never_reach_the_url_allow_list() {
        let net = s(&[
            "knowledge://create",
            "https://api.example.com/*",
            "knowledge://bogus",
            "infra://cache/redis",
        ]);
        assert_eq!(
            without_knowledge_tokens(&net),
            s(&["https://api.example.com/*", "infra://cache/redis"])
        );
    }
}
