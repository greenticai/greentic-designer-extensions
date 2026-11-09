//! Per-dispatch network grants derived from a connected infra resource.
//!
//! An extension that needs to reach a tenant-chosen host (an operator-run
//! Qdrant, a Redis REST gateway) cannot name that host in its describe: the
//! host is entered by a tenant member long after the extension was published.
//! Instead it lists an `infra://<family>/<name>` token in its existing
//! `permissions.network`. No new `describe.json` key exists — the contract
//! types are `deny_unknown_fields`, and on an older runtime the token is an
//! `infra`-scheme pattern that can never match an https request, so it is
//! inert and the extension still loads.
//!
//! When — and only when — the extension then reads the staged
//! `secret://infra/<kind>` connection document successfully, the runtime
//! derives ONE extra allowed pattern, `https://<host>:<port>/*`, for the
//! current dispatch. A `HostState` (and its wasmtime `Store`) is built per
//! dispatch in `LoadedExtension::build_store_and_instance`, the only place a
//! `Store` is created, so the grant dies with the call and never reaches
//! another extension or tenant.
//!
//! The host is tenant input, so it passes [`admit`] first: https only, no
//! userinfo or wildcard, no `localhost`/`.internal`/`.local`, no loopback,
//! private, CGNAT, link-local, metadata, unspecified, multicast or
//! IPv4-in-IPv6 address, and a hostname must resolve to public addresses only.
//!
//! ## DNS rebinding
//!
//! The name is resolved at grant time and again before every request to a
//! granted host ([`HostState::check_granted_destination`]), but the HTTP
//! client the embedder supplies resolves it a third time when it connects, and
//! that answer is out of this crate's hands. [`PublicOnlyResolver`] closes the
//! gap: an embedder that builds its shared client with
//! `ClientBuilder::dns_resolver(Arc::new(resolver))` gets non-public answers
//! dropped at connect time for every granted name (and only those, so a
//! declared loopback-http dev pattern keeps working). Without it, rebinding
//! between the last check and the connect remains possible.

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, RwLock};

use crate::host_state::HostState;
use crate::infra_grant_policy::all_public;
pub use crate::infra_grant_policy::{
    GrantRefusal, HostResolver, SystemResolver, admit, is_public_ip,
};

const INFRA_SCHEME: &str = "infra://";
const SECRET_PREFIXES: [&str; 2] = ["secret://infra/", "secrets://infra/"];
/// Bound on distinct names remembered for connect-time filtering.
const MAX_GRANTED_HOSTS: usize = 4096;

/// A declared `infra://<family>/<name>` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindGrant {
    family: String,
    name: String,
}

impl KindGrant {
    /// The secret URI the connection document is read from, in the canonical
    /// spelling the staging side uses (`vector-store/qdrant` ->
    /// `secret://infra/vector_store_qdrant`).
    #[must_use]
    pub fn secret_uri(&self) -> String {
        format!("{}{}", SECRET_PREFIXES[0], self.canonical())
    }

    fn canonical(&self) -> String {
        format!("{}_{}", self.family, self.name).replace('-', "_")
    }

    fn matches_uri(&self, uri: &str) -> bool {
        SECRET_PREFIXES
            .iter()
            .filter_map(|p| uri.strip_prefix(p))
            .any(|rest| rest == self.canonical())
    }
}

fn valid_segment(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.first().is_some_and(u8::is_ascii_alphanumeric)
        && b.last().is_some_and(u8::is_ascii_alphanumeric)
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

fn parse_grant(pattern: &str) -> Option<KindGrant> {
    let rest = pattern.trim().get(INFRA_SCHEME.len()..)?;
    let (family, name) = rest.split_once('/')?;
    let (family, name) = (family.to_ascii_lowercase(), name.to_ascii_lowercase());
    (valid_segment(&family) && valid_segment(&name)).then_some(KindGrant { family, name })
}

fn is_grant_token(pattern: &str) -> bool {
    pattern
        .trim()
        .get(..INFRA_SCHEME.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(INFRA_SCHEME))
}

/// Split the declared network patterns into ordinary URL patterns and
/// `infra://` grants. A malformed token is dropped (with a warning), never
/// handed to the URL matcher.
#[must_use]
pub(crate) fn split_infra_grants(declared: &[String]) -> (Vec<String>, Vec<KindGrant>) {
    let mut patterns = Vec::new();
    let mut grants = Vec::new();
    for p in declared {
        if !is_grant_token(p) {
            patterns.push(p.clone());
        } else if let Some(g) = parse_grant(p) {
            if !grants.contains(&g) {
                grants.push(g);
            }
        } else {
            tracing::warn!(pattern = %p, "ignoring a malformed infra:// network token");
        }
    }
    (patterns, grants)
}

/// The one host:port a grant allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedTarget {
    pub host: String,
    pub port: u16,
}

impl GrantedTarget {
    fn pattern(&self) -> String {
        if self.host.contains(':') {
            format!("https://[{}]:{}/*", self.host, self.port)
        } else {
            format!("https://{}:{}/*", self.host, self.port)
        }
    }

    fn covers(&self, url: &url::Url) -> bool {
        let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
        url.scheme() == "https"
            && host.eq_ignore_ascii_case(&self.host)
            && url.port_or_known_default() == Some(self.port)
    }
}

/// Names granted by any dispatch of this runtime; read by [`PublicOnlyResolver`].
///
/// Shared across dispatches on purpose and safe for it: membership only makes
/// the connect-time resolver STRICTER for that name, never more permissive.
#[derive(Debug, Clone, Default)]
pub struct GrantedHosts(Arc<RwLock<HashSet<String>>>);

impl GrantedHosts {
    pub(crate) fn insert(&self, host: &str) {
        if let Ok(mut set) = self.0.write()
            && set.len() < MAX_GRANTED_HOSTS
        {
            set.insert(host.to_ascii_lowercase());
        }
    }

    #[must_use]
    pub fn contains(&self, host: &str) -> bool {
        self.0
            .read()
            .is_ok_and(|s| s.contains(&host.to_ascii_lowercase()))
    }
}

/// Connect-time DNS resolver for the embedder's shared HTTP client: names the
/// runtime has granted get public answers only; everything else resolves as
/// the system would.
#[derive(Debug, Clone)]
pub struct PublicOnlyResolver {
    granted: GrantedHosts,
}

impl PublicOnlyResolver {
    #[must_use]
    pub fn new(granted: GrantedHosts) -> Self {
        Self { granted }
    }
}

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let granted = self.granted.clone();
        Box::pin(async move {
            let host = name.as_str().to_string();
            let strict = granted.contains(&host);
            let addrs = tokio::task::spawn_blocking(move || {
                (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(Iterator::collect::<Vec<SocketAddr>>)
            })
            .await??;
            let kept: Vec<SocketAddr> = if strict {
                addrs.into_iter().filter(|a| is_public_ip(a.ip())).collect()
            } else {
                addrs
            };
            if kept.is_empty() {
                return Err("no public address for a granted host".into());
            }
            Ok(Box::new(kept.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Runtime-wide switch and collaborators for infra grants.
#[derive(Clone)]
pub struct InfraGrantSettings {
    pub(crate) enabled: bool,
    pub(crate) granted_hosts: GrantedHosts,
    pub(crate) resolver: Arc<dyn HostResolver>,
}

impl Default for InfraGrantSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            granted_hosts: GrantedHosts::default(),
            resolver: Arc::new(SystemResolver),
        }
    }
}

impl InfraGrantSettings {
    /// Grants on (the default) or off. Off ignores every `infra://` token.
    #[must_use]
    pub fn enabled(mut self, on: bool) -> Self {
        self.enabled = on;
        self
    }

    /// Share a [`GrantedHosts`] with the embedder's [`PublicOnlyResolver`].
    #[must_use]
    pub fn granted_hosts(mut self, hosts: GrantedHosts) -> Self {
        self.granted_hosts = hosts;
        self
    }

    /// Replace the grant-time resolver (tests, or an embedder with its own).
    #[must_use]
    pub fn resolver(mut self, r: Arc<dyn HostResolver>) -> Self {
        self.resolver = r;
        self
    }
}

impl std::fmt::Debug for InfraGrantSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfraGrantSettings")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl HostState {
    /// Called after a permitted `secrets.get` returned `value`. Adds the
    /// per-dispatch grant when `uri` is a declared infra kind and the document
    /// passes [`admit`]; otherwise changes nothing (the read itself is never
    /// failed by a refused grant).
    pub(crate) fn apply_infra_grant(&mut self, uri: &str, value: &str) {
        if !self.infra_settings.enabled || !self.infra_grants.iter().any(|g| g.matches_uri(uri)) {
            return;
        }
        match admit(value, self.infra_settings.resolver.as_ref()) {
            Ok(target) => {
                if self.granted.contains(&target) {
                    return;
                }
                self.infra_settings.granted_hosts.insert(&target.host);
                self.url_matcher =
                    std::mem::take(&mut self.url_matcher).with_extra_pattern(&target.pattern());
                self.granted.push(target);
            }
            Err(why) => tracing::warn!(
                ext = %self.extension_id,
                kind_uri = %uri,
                reason = %why,
                "infra network grant refused"
            ),
        }
    }

    /// Before every request to a granted host: resolve again and require
    /// public answers only (narrows the rebinding window; see module docs).
    pub(crate) fn check_granted_destination(&self, url: &str) -> Result<(), String> {
        let Ok(parsed) = url::Url::parse(url) else {
            return Ok(());
        };
        let Some(target) = self.granted.iter().find(|t| t.covers(&parsed)) else {
            return Ok(());
        };
        all_public(self.infra_settings.resolver.as_ref(), &target.host, target.port).map_err(
            |why| {
                tracing::warn!(ext = %self.extension_id, reason = %why, "granted host refused at request time");
                format!("granted host refused: {why}")
            },
        )
    }
}
