//! Accept/reject matrix and per-dispatch scoping for infra network grants.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use greentic_extension_sdk_contract::describe::Permissions;

use crate::host_bindings::greentic::extension_host::http::{Host as HttpHost, Request};
use crate::host_bindings::greentic::extension_host::secrets::Host as SecretsHost;
use crate::host_ports::InMemorySecrets;
use crate::host_state::HostState;
use crate::infra_grant::{GrantedHosts, HostResolver, InfraGrantSettings, split_infra_grants};
use crate::net_permissions::effective_url_matcher_with_grants;
use crate::url_matcher::UrlMatcher;

const QDRANT_URI: &str = "secret://infra/vector_store_qdrant";
const TOKEN: &str = "infra://vector-store/qdrant";

/// Resolver answering from a table; `None` entry = resolution failure.
#[derive(Default)]
pub(crate) struct FakeDns(Mutex<Vec<(String, Vec<IpAddr>)>>);

impl FakeDns {
    pub(crate) fn with(host: &str, ips: &[&str]) -> Arc<Self> {
        let d = Self::default();
        d.set(host, ips);
        Arc::new(d)
    }
    pub(crate) fn set(&self, host: &str, ips: &[&str]) {
        let mut g = self.0.lock().unwrap();
        g.retain(|(h, _)| h != host);
        g.push((
            host.into(),
            ips.iter().map(|i| i.parse().unwrap()).collect(),
        ));
    }
}

impl HostResolver for FakeDns {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|(h, _)| h == host)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| io::Error::other("no such host"))
    }
}

pub(crate) fn doc(host: &str, port: u16, scheme: &str) -> String {
    format!(r#"{{"host":"{host}","port":{port},"scheme":"{scheme}","credential":"k"}}"#)
}

pub(crate) fn public_dns() -> Arc<FakeDns> {
    FakeDns::with("qdrant.acme.example", &["203.0.114.7", "93.184.216.34"])
}

fn state(declared: &[&str], dns: Arc<FakeDns>, stored: Option<&str>) -> HostState {
    state_with(
        declared,
        InfraGrantSettings::default().resolver(dns),
        stored,
    )
}

fn state_with(declared: &[&str], settings: InfraGrantSettings, stored: Option<&str>) -> HostState {
    let backend = InMemorySecrets::default();
    if let Some(v) = stored {
        backend.insert(QDRANT_URI, v);
    }
    let declared: Vec<String> = declared.iter().map(|s| (*s).to_string()).collect();
    let (matcher, grants) = effective_url_matcher_with_grants(&declared, UrlMatcher::default());
    let mut perms = Permissions::default();
    perms.secrets.push(QDRANT_URI.into());
    HostState::builder("rag".into(), perms)
        .secrets_backend(Arc::new(backend))
        .url_matcher(matcher)
        .infra_grants(grants, Arc::new(settings))
        .build()
}

fn read(h: &mut HostState) -> Result<String, String> {
    h.get(QDRANT_URI.to_string())
}

fn allowed(h: &HostState, url: &str) -> bool {
    h.url_matcher().is_allowed(url)
}

fn fetch(h: &mut HostState, url: &str) -> String {
    h.fetch(Request {
        method: "GET".into(),
        url: url.into(),
        headers: vec![],
        body: None,
    })
    .err()
    .unwrap_or_default()
}

#[test]
fn grant_tokens_are_split_from_url_patterns() {
    let declared: Vec<String> = [
        "https://api.openai.com/*",
        TOKEN,
        "INFRA://Cache/Redis",
        "infra://bad kind/x",
        "infra://only-one-segment",
        "infra://a/b/c",
        TOKEN,
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let (patterns, grants) = split_infra_grants(&declared);
    assert_eq!(patterns, vec!["https://api.openai.com/*".to_string()]);
    let uris: Vec<_> = grants
        .iter()
        .map(crate::infra_grant::KindGrant::secret_uri)
        .collect();
    assert_eq!(
        uris,
        vec![
            "secret://infra/vector_store_qdrant",
            "secret://infra/cache_redis"
        ]
    );
}

#[test]
fn a_successful_read_earns_exactly_the_resource_host_and_port() {
    let mut h = state(
        &["https://api.openai.com/*", TOKEN],
        public_dns(),
        Some(&doc("qdrant.acme.example", 6333, "https")),
    );
    assert!(!allowed(&h, "https://qdrant.acme.example:6333/collections"));
    read(&mut h).expect("read");
    assert!(allowed(&h, "https://qdrant.acme.example:6333/collections"));
    assert!(allowed(&h, "https://QDRANT.acme.example:6333/x"));
    assert!(
        !allowed(&h, "https://qdrant.acme.example:6334/x"),
        "other port"
    );
    assert!(
        !allowed(&h, "https://qdrant.acme.example/x"),
        "default port"
    );
    assert!(!allowed(&h, "http://qdrant.acme.example:6333/x"), "http");
    assert!(
        !allowed(&h, "https://other.acme.example:6333/x"),
        "other host"
    );
    assert!(!allowed(&h, "https://evil.example/"), "unrelated host");
    assert!(allowed(&h, "https://api.openai.com/v1"), "declared stays");
}

#[test]
fn a_granted_host_reaches_the_http_client_stage() {
    let mut h = state(
        &[TOKEN],
        public_dns(),
        Some(&doc("qdrant.acme.example", 443, "https")),
    );
    assert!(fetch(&mut h, "https://qdrant.acme.example/").contains("network not allowed"));
    read(&mut h).unwrap();
    // No client is wired in a unit test: getting that error means the
    // allow-list let the request through.
    assert!(fetch(&mut h, "https://qdrant.acme.example/").contains("http client not configured"));
    assert!(fetch(&mut h, "https://evil.example/").contains("network not allowed"));
}

#[test]
fn a_redirect_hop_off_the_granted_host_is_refused_by_the_matcher() {
    let mut h = state(
        &[TOKEN],
        public_dns(),
        Some(&doc("qdrant.acme.example", 6333, "https")),
    );
    read(&mut h).unwrap();
    // `send_following_redirects` checks every `Location` with this matcher.
    for hop in [
        "https://169.254.169.254/latest/meta-data/",
        "https://other.acme.example:6333/",
        "https://qdrant.acme.example:7000/",
        "http://qdrant.acme.example:6333/",
    ] {
        assert!(!allowed(&h, hop), "{hop}");
    }
}

#[test]
fn a_grant_never_leaks_to_the_next_dispatch_or_another_extension() {
    let settings = InfraGrantSettings::default().resolver(public_dns());
    let stored = doc("qdrant.acme.example", 6333, "https");
    let mut first = state_with(&[TOKEN], settings.clone(), Some(&stored));
    read(&mut first).unwrap();
    assert!(allowed(&first, "https://qdrant.acme.example:6333/"));

    // The next dispatch builds a fresh HostState from the same settings.
    let second = state_with(&[TOKEN], settings.clone(), Some(&stored));
    assert!(!allowed(&second, "https://qdrant.acme.example:6333/"));

    // Another extension, same runtime settings, even reading the same secret:
    // no token, so no grant.
    let mut other = state_with(&["https://api.openai.com/*"], settings, Some(&stored));
    read(&mut other).unwrap();
    assert!(!allowed(&other, "https://qdrant.acme.example:6333/"));
}

#[test]
fn an_extension_without_the_token_never_gets_a_grant() {
    for declared in [
        &[][..],
        &["https://api.openai.com/*"],
        &["infra://cache/redis"],
    ] {
        let mut h = state(
            declared,
            public_dns(),
            Some(&doc("qdrant.acme.example", 443, "https")),
        );
        read(&mut h).unwrap();
        assert!(!allowed(&h, "https://qdrant.acme.example/"), "{declared:?}");
    }
}

#[test]
fn a_failed_secret_read_grants_nothing() {
    let mut missing = state(&[TOKEN], public_dns(), None);
    assert!(read(&mut missing).is_err());
    assert!(!allowed(&missing, "https://qdrant.acme.example/"));

    // Permission denied (secret not declared in permissions.secrets): the gate
    // runs before the backend, so no grant either.
    let backend = InMemorySecrets::default();
    backend.insert(QDRANT_URI, &doc("qdrant.acme.example", 443, "https"));
    let (matcher, grants) =
        effective_url_matcher_with_grants(&[TOKEN.into()], UrlMatcher::default());
    let mut denied = HostState::builder("rag".into(), Permissions::default())
        .secrets_backend(Arc::new(backend))
        .url_matcher(matcher)
        .infra_grants(
            grants,
            Arc::new(InfraGrantSettings::default().resolver(public_dns())),
        )
        .build();
    assert!(read(&mut denied).is_err());
    assert!(!allowed(&denied, "https://qdrant.acme.example/"));
}

#[test]
fn a_refused_document_grants_nothing_but_the_read_still_succeeds() {
    for stored in [
        doc("10.0.0.5", 6333, "https"),
        doc("qdrant.acme.example", 6333, "http"),
        doc("localhost", 6333, "https"),
        "garbage".to_string(),
    ] {
        let mut h = state(&[TOKEN], public_dns(), Some(&stored));
        assert_eq!(read(&mut h).as_deref(), Ok(stored.as_str()));
        assert!(h.url_matcher().patterns().is_empty(), "{stored}");
    }
}

#[test]
fn the_kill_switch_disables_grants() {
    let settings = InfraGrantSettings::default()
        .resolver(public_dns())
        .enabled(false);
    let mut h = state_with(
        &[TOKEN],
        settings,
        Some(&doc("qdrant.acme.example", 443, "https")),
    );
    read(&mut h).unwrap();
    assert!(!allowed(&h, "https://qdrant.acme.example/"));
}

#[test]
fn a_grant_registers_the_name_for_connect_time_filtering() {
    let hosts = GrantedHosts::default();
    let settings = InfraGrantSettings::default()
        .resolver(public_dns())
        .granted_hosts(hosts.clone());
    let mut h = state_with(
        &[TOKEN],
        settings,
        Some(&doc("qdrant.acme.example", 443, "https")),
    );
    assert!(!hosts.contains("qdrant.acme.example"));
    read(&mut h).unwrap();
    assert!(hosts.contains("QDRANT.acme.example"));
    assert!(
        !hosts.contains("api.openai.com"),
        "declared hosts stay unfiltered"
    );
}

#[test]
fn rebinding_between_grant_and_request_is_caught() {
    let dns = public_dns();
    let mut h = state(
        &[TOKEN],
        dns.clone(),
        Some(&doc("qdrant.acme.example", 6333, "https")),
    );
    read(&mut h).unwrap();
    assert!(
        h.check_granted_destination("https://qdrant.acme.example:6333/x")
            .is_ok()
    );
    // The attacker flips the record to the metadata address after admission.
    dns.set("qdrant.acme.example", &["169.254.169.254"]);
    assert!(
        h.check_granted_destination("https://qdrant.acme.example:6333/x")
            .is_err()
    );
    // A URL that is not the granted target is not this check's business.
    assert!(
        h.check_granted_destination("https://api.openai.com/")
            .is_ok()
    );
}

#[test]
fn grants_only_extensions_get_deny_all_not_the_operator_list() {
    let ceiling = UrlMatcher::from_patterns(vec!["https://operator.example/*".into()]);
    let (m, grants) = effective_url_matcher_with_grants(&[TOKEN.into()], ceiling.clone());
    assert_eq!(grants.len(), 1);
    assert!(m.patterns().is_empty());
    // Mixed: declared pattern is still subject to the ceiling, the grant is not.
    let (m, grants) = effective_url_matcher_with_grants(
        &["https://api.openai.com/*".into(), TOKEN.into()],
        ceiling,
    );
    assert_eq!(grants.len(), 1);
    assert!(!m.is_allowed("https://api.openai.com/"));
}

#[test]
fn an_older_runtime_sees_an_inert_pattern_and_the_contract_still_parses() {
    // What a runtime without this feature does with the token.
    let m = UrlMatcher::from_patterns(vec![TOKEN.into(), "https://api.openai.com/*".into()]);
    assert!(!m.is_allowed("https://vector-store/qdrant"));
    assert!(!m.is_allowed("https://qdrant.acme.example/"));
    assert!(m.is_allowed("https://api.openai.com/v1"));
    // The contract type (deny_unknown_fields) takes it as a plain string.
    let p: Permissions = serde_json::from_str(&format!(
        r#"{{"network":["{TOKEN}","https://api.openai.com/*"],"secrets":["{QDRANT_URI}"]}}"#
    ))
    .expect("describe permissions parse");
    assert_eq!(p.network.len(), 2);
}

#[tokio::test]
async fn the_connect_time_resolver_filters_only_granted_names() {
    use reqwest::dns::Resolve;
    let hosts = GrantedHosts::default();
    let resolver = crate::infra_grant::PublicOnlyResolver::new(hosts.clone());
    let name = |n: &str| n.parse::<reqwest::dns::Name>().unwrap();
    // Not granted: resolves as the system would (declared loopback dev
    // patterns keep working).
    assert!(resolver.resolve(name("localhost")).await.is_ok());
    // Granted: loopback answers are dropped, leaving nothing to dial.
    hosts.insert("localhost");
    assert!(resolver.resolve(name("localhost")).await.is_err());
}
