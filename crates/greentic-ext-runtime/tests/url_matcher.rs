//! Strict URL allow-list matcher tests. The cases below pin the behaviour
//! that defends against the three classic attack vectors (open redirect,
//! subdomain confusion, scheme downgrade) plus a happy path.

use greentic_ext_runtime::UrlMatcher;

fn matcher(patterns: &[&str]) -> UrlMatcher {
    UrlMatcher::from_patterns(patterns.iter().map(|s| (*s).to_string()).collect())
}

#[test]
fn allows_exact_host_and_path_prefix_match() {
    let m = matcher(&["https://api.openai.com/v1/*"]);
    assert!(m.is_allowed("https://api.openai.com/v1/chat/completions"));
    assert!(m.is_allowed("https://api.openai.com/v1/embeddings"));
}

#[test]
fn rejects_open_redirect_via_query_string() {
    let m = matcher(&["https://evil.com/*"]);
    assert!(
        !m.is_allowed("https://allowed.com/redirect?to=https://evil.com/"),
        "matcher must not be fooled by a substring of evil.com in the query"
    );
}

#[test]
fn rejects_subdomain_confusion() {
    let m = matcher(&["https://allowed.com/*"]);
    assert!(
        !m.is_allowed("https://evil.com.allowed.com/"),
        "matcher must require a host boundary, not a substring"
    );
}

#[test]
fn rejects_scheme_downgrade() {
    let m = matcher(&["https://allowed.com/*"]);
    assert!(
        !m.is_allowed("http://allowed.com/"),
        "matcher must require exact scheme — no http when https expected"
    );
}

#[test]
fn allows_wildcard_subdomain_when_pattern_uses_star_dot() {
    let m = matcher(&["https://*.example.com/*"]);
    assert!(m.is_allowed("https://api.example.com/v1/foo"));
    assert!(m.is_allowed("https://cdn.example.com/assets/logo.png"));
    assert!(
        !m.is_allowed("https://example.com/x"),
        "bare host must not match *.example.com — wildcard needs at least one label"
    );
}

#[test]
fn rejects_non_https_by_default() {
    let m = matcher(&["http://allowed.com/*"]);
    assert!(
        !m.is_allowed("http://allowed.com/"),
        "http rejected by default even when pattern uses http://"
    );
}

#[test]
fn opt_in_allow_http_lets_http_through() {
    let m = UrlMatcher::from_patterns(vec!["http://allowed.com/*".into()]).with_allow_http(true);
    assert!(m.is_allowed("http://allowed.com/anything"));
}

#[test]
fn rejects_url_that_fails_to_parse() {
    let m = matcher(&["https://allowed.com/*"]);
    assert!(!m.is_allowed("not a url at all"));
}

#[test]
fn rejects_a_different_port_on_an_allowed_host() {
    // Loopback is the case that makes this load-bearing: every local service
    // shares 127.0.0.1, so a matcher that ignored the port would turn one
    // declared dev port into a pass to every other listener on the box.
    let m = UrlMatcher::from_patterns(vec!["http://127.0.0.1:8787/*".into()]).with_allow_http(true);
    assert!(m.is_allowed("http://127.0.0.1:8787/execute"));
    assert!(
        !m.is_allowed("http://127.0.0.1:9200/_search"),
        "a pattern that names a port must grant only that port"
    );
}

#[test]
fn rejects_a_non_default_port_on_a_public_host() {
    let m = matcher(&["https://api.example.com/*"]);
    assert!(m.is_allowed("https://api.example.com/v1/foo"));
    assert!(
        !m.is_allowed("https://api.example.com:8443/v1/foo"),
        "an implicit :443 pattern must not grant an explicit alternate port"
    );
}

#[test]
fn treats_an_explicit_default_port_as_the_implicit_one() {
    let m = matcher(&["https://api.example.com:443/*"]);
    assert!(
        m.is_allowed("https://api.example.com/v1/foo"),
        "https://h:443 and https://h are the same rule"
    );
}

#[test]
fn path_prefix_stops_at_a_segment_boundary() {
    let m = matcher(&["https://api.openai.com/v1/*"]);
    assert!(m.is_allowed("https://api.openai.com/v1/chat/completions"));
    assert!(
        m.is_allowed("https://api.openai.com/v1"),
        "the prefix itself is covered"
    );
    assert!(
        !m.is_allowed("https://api.openai.com/v1evil/steal"),
        "a neighbouring path must not smuggle itself past a narrow grant"
    );
    assert!(
        !m.is_allowed("https://api.openai.com/v2/chat"),
        "a sibling path stays denied"
    );
}

#[test]
fn wildcard_requires_a_real_label_boundary_not_just_a_suffix() {
    // `notexample.com` ends with `example.com` as a *string*. Without the
    // separating-dot check the wildcard would read that as a subdomain and hand
    // an attacker-registrable domain the same grant as the real one.
    let m = matcher(&["https://*.example.com/*"]);
    assert!(m.is_allowed("https://api.example.com/x"));
    assert!(
        !m.is_allowed("https://notexample.com/x"),
        "a bare suffix match is not a subdomain"
    );
    assert!(
        !m.is_allowed("https://evilexample.com/x"),
        "a bare suffix match is not a subdomain"
    );
}

#[test]
fn enabling_http_does_not_downgrade_an_https_pattern() {
    // `allow_http` is matcher-wide, so it has to be the per-pattern scheme
    // comparison that keeps an https-only host https-only. Every other test
    // short-circuits at the global https gate and never reaches that check.
    let m =
        UrlMatcher::from_patterns(vec!["https://api.example.com/*".into()]).with_allow_http(true);
    assert!(m.is_allowed("https://api.example.com/v1"));
    assert!(
        !m.is_allowed("http://api.example.com/v1"),
        "the http opt-in must not downgrade a host declared over https"
    );
}

#[test]
fn host_matching_is_case_insensitive() {
    let m = matcher(&["https://API.Example.COM/*"]);
    assert!(m.is_allowed("https://api.example.com/x"));
}
