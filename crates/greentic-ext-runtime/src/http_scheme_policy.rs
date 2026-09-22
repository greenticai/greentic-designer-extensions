//! Which declared `http://` patterns the runtime is willing to honour.
//!
//! Split from [`crate::net_permissions`]: the plain-http rule carries its own
//! set of adversarial cases — authority-delimiter smuggling, scheme spelling,
//! loopback spellings, bracketed IPv6 — and they earn the room to be stated.

/// How a declared pattern is classified for the plain-http rule.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HttpClass {
    /// Plain http to a loopback address — keep it, and switch the toggle on.
    Loopback,
    /// Plain http to anything else — drop it; it could never be honoured safely.
    Public,
    /// Not plain http (https, or a scheme the matcher will reject on its own).
    Other,
}

/// Classify a declared pattern with the *same parser the matcher uses*.
///
/// This used to be hand-rolled string surgery — `strip_prefix("http://")`, then
/// split on `/`, then `rsplit('@')` — and the two disagreed about where the
/// authority ends. `Url` terminates it at `/`, `?`, `#`, or `\`, and normalizes
/// the scheme; the string version stopped only at `/` and matched the scheme
/// literally. Every gap between them was a plain-http downgrade to a public
/// host: `http://evil.com?@localhost/*` classified as loopback (last `@` yields
/// `localhost`) and so both survived the drop *and* switched the toggle on,
/// while the matcher resolved the host to `evil.com` with a path prefix of `/`.
/// `HTTP://evil.com/*` and a leading space did the same by failing the literal
/// prefix test and being waved through as "not http".
///
/// One parser decides both, so there is no gap left to disagree in.
pub(crate) fn classify(pattern: &str) -> HttpClass {
    // The matcher normalizes `*.` into a placeholder label before parsing;
    // do the same here so a wildcard pattern reaches `Url` in the same shape.
    let normalized = pattern
        .trim_end_matches("/*")
        .replace("://*.", "://__wildcard__.");
    let Ok(url) = url::Url::parse(&normalized) else {
        // Unparseable patterns are dropped by `UrlMatcher::from_patterns`
        // anyway; classifying as NotHttp keeps them out of the toggle.
        return HttpClass::Other;
    };
    if url.scheme() != "http" {
        return HttpClass::Other;
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() => HttpClass::Loopback,
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => HttpClass::Loopback,
        // `localhost` only, and only as the whole host. A wildcard pattern
        // arrives here as `__wildcard__.localhost`, which is not loopback —
        // `*.localhost` resolves through the system resolver like any other
        // name, so treating it as loopback would hand plain http to whatever a
        // search-domain quirk points `evil.localhost` at.
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => HttpClass::Loopback,
        _ => HttpClass::Public,
    }
}

#[cfg(test)]
mod tests {
    use crate::net_permissions::effective_url_matcher;
    use crate::url_matcher::UrlMatcher;

    fn empty_override() -> UrlMatcher {
        UrlMatcher::default()
    }

    /// A declared loopback `http://127.0.0.1` pattern must be reachable
    /// over plain http. The matcher rejects non-https by default, so the
    /// effective matcher has to opt http in — but ONLY because the
    /// declared pattern is loopback.
    #[test]
    fn declared_http_loopback_127_allows_plain_http() {
        let declared = vec!["http://127.0.0.1:8787/*".to_string()];
        let matcher = effective_url_matcher(&declared, empty_override());

        assert!(
            matcher.is_allowed("http://127.0.0.1:8787/execute"),
            "declared http loopback pattern must permit plain http to that loopback"
        );
    }

    /// `http://localhost` is the other loopback spelling and must behave
    /// the same as `127.0.0.1`.
    #[test]
    fn declared_http_loopback_localhost_allows_plain_http() {
        let declared = vec!["http://localhost:8787/*".to_string()];
        let matcher = effective_url_matcher(&declared, empty_override());

        assert!(
            matcher.is_allowed("http://localhost:8787/execute"),
            "declared http localhost pattern must permit plain http to localhost"
        );
    }

    /// The loopback-http opt-in must NOT leak to non-loopback http: a
    /// declared `http://evil.com` pattern must stay denied (no plain-http
    /// downgrade for a public host) even though the pattern technically
    /// targets http.
    #[test]
    fn declared_http_non_loopback_stays_denied() {
        let declared = vec!["http://evil.com/*".to_string()];
        let matcher = effective_url_matcher(&declared, empty_override());

        assert!(
            !matcher.is_allowed("http://evil.com/anything"),
            "plain http must stay denied for a non-loopback declared host"
        );
    }

    /// A mixed declaration (loopback http + a normal https host) must keep
    /// https reachable AND the loopback http reachable, while still
    /// refusing plain http to the https host (the global `allow_http` toggle
    /// must not downgrade the https-only host because no http pattern for
    /// it exists, and `is_allowed` matches scheme exactly per pattern).
    #[test]
    fn mixed_loopback_http_and_https_host() {
        let declared = vec![
            "http://127.0.0.1:8787/*".to_string(),
            "https://api.example.com/*".to_string(),
        ];
        let matcher = effective_url_matcher(&declared, empty_override());

        assert!(
            matcher.is_allowed("http://127.0.0.1:8787/execute"),
            "loopback http must be allowed in a mixed declaration"
        );
        assert!(
            matcher.is_allowed("https://api.example.com/v1/foo"),
            "declared https host must stay reachable"
        );
        assert!(
            !matcher.is_allowed("http://api.example.com/v1/foo"),
            "plain http to the https-only host must stay denied even with loopback http enabled"
        );
    }

    /// A declaration that mixes loopback http with a *public* http host must
    /// keep only the loopback one.
    ///
    /// This is the case that isolates the drop step. Every other http test
    /// declares a public host alone, where the denial comes from
    /// `allow_loopback_http` never being switched on — so the `retain` that
    /// drops public-host http patterns could be deleted outright and the suite
    /// would stay green, while an extension declaring both got cleartext http
    /// to the public host.
    #[test]
    fn a_loopback_declaration_does_not_carry_a_public_http_host_with_it() {
        let declared = vec![
            "http://127.0.0.1:8787/*".to_string(),
            "http://evil.com/*".to_string(),
        ];
        let matcher = effective_url_matcher(&declared, empty_override());

        assert!(
            matcher.is_allowed("http://127.0.0.1:8787/execute"),
            "the loopback pattern must survive"
        );
        assert!(
            !matcher.is_allowed("http://evil.com/anything"),
            "the loopback opt-in must not carry a public http host through with it"
        );
    }

    /// A bracketed IPv6 loopback `http://[::1]:8787/*` must survive the
    /// loopback filter and allow plain http to `http://[::1]:8787/x`.
    ///
    /// The url crate's `host_str()` returns the bracketed form `"[::1]"` for
    /// both the pattern and the request URL, so the Exact host rule matches.
    /// The bug this test guards against: `http_pattern_host` previously split
    /// on the first `:`, yielding `"["` as the host, which was classified as
    /// non-loopback and dropped.
    #[test]
    fn declared_http_ipv6_loopback_allows_plain_http() {
        let declared = vec!["http://[::1]:8787/*".to_string()];
        let matcher = effective_url_matcher(&declared, empty_override());

        assert!(
            matcher.is_allowed("http://[::1]:8787/x"),
            "declared http IPv6 loopback pattern must permit plain http to [::1]"
        );
        // Must not bleed to arbitrary non-loopback hosts.
        assert!(
            !matcher.is_allowed("http://evil.com/x"),
            "IPv6 loopback opt-in must not permit plain http to non-loopback hosts"
        );
    }

    /// An adversarial pattern `http://[::1].evil.com/*` that tries to smuggle
    /// a non-loopback host inside brackets must be rejected. The url crate
    /// refuses to parse this (it is not a valid bracketed IPv6 literal), so
    /// the pattern is either unparseable (dropped by `UrlMatcher`) or the
    /// resulting host does not match `[::1]` in `is_loopback_host`.
    ///
    /// Either way the request to `http://[::1].evil.com/x` must be denied.
    #[test]
    fn adversarial_fake_ipv6_bracket_host_is_denied() {
        let declared = vec!["http://[::1].evil.com/*".to_string()];
        let matcher = effective_url_matcher(&declared, empty_override());

        // The pattern is malformed: url::Url::parse rejects `[::1].evil.com`
        // as a host, so the pattern is silently dropped and the matcher
        // remains deny-all for this declaration.
        assert!(
            !matcher.is_allowed("http://[::1].evil.com/x"),
            "malformed bracketed host must not be allowed"
        );
        // Real IPv6 loopback must also NOT be granted by a bad pattern.
        assert!(
            !matcher.is_allowed("http://[::1]/x"),
            "bad pattern must not accidentally allow real IPv6 loopback"
        );
    }

    /// Authority-delimiter smuggling. `Url` ends the authority at `?`, `#` or
    /// `\` as well as `/`; the old hand-rolled parser stopped only at `/` and
    /// then took the text after the last `@`, so each of these read as
    /// `localhost` — surviving the drop AND switching the matcher-wide http
    /// toggle on — while the matcher resolved the host to `evil.com`.
    #[test]
    fn a_pattern_that_smuggles_loopback_past_the_authority_is_not_loopback() {
        for pattern in [
            "http://evil.com?@localhost/*",
            "http://evil.com#@localhost/*",
            "http://evil.com\\@localhost/*",
        ] {
            let matcher = effective_url_matcher(&[pattern.to_string()], empty_override());
            assert!(
                !matcher.is_allowed("http://evil.com/anything"),
                "{pattern} must not grant plain http to evil.com"
            );
            assert!(
                !matcher.is_allowed("http://evil.com/@localhost/pwn"),
                "{pattern} must not grant plain http to evil.com"
            );
        }
    }

    /// Scheme spelling and leading whitespace. `strip_prefix("http://")` is a
    /// literal, non-trimming match, so both of these were misclassified as
    /// "not http" and kept verbatim — and once any loopback pattern turned the
    /// toggle on, the matcher honoured them.
    #[test]
    fn an_oddly_spelled_http_pattern_is_still_classified_as_http() {
        for odd in ["HTTP://evil.com/*", " http://evil.com/*"] {
            let declared = vec!["http://127.0.0.1:1/*".to_string(), odd.to_string()];
            let matcher = effective_url_matcher(&declared, empty_override());
            assert!(
                !matcher.is_allowed("http://evil.com/anything"),
                "{odd} must not survive the public-http drop"
            );
        }
    }

    /// `*.localhost` is not loopback: it resolves through the system resolver
    /// like any other name, so a search-domain quirk could point
    /// `evil.localhost` anywhere.
    ///
    /// Declared *alongside* a real loopback pattern on purpose. On its own the
    /// wildcard is denied by the global https gate however it was classified,
    /// so the test would pass even if the classifier waved it through. It is
    /// the real loopback entry that switches the matcher-wide http toggle on,
    /// and only with the toggle on does the wildcard's classification decide
    /// anything.
    #[test]
    fn a_wildcard_localhost_pattern_is_not_treated_as_loopback() {
        let declared = vec![
            "http://127.0.0.1:8787/*".to_string(),
            "http://*.localhost/*".to_string(),
        ];
        let matcher = effective_url_matcher(&declared, empty_override());

        assert!(
            matcher.is_allowed("http://127.0.0.1:8787/x"),
            "the real loopback pattern must still work"
        );
        assert!(
            !matcher.is_allowed("http://evil.localhost/x"),
            "a wildcard under .localhost must not get the loopback exemption"
        );
    }

    /// Any address in `127.0.0.0/8` is loopback, not just the canonical
    /// spelling — and `Url` normalizes `127.1` and `0x7f000001` into it.
    #[test]
    fn other_ipv4_loopback_spellings_are_loopback() {
        for pattern in ["http://127.0.0.2:8787/*", "http://127.1:8787/*"] {
            let matcher = effective_url_matcher(&[pattern.to_string()], empty_override());
            assert!(
                matcher.patterns().iter().any(|p| p == pattern),
                "{pattern} should have been kept as loopback"
            );
        }
    }
}
