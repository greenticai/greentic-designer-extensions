//! Per-extension network permission resolution.
//!
//! Split out of [`crate::loaded`]: deciding which URLs an extension may reach
//! is its own concern with its own adversarial edge cases (loopback spellings,
//! bracketed IPv6, plain-http downgrade), and it earns the room to state them.

/// Select the URL matcher for a single extension instantiation.
///
/// **Narrowing semantics:** the extension's `runtime.permissions.network`
/// patterns say what it wants; the host-level `override_matcher`, when the
/// operator sets one, says what it may have. The effective list is their
/// intersection — a declared pattern the operator's list does not contain is
/// dropped.
///
/// When the operator sets no list at all, the declared patterns stand on their
/// own. That is deliberate and load-bearing: the default `override_matcher` is
/// empty (deny-all), so intersecting against it unconditionally would hand
/// every extension that declares anything an empty allow-list.
///
/// This used to be *replace* semantics — declared patterns won outright and the
/// operator's list was ignored. Combined with TOFU, which lets a first-seen
/// pack self-sign, an extension self-granted its own network reach with nothing
/// above it to say otherwise.
///
/// When the declaration is empty the host-level override is returned
/// unchanged, which is the deny-all default in most deployments. This
/// preserves existing behavior for extensions that do not need outbound HTTP.
///
/// # Loopback-http rule
///
/// [`UrlMatcher`] rejects non-`https` URLs by default (scheme-downgrade
/// defence) and only honours plain `http` when `with_allow_http(true)` is
/// set. That toggle is **matcher-wide** — it cannot be scoped to a single
/// pattern. To let an extension talk to a local dev service over
/// `http://127.0.0.1` / `http://localhost` WITHOUT also opening plain http
/// to public hosts, we:
///
/// 1. drop any declared `http://` pattern whose host is NOT loopback (it
///    could never be safely honoured — a public-host plain-http downgrade
///    is exactly the attack the matcher defends against), and
/// 2. enable `with_allow_http(true)` only when at least one *loopback*
///    `http://` pattern survives.
///
/// Because the matcher matches scheme exactly per declared pattern, a
/// co-declared `https://host/*` pattern still requires `https` even when
/// the toggle is on — the toggle only decides whether `http` patterns are
/// consulted at all, and after step 1 the only surviving `http` patterns
/// are loopback.
///
/// # Arguments
///
/// * `declared_patterns` — the `runtime.permissions.network` slice from
///   the extension's parsed `describe.json`.
/// * `override_matcher` — the host-level matcher supplied via
///   [`HostOverrides`]. Used only when `declared_patterns` is empty.
///
/// # Returns
///
/// A [`UrlMatcher`] that enforces the correct allow-list for this extension.
pub(crate) fn effective_url_matcher(
    declared_patterns: &[String],
    override_matcher: crate::url_matcher::UrlMatcher,
) -> crate::url_matcher::UrlMatcher {
    if declared_patterns.is_empty() {
        return override_matcher;
    }

    // The operator's list, when they set one, is a **ceiling**: a declared
    // pattern the operator did not allow is dropped, not honoured. Replacing it
    // outright let an extension grant itself any host it liked — its own
    // describe was the only thing consulted, and TOFU makes a self-signed pack
    // trivial on first load.
    //
    // Only when the operator sets NO ceiling do declared patterns stand alone.
    // That case must keep working: the default override is deny-all, so
    // intersecting against it unconditionally would give every extension that
    // declares anything an empty allow-list.
    let ceiling: Option<Vec<String>> = if override_matcher.patterns().is_empty() {
        None
    } else {
        Some(override_matcher.patterns().to_vec())
    };

    let mut patterns: Vec<String> = declared_patterns
        .iter()
        .filter(|p| match &ceiling {
            None => true,
            Some(allowed) => {
                let within = allowed.iter().any(|a| a == *p);
                if !within {
                    tracing::warn!(
                        pattern = %p,
                        "dropping a declared url pattern the host allow-list does not contain; \
                         the operator's list is a ceiling, not a default"
                    );
                }
                within
            }
        })
        .cloned()
        .collect();

    // Loopback-http handling: keep loopback http patterns, drop public-host
    // http patterns (they can never be honoured safely), and record whether
    // any loopback http pattern remains so we can flip the matcher-wide
    // allow_http toggle.
    let mut allow_loopback_http = false;
    patterns.retain(|p| match crate::http_scheme_policy::classify(p) {
        crate::http_scheme_policy::HttpClass::Loopback => {
            allow_loopback_http = true;
            true
        }
        crate::http_scheme_policy::HttpClass::Public => {
            tracing::warn!(
                pattern = %p,
                "dropping non-loopback http url pattern; plain http is only honoured for loopback hosts"
            );
            false
        }
        // https (or any non-http) pattern — kept verbatim; UrlMatcher
        // validates it on construction.
        crate::http_scheme_policy::HttpClass::Other => true,
    });

    crate::url_matcher::UrlMatcher::from_patterns(patterns).with_allow_http(allow_loopback_http)
}

/// Return the host portion of a `http://` pattern, or `None` when the
/// pattern is not plain http. The leading `*.` wildcard label (e.g.
/// `http://*.example.com/*`) is stripped so the remaining host can be
/// classified; a bare wildcard host is treated as non-loopback.
///
/// Bracketed IPv6 literals (e.g. `[::1]` in `http://[::1]:8787/*`) are
/// returned with their brackets intact so that `is_loopback_host` can strip
/// them: splitting on the first `:` would otherwise yield the bare `"["`
/// opener and misclassify `[::1]` as non-loopback.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::url_matcher::UrlMatcher;

    fn empty_override() -> UrlMatcher {
        UrlMatcher::default()
    }

    fn override_with_pattern(pattern: &str) -> UrlMatcher {
        UrlMatcher::from_patterns(vec![pattern.to_string()])
    }

    /// Extensions that declare network patterns must have exactly those
    /// patterns enforced — the host-level override must NOT apply.
    #[test]
    fn declared_patterns_allow_declared_host_and_deny_undeclared() {
        let declared = vec!["https://api.github.com/*".to_string()];
        let matcher = effective_url_matcher(&declared, empty_override());

        assert!(
            matcher.is_allowed("https://api.github.com/repos/org/repo"),
            "declared host must be allowed"
        );
        assert!(
            !matcher.is_allowed("https://evil.com/"),
            "undeclared host must be denied even though host override is empty"
        );
    }

    /// When no network patterns are declared the host-level override is
    /// returned verbatim — behavior is unchanged for legacy extensions.
    #[test]
    fn empty_declaration_falls_back_to_host_override() {
        let override_matcher = override_with_pattern("https://allowed.com/*");
        let matcher = effective_url_matcher(&[], override_matcher);

        assert!(
            matcher.is_allowed("https://allowed.com/path"),
            "host-override host must be reachable when declare is empty"
        );
        assert!(
            !matcher.is_allowed("https://other.com/path"),
            "host-override deny must still apply"
        );
    }

    /// The operator's list is a ceiling, not a default.
    ///
    /// Under the old replace semantics this host was reachable: the extension's
    /// own describe was the only thing consulted, which — with TOFU making a
    /// self-signed pack trivial — is an extension granting itself network reach
    /// the operator never approved.
    #[test]
    fn a_declared_pattern_outside_the_operator_ceiling_is_dropped() {
        let declared = vec!["https://api.github.com/*".to_string()];
        let override_matcher = override_with_pattern("https://operator-allowed.com/*");
        let matcher = effective_url_matcher(&declared, override_matcher);

        assert!(
            !matcher.is_allowed("https://api.github.com/repos/org/repo"),
            "a declared host outside the operator ceiling must not be reachable"
        );
        assert!(
            !matcher.is_allowed("https://operator-allowed.com/anything"),
            "and the ceiling is not itself a grant — the extension never asked for this host"
        );
    }

    /// The intersection, not just the exclusion: what both sides name survives.
    #[test]
    fn a_declared_pattern_inside_the_operator_ceiling_survives() {
        let declared = vec![
            "https://api.github.com/*".to_string(),
            "https://evil.com/*".to_string(),
        ];
        let override_matcher = UrlMatcher::from_patterns(vec![
            "https://api.github.com/*".to_string(),
            "https://unused.example/*".to_string(),
        ]);
        let matcher = effective_url_matcher(&declared, override_matcher);

        assert!(
            matcher.is_allowed("https://api.github.com/repos/org/repo"),
            "a pattern both sides name must survive"
        );
        assert!(
            !matcher.is_allowed("https://evil.com/x"),
            "one the operator did not name must not"
        );
        assert!(
            !matcher.is_allowed("https://unused.example/x"),
            "and one the extension did not declare must not either"
        );
    }

    /// Empty declaration + empty host override must deny every URL —
    /// this is the default deny-all posture for extensions that never
    /// call the network.
    #[test]
    fn empty_declaration_and_empty_override_denies_everything() {
        let matcher = effective_url_matcher(&[], empty_override());

        assert!(
            !matcher.is_allowed("https://api.github.com/anything"),
            "empty declaration + empty override must produce deny-all matcher"
        );
    }
}
