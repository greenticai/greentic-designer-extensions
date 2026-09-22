//! Strict URL allow-list matcher.
//!
//! The matcher parses both the pattern and the request URL with
//! `url::Url`, then compares four orthogonal facets:
//!
//! 1. **Scheme** — exact match; we additionally reject non-`https://`
//!    by default to defend against scheme-downgrade attacks. (Operators
//!    can opt into `http` by calling `with_allow_http(true)`.)
//! 2. **Host** — either exact match or `*.<suffix>` wildcard. The
//!    wildcard requires at least one label (so `*.example.com` does
//!    NOT match `example.com`). Substring matches are explicitly
//!    rejected — the test suite pins both the "subdomain confusion"
//!    (`evil.com.allowed.com`) and the "open-redirect via query
//!    string" cases.
//! 3. **Port** — exact match against the pattern's port, with each
//!    scheme's default filled in when either side omits it (so
//!    `https://h/*` and `https://h:443/*` are the same rule). A pattern
//!    that names a port grants *only* that port: `http://127.0.0.1:8787/*`
//!    must not reach `http://127.0.0.1:9200/*`. Loopback makes this
//!    load-bearing — every local service shares the host, so without a
//!    port comparison one declared dev port is a pass to all of them.
//! 4. **Path** — segment-boundary prefix match against `pattern.path`
//!    with the trailing `*` stripped. `/v1/*` matches `/v1/chat/completions`
//!    and `/v1` itself, but NOT `/v1evil` — a raw `starts_with` would let
//!    a neighbouring path smuggle itself past a narrow grant. A bare
//!    pattern path of `/` matches any path.

use url::Url;

#[derive(Debug, Clone, Default)]
pub struct UrlMatcher {
    patterns: Vec<ParsedPattern>,
    raw: Vec<String>,
    allow_http: bool,
}

#[derive(Debug, Clone)]
struct ParsedPattern {
    scheme: String,
    host_rule: HostRule,
    /// Effective port: the pattern's explicit port, else the scheme default.
    /// `None` only for schemes `url` knows no default for.
    port: Option<u16>,
    path_prefix: String,
}

#[derive(Debug, Clone)]
enum HostRule {
    Exact(String),
    /// `*.example.com` — matches any host that ends with `.example.com`.
    WildcardSuffix(String),
}

impl UrlMatcher {
    #[must_use]
    pub fn from_patterns(patterns: Vec<String>) -> Self {
        let mut parsed = Vec::with_capacity(patterns.len());
        for p in &patterns {
            if let Some(pp) = Self::parse_pattern(p) {
                parsed.push(pp);
            } else {
                tracing::warn!(pattern = %p, "unparseable url pattern; ignoring");
            }
        }
        Self {
            patterns: parsed,
            raw: patterns,
            allow_http: false,
        }
    }

    #[must_use]
    pub fn with_allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.raw
    }

    fn parse_pattern(pattern: &str) -> Option<ParsedPattern> {
        let stripped = pattern.trim_end_matches("/*");
        let (placeholder_used, normalized) = if let Some(rest) = stripped.strip_prefix("https://*.")
        {
            (true, format!("https://__wildcard__.{rest}"))
        } else if let Some(rest) = stripped.strip_prefix("http://*.") {
            (true, format!("http://__wildcard__.{rest}"))
        } else {
            (false, stripped.to_string())
        };
        let parsed = Url::parse(&normalized).ok()?;
        let host_str = parsed.host_str()?.to_string();
        let host_rule = if placeholder_used {
            let suffix = host_str.strip_prefix("__wildcard__.")?.to_string();
            HostRule::WildcardSuffix(suffix)
        } else {
            HostRule::Exact(host_str)
        };
        let path_prefix = if parsed.path().is_empty() || parsed.path() == "/" {
            "/".to_string()
        } else {
            parsed.path().to_string()
        };
        Some(ParsedPattern {
            scheme: parsed.scheme().to_string(),
            host_rule,
            port: parsed.port_or_known_default(),
            path_prefix,
        })
    }

    #[must_use]
    pub fn is_allowed(&self, url: &str) -> bool {
        let Ok(parsed) = Url::parse(url) else {
            return false;
        };
        // `allow_http` opts in to *http*, not to "anything that is not https".
        // Treating it as the latter let `file://` and `ftp://` reach pattern
        // matching the moment any loopback-http pattern flipped the toggle.
        // Unreachable through `fetch` today because reqwest refuses those
        // schemes — but this is public API with a public accessor, and the
        // module doc promises the opposite.
        let scheme_allowed =
            parsed.scheme() == "https" || (self.allow_http && parsed.scheme() == "http");
        if !scheme_allowed {
            return false;
        }
        let Some(host) = parsed.host_str() else {
            return false;
        };
        let port = parsed.port_or_known_default();
        let path = parsed.path();
        // `url` decodes and normalizes `..`, but leaves `%2f` and `%5c` encoded
        // — and a server that decodes them before routing resolves
        // `/v1/..%2f..%2fadmin` to `/admin`, walking straight out of a narrow
        // path grant. An encoded separator has no legitimate use in a path we
        // are about to prefix-match, so it is refused rather than guessed at.
        if contains_encoded_separator(path) {
            return false;
        }
        self.patterns
            .iter()
            .any(|pat| pat.matches(parsed.scheme(), host, port, path))
    }
}

/// Does `path` carry a percent-encoded `/` or `\`?
fn contains_encoded_separator(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.windows(3).any(|w| {
        w[0] == b'%'
            && matches!(
                (w[1].to_ascii_lowercase(), w[2].to_ascii_lowercase()),
                (b'2', b'f') | (b'5', b'c')
            )
    })
}

impl ParsedPattern {
    /// All four facets must agree. Every early return is a denial, so an
    /// unhandled shape falls through to "not allowed" rather than to a grant.
    fn matches(&self, scheme: &str, host: &str, port: Option<u16>, path: &str) -> bool {
        self.scheme == scheme
            && self.port == port
            && self.host_matches(host)
            && self.path_covers(path)
    }

    fn host_matches(&self, host: &str) -> bool {
        match &self.host_rule {
            HostRule::Exact(h) => h.eq_ignore_ascii_case(host),
            HostRule::WildcardSuffix(suffix) => {
                let lower_host = host.to_ascii_lowercase();
                let lower_suffix = suffix.to_ascii_lowercase();
                let Some(prefix) = lower_host.strip_suffix(&lower_suffix) else {
                    return false;
                };
                // `*.example.com` requires at least one leading label, so the
                // remainder must be a non-empty run ending in the separating
                // dot. This is what keeps `evil.com.example.com` from reading
                // as a bare-suffix match and `example.com` from matching at all.
                prefix.ends_with('.') && prefix.len() > 1
            }
        }
    }

    /// Segment-boundary prefix match: `/v1` covers `/v1` and `/v1/chat`, but
    /// never `/v1evil`. A `/` prefix covers everything.
    fn path_covers(&self, path: &str) -> bool {
        if self.path_prefix == "/" {
            return true;
        }
        let Some(rest) = path.strip_prefix(&self.path_prefix) else {
            return false;
        };
        rest.is_empty() || rest.starts_with('/')
    }
}
