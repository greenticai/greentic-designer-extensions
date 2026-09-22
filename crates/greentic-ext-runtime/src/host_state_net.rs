//! `Host` impls for the network-facing host interfaces: http and llm.
//!
//! Split out of [`crate::host_state`]; the local impls (logging, i18n, secrets,
//! broker) live in [`crate::host_state_ports`] and the oauth-broker impl in
//! [`crate::host_state_oauth`].

use std::io::Read;

use crate::host_bindings::greentic::extension_host::http;
use crate::host_state::HostState;

/// Maximum response body the host will hand back to a guest, in bytes.
///
/// `Response::bytes()` buffers the whole body with no ceiling, so an allowed
/// endpoint serving an endless stream could exhaust host memory — the guest
/// does not even have to be malicious, only pointed at the wrong URL. 32 MiB is
/// far above any real design-extension payload (schemas, card JSON, small
/// assets) and far below anything that threatens the process.
const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

/// Render a URL for logging with its credential-bearing parts removed.
///
/// Query strings routinely carry `?api_key=`, `?access_token=`, presigned SAS
/// tokens and OAuth `?code=`, and userinfo carries a password outright. The
/// denial log below is the sharp case: it fires *because* the URL was rejected,
/// which is to say on attacker-influenced input.
fn loggable(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            u.set_query(None);
            u.set_fragment(None);
            let _ = u.set_password(None);
            let _ = u.set_username("");
            u.to_string()
        }
        // Unparseable: the matcher rejected it anyway, and echoing it back into
        // a log is not worth the chance that it is a credential-bearing string.
        Err(_) => "<unparseable url>".to_string(),
    }
}

/// How many redirects `fetch` will follow before giving up.
///
/// Matches reqwest's own default so behaviour does not change for a client that
/// follows them itself.
const MAX_REDIRECT_HOPS: usize = 10;

/// Hop-by-hop and framing headers a guest must not set.
///
/// The guest picks its own headers, which is the point — but `Host` chooses the
/// vhost behind a shared reverse proxy, and the framing headers let it argue
/// with hyper about where the body ends.
const FORBIDDEN_REQUEST_HEADERS: [&str; 6] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "expect",
];

/// The `Location` of a redirect response, resolved against the request URL.
fn redirect_target(resp: &reqwest::blocking::Response) -> Option<url::Url> {
    if !resp.status().is_redirection() {
        return None;
    }
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)?
        .to_str()
        .ok()?;
    resp.url().join(location).ok()
}

impl HostState {
    /// Issue exactly one request, with no redirect following of our own.
    fn send_once(
        &self,
        client: &reqwest::blocking::Client,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::blocking::Response, String> {
        let mut builder = client.request(method, url);
        for (k, v) in headers {
            if FORBIDDEN_REQUEST_HEADERS
                .iter()
                .any(|h| k.eq_ignore_ascii_case(h))
            {
                tracing::debug!(
                    ext = %self.extension_id,
                    header = %k,
                    "dropping a guest-set hop-by-hop or framing header"
                );
                continue;
            }
            builder = builder.header(k.as_str(), v.as_str());
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }
        // The wasm deadline is evaluated only by running wasm, so it cannot
        // fire while this thread is parked in `send()`. Without a per-request
        // timeout a stalled server holds the dispatch thread indefinitely and
        // nothing can interrupt it — so the bound has to be set here, by the
        // runtime, rather than left to whatever client the embedder supplied.
        builder.timeout(self.http_timeout).send().map_err(|e| {
            tracing::error!(ext = %self.extension_id, error = %e, "http::fetch transport error");
            format!("http transport error: {e}")
        })
    }
}

impl http::Host for HostState {
    fn fetch(&mut self, req: http::Request) -> Result<http::Response, String> {
        // 1. Permission check via strict UrlMatcher.
        if !self.url_matcher.is_allowed(&req.url) {
            tracing::warn!(
                ext = %self.extension_id,
                url = %loggable(&req.url),
                "http::fetch permission denied"
            );
            return Err(format!("network not allowed for url: {}", req.url));
        }

        // 2. Build the reqwest request. `http_client` is `None` when the
        //    host wasn't given one (typical for unit tests). Surface a
        //    clean error rather than panic, and don't lazy-construct a
        //    client here — see `HostOverrides` doc comment.
        let client = self
            .http_client
            .as_ref()
            .ok_or_else(|| "http client not configured for this runtime".to_string())?;
        let method = match req.method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            "HEAD" => reqwest::Method::HEAD,
            other => return Err(format!("unsupported http method: {other}")),
        };
        // 3. Follow redirects ourselves, re-checking the allow-list at every
        //    hop. The previous shape checked only `resp.url()` — where the
        //    chain *ended* — which withholds the response but cannot withhold
        //    the request: every intermediate hop had already gone out, and
        //    307/308 preserve method and body, so an allow-listed host with an
        //    open redirect became a launcher for guest-chosen POST/PUT/DELETE
        //    into loopback and metadata endpoints. Checking before each hop is
        //    the only placement that stops the write from happening.
        //
        //    This is complete only when the client does not follow redirects on
        //    its own — see `HostStateBuilder::http_client`. When it does, we
        //    never see the 3xx, so the end-of-chain check below stays as the
        //    fallback for that case.
        let mut url = req.url.clone();
        let mut resp =
            self.send_once(client, method.clone(), &url, &req.headers, req.body.clone())?;

        for _ in 0..MAX_REDIRECT_HOPS {
            let Some(next) = redirect_target(&resp) else {
                break;
            };
            if !self.url_matcher.is_allowed(next.as_str()) {
                tracing::warn!(
                    ext = %self.extension_id,
                    from = %loggable(&url),
                    to = %loggable(next.as_str()),
                    "http::fetch refused a redirect off the allow-list"
                );
                return Err(format!(
                    "network not allowed for redirect target: {}",
                    loggable(next.as_str())
                ));
            }
            url = next.to_string();
            resp = self.send_once(client, method.clone(), &url, &req.headers, req.body.clone())?;
        }

        // 4. Fallback for a client that followed redirects itself: re-check
        //    where it landed. This withholds the response but cannot unsend the
        //    hops, which is why the loop above exists.
        let final_url = resp.url().clone();
        if final_url.as_str() != url && !self.url_matcher.is_allowed(final_url.as_str()) {
            tracing::warn!(
                ext = %self.extension_id,
                requested = %loggable(&req.url),
                final_url = %loggable(final_url.as_str()),
                "http::fetch redirected off the allow-list; response withheld"
            );
            return Err(format!(
                "network not allowed for redirect target: {}",
                loggable(final_url.as_str())
            ));
        }

        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            // The WIT response type is `list<tuple<string, string>>`, so a
            // header whose bytes are not valid UTF-8 has no representation to
            // hand the guest. Dropping it is the only faithful option — this is
            // a limit of the contract, not a failure of the request.
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();

        // 5. Read the body under a ceiling. Reading one byte past the cap is
        //    what distinguishes "exactly at the limit" from "truncated", so an
        //    oversized body is rejected rather than silently cut short.
        let mut body = Vec::new();
        resp.take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("http body error: {e}"))?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            tracing::warn!(
                ext = %self.extension_id,
                url = %loggable(&req.url),
                cap = MAX_RESPONSE_BYTES,
                "http::fetch response exceeded the body cap"
            );
            return Err(format!(
                "http response body exceeds the {MAX_RESPONSE_BYTES} byte cap"
            ));
        }

        Ok(http::Response {
            status,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_bindings::greentic::extension_host::http::{Host as HttpHost, Request};
    use greentic_extension_sdk_contract::describe::Permissions;

    #[test]
    fn loggable_strips_the_credential_bearing_parts_of_a_url() {
        // The denial log fires *because* the URL was rejected, i.e. on
        // attacker-influenced input. Query strings routinely carry `?api_key=`,
        // presigned SAS tokens and OAuth `?code=`; userinfo carries a password
        // outright.
        let rendered = loggable("https://user:hunter2@api.example.com/v1?api_key=sk-secret#frag");
        assert!(!rendered.contains("hunter2"), "password leaked: {rendered}");
        assert!(
            !rendered.contains("sk-secret"),
            "query secret leaked: {rendered}"
        );
        assert!(!rendered.contains("frag"), "fragment leaked: {rendered}");
        assert!(!rendered.contains("user"), "username leaked: {rendered}");
        // The parts that make the log useful survive.
        assert!(rendered.contains("api.example.com"), "{rendered}");
        assert!(rendered.contains("/v1"), "{rendered}");
    }

    #[test]
    fn loggable_refuses_to_echo_an_unparseable_url() {
        assert_eq!(loggable("not a url at all"), "<unparseable url>");
    }

    #[test]
    fn http_fetch_denied_when_url_not_in_matcher() {
        let mut h = HostState::builder("test-ext".into(), Permissions::default())
            .url_matcher(crate::url_matcher::UrlMatcher::from_patterns(vec![
                "https://allowed.com/*".into(),
            ]))
            .build();
        let req = Request {
            method: "GET".into(),
            url: "https://evil.com/".into(),
            headers: vec![],
            body: None,
        };
        let err = h.fetch(req).unwrap_err();
        assert!(
            err.contains("not allowed") || err.contains("permission denied"),
            "got: {err}"
        );
    }

    #[test]
    fn http_fetch_without_a_client_reports_it_rather_than_panicking() {
        let mut h = HostState::builder("test-ext".into(), Permissions::default())
            .url_matcher(crate::url_matcher::UrlMatcher::from_patterns(vec![
                "https://allowed.com/*".into(),
            ]))
            .build();
        let req = Request {
            method: "GET".into(),
            url: "https://allowed.com/x".into(),
            headers: vec![],
            body: None,
        };
        let err = h.fetch(req).unwrap_err();
        assert!(err.contains("http client not configured"), "got: {err}");
    }
}
