//! OAuth broker HTTP client for the design-extension runtime.
//!
//! Ported from `greentic-runner` `greentic-runner-host/src/oauth.rs`. The broker
//! service performs token refresh; this client just relays a `resource-token`
//! request and returns the (already-fresh) access token.

use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration the host supplies so the extension runtime can reach the OAuth broker.
#[derive(Clone, Default)]
pub struct OAuthBrokerConfig {
    pub http_base_url: String,
    pub env: String,
    pub tenant: String,
    pub team: Option<String>,
    /// Bearer credential authenticating this host to the broker.
    ///
    /// Never rendered by [`std::fmt::Debug`] — see the manual impl below.
    pub shared_secret: Option<String>,
}

impl std::fmt::Debug for OAuthBrokerConfig {
    /// Redacts `shared_secret`. A derived `Debug` put the broker credential
    /// into every `{:?}` of this struct — and of anything holding it — so one
    /// debug log of a runtime config was enough to leak it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthBrokerConfig")
            .field("http_base_url", &self.http_base_url)
            .field("env", &self.env)
            .field("tenant", &self.tenant)
            .field("team", &self.team)
            .field(
                "shared_secret",
                &self.shared_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResourceTokenRequest {
    pub http_base_url: String,
    pub env: String,
    pub tenant: String,
    pub team: Option<String>,
    pub resource_id: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResourceTokenResponse {
    pub access_token: String,
    pub expires_at: u64,
}

impl std::fmt::Debug for ResourceTokenResponse {
    /// Redacts `access_token` for the same reason as [`OAuthBrokerConfig`]:
    /// this type crosses error and tracing paths, and a bearer token that
    /// reaches a log is a bearer token that has to be rotated.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceTokenResponse")
            .field("access_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// POST `{http_base_url}/resource-token` and return the resolved access token.
///
/// The broker refreshes the token if needed; the shared secret (when present)
/// authenticates this host→broker call and is never logged or returned.
pub fn request_resource_token_blocking(
    client: &reqwest::blocking::Client,
    request: &ResourceTokenRequest,
    shared_secret: Option<&str>,
    timeout: std::time::Duration,
) -> anyhow::Result<ResourceTokenResponse> {
    let mut base = Url::parse(&request.http_base_url)?;
    let is_local = base.host_str() == Some("127.0.0.1") || base.host_str() == Some("localhost");
    anyhow::ensure!(
        base.scheme() == "https" || is_local,
        "oauth broker http_base_url must be https"
    );
    anyhow::ensure!(
        base.query().is_none(),
        "oauth broker http_base_url must not carry a query"
    );
    // `Url::join` treats the last path segment as a file and replaces it, so
    // `https://broker/api` would post to `https://broker/resource-token` and
    // silently drop the deployment's base path. Anchor the base at a directory
    // first so the endpoint always appends.
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    let url = base.join("resource-token")?;
    // Same reason as `host.http.fetch`: this runs on the dispatch thread, and
    // the wasm deadline cannot interrupt a blocking host call.
    let mut rb = client.post(url).timeout(timeout).json(request);
    if let Some(secret) = shared_secret {
        rb = rb.bearer_auth(secret);
    }
    let response = rb.send()?.error_for_status()?;
    Ok(response.json()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_token_request_serializes_expected_shape() {
        let req = ResourceTokenRequest {
            http_base_url: "https://oauth.example/".into(),
            env: "dev".into(),
            tenant: "acme".into(),
            team: None,
            resource_id: "hubspot".into(),
            scopes: vec!["crm.objects.contacts.read".into()],
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["resource_id"], "hubspot");
        assert_eq!(v["tenant"], "acme");
        assert_eq!(v["scopes"][0], "crm.objects.contacts.read");
    }

    #[test]
    fn debug_never_renders_the_shared_secret() {
        let cfg = OAuthBrokerConfig {
            http_base_url: "https://oauth.example/".into(),
            env: "prod".into(),
            tenant: "acme".into(),
            team: None,
            shared_secret: Some("super-secret-value".into()),
        };
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("super-secret-value"),
            "the broker credential must never reach a debug log: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // The non-secret fields stay legible so the struct is still debuggable.
        assert!(rendered.contains("acme"), "{rendered}");
    }

    #[test]
    fn debug_never_renders_the_access_token() {
        let resp = ResourceTokenResponse {
            access_token: "ya29.super-secret-bearer".into(),
            expires_at: 123,
        };
        let rendered = format!("{resp:?}");
        assert!(
            !rendered.contains("ya29.super-secret-bearer"),
            "a bearer token that reaches a log has to be rotated: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("123"), "{rendered}");
    }

    #[test]
    fn a_base_url_with_a_path_keeps_it_when_the_endpoint_is_appended() {
        // `Url::join` treats the last path segment as a file and replaces it,
        // so `https://broker/api` posted to `https://broker/resource-token` and
        // silently dropped the deployment's base path.
        let base = url::Url::parse("https://broker.example/api").unwrap();
        let mut anchored = base.clone();
        anchored.set_path(&format!("{}/", base.path()));
        assert_eq!(
            anchored.join("resource-token").unwrap().as_str(),
            "https://broker.example/api/resource-token"
        );
    }

    #[test]
    fn resource_token_response_deserializes() {
        let r: ResourceTokenResponse =
            serde_json::from_str(r#"{"access_token":"tok","expires_at":123}"#).unwrap();
        assert_eq!(r.access_token, "tok");
        assert_eq!(r.expires_at, 123);
    }
}
