//! `Host` impl for the `greentic:oauth-broker/broker-v1` import.
//!
//! Separate from [`crate::host_state_net`] because the WIT returns a bare
//! `string` for every call: the error envelopes below are the whole contract
//! the guest can branch on, and they deserve to be stated in one place.

use crate::host_state::HostState;

/// The oauth-broker WIT returns a bare `string`, so every outcome — including
/// failure — has to be encoded in it. These are the error envelopes the guest
/// can branch on.
const ERR_UNCONFIGURED: &str = r#"{"error":"oauth_broker_unconfigured"}"#;
const ERR_ENCODE_FAILED: &str = r#"{"error":"encode_failed"}"#;
const ERR_BROKER_REQUEST_FAILED: &str = r#"{"error":"broker_request_failed"}"#;
const ERR_NOT_IMPLEMENTED: &str = r#"{"error":"not_implemented"}"#;

impl HostState {
    /// The provider allow-list check every call on this interface must pass.
    ///
    /// Shared rather than inlined once: `get_consent_url` and `exchange_code`
    /// had **no** gate at all. Both return `not_implemented` today, so nothing
    /// leaked — but whoever implements them would have inherited an ungated
    /// path, and the asymmetry was invisible next to a gated `get_token`.
    fn check_provider(&self, provider_id: &str, op: &str) -> Result<(), String> {
        if self
            .permissions
            .oauth_providers
            .iter()
            .any(|p| p == provider_id)
        {
            return Ok(());
        }
        tracing::warn!(
            ext = %self.extension_id,
            provider = %provider_id,
            op,
            "oauth permission denied"
        );
        Err(serde_json::json!({"error": "permission_denied", "provider": provider_id}).to_string())
    }
}

impl crate::host_bindings::design_v04::greentic::oauth_broker::broker_v1::Host for HostState {
    /// Retrieve a token for the given OAuth provider.
    ///
    /// Permission gate: the provider must be declared in
    /// `permissions.oauth_providers`. If not, returns a JSON error string with
    /// `"error": "permission_denied"` — fails closed.
    ///
    /// When permitted but no `oauth_config` or `http_client` is present (e.g.
    /// the runtime was not configured with an OAuth broker), returns
    /// `"error": "oauth_broker_unconfigured"`.
    ///
    /// The `shared_secret` is NEVER logged.
    fn get_token(&mut self, provider_id: String, _subject: String, scopes: Vec<String>) -> String {
        if let Err(denied) = self.check_provider(&provider_id, "get-token") {
            return denied;
        }

        let (Some(cfg), Some(client)) = (self.oauth_config.clone(), self.http_client.clone())
        else {
            return ERR_UNCONFIGURED.to_string();
        };

        let req = crate::oauth::ResourceTokenRequest {
            http_base_url: cfg.http_base_url,
            env: cfg.env,
            tenant: cfg.tenant,
            team: cfg.team,
            resource_id: provider_id.clone(),
            scopes,
        };

        match crate::oauth::request_resource_token_blocking(
            &client,
            &req,
            cfg.shared_secret.as_deref(),
            self.http_timeout,
        ) {
            Ok(resp) => {
                serde_json::to_string(&resp).unwrap_or_else(|_| ERR_ENCODE_FAILED.to_string())
            }
            Err(e) => {
                tracing::warn!(provider = %provider_id, error = %e, "oauth get-token failed");
                ERR_BROKER_REQUEST_FAILED.to_string()
            }
        }
    }

    /// Build a consent URL for the given OAuth provider.
    ///
    /// Not implemented in the design-extension runtime: consent flows are
    /// driven by the OAuth broker service directly. Returns the
    /// `not_implemented` envelope rather than an empty string — an empty
    /// string is a *valid* URL-shaped answer as far as the guest can tell, so
    /// returning one turned "this host cannot do that" into a silent failure
    /// the extension had no way to detect.
    fn get_consent_url(
        &mut self,
        provider_id: String,
        _subject: String,
        _scopes: Vec<String>,
        _redirect_path: String,
        _extra_json: String,
    ) -> String {
        if let Err(denied) = self.check_provider(&provider_id, "get-consent-url") {
            return denied;
        }
        ERR_NOT_IMPLEMENTED.to_string()
    }

    /// Exchange an authorization code for a token set.
    ///
    /// Not implemented here for the same reason as [`Self::get_consent_url`],
    /// and reports itself the same way rather than returning an empty string.
    fn exchange_code(
        &mut self,
        provider_id: String,
        _subject: String,
        _code: String,
        _redirect_path: String,
    ) -> String {
        if let Err(denied) = self.check_provider(&provider_id, "exchange-code") {
            return denied;
        }
        ERR_NOT_IMPLEMENTED.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_bindings::design_v04::greentic::oauth_broker::broker_v1::Host as OAuthHost;
    use greentic_extension_sdk_contract::describe::Permissions;

    #[test]
    fn oauth_get_token_denied_when_provider_not_declared() {
        let mut h = HostState::builder("ext".into(), Permissions::default()).build();
        let out = h.get_token("hubspot".into(), String::new(), vec![]);
        assert!(out.contains("permission_denied"), "got: {out}");
    }

    #[test]
    fn oauth_get_token_errors_when_unconfigured() {
        let mut perms = Permissions::default();
        perms.oauth_providers.push("hubspot".into());
        let mut h = HostState::builder("ext".into(), perms).build();
        let out = h.get_token("hubspot".into(), String::new(), vec![]);
        assert!(out.contains("oauth_broker_unconfigured"), "got: {out}");
    }

    #[test]
    fn unimplemented_oauth_calls_report_themselves_instead_of_returning_empty() {
        // An empty string reads as a successful (if odd) answer on the guest
        // side; the guest has to be able to tell "not implemented" apart from
        // "here is your consent URL".
        let mut perms = Permissions::default();
        perms.oauth_providers.push("hubspot".into());
        let mut h = HostState::builder("ext".into(), perms).build();

        let consent = h.get_consent_url(
            "hubspot".into(),
            String::new(),
            vec![],
            "/cb".into(),
            "{}".into(),
        );
        assert!(consent.contains("not_implemented"), "got: {consent}");

        let exchanged =
            h.exchange_code("hubspot".into(), String::new(), "code".into(), "/cb".into());
        assert!(exchanged.contains("not_implemented"), "got: {exchanged}");
    }

    #[test]
    fn every_call_on_this_interface_is_permission_gated() {
        // `get_consent_url` and `exchange_code` had no gate at all. Both return
        // `not_implemented`, so nothing leaked — but whoever implements them
        // would have inherited an ungated path, and the asymmetry was invisible
        // next to a gated `get_token`.
        let mut h = HostState::builder("ext".into(), Permissions::default()).build();

        for out in [
            h.get_token("hubspot".into(), String::new(), vec![]),
            h.get_consent_url(
                "hubspot".into(),
                String::new(),
                vec![],
                "/cb".into(),
                "{}".into(),
            ),
            h.exchange_code("hubspot".into(), String::new(), "code".into(), "/cb".into()),
        ] {
            assert!(
                out.contains("permission_denied"),
                "an undeclared provider must be refused on every call: {out}"
            );
        }
    }
}
