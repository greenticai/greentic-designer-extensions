//! What a hosting provider declares about itself, and the hash that binds an
//! admin approval to it.
//!
//! The declaration is returned by the guest's pure `describe-provider` export,
//! not by a new `describe.json` key: `DescribeJson` and every type under it is
//! `deny_unknown_fields`, so a new key unloads the extension on every reader
//! that predates it (see `docs/hosting-provider-world.md`, "Kind versus
//! capability"). The strings in the WIT descriptor are parsed here and nowhere
//! else, and parsing is strict on purpose: this surface decides where a
//! credential may be sent, so an unknown field makes the declaration invalid
//! rather than being ignored.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::endpoint::{ActionRule, validate_host_template};
use super::error::DeclarationError;

/// The capability a hosting extension offers in `describe.json`
/// (`capabilities.offered[].id`). An existing field, so older readers parse the
/// describe unchanged.
pub const HOSTING_PROVIDER_CAPABILITY: &str = "cap://hosting/provider";

/// Auth profiles the host implements. Closed: adding one is a host release,
/// because it is protocol code that touches credentials.
pub const KNOWN_PROFILES: &[&str] = &[
    "aws-sigv4",
    "gcp-oauth-sa",
    "bearer",
    "k8s-token",
    "mtls",
    "none",
];

const MAX_ENDPOINTS: usize = 32;
const MAX_ACTIONS_PER_ENDPOINT: usize = 128;
const MAX_FIELD_BYTES: usize = 64 * 1024;

/// The descriptor exactly as the guest returned it: strings.
#[derive(Debug, Clone)]
pub struct RawDescriptor {
    pub id: String,
    pub display_name: String,
    pub settings_schema: String,
    pub credential_schema: String,
    pub endpoints: String,
    pub capabilities: String,
    pub ref_prefix: String,
}

/// How an endpoint authenticates. `id` is one of [`KNOWN_PROFILES`]; the other
/// keys are profile parameters (`service`, `scopes`, ...) the host's profile
/// implementation reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRef {
    pub id: String,
    #[serde(flatten)]
    pub params: BTreeMap<String, Value>,
}

/// One API endpoint a provider may call, by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointDecl {
    pub id: String,
    /// Host template, e.g. `ecs.{region}.amazonaws.com`. `{key}` is replaced
    /// by the target setting `key`.
    pub host: String,
    pub profile: ProfileRef,
    /// Allowed actions: a bare service action (`DescribeServices`) or a REST
    /// rule (`GET /api/v1/namespaces/*`).
    pub actions: Vec<String>,
}

/// What the provider says about the hosts it creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilities {
    #[serde(rename = "persistent-data")]
    pub persistent_data: bool,
    #[serde(rename = "public-https")]
    pub public_https: bool,
    /// `public` or `private`.
    pub reachability: String,
}

/// A validated hosting declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingDeclaration {
    pub provider_id: String,
    pub display_name: String,
    pub ref_prefix: String,
    pub endpoints: Vec<EndpointDecl>,
    pub capabilities: ProviderCapabilities,
    pub settings_schema: Value,
    pub credential_schema: Value,
}

impl HostingDeclaration {
    /// Parse and validate a descriptor.
    ///
    /// # Errors
    ///
    /// [`DeclarationError`] naming the first rule broken. The caller must not
    /// run the provider's lifecycle with a declaration that fails here.
    pub fn parse(raw: &RawDescriptor) -> Result<Self, DeclarationError> {
        for (name, s) in [
            ("settings-schema", &raw.settings_schema),
            ("credential-schema", &raw.credential_schema),
            ("endpoints", &raw.endpoints),
            ("capabilities", &raw.capabilities),
        ] {
            if s.len() > MAX_FIELD_BYTES {
                return Err(DeclarationError::new(format!("{name} is too large")));
            }
        }
        validate_ident(&raw.id, "id")?;
        if raw.display_name.trim().is_empty() || raw.display_name.len() > 128 {
            return Err(DeclarationError::new("display-name must be 1..=128 bytes"));
        }
        validate_ref_prefix(&raw.ref_prefix)?;
        let endpoints: Vec<EndpointDecl> = serde_json::from_str(&raw.endpoints)
            .map_err(|e| DeclarationError::new(format!("endpoints: {e}")))?;
        validate_endpoints(&endpoints)?;
        let capabilities: ProviderCapabilities = serde_json::from_str(&raw.capabilities)
            .map_err(|e| DeclarationError::new(format!("capabilities: {e}")))?;
        if !matches!(capabilities.reachability.as_str(), "public" | "private") {
            return Err(DeclarationError::new(
                "capabilities.reachability must be \"public\" or \"private\"",
            ));
        }
        Ok(Self {
            provider_id: raw.id.clone(),
            display_name: raw.display_name.clone(),
            ref_prefix: raw.ref_prefix.clone(),
            endpoints,
            capabilities,
            settings_schema: parse_schema(&raw.settings_schema, "settings-schema")?,
            credential_schema: parse_schema(&raw.credential_schema, "credential-schema")?,
        })
    }

    /// The endpoint with this id.
    #[must_use]
    pub fn endpoint(&self, id: &str) -> Option<&EndpointDecl> {
        self.endpoints.iter().find(|e| e.id == id)
    }

    /// Hash of everything an approval has to cover: endpoint hosts, profiles
    /// and scopes, allowed actions, capabilities and the settings schema.
    ///
    /// Order-insensitive (endpoints sort by id, actions sort and dedupe) so a
    /// re-ordered but identical declaration keeps its approval, and canonical
    /// JSON (RFC 8785) so the same declaration hashes the same everywhere.
    /// `sha256:<64 hex>`.
    ///
    /// # Panics
    ///
    /// Never in practice: serialising already-parsed JSON values cannot fail.
    #[must_use]
    pub fn capability_hash(&self) -> String {
        let mut endpoints: Vec<Value> = self
            .endpoints
            .iter()
            .map(|e| {
                let actions: BTreeSet<&String> = e.actions.iter().collect();
                serde_json::json!({
                    "id": e.id,
                    "host": e.host,
                    "profile": e.profile,
                    "actions": actions,
                })
            })
            .collect();
        endpoints.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let doc = serde_json::json!({
            "v": 1,
            "provider": self.provider_id,
            "ref_prefix": self.ref_prefix,
            "endpoints": endpoints,
            "capabilities": self.capabilities,
            "settings_schema": self.settings_schema,
        });
        // `serde_jcs` fails only on non-finite numbers, which JSON cannot hold.
        let canonical = serde_jcs::to_vec(&doc).unwrap_or_default();
        let digest = Sha256::digest(&canonical);
        let mut out = String::from("sha256:");
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

fn parse_schema(s: &str, name: &str) -> Result<Value, DeclarationError> {
    let v: Value = serde_json::from_str(s)
        .map_err(|e| DeclarationError::new(format!("{name} is not JSON: {e}")))?;
    if !v.is_object() {
        return Err(DeclarationError::new(format!(
            "{name} must be a JSON object"
        )));
    }
    Ok(v)
}

fn validate_ident(s: &str, what: &str) -> Result<(), DeclarationError> {
    let ok = !s.is_empty()
        && s.len() <= 32
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(DeclarationError::new(format!(
            "{what} must match [a-z][a-z0-9_]{{0,31}}"
        )))
    }
}

fn validate_ref_prefix(p: &str) -> Result<(), DeclarationError> {
    let body = p.strip_suffix(':').unwrap_or("");
    let ok = !body.is_empty()
        && body.len() <= 16
        && body
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(DeclarationError::new(
            "ref-prefix must be 1..=16 lowercase alphanumerics followed by ':'",
        ))
    }
}

fn validate_endpoints(endpoints: &[EndpointDecl]) -> Result<(), DeclarationError> {
    if endpoints.is_empty() || endpoints.len() > MAX_ENDPOINTS {
        return Err(DeclarationError::new(format!(
            "a provider declares 1..={MAX_ENDPOINTS} endpoints"
        )));
    }
    let mut seen = BTreeSet::new();
    for e in endpoints {
        let id_ok = !e.id.is_empty()
            && e.id.len() <= 64
            && e.id.starts_with(|c: char| c.is_ascii_lowercase())
            && e.id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c));
        if !id_ok || !seen.insert(e.id.as_str()) {
            return Err(DeclarationError::new(format!(
                "endpoint id '{}' is malformed or duplicated",
                e.id
            )));
        }
        validate_host_template(&e.host)?;
        if !KNOWN_PROFILES.contains(&e.profile.id.as_str()) {
            return Err(DeclarationError::new(format!(
                "endpoint '{}' names unknown auth profile '{}'",
                e.id, e.profile.id
            )));
        }
        if e.actions.is_empty() || e.actions.len() > MAX_ACTIONS_PER_ENDPOINT {
            return Err(DeclarationError::new(format!(
                "endpoint '{}' declares 1..={MAX_ACTIONS_PER_ENDPOINT} actions",
                e.id
            )));
        }
        for a in &e.actions {
            ActionRule::parse(a).map_err(|m| {
                DeclarationError::new(format!("endpoint '{}' action '{a}': {m}", e.id))
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "declaration_tests.rs"]
mod tests;
