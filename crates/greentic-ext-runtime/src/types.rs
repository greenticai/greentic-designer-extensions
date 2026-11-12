/// Host-side declaration of a UI view an extension contributes to a host
/// surface (Designer sidebar, Admin tenant detail panel, etc).
///
/// Mirrors `greentic_extension_sdk_contract::describe::contributions::View`
/// field-for-field — `surface`, `placement`, and `min_visibility` are that
/// crate's own types reused directly rather than re-mirrored, the same way
/// [`ToolDefinition::secret_requirements`] reuses `greentic_types` directly;
/// there is no WIT-bindgen type here to keep out of the public API, so
/// duplicating them would only be extra upkeep. Two fields have no contract
/// equivalent because they depend on where this extension actually landed on
/// disk:
///
/// - `asset_dir`: `<source_dir>/assets/views/<id>/`, the directory the whole
///   view bundle (entry HTML plus its JS/CSS/images) lives under. A host
///   serving the view as a static page needs this to serve every relative
///   resource the entry references, not just the entry file itself.
/// - `entry_path`: `asset_dir` joined with `entry`, resolved and checked for
///   path traversal here (the same discipline
///   [`crate::runtime_verify::pack_relative_path`] applies to
///   `gtpack.file`) rather than left for every host to re-derive — and,
///   more importantly, to re-remember the `..`-rejection. `entry` is a
///   publisher-controlled string from a signed `describe.json`; resolving it
///   once in the loader means every host gets the same guard.
///
/// Both fields are kept because they answer different questions: `entry_path`
/// is what a host opens first, `asset_dir` is the root it serves everything
/// else from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ViewDefinition {
    /// Unique within the extension. The host namespaces it as
    /// `<extension_id>/<id>`.
    pub id: String,
    pub surface: greentic_extension_sdk_contract::describe::contributions::Surface,
    /// Key resolved against the top-level `localization` block.
    pub title_key: String,
    /// Literal shown when `title_key` has no entry for the active locale.
    pub title_fallback: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// Entry HTML, relative to `asset_dir` inside the pack. See
    /// [`Self::entry_path`] for the resolved, path-safety-checked form.
    pub entry: String,
    pub placement: greentic_extension_sdk_contract::describe::contributions::Placement,
    #[serde(default)]
    pub min_visibility: greentic_extension_sdk_contract::describe::contributions::Visibility,
    /// Names of this extension's own contributed tools the view may invoke
    /// through the host bridge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    /// `<source_dir>/assets/views/<id>/` — the directory this view's whole
    /// asset bundle lives under.
    pub asset_dir: std::path::PathBuf,
    /// `asset_dir` joined with `entry`, resolved and checked against path
    /// traversal.
    pub entry_path: std::path::PathBuf,
}

/// Host-side mirror of WIT `greentic:extension-design/tools@0.2.0::tool-definition`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema_json: Option<String>,
    /// Runtime contexts the tool supports (`"flow"`, `"agentic_worker"`).
    /// Legacy extensions return `None`; consumers must default to `["flow"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// JSON-encoded `AgenticWorkerMetadata` blob. Decode via
    /// `greentic_extension_sdk_contract::AgenticWorkerMetadata::decode`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agentic_worker_metadata: Option<String>,
    /// Per-tool secret/credential requirements (v2 declarative tools).
    /// Legacy v1 WIT tools have none; defaults to empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_requirements: Vec<greentic_types::secrets::SecretRequirement>,
}

/// Host-side mirror of WIT `greentic:extension-design/prompting@0.2.0::prompt-fragment`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PromptFragment {
    pub section: String,
    pub content_markdown: String,
    pub priority: u32,
}

/// Host-side mirror of WIT `greentic:extension-design/knowledge@0.2.0::entry-summary`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeEntrySummary {
    pub id: String,
    pub title: String,
    pub category: String,
    pub tags: Vec<String>,
}

/// Host-side mirror of WIT `greentic:extension-design/knowledge@0.2.0::entry`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeEntry {
    pub id: String,
    pub title: String,
    pub category: String,
    pub tags: Vec<String>,
    pub content_json: String,
}

/// Host-side mirror of WIT `greentic:extension-base/types@0.1.0::severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

/// Host-side mirror of WIT `greentic:extension-base/types@0.1.0::diagnostic`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Host-side mirror of WIT `greentic:extension-deploy/targets@0.1.0::target-summary`.
///
/// Returned by `ExtensionRuntime::list_targets` for each deploy target a
/// loaded extension declares.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TargetSummary {
    pub id: String,
    pub display_name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_path: Option<String>,
    pub supports_rollback: bool,
}

/// Host-side mirror of WIT `greentic:extension-deploy/deployment@0.1.0::deploy-request`.
///
/// Note: no `serde` derives — `artifact_bytes` is a raw binary blob handed
/// to the WASM guest verbatim; JSON-encoding it would be wasteful and
/// incorrect. No derived `Debug` either: see the manual impl below.
#[derive(Clone)]
pub struct DeployRequest {
    pub target_id: String,
    pub artifact_bytes: Vec<u8>,
    pub credentials_json: String,
    pub config_json: String,
    pub deployment_name: String,
}

impl std::fmt::Debug for DeployRequest {
    /// Redacts `credentials_json` and elides `artifact_bytes`.
    ///
    /// `credentials_json` is the cloud credential the deploy target needs —
    /// AWS keys, GitHub tokens, registry passwords. A derived `Debug` put all
    /// of it into any `{:?}` of the request, which the wizard's deploy step is
    /// exactly the kind of code to log on failure. `artifact_bytes` is elided
    /// for a duller reason: it is megabytes of zip.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeployRequest")
            .field("target_id", &self.target_id)
            .field(
                "artifact_bytes",
                &format_args!("<{} bytes>", self.artifact_bytes.len()),
            )
            .field("credentials_json", &"<redacted>")
            .field("config_json", &self.config_json)
            .field("deployment_name", &self.deployment_name)
            .finish()
    }
}

/// Host-side mirror of WIT `greentic:extension-deploy/deployment@0.1.0::deploy-status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeployStatus {
    Pending,
    Provisioning,
    Configuring,
    Starting,
    Running,
    Failed,
    RolledBack,
}

/// Host-side mirror of WIT `greentic:extension-deploy/deployment@0.1.0::deploy-job`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeployJob {
    pub id: String,
    pub status: DeployStatus,
    pub message: String,
    pub endpoints: Vec<String>,
}

/// Typed extension-level error surfaced by `deploy`/`poll`/`rollback`.
///
/// Variant choice is a host-visible contract: the designer treats
/// `Internal` from `deploy()` as "not implemented in WASM" (Mode A stub)
/// and falls back to the greentic-deployer binary. Mode B extensions
/// must use the other variants for expected failures.
///
/// Structurally mirrors [`HostExtensionError`] by design; kept separate
/// because the two types participate in different dispatch paths and may
/// diverge as the deploy surface grows.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DeployExtensionError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("missing capability: {0}")]
    MissingCapability(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("schema invalid: {0}")]
    SchemaInvalid(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Host-side mirror of WIT `greentic:extension-design/validation@0.2.0::validate-result`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidateResult {
    pub valid: bool,
    pub diagnostics: Vec<Diagnostic>,
}

/// Host-side mirror of WIT
/// `greentic:extension-bundle/bundling@0.1.0::designer-session`.
///
/// The full payload the host hands to a bundle extension to render.
/// `flows_json` and `contents_json` are pre-serialised JSON blobs from
/// the designer; `assets` carries auxiliary file bytes (images, fonts,
/// vendored resources) keyed by their relative path inside the bundle.
#[derive(Debug, Clone, Default)]
pub struct BundleSession {
    pub flows_json: String,
    pub contents_json: String,
    pub assets: Vec<(String, Vec<u8>)>,
    pub capabilities_used: Vec<String>,
}

/// Host-side mirror of WIT
/// `greentic:extension-bundle/bundling@0.1.0::bundle-artifact`.
///
/// What `bundling.render` returns on success — the rendered artefact
/// bytes (typically a `.gtpack` zip) plus its filename and sha256 for
/// integrity checks. The host writes the bytes to disk verbatim.
#[derive(Debug, Clone)]
pub struct BundleArtifact {
    pub filename: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// Host-side mirror of WIT
/// `greentic:extension-design/roles@0.2.0::target-kind`.
///
/// Output channel a compiled role targets. Closed enum: a new target
/// requires a WIT minor bump on the design package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    AdaptiveCard,
    SlackBlockKit,
    TeamsCard,
    PlainText,
}

/// Host-side mirror of WIT
/// `greentic:extension-design/roles@0.2.0::role-spec`.
///
/// One role advertised by an extension. Aggregated across every loaded
/// design extension into a single registry keyed by `name`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoleSpec {
    pub name: String,
    pub description: String,
    pub json_schema: String,
    pub target: TargetKind,
    pub schema_version: u32,
    pub context_aware: bool,
}

/// Host-side mirror of WIT
/// `greentic:extension-design/roles@0.2.0::compile-context`.
///
/// Flow-level context handed to context-aware compilers. Empty for pure
/// roles. Designer fills this from the in-progress DSL document before
/// dispatch.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CompileContext {
    pub flow_entries_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    pub locale: String,
}

/// Host-side mirror of WIT
/// `greentic:extension-base/types@0.1.0::extension-error`.
///
/// Host-level failure that a role compiler may surface. Mirrored here
/// so [`RoleError::Host`] can carry the variant without dragging in
/// the bindgen-generated type at the public API boundary.
///
/// The `code()` method returns a stable kebab-case string that matches
/// the WIT `extension-error` variant name — used as the wire contract
/// for the designer's `{ok, data, error}` response envelope. Never
/// rename existing codes without a wire-breaking version bump.
#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "message")]
pub enum HostExtensionError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("missing capability: {0}")]
    MissingCapability(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("schema invalid: {0}")]
    SchemaInvalid(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl HostExtensionError {
    /// Stable kebab-case code matching the WIT `extension-error` variant
    /// name. This string is the wire contract for the designer's
    /// `{ok, data, error}` envelope — never rename existing codes.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid-input",
            Self::MissingCapability(_) => "missing-capability",
            Self::PermissionDenied(_) => "permission-denied",
            Self::NotFound(_) => "not-found",
            Self::SchemaInvalid(_) => "schema-invalid",
            Self::Internal(_) => "internal",
        }
    }
}

/// Host-side mirror of WIT
/// `greentic:extension-design/roles@0.2.0::role-error`.
///
/// Why a `compile-role` call failed. Distinct from
/// [`crate::error::RuntimeError`]: `RuntimeError` represents host /
/// runtime failures (extension-not-found, signature, IO), while
/// `RoleError` represents domain-level outcomes the LLM and designer
/// can act on (unknown role, invalid input, target not supported).
#[derive(Debug, Clone, thiserror::Error)]
pub enum RoleError {
    #[error("unknown role: {0}")]
    UnknownRole(String),
    #[error("invalid input: {0:?}")]
    InvalidInput(Vec<Diagnostic>),
    #[error("compile failed: {0}")]
    CompileFailed(String),
    #[error("target not supported: {0:?}")]
    TargetNotSupported(TargetKind),
    #[error("schema version not supported: {0}")]
    VersionNotSupported(u32),
    #[error("host: {0}")]
    Host(#[from] HostExtensionError),
}

#[cfg(test)]
mod host_extension_error_tests {
    #[test]
    fn host_extension_error_codes_are_stable_kebab() {
        use super::HostExtensionError as E;
        let cases = [
            (E::InvalidInput("x".into()), "invalid-input"),
            (E::MissingCapability("x".into()), "missing-capability"),
            (E::PermissionDenied("x".into()), "permission-denied"),
            (E::NotFound("x".into()), "not-found"),
            (E::SchemaInvalid("x".into()), "schema-invalid"),
            (E::Internal("x".into()), "internal"),
        ];
        for (e, code) in cases {
            assert_eq!(e.code(), code);
        }
    }
}

#[cfg(test)]
mod target_summary_tests {
    use super::*;

    #[test]
    fn target_summary_serializes_and_deserializes() {
        let t = TargetSummary {
            id: "aws-ecs-fargate-local".into(),
            display_name: "AWS ECS Fargate (local creds)".into(),
            description: "Deploy to AWS ECS Fargate using ambient credentials.".into(),
            icon_path: Some("icons/aws.svg".into()),
            supports_rollback: true,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: TargetSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, t.id);
        assert!(back.supports_rollback);
    }
}

#[cfg(test)]
mod deploy_request_tests {
    use super::DeployRequest;

    #[test]
    fn debug_never_renders_deploy_credentials() {
        let req = DeployRequest {
            target_id: "aws-ecs".into(),
            artifact_bytes: vec![0u8; 4096],
            credentials_json: r#"{"aws_secret_access_key":"AKIAsupersecret"}"#.into(),
            config_json: r#"{"region":"eu-west-1"}"#.into(),
            deployment_name: "demo".into(),
        };
        let rendered = format!("{req:?}");
        assert!(
            !rendered.contains("AKIAsupersecret"),
            "deploy credentials must never reach a log: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // Non-secret fields stay legible, and the blob is summarised not dumped.
        assert!(rendered.contains("aws-ecs"), "{rendered}");
        assert!(rendered.contains("eu-west-1"), "{rendered}");
        assert!(rendered.contains("<4096 bytes>"), "{rendered}");
    }
}
