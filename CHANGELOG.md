# Changelog

## [1.3.0]

Full audit pass — security, correctness, error handling, dead code, and the
500-line-per-file convention — run as three rounds, with independent re-audits
between them. The second round found that the first round's headline fix could
be walked around entirely, which is why the security list below reads as pairs.

### Fixed (security)

- **The ledger did not cover the file that gets executed.** `verify_dir_manifest`
  checked that every *listed* file hash-matched but never that every file *on
  disk* was listed, while the SDK's archive verifier rejects exactly that. Since
  `wasm_component_path` prefers a root `extension.wasm` unconditionally,
  dropping one into a pack that ships none bought arbitrary code execution with
  the describe signature, the manifest binding, and every listed hash still
  verifying. The directory and the ledger must now cover each other — and
  `gtpack.file`, a publisher-controlled string that previously went into
  `join()` unvalidated, goes through the same path rule, so the file actually
  loaded is necessarily one the ledger lists.
- **Ledger paths could leave the pack.** An absolute path made `Path::join`
  discard the pack root and `..` walked out of it; entries were read through a
  symlink-following `read`. Paths must be plain and relative, and entries
  regular files (`symlink_metadata`, so the link itself is what is checked).
  The coverage comparison also lowered on-disk names through
  `to_string_lossy().replace('\\', "/")`, so on Linux a file named `a\b.txt`
  matched a ledger entry for `a/b.txt`; it compares paths now.
- **Two URL parsers that disagreed.** `http_pattern_host` — the hand-rolled
  parser gating the plain-http toggle — differed from `Url::parse` about where
  an authority ends and how a scheme is spelled, so
  `http://evil.com?@localhost/*` (and the `#@`, `\@`, `HTTP://`, leading-space
  variants) got cleartext http to a public host. One parser decides both now.
- **`UrlMatcher` ignored the port**, so one declared loopback dev port granted
  every local listener; its path check was a raw `starts_with`, so `/v1/*`
  covered `/v1evil`; and `%2f`/`%5c` survived normalization to re-emerge as
  separators server-side. All three are exact now.
- **`http::fetch` followed redirects off the allow-list.** The final URL is
  re-checked and the response withheld when it lands off-list. Response bodies
  are capped at 32 MiB; previously unbounded.
- **Nothing bounded execution.** No fuel, no epoch, no `StoreLimits` — `loop {}`
  in any loaded extension wedged the calling thread for the life of the process.
  Every store now carries memory and table ceilings plus a wall-clock deadline
  (`RuntimeConfig::dispatch_timeout`, default 5 minutes).
- **Secrets in `Debug`.** `OAuthBrokerConfig::shared_secret`,
  `ResourceTokenResponse::access_token`, and `DeployRequest::credentials_json`
  were all rendered by derived impls. All redact. Guest URLs no longer reach
  logs with their query strings intact.
- **Secret declarations were not validated.** `secrets:` lined a `/` up at the
  boundary offset and granted the whole namespace — and one process-wide
  backend serves every extension, so that predicate is the entire isolation
  boundary. A declaration naming no path segment is refused.
- **`find_extension_dir` walked to the filesystem root**, so anything writable
  under the watched tree got a load attempt and, on success, a TOFU pin under
  an id of the writer's choosing. Bounded to `<root>/<kind>/<name>`.
- The verified describe is threaded into the load rather than re-read, so the
  id a pack is pinned under and the permissions it runs with are the ones the
  gate checked.

### Fixed

- **Uninstalling an extension never unloaded it.** The removal path looked for
  a `describe.json` beside the changed path — exactly the file an uninstall
  deletes — so the event was dropped and the extension stayed dispatchable with
  its capabilities advertised until restart.
- **The three read-modify-writes of `loaded` were unsynchronised**, so a
  concurrent removal could be lost, leaving an evicted extension's capabilities
  advertised. All go through `ExtensionRuntime::mutate_loaded` under one lock,
  which stores the map and its registry together.
- `CapabilityRegistry` fell back to `VersionReq::STAR` on an unparseable
  requirement — the narrowest input producing the widest grant, and enough for
  one typo to manufacture a dependency cycle. Now unresolvable.
- Guardrail `direction` defaulted to `inbound` on any unrecognised string.
- The filesystem watcher discarded debouncer errors, so a dropped inotify queue
  stopped hot reload silently.
- The oauth-broker consent/exchange stubs returned `""`, indistinguishable from
  success; they report `not_implemented`. `Url::join` no longer drops a base
  path.

### Changed

- **Module layout.** `runtime.rs` (1702 lines) split into `runtime_config`,
  `runtime_verify`, `runtime_registry`, `runtime_design`, `runtime_knowledge`,
  `runtime_targets`, `runtime_bundle`; `host_state.rs` (907) into
  `host_state_ports` / `host_state_net` / `host_state_oauth`; `loaded.rs` (621)
  shed `net_permissions`. `limits.rs` is new. Largest source file: 439 lines.
  A shared `dispatch_instance` helper replaced ~15 copies of the same preamble.
- `ci/local_check.sh` runs the test suite in **both** feature shapes. An
  all-features-only run never exercised the production build's lack of a
  signature bypass, which is the claim that matters most.
- No `unwrap()`, `expect()`, or `panic!()` remains on a non-test path.

### Removed

- `InstancePool` (`pool.rs`) — constructed per extension, never acquired from,
  held `Store<()>` where the runtime uses `Store<HostState>` so it could not
  have worked, and panicked on a poisoned lock.
- `RuntimeError::{AlreadyLoaded, Contract, PermissionDenied}` and
  `RuntimeEvent::CapabilityRegistryRebuilt` — never constructed, so dead arms
  in every caller's `match`.

### Breaking

- `ExtensionRuntime::for_test()` returns `Result<Self, RuntimeError>`.
- `HostState` fields are private; use the accessors.
- `LoadedExtension::{load_from_dir, build_store_and_instance}` are
  crate-private, so no public path instantiates unverified wasm.
- `InMemorySecrets::insert` takes `&self`.
- `RuntimeConfig` gains `dispatch_timeout`; construct via `from_paths`.

## [Unreleased]

### Changed

- **Unified 6-variant `extension-error` WIT contract with host dual-support.**
  `extension-base@0.2.0` adds `not-found` + `schema-invalid`; design@0.3.0,
  bundle/deploy/provider/dw-composer/runtime-side@0.2.0 adopt it. provider drops
  its local 3-variant error; dw-composer `compose` returns `extension-error`
  instead of a bare string. The runtime resolves each extension's contract
  version at dispatch and maps old (4-variant) and new (6-variant) errors into
  a single typed `RuntimeError::Extension` / `RoleError` / `DeployExtensionError`
  surface — legacy extensions keep working, with a one-shot deprecation warning.

### Added (security)

- **Loopback-http rule for extension network allow-lists.** A declared
  `http://127.0.0.1` / `http://localhost` pattern in an extension's
  `runtime.permissions.network` now permits plain http to that loopback host
  (the matcher enables `allow_http` only when a loopback http pattern is
  present). Non-loopback `http://` patterns are dropped with a warning —
  plain http to public hosts is never honoured. This lets a design extension
  reach a local dev service (e.g. the telco-x service on
  `http://127.0.0.1:8787`) without weakening the scheme-downgrade defence for
  public hosts. Replace semantics remain: a non-empty declaration is the
  authoritative allow-list for that extension; the host-level override is not
  added.

### Changed (BREAKING — security)

- **Contract bump to `1.2.4-research`** (typed v2 describe + C1/C2 trust-chain
  APIs). The runtime now consumes `verify_describe_self_consistent` +
  `verify_manifest_binding` from the contract.
- **Extension verify now fails closed (audit P5).** `verify_dir_signature` →
  `verify_dir_manifest` now: (1) rejects a pack with no `manifest.json`
  (previously fail-open for legacy packs) — the `dev-allow-unsigned` build +
  `GREENTIC_EXT_ALLOW_UNSIGNED` escape still loads it for local dev; (2) verifies
  the signed describe is **bound** to the on-disk `manifest.json`
  (`manifestSha256`), so the signature transitively covers the ledger — a
  swapped manifest is rejected before any per-entry check; (3) keeps the
  per-entry sha256 hash-match. Anchored authenticity (`verify_describe_with_key`
  against a trust-anchored key) remains a follow-up: it needs a runtime trust
  store and the org-provisioned prod root key.

### Tests

- **Real-wasm v2-contract two-path coverage.** New optional end-to-end test
  `ac_invoke_v2` (reads `GTDX_TEST_GTXPACK_V2`) loads an adaptive-cards
  extension built against the v2 contract (extension-base@0.2.0,
  extension-design@0.3.0, 6-variant `extension-error`) and asserts both a
  success invoke (`validate_card` → `valid=true`) and a typed
  `RuntimeError::Extension` error path (unknown tool → `not-found`). Mirrors
  the v1 `ac_invoke` gating and self-skips when the env var is unset. Fixture
  provenance: AC-MCP PR #74, `2.0.4-research`. The unsigned local fixture
  requires the `dev-allow-unsigned` build + `GREENTIC_EXT_ALLOW_UNSIGNED=1`.

## [0.3.0] - 2026-04-22

### Changed

- **Contract:** `runtime.gtpack` is now permitted on `DesignExtension` when `contributions.nodeTypes` is non-empty. Previously only `ProviderExtension` could embed a runtime `.gtpack`. This enables node-providing design extensions (first consumer: `greentic.llm-openai`). The invariant remains tight: embedding a runtime requires contributing at least one node type.
- **Schema:** `describe-v1.json` gains a matching top-level `allOf` conditional mirroring the Rust invariant for `DesignExtension + runtime.gtpack`.

### Fixed
- `gtdx publish` now embeds `runtime.gtpack.file` (with sha256 verification)
  for Provider extensions. Previously the runtime artifact was omitted from
  the published `.gtxpack`, causing Wave A `post_install_provider` to reject
  the install for sha256 mismatch / missing file. Unblocks auto-publish of
  provider extensions via `greenticai/greentic-designer-extension-action`.

### Added
- `gtdx search` accepts an optional QUERY (lists everything when omitted).
- `gtdx doctor` expands to four sections: toolchain (cargo / cargo-component /
  rustup / wasm32-wasip2 target), registries (reachability probe via /health),
  credentials (JWT expiry decode from token), and installed extensions
  (existing describe validation). `--offline` skips network probes.
- `gtdx publish` maps error kinds to numeric exit codes per spec §9
  (describe=2, build=70, version-exists=10, auth=20, registry=30,
  not-implemented=50, io=74, other=1).
- `gtdx publish --format json` emits a single JSON object per invocation
  (`event`: `dry_run` / `verify_only` / `published`) for IDE + CI consumers.
- `gtdx publish --registry oci://<host>/<namespace>[/<artifact>]` pushes the
  `.gtxpack` directly to any OCI Distribution v2-compatible registry (GHCR,
  Docker Hub, Harbor, Azure ACR). Artifact is a single layer with media type
  `application/vnd.greentic.gtxpack.v1`. Auth priority: `--oci-token` flag >
  `GHCR_TOKEN` > `GITHUB_TOKEN` > `OCI_TOKEN` > anonymous. 401/403 → hint to
  refresh `write:packages` scope; 409 → `VersionExists`.

## [0.2.0] - 2026-04-19

### Added
- `ExtensionKind::Provider` — 4th extension kind alongside Design/Bundle/Deploy
- `greentic:extension-provider@0.1.0` WIT contract with 3 sub-interfaces
  (messaging, event-source, event-sink) and 6 worlds for mixed capabilities
- `describe.json` `runtime.gtpack` field — required when `kind=ProviderExtension`,
  enforces kind↔gtpack invariant via `TryFrom<DescribeJsonRaw>`
- Lifecycle `install_provider` path: sha256 verification (constant-time), manual-pack
  conflict detection via CBOR `manifest.cbor.pack_id`, extraction to
  `~/.greentic/runtime/packs/providers/gtdx/`
- `ExtensionRegistry::list_by_kind` + `get_describe` trait methods (default impls)
- `gtdx list --kind <design|bundle|deploy|provider|all>` filter
- `gtdx info <name>` — local-first lookup, renders provider runtime pack +
  component version, uniform capabilities line
- `gtdx install <.gtxpack>` now routes `kind=Provider` through `post_install_provider`
- Shared provider fixture helpers in `greentic-extension-sdk-testing::provider_fixtures`
- `greentic-extension-sdk-contract::hex` — centralized hex encoder
- `gtdx new <name>` — scaffold a new design/bundle/deploy extension with
  vendored WIT contract and `.gtdx-contract.lock` (Phase 1 Track A, S1).
- `gtdx dev` subcommand: inner-loop build + pack + install for extension authors.
  Supports `--once` (CI-friendly one-shot), `--watch` (default continuous mode),
  `--no-install` (pack only), `--release`, `--debounce-ms`, and `--format json`
  for IDE integrations. File watcher filters `target/`, VCS dirs, editor swap
  files, and backup files automatically. Skip-unchanged logic avoids redundant
  installs when the pack's sha256 has not changed.
- `gtdx publish` subcommand: validate describe.json, build release WASM, pack
  into a deterministic `.gtxpack`, and publish into the filesystem registry at
  `$GREENTIC_HOME/registries/local/<id>/<version>/`. Supports `--dry-run`,
  `--force`, `--sign --key-id <id>`, `--version` override, and `--verify-only`.
  Writes a receipt at `./dist/publish-<id>-<version>.json`. Store and OCI
  registries return `NotImplemented` for now (Phase 2).
- `greentic-extension-sdk-contract::pack_writer` — deterministic ZIP writer (sorted
  entries, zeroed timestamps, LF normalization) shared by `gtdx dev` and
  `gtdx publish`.
- `gtdx publish --registry <name>` now uploads `.gtxpack` artifacts to a
  Greentic Store HTTP server via multipart POST to `/api/v1/extensions` with
  bearer-token auth. Registry URL is resolved from `~/.greentic/config.toml`
  (add with `gtdx registries add <name> <url>`); token is read from
  `~/.greentic/credentials.toml` (`gtdx login --registry <name>`) or the
  env-var named in the registry's `token-env` entry. 401 → `AuthRequired`
  with actionable hint; 409 → `VersionExists`; 2xx → parsed `PublishReceipt`.

### Changed
- `InstallOptions` gained `force: bool` field (default `false`)
- `RegistryError::ProviderInstall`, `VersionExists`, `NotImplemented` variants added
- `Storage::root()` accessor exposed
- `ExtensionRegistry::publish` signature: now takes `PublishRequest` and returns `PublishReceipt` (replaces prior `ExtensionArtifact + AuthToken` shape)
- Workspace version bumped 0.1.0 → 0.2.0 (additive — existing kinds unaffected)

### Fixed
- `describe-v1.json` schema: added `ProviderExtension` to kind enum
  (was missing since commit `4bf0e02`, blocked CLI install path)
- `wit_files_returns_all_embedded_packages` test count 6 → 7 after A4

### Notes
- Runner integration is zero-change: `greentic-runner` picks up extracted
  `.gtpack` files via existing 30s pack-index polling
