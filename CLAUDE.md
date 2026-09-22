# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## What this repo is

`greentic-ext-runtime` — the wasmtime-based host the Greentic Designer
uses to load and dispatch WebAssembly extensions. Three extension
kinds share a unified contract:

- **Design extension** (e.g. `greentic.adaptive-cards`) — exposes
  `tools`, `validation`, `prompting`, `knowledge` interfaces. The
  designer drives these from `/api/chat`, `/api/agent`, the
  inspector preview, and the LLM tool-calling loop.
- **Deploy extension** (e.g. `greentic.deploy-aws`) — exposes
  `targets`, `deployment`. The wizard's deploy step calls these to
  push `.gtbundle` artefacts to a target.
- **Bundle extension** (e.g. `greentic.bundle-standard`) — exposes
  `recipes`, `bundling.render`. Pack/Deploy renders the designer
  session into a `.gtpack` here. Wired through the runtime since
  `v0.12.0` (2026-05-01) — the previous out-of-band
  `greentic-bundle ext render` subprocess was retired (cf. designer
  PR #130 + plan
  `greentic-designer/docs/superpowers/plans/2026-04-30-bundle-dispatch-in-runtime.md`).

The runtime lives at `crates/greentic-ext-runtime`. The supporting
SDK crates (`-contract`, `-state`, `-cli`, `-registry`, `-testing`)
were split out to the public
[`greenticai/greentic-designer-sdk`](https://github.com/greenticai/greentic-designer-sdk)
repo and ship to crates.io as `greentic-extension-sdk-*` (#37 + #38).
Designer consumes them from crates.io while keeping `-runtime`
git-pinned here.

## Workspace layout

```toml
[workspace]
members = [
  "crates/greentic-ext-runtime",
  "crates/_wit-lint",
]
```

Reference extension repos (`greentic-bundle-extensions`,
`greentic-deployer-extensions`, `greentic-adaptive-card-mcp`) live
in their own GitHub orgs and consume this runtime via crates.io
(when the SDK pieces it depends on are published) or git tag.

## Public API surface

`greentic-ext-runtime` exposes (see `crates/greentic-ext-runtime/src/lib.rs`):

- `ExtensionRuntime::new(config)` — build the wasmtime engine. It loads
  **nothing**: the returned runtime has an empty extension map, and
  registration is the embedder's job via `register_loaded_from_dir`
  (which is where the verify gate runs) or `start_watcher`.
- `register_loaded_from_dir(path)` — explicit registration; designer
  calls this for design + deploy + bundle dirs at startup. Bundle
  registration is required for `render_bundle()` to find the
  recipe.
- `invoke_tool(ext_id, name, args_json)` — design extension tool
  dispatch.
- `validate_content(ext_id, content_type, content_json)` — design
  extension validator.
- `list_tools` / `prompt_fragments` / `knowledge_*` — design
  extension introspection helpers.
- `validate_credentials` / `credential_schema` / `list_targets` —
  deploy extension surface.
- `render_bundle(ext_id, recipe_id, config_json, session)` —
  bundle extension entry point. Takes a typed `BundleSession`
  (`flows_json`, `contents_json`, `assets`, `capabilities_used`) and
  returns a `BundleArtifact` (`filename`, `bytes`, `sha256`). Same
  lookup pattern as the design / deploy methods above; runs the
  WIT call on a sync wasmtime store, so callers in async contexts
  should wrap in `spawn_blocking`.

Wasmtime store + linker plumbing lives in `host_bindings.rs` (one
`bindgen!` per world to keep the `extension-base` / `extension-host`
shared types from colliding) and `host_state.rs` (capability +
broker + logging + i18n imports).

## Conventions

- **Rust 1.95.0**, edition 2024 (`rust-toolchain.toml` is canonical).
- **WASM target** for reference extensions: `wasm32-wasip2` —
  governed by the consuming repo (`greentic-bundle-extensions`,
  `greentic-deployer-extensions`).
- **Max 500 lines per source file.** Split modules before exceeding.
- **English only** in source, tests, comments, commit messages,
  tracing logs.
- **No Claude co-authorship** on commits.
- **Husky hooks** — pre-commit runs fmt + clippy; pre-push runs full
  `ci/local_check.sh`.
- **Feature branches + PRs** — never push directly to `main`.
- **Tag releases** — `v0.X.Y` workspace tags + `<crate>-vX.Y.Z` per-
  crate tags. See "How consumers actually pin" below — it is not the
  workspace tag, and getting this wrong makes a release look adopted
  when nothing has moved.

## Adding a new world / interface

1. Vendor the WIT under `crates/greentic-ext-runtime/wit/deps/<package>/`
   (each kind gets its own subdir to dodge namespace collisions).
2. Add a sibling `mod <kind>` in `host_bindings.rs` with
   `wasmtime::component::bindgen!({ path: "wit", world: "..." })`.
3. Mirror the WIT records as Rust structs in `types.rs`; re-export
   from `lib.rs`.
4. Add a `runtime_<kind>.rs` sibling carrying its own
   `impl ExtensionRuntime` block. Open with
   `self.dispatch_instance(ext_id)?`, resolve the interface with
   `resolve_iface_versions`, the function with `resolve_func`, call the
   typed signature, and map the WIT-level error through
   `ext_error::from_*` into `RuntimeError::Extension` — never collapse
   it into `Wasmtime`, which erases the extension's own error code.
5. Register the module in `lib.rs` and add a smoke test in its
   `#[cfg(test)]` module that exercises the `RuntimeError::NotFound`
   path via `ExtensionRuntime::for_test()`.

`runtime_bundle.rs` is the smallest complete example to mirror.

### Module layout

`runtime.rs` holds only the core: the `ExtensionRuntime` handle and its
stores, the shared `dispatch_instance` / `lookup` / `mutate_loaded` /
`resolve_iface_versions` / `resolve_func` plumbing, and the per-family
version tables. Everything else is a sibling with its own
`impl ExtensionRuntime` block:

| Module | Surface |
| --- | --- |
| `runtime_config` | `RuntimeConfig` — the knobs a host sets |
| `runtime_verify` | the load gate (signature, ledger, TOFU anchor) |
| `runtime_registry` | registration, `rebuild_registry`, the fs watcher |
| `runtime_design` | `tools`, `validation`, `guardrail` |
| `runtime_knowledge` | `prompting`, `knowledge` |
| `runtime_roles` | `roles` |
| `runtime_deploy` | `deployment` |
| `runtime_targets` | `targets` |
| `runtime_bundle` | `bundling.render` |
| `runtime_dw_composer` | `composer` |

`host_state.rs` is split the same way: the state and its builder there,
the `Host` impls in `host_state_ports` (logging / i18n / secrets /
broker), `host_state_net` (http / llm), and `host_state_oauth`.
`net_permissions` resolves an extension's URL allow-list — **intersecting**
the declared patterns with the operator's, when the operator set one, so a
self-signed pack cannot self-grant network reach past the host's ceiling —
`http_scheme_policy` decides which `http://` patterns are honourable at all,
and `limits` carries the per-store execution ceilings.

**Every mutation of `loaded` goes through `ExtensionRuntime::mutate_loaded`.**
It holds the write lock across the read-modify-write and stores the map
together with a registry rebuilt from it, so no caller can drop a
concurrent edit or leave the two out of step. A new mutation path that
clones and stores by hand reintroduces both bugs at once.

## External tool integration

- **`greentic-designer`** — primary consumer. Pins this crate by **git
  rev**, not by tag (see below).
- **`greentic-bundle-extensions`** — bundles the
  `bundle-standard` reference recipe + the OSS-side dispatcher stub
  (`greentic-bundle-extension-host::dispatcher::invoke_recipe`
  returns `ModeBNotImplemented` by design — designer goes through
  this runtime instead).
- **`greentic-adaptive-card-mcp`** — ships the `adaptive-cards`
  design extension (built against this runtime's WIT).
- **`greentic-store-server`** — distributes signed `.gtxpack`
  artefacts. The runtime's verify chain (`verify_dir_signature`)
  checks the describe signature for self-consistency, that the
  describe is bound to the whole-archive `manifest.json`
  (`manifestSha256`), and that the directory and the ledger cover each
  other exactly — failing closed on a missing manifest (audit P5). It
  then anchors the signature (see below).

## How consumers actually pin

Neither consumer pins the workspace tag, and they do not agree with each
other. Verified against their committed manifests and lockfiles:

| Consumer | Spec | Source |
| --- | --- | --- |
| `greentic-designer` | `rev = "8bc7713…"` | git |
| `greentic-runner` — `greentic-aw-runtime` | `"=1.2.24"` | **crates.io** |
| `greentic-runner` — `greentic-runner-host` | `"=1.2.24"` (optional) | **crates.io** |

`greentic-ext-runtime` **is** on crates.io (1.2.24–1.2.27, plus some
CI-generated timestamp versions) even though this crate carries
`publish = false` and this repo has no publish workflow — those releases
came from somewhere else. Nothing from 1.2.28 on has ever been
published, this line's tags included.

That combination is why the designer builds today, and it is fragile.
Its lockfile holds exactly **one** `greentic-ext-runtime`, from the git
rev, shared by all three consumers — and that unification works only
because the rev's workspace version happens to be exactly `1.2.24`, the
version the two runner crates require with `=`. Bump the rev to a
different version and the `=1.2.24` requirement can no longer be met by
it, so Cargo pulls a second copy from crates.io. Two copies means two
distinct `ExtensionRuntime` types and a build that fails on type
mismatch, which is what the designer's own Cargo.toml comment warns
about.

So a version bump here is a **three-repo, lockstep change**, not a tag
push:

1. `greentic-runner` — move both `=1.2.24` requirements, and add the
   `[patch.crates-io]` redirect its root `Cargo.toml` still has a
   dangling comment for (the comment ends mid-sentence at "onto the
   git"; the section itself is gone).
2. `greentic-designer` — the patch has to live here too. `[patch]` is
   honoured only from the *root* workspace of a build, so the runner's
   own patch does nothing when the runner is consumed as a dependency.
3. Land them together.

## Signature anchoring (TOFU)

`verify_dir_signature` runs three steps, in this order:

1. `verify_describe_self_consistent` — **describe integrity**. Any key
   passes; this only proves the describe is unchanged since signing.
2. `verify_dir_manifest` — **artifact integrity**: the describe is bound
   to the whole-archive ledger, and the ledger and the directory cover
   each other exactly. Four rules, all fail-closed:
   - every listed file must hash to its recorded sha256;
   - every file **on disk** must be listed (`describe.json` and
     `manifest.json` excepted — they are covered by steps 1 and 2
     themselves). Without this the directory gate was strictly weaker
     than the archive gate it stands in for, and since
     `wasm_component_path` prefers a root `extension.wasm`
     unconditionally, dropping one into a gtpack-layout pack bought
     arbitrary code execution with every other check still passing;
   - ledger paths must be plain relative paths — an absolute path makes
     `Path::join` discard the pack root, and `..` walks out of it;
   - a ledger entry must be a regular file, checked with
     `symlink_metadata` so a symlink is rejected rather than followed to
     bytes that live outside the pack.
3. `TrustStore::pin_or_verify` — **the anchor**, and the only step that
   supplies authenticity. Trust-on-first-use: the publisher key is
   pinned per `extension.id` on first load, and every later load of that
   id must present the same key. Step 1 proved the signature verifies
   against that key, so pinning it is what makes the pair meaningful.

**The anchor must stay last.** Pinning is a *write*, into the store
`gtdx` shares — so a pin from a load that later fails permanently blocks
the genuine publisher for that id in both tools, recoverable only by
hand-editing `publishers.json`. An attacker who cannot complete a load
must not be able to squat an id that way. `gtdx` orders it the same, one
level up: `sdk-registry/src/lifecycle.rs` runs `verify_integrity` then
`verify_authenticity`.

There is deliberately **no `verify_describe_with_key` step**. Handing it
a key read out of the describe under verification compares that key
against itself — a tautology that cannot fail where step 1 passed. The
SDK's own doc says the key "must come from a trust anchor ... never from
the artifact alone"; here the trust anchor is the pin.

The store is `greentic-extension-sdk-registry`'s `TrustStore` — the
same one `gtdx install` writes, reused rather than reimplemented. It
lives at `<root>/trust/publishers.json` where root is `$GREENTIC_HOME`,
else `~/.greentic` (`RuntimeConfig::resolve_trust_root`, mirroring
gtdx's own resolution). It is deliberately **not** derived from
`DiscoveryPaths` — that diverges under `$GREENTIC_HOME` or the runner's
`GREENTIC_EXTENSIONS_DIR`, and would silently pin into a store gtdx
never reads.

This gate applies to **both** load paths — `register_loaded_from_dir`
and the watcher's `handle_added_or_modified`. The watcher path
previously verified nothing at all.

TOFU is what is available without a trust root. A **KMS-rooted cert
chain (D.5) is still blocked** on key custody; until then a first load
trusts whatever key it first sees. Consequence worth knowing: an update
signed by a different key than the first load is **rejected**
(`PublisherKeyChanged`, naming both keys) — intended, but it means two
developers publishing one extension from their own local keys will
collide.

`GREENTIC_EXT_ALLOW_UNSIGNED=1` (only under the `dev-allow-unsigned`
feature) still skips all three steps. Because that feature also decides
whether the bypass is compiled at all, `ci/local_check.sh` runs the test
suite in **both** feature shapes — an all-features-only run never
exercises the production build's lack of a bypass.

## Real-component test coverage

Every fixture the normal suite builds is `(component)` — an empty shell. So
`invoke_tool`, `validate_content`, `list_targets` and `credential_schema` are
never exercised against a component that actually exports the interfaces they
call. The tests for that path exist but are `#[ignore]`d, because the packs
come from two private repos.

They run in the `fixture-tests` workflow (nightly + `workflow_dispatch`),
which builds the packs and calls `cargo test --tests -- --ignored`. It needs a
`FIXTURE_REPO_TOKEN` secret with read access to
`greentic-adaptive-card-mcp` and `greentic-deployer-extensions`.

**This repo is public and both fixture repos are private**, so running that
lane here would put private source into publicly-readable build logs. The copy
meant to actually run lives in `ci/private-lane/` and belongs in a private
repo; the one in `.github/workflows/` documents the gap and stays inert.

Without that secret a scheduled run **skips** with a notice, while a manual
dispatch **fails** — somebody pressed the button, so quietly doing nothing
would be the wrong answer. A green scheduled run is therefore not by itself
evidence the fixture tests ran; the job summary says when it skipped. A nightly
that is red every night until a secret is provisioned is how a workflow gets
ignored, which is the same failure this lane exists to fix.

**Never turn one of these back into a bare `return`.** They used to print
"skipping" and return, which reports the test as *passed* — a run with no
fixture was indistinguishable from one that exercised a real component, and
CI counted it green. `#[ignore]` is counted and named in the summary instead,
and a missing or unset fixture path now fails loudly, because running an
ignored test is always deliberate.

Still uncovered: `ac_invoke_v2`'s two tests need a pack built against the v2
contract, which ships unsigned and so also needs `--features
dev-allow-unsigned`; the workflow skips them by name rather than pretending.
`render_bundle`, `knowledge_*` and `evaluate_guardrail` have no
behavioural coverage at all — their tests assert `NotFound` and nothing else.

## Execution limits

Every dispatch store gets a memory/table ceiling and, by default, a
wall-clock deadline (`RuntimeConfig::dispatch_timeout`, 5 minutes; see
`limits.rs`). The deadline needs `Config::epoch_interruption` on the
engine plus the `EpochTicker` the runtime holds for its lifetime — if a
future change constructs an `Engine` without both, deadlines silently
stop firing.

## Capability registry

`CapabilityRegistry` is derived wholesale from the loaded set by
`ExtensionRuntime::rebuild_registry`, never patched incrementally.
Every path that mutates `loaded` must store a registry rebuilt from
the new map. This is what makes eviction correct by construction —
a dropped capability, a removed extension, and a re-registered dir all
fall out automatically. Do not reintroduce per-call-site registry
mutation: the previous clone-forward-then-append got all three wrong,
and a stale offering is a live false positive for anything that reads
`offerings()` to decide what is resolvable.
