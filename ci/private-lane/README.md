# Fixture-test lane, for a private repo

`fixture-tests.yml` here is the copy that should actually run. Drop it into
`.github/workflows/` of a **private** repo in the same org as the fixture
repos — `greentic-biz/greentic-adaptive-card-mcp` itself is a reasonable home,
or a private CI repo.

## Why it is not in this repo

`greenticai/greentic-designer-extensions` is public. The lane clones and
compiles two private repos, and on a public repo **Actions logs and artifacts
are readable by anyone**. A failing `cargo component build` prints source
snippets, so a broken fixture build would publish private source. That is not a
risk you can configure away inside a public repo; the workflow has to move.

The copy at `.github/workflows/fixture-tests.yml` in this repo stays because it
documents the gap and can be dispatched by someone who has weighed that
tradeoff. Without `FIXTURE_REPO_TOKEN` it skips rather than failing, so it is
inert by default.

## What it covers

`invoke_tool`, `validate_content`, `list_targets` and `credential_schema`
against components that really export the interfaces the runtime calls. Every
fixture the ext-runtime suite builds on its own is `(component)` — an empty
shell — so without this lane those four entry points have no coverage at all,
and eight tests sit `#[ignore]`d.

## Setup

1. Copy `fixture-tests.yml` into the private repo's `.github/workflows/`.
2. If the fixture repos are in the **same org** as that repo, the default
   `GITHUB_TOKEN` may already reach them — check
   *Settings → Actions → General → Workflow permissions* and the repos' access
   lists. Otherwise add a `FIXTURE_REPO_TOKEN` secret: a fine-grained PAT with
   resource owner `greentic-biz`, the two fixture repos selected, and
   **Contents: Read-only**. A GitHub App token is preferable to a PAT for
   anything long-lived — a PAT is tied to one person and dies quietly when they
   leave or it expires, which a nightly will not surface for a long time.
3. Run it once by hand to confirm the happy path before trusting the schedule.

## Pin the ref

`EXT_RUNTIME_REF` defaults to a tag, not a branch, on purpose: a nightly that
silently follows `main` reports on code nobody decided to release. Bump it when
you cut a release.

## Still uncovered

- `ac_invoke_v2`'s two tests need a pack built against the v2 contract, which
  ships unsigned and so also needs `--features dev-allow-unsigned`. Skipped by
  name.
- `render_bundle`, `knowledge_*` and `evaluate_guardrail` have no behavioural
  coverage anywhere — their tests assert `NotFound` and nothing else.
