# The hosting-provider world (`greentic:extension-hosting@0.1.0`)

A hosting extension holds the **provider logic** for running a containerised
service somewhere (ECS, Cloud Run, Kubernetes, a VM agent). The host (the admin,
through this runtime) holds everything else: credentials, policy, the audit
trail and the reconcile loop. The extension is untrusted code with a narrow
window onto one cloud API.

Design: `greentic-admin/docs/infra-provisioning-in-extensions.md`. WIT:
`wit/extension-hosting.wit` (vendored copy under
`crates/greentic-ext-runtime/wit/deps/extension-hosting/`, checked equal by
`ci/local_check.sh`).

## Kind versus capability

A hosting provider is declared as an extension of the **existing kind
`DeployExtension`** that offers the capability **`greentic:hosting/provider`**.
It is not a new `ExtensionKind`, and the declaration does not live in a new
`describe.json` key. Both are proven non-additive by
`crates/greentic-ext-runtime/tests/hosting_contract_compat.rs`, run against the
SDK contract crate this runtime resolves:

| Change | Result on a reader that predates it | Test |
| --- | --- | --- |
| `"kind": "HostingExtension"` | the whole describe fails (`unknown variant`): `ExtensionKind` has no catch-all | `a_new_extension_kind_is_not_additive` |
| top-level `"hosting": {...}` | fails (`unknown field`): `DescribeJson` is `deny_unknown_fields` | `a_new_top_level_hosting_block_is_not_additive_either` |
| `runtime.hosting`, `runtime.permissions.hosting`, `contributions.hosting` | fail, same reason | same test |
| `kind: DeployExtension` + `capabilities.offered[].id = "greentic:hosting/provider"` | parses unchanged; `capabilities.offered` is an open list of ids | `a_hosting_provider_describe_is_an_ordinary_deploy_describe` |
| a describe without the capability | unchanged | `an_older_shaped_describe_without_the_capability_still_parses` |

Two consequences:

* **The capability id is `greentic:hosting/provider`, not `cap://hosting/provider`.**
  The v2 describe schema constrains `capabilities.offered[].id` to
  `^[a-z][a-z0-9-]*:[a-z][a-z0-9/._-]*$`; the `cap://` spelling belongs to
  `contributions.dwProviders` and an extension offering it fails to register
  (`the_capability_id_must_fit_the_describe_schema`).
* **Endpoints, actions and auth profiles are declared by the guest's pure
  `describe-provider` export**, not in `describe.json`. The host parses that
  JSON strictly (`HostingDeclaration::parse`; an unknown field makes the
  declaration invalid) and binds the platform admin's approval to its
  **capability hash**.

`HostingProvider` therefore refuses an extension unless it is a
`DeployExtension` offering the capability (`HostingError::NotAProvider`).

## What the guest gets, and what it does not

World `hosting-extension`: imports `log`, `target`, `api`; exports `provider`.

```wit
interface target { get: func(key: string) -> option<string>; }
interface api {
  enum api-error { not-declared, denied-by-policy, timeout, transport, too-large }
  call: func(endpoint-id: string, method: string, path: string,
             body: option<list<u8>>, headers: list<tuple<string, string>>)
        -> result<response, api-error>;
}
interface provider {   // 1:1 with the admin's HostAdapter
  describe-provider, validate-settings, preflight, supports, host-ref-for,
  ensure-host, describe-host, list-owned, destroy
}
```

The hosting linker (`loaded_hosting.rs`) is built from scratch, not as a subset
of the design-extension linker. It provides the three imports and only the WASI
a `std` guest cannot be built without (`cli`, `io`). It has **no**
`greentic:extension-host/{secrets,http,broker,llm,artifact}`, no OAuth broker,
and no WASI filesystem, sockets, random or **clocks**. A component importing any
of them fails at instantiation (tests
`components_importing_secrets_http_or_a_clock_do_not_instantiate`,
`a_component_that_reads_the_clock_does_not_instantiate`). Without a clock there
is no timer pollable, so the one thing an epoch deadline cannot interrupt, a
guest sleeping inside a blocking host call, cannot start. No other extension
kind can import the hosting interfaces either
(`no_other_extension_can_import_the_hosting_api`).

## Policy engine (per `api.call`)

Rules run in this order; nothing before step 6 touches a credential.

1. Call budget (refused calls count) and invocation deadline.
2. The endpoint id must be declared. A guest names an id, never a host.
3. Method (`GET POST PUT PATCH DELETE HEAD`), path shape (single leading `/`,
   no authority, scheme, `..`, backslash or control characters), header
   allow-list (`content-type accept x-amz-target if-match if-none-match
   idempotency-key x-request-id prefer`; never `authorization`, `cookie`,
   `host`, `x-amz-security-token`, `x-api-key`), request size.
4. The action must be one the endpoint declared: a bare service action
   (`DescribeServices`, read from `x-amz-target` or `Action=`) or a REST rule
   (`GET /api/v1/namespaces/*`). `GET /*` and `*` are refused at declaration.
5. The host is built from the endpoint's template and the target settings, must
   be a well-formed `host[:port]`, must match the platform admin's `api_hosts`
   (`*.suffix` needs a label and a dot boundary), and must not be private,
   loopback, link-local, metadata or `*.internal` unless the admin listed that
   exact host.
6. Only now are `${resource.credential}` and `${resource.credential_fingerprint}`
   substituted (UTF-8 bodies and header values, never the path) and the
   `HostingPort` asked to sign and carry the call.
7. The answer is size-checked, its headers cut to a benign allow-list and every
   occurrence of the credential (and any value the port lists) redacted.

Every call, allowed or refused, writes one `AuditEvent` (target, extension,
version, operation, endpoint, action, outcome, duration, byte counts). There is
no field that could carry a body, a header value or a query.

`target.get` answers `none` for any key that names key material (`credential`,
`secret`, `token`, `password`, `private`, `api-key`, `access-key`, `bearer`,
`kubeconfig`) whatever the target holds; the reserved keys are
`installation-id`, `owner-tags` and `credential-fingerprint`.

## What the platform admin sets per target (`TargetPolicy`)

The admin can only **narrow** what the extension declared.

| Knob | Meaning | Default |
| --- | --- | --- |
| `api_hosts` | hosts a credential may be sent to | empty: every call refused |
| `private_hosts` | private API hosts allowed anyway (exact `host[:port]`) | none |
| `ingress_domains` | domains a returned host handle must sit in (https only) | empty: no handle accepted |
| `limits` | request 1 MiB, response 8 MiB, 30 s per call, 120 s and 150 calls per invocation, 100 log lines of 512 B | clamped to `platform_max` |
| `approved_capability_hash` | the `HostingProvider::capability_hash()` the admin approved | none: `ensure-host` refused |
| `enabled`, `frozen` | stop creating hosts; describe, list-owned and destroy keep working | enabled, not frozen |

`ensure-host` is refused unless the target is enabled, not frozen and the
approved hash equals the extension's current one (`Refusal::{TargetDisabled,
Frozen, NotApproved, NeedsReapproval}`). Reads and deletes are never gated, so
an upgrade or an incident cannot orphan existing hosts. The hash covers
endpoint hosts, profiles and scopes, actions, capabilities and the settings
schema, order-insensitively.

What a guest returns is untrusted: a handle must be `https`, on a non-zero
port, in `ingress_domains`, with a ref carrying the declared prefix
(`Refusal::HandleRejected`); `list-owned` entries without the prefix are
dropped; diagnostics are scrubbed and truncated; errors are the closed
`host-error` enum.

## Implementing the port (embedders)

`HostingPort` is the seam. The runtime decides whether a call may happen; the
port authorises and carries it. It never sees a refused call and is handed an
`AuthorizedCall` (resolved host, method, path, headers, substituted body, a hard
`timeout` it **must** enforce, and a response cap). `MockHostingPort` is the
scripted implementation used by the tests.

```rust
let provider = runtime.hosting_provider(
    "greentic.hosting-aws-ecs",
    HostingContext { target_id, port, policy, audit },
)?;
provider.ensure_host(&spec, "h-123")?;   // Pending: ask again next pass
```

Calls are synchronous; wrap them in `spawn_blocking`.

## How to write a hosting extension

1. Component for `wasm32-wasip2` whose world is `hosting-extension`
   (`wit-bindgen` with `path = ".../wit/extension-hosting.wit"`). Do not read a
   clock or the environment; derive every name from `host-id`.
2. `describe.json`: `kind: "DeployExtension"`, `capabilities.offered` containing
   `{"id": "greentic:hosting/provider", "version": "1.0.0"}`, no network or
   secret permissions.
3. Return the endpoints from `describe-provider`:
   `[{"id":"aws.ecs","host":"ecs.{region}.amazonaws.com","profile":{"id":"aws-sigv4","service":"ecs"},"actions":["DescribeServices","CreateService"]}]`.
   Profiles: `aws-sigv4 gcp-oauth-sa bearer k8s-token mtls none`. Declare only
   what you use; the admin approves exactly that.
4. Implement the lifecycle idempotently. Return `pending` to wait.

A minimal exchange with the API (this is the whole of `hosting-test-guest`'s
honest path):

```rust
let r = api::call("aws.secretsmanager", "POST", "/",
    Some(br#"{"SecretString":"${resource.credential}"}"#),
    &[("x-amz-target".into(), "secretsmanager.CreateSecret".into())])?;
```

`crates/hosting-test-guest` is the reference component. It is built by the
runtime's integration tests (`tests/support/hosting.rs`) with
`cargo build --release --locked --target wasm32-wasip2`.

## Not covered here

* Signing, token minting and the real provider APIs: the embedder's
  `HostingPort`. No `HostingPort` over a real cloud client exists in this repo.
* `destroy` is forwarded for any well-formed ref; the admin must restrict it to
  refs in an intent row or returned by `list-owned` (design section 6.1).
* Read-only operations (`describe-host`, `list-owned`, `preflight`) are not
  restricted to read actions: the action allow-list is per endpoint, not per
  operation.
* `wasi:io/poll` remains linked (needed by `std` streams); with no clock it can
  only wait on streams.
