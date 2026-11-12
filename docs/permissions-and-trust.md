# Permissions and Trust

This document describes how extensions declare what they need, how the
runtime enforces those declarations, and how trust is established through
signing.

---

## Declared Permissions

An extension declares every resource it may access in the `runtime.permissions`
section of `describe.json`:

```json
"runtime": {
  "memoryLimitMB": 64,
  "permissions": {
    "network": [
      "https://api.example.com/*",
      "https://*.cdn.example.com/assets/*"
    ],
    "secrets": [
      "secret://my-ext/api_key"
    ],
    "callExtensionKinds": ["design"],
    "llmRoles": [],
    "oauthProviders": []
  },
  "components": {
    "my-ext": {
      "gtpack": {
        "file": "extension.wasm",
        "sha256": "<64 lowercase hex>",
        "pack_id": "greentic.my-ext",
        "component_version": "0.1.0"
      },
      "sha256": "<64 lowercase hex>",
      "world": "greentic:my-ext/extension@1.0.0"
    }
  }
}
```

(The v1 `runtime.component` string became the `runtime.components` map in v2 —
see [describe-json-spec.md](./describe-json-spec.md#runtime).)

### `network`

An allowlist of URL patterns the extension may call via
`greentic:extension-host/http`. `UrlMatcher` compares three facets
independently:

- **Scheme** — exact, and non-`https` is rejected outright unless the host
  opts in (`with_allow_http`). This is a deliberate defence against
  scheme-downgrade.
- **Host** — exact, or a `*.<suffix>` wildcard that requires **at least one
  label**: `https://*.example.com/*` matches `api.example.com` but **not**
  bare `example.com`. Substring matches are rejected, so
  `evil.com.allowed.com` does not match `allowed.com`.
- **Path** — prefix match against the pattern's path with a trailing `/*`
  stripped: `https://api.example.com/v1/*` matches `/v1/chat/completions`. A
  pattern with a bare `/` path (or no path) matches any path.

An unparseable pattern is **logged at WARN and ignored**, so a typo does not
fail the load — it silently allows nothing.

An extension that leaves `network` empty (or omits it) cannot make any
outbound HTTP calls even if it imports the `http` interface.

### `secrets`

An allowlist of secret URIs the extension may read via
`greentic:extension-host/secrets`. **This list is not a glob**, and it does
not use the same matcher as `network`. A declared entry permits a requested
URI only when the URI **equals** it, or **starts with the entry followed by
`/`**:

```rust
uri == *allowed || uri.starts_with(&format!("{allowed}/"))
```

Three consequences, none of which produce an install-time error — only
`permission denied for secret: <uri>` when the tool runs:

- **`*` is a literal asterisk.** `secret://my-ext/*` permits nothing.
- **A trailing slash breaks the prefix**, because the code appends its own
  separator: `secret://notion/` permits `secret://notion//token`, never
  `secret://notion/token`.
- The scheme is `secret://`, singular.

Working forms are the full URIs:

```json
"secrets": ["secret://calendly/token", "secret://calendly/auth_mode"]
```

or a prefix with **no** trailing slash:

```json
"secrets": ["secret://notion"]
```

An extension that omits `secrets` cannot read any secrets.

### `callExtensionKinds`

A list of extension kinds this extension may call via the broker. Valid
values: `"design"`, `"bundle"`, `"deploy"`. An empty list (or omitted
field) means the extension cannot call any other extension.

---

## Views May Only Invoke Their Own Extension's Tools

A view contributed under `contributions.views[]` invokes tools **by name**
through the designer's view bridge. Because that dispatch is by name, the
designer enforces an own-tools-only rule: a view may invoke a tool only when
both of these hold.

1. The tool appears in the **same extension's** `contributions.tools`. This
   is the security boundary — without it, a view could name any loaded
   extension's tool and by-name dispatch would run it.
2. The view named that tool in its own `contributions.views[].tools`. This is
   the author's own narrowing of the boundary above, not a security property.

A refusal is an HTTP `403` carrying a stable code, so a caller can tell an
authoring mistake from an escalation attempt without parsing prose:

| Code | Meaning |
|------|---------|
| `E_TOOL_NOT_CONTRIBUTED` | This extension contributes no tool by that name. |
| `E_TOOL_NOT_DECLARED_BY_VIEW` | The extension contributes it, but this view did not list it. Fix `describe.json`. |
| `E_TOOL_OWNED_BY_OTHER_EXTENSION` | The name resolves to a **different** loaded extension. |
| `E_TOOL_RESERVED_NAME` | The name collides with a designer-native tool. |
| `E_TOOL_NOT_ADVERTISED_BY_RUNTIME` | `describe.json` promises the tool but the loaded pack does not advertise it — a broken pack, not a caller error. |
| `E_TOOL_REQUIRES_TENANT_SCOPE` | The call has no tenant to resolve secrets and per-tenant config against. |

`E_TOOL_OWNED_BY_OTHER_EXTENSION` fires only when two loaded extensions
advertise the **same tool name**. Running the other extension's copy is
precisely the privilege escalation this rule exists to prevent, so the call is
refused rather than resolved to either one. This is deliberate and permanent —
unlike the broker gap in
[Cross-Extension Communication](cross-extension-communication.md), it is not
awaiting an implementation. An extension that genuinely needs another
extension's capability must go through the broker once dispatch lands, where
the call is gated by `callExtensionKinds` above and the target runs under its
own identity and permissions.

---

## Default-Deny Semantics

Every permission field defaults to empty — **denied unless explicitly
granted.** The runtime does not infer or grant permissions beyond what is
declared. This is intentional:

- Users see exactly what an extension can do before they install it.
- Compromised or malicious extensions cannot escalate beyond declared scope.
- Extensions that do not need network access cannot exfiltrate data even
  if their code tries.

---

## Trust Policies

Trust policies control which signatures are required for installation.

| Policy | Description |
|--------|-------------|
| `strict` | Extension must be countersigned by the Greentic Store. Used in production environments where only store-vetted extensions are accepted. |
| `normal` | Extension must carry a valid developer signature (Ed25519). The developer's public key must match the `metadata.author.publicKey` and `signature.publicKey` fields. Default for most installs. |
| `loose` | Extension may be unsigned. Suitable for local development and testing only. Not recommended for shared or production environments. |

The default trust policy is configured in `<home>/config.toml` and can be
overridden per-install with `gtdx install --trust <policy>`.

---

## Ed25519 Signing

### How `gtdx publish` signs

When you run `gtdx publish ./my-extension-0.1.0.gtxpack`, the CLI:

1. Reads your private key from `~/.greentic/credentials.toml` (or generates
   one on first publish).
2. Computes the canonical JSON of `describe.json` with the `signature` field
   removed.
3. Signs the canonical JSON with Ed25519.
4. Encodes the signature as base64url.
5. Writes the `signature` object into `describe.json` inside the pack.
6. Uploads the pack to the registry.

The `signature` object in the published pack:

```json
"signature": {
  "algorithm": "ed25519",
  "publicKey": "AAAA...base64url",
  "value":     "BBBB...base64url"
}
```

### How `gtdx install` verifies

When installing from a registry, the CLI:

1. Downloads the `.gtxpack`.
2. Reads `describe.json` from the archive.
3. Extracts the `signature` field.
4. Recomputes the canonical JSON of `describe.json` without `signature`.
5. Verifies the Ed25519 signature against `signature.publicKey`.
6. For `strict` policy: additionally checks that the store has countersigned
   the artifact (store countersignature is a second `signature` block added
   by the Store server after review).
7. For `normal` policy: accepts a valid developer signature.
8. For `loose` policy: skips signature verification.

If verification fails, the install is aborted.

---

## Credential Storage

Credentials (tokens, keys) are stored in `~/.greentic/credentials.toml`.

On Unix: file mode is set to `0600` (owner read/write only) on first write.
On Windows: the file inherits the directory's ACL; consider using a
credential manager for production use.

The file is a plain TOML map of registry name to token:

```toml
[tokens]
greentic-store = "gts_live_..."
my-mirror      = "..."
```

Never commit this file to version control. It is listed in `.gitignore` by
the standard project templates.

---

## Install Permission Prompt

The first time you install an extension (and any time a new version declares
new or changed permissions), `gtdx install` displays the permissions being
requested and asks for confirmation:

```
greentic.flow-designer@0.2.0 requests the following permissions:

  network:
    https://api.greentic.ai

  secrets:
    secrets://*/default/flow-designer/*

  callExtensionKinds:
    design

Accept permissions? [y/N]
```

For subsequent installs of the same extension with identical permissions,
the prompt is skipped. Pass `--yes` / `-y` to accept automatically in
non-interactive environments (CI, scripted setup).

If you reject the prompt, the install is aborted. The extension is not
written to disk.
