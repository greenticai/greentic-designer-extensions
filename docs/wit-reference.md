# WIT Reference

This document covers every WIT package and interface in the
`greentic-designer-extensions` repository. Use it when implementing an
extension or when reading the host-side runtime code.

WIT files live in the `wit/` directory at the repository root.

---

## Package Overview

| Package | File | Role |
|---------|------|------|
| `greentic:extension-base@0.1.0` | `wit/extension-base.wit` | Shared types, manifest, lifecycle — required by all four kinds |
| `greentic:extension-host@0.1.0` | `wit/extension-host.wit` | Host services imported by extension WASM — logging, i18n, secrets, broker, HTTP |
| `greentic:extension-design@0.2.0` | `wit/extension-design.wit` | Design-extension specific interfaces — tools, validation, prompting, knowledge |
| `greentic:extension-bundle@0.1.0` | `wit/extension-bundle.wit` | Bundle-extension specific interfaces — recipes, bundling |
| `greentic:extension-deploy@0.1.0` | `wit/extension-deploy.wit` | Deploy-extension specific interfaces — targets, deployment |
| `greentic:extension-provider@0.1.0` | `wit/extension-provider.wit` | Provider-extension specific interfaces — flow node execution against external services |

**Import / export direction** (from the extension's perspective):

```
extension.wasm
├── IMPORTS (provided by host)
│   ├── greentic:extension-base/types          (shared types)
│   ├── greentic:extension-host/logging        (structured log output)
│   ├── greentic:extension-host/i18n           (translation lookup)
│   ├── greentic:extension-host/secrets        (secret URI resolution)
│   ├── greentic:extension-host/broker         (cross-extension calls)
│   └── greentic:extension-host/http           (outbound HTTP, allowlisted)
│
└── EXPORTS (implemented by extension, called by host)
    ├── greentic:extension-base/manifest       (identity + capability refs)
    ├── greentic:extension-base/lifecycle      (init + shutdown)
    └── <kind-specific interfaces>
        DesignExtension:
            greentic:extension-design/tools
            greentic:extension-design/validation
            greentic:extension-design/prompting
            greentic:extension-design/knowledge
        BundleExtension:
            greentic:extension-bundle/recipes
            greentic:extension-bundle/bundling
        DeployExtension:
            greentic:extension-deploy/targets
            greentic:extension-deploy/deployment
```

---

## `greentic:extension-base@0.1.0`

### `greentic:extension-base/types`

Shared primitive types used by all packages. Imported by extensions via the
world's `import greentic:extension-base/types` line.

#### Records and Enums

**`extension-identity`** — Identifies an extension uniquely.

```wit
record extension-identity {
  id:      string,   // e.g. "greentic.adaptive-cards"
  version: string,   // semver, e.g. "1.6.0"
  kind:    kind,
}
```

**`kind`** — The four extension kinds.

```wit
enum kind {
  design,
  bundle,
  deploy,
  provider,
}
```

**`capability-ref`** — Points to a specific capability at a version.

```wit
record capability-ref {
  id:      string,   // e.g. "greentic:adaptive-cards/validate"
  version: string,   // semver for offered; semver range for required
}
```

**`diagnostic`** — A single validation finding.

```wit
record diagnostic {
  severity: severity,
  code:     string,          // machine-readable code, e.g. "missing-version"
  message:  string,          // human-readable description
  path:     option<string>,  // JSON pointer if applicable, e.g. "/body/0"
}
```

**`severity`** — Diagnostic severity levels.

```wit
enum severity {
  error,
  warning,
  info,
  hint,
}
```

**`extension-error`** — Typed error variant returned from extension calls.

```wit
variant extension-error {
  invalid-input(string),
  missing-capability(string),
  permission-denied(string),
  internal(string),
}
```

Use `invalid-input` for caller mistakes (bad JSON, wrong field). Use
`missing-capability` when a required peer extension is not available. Use
`permission-denied` when a resource access is blocked. Use `internal` for
unexpected implementation errors.

---

### `greentic:extension-base/manifest`

Exported by every extension. The host calls these at install time and at
startup to build the capability registry.

```wit
interface manifest {
  use types.{extension-identity, capability-ref};

  get-identity: func() -> extension-identity;
  get-offered:  func() -> list<capability-ref>;
  get-required: func() -> list<capability-ref>;
}
```

**`get-identity`** — Returns the extension's id, version, and kind. Must
match `metadata.id`, `metadata.version`, and `kind` in `describe.json`.

**`get-offered`** — Returns the list of capabilities this extension provides
to others. Must match `capabilities.offered` in `describe.json`.

**`get-required`** — Returns the list of capabilities this extension needs
from other extensions. Must match `capabilities.required` in `describe.json`.

---

### `greentic:extension-base/lifecycle`

Exported by every extension. The host calls `init` once after loading and
`shutdown` before unloading.

```wit
interface lifecycle {
  use types.{extension-error};

  init:     func(config-json: string) -> result<_, extension-error>;
  shutdown: func();
}
```

**`init`** — Called once with a JSON configuration string. The host passes
any user-supplied per-extension config here. Return `Ok(())` on success.
Return an `extension-error` if the config is invalid or a required resource
is unavailable.

**`shutdown`** — Called before the extension is unloaded. Release resources,
flush buffers. No return value.

---

## `greentic:extension-host@0.1.0`

Host services imported by extension WASM at runtime. All interfaces here are
provided by `greentic-ext-runtime` — extensions cannot provide them.

### `greentic:extension-host/logging`

Structured logging forwarded to the host's tracing subscriber.

```wit
interface logging {
  enum level { trace, debug, info, warn, error }

  log:    func(level: level, target: string, message: string);
  log-kv: func(level: level, target: string, message: string,
               fields: list<tuple<string, string>>);
}
```

**`log`** — Simple log line. `target` is typically the Rust module path.

**`log-kv`** — Log with key-value fields for structured output.

Example usage from Rust extension code (via generated bindings):

```rust
logging::log(
    logging::Level::Info,
    "my_ext::tools",
    "validating card",
);
logging::log_kv(
    logging::Level::Debug,
    "my_ext::tools",
    "card parsed",
    &[("body_len", "3"), ("version", "1.6")],
);
```

---

### `greentic:extension-host/i18n`

Translation lookup for extension-contributed strings. The host resolves
locale based on the designer's active language.

```wit
interface i18n {
  t:  func(key: string) -> string;
  tf: func(key: string, args: list<tuple<string, string>>) -> string;
}
```

**`t`** — Translate a key. Returns the key itself if no translation is found.

**`tf`** — Translate with named substitution variables. Each tuple is
`(variable-name, value)`.

---

### `greentic:extension-host/secrets`

Read secrets by URI from the host secrets store. The extension's
`runtime.permissions.secrets` allowlist in `describe.json` gates which URIs
are accessible.

```wit
interface secrets {
  get: func(uri: string) -> result<string, string>;
}
```

**`get`** — Resolve a secret URI. Returns `Ok(value)` on success. Returns
`Err(message)` if the URI is not in the allowlist, the secret does not exist,
or the store is unavailable.

URI format: `secrets://{env}/{tenant}/{team}/{provider}/{key}`

---

### `greentic:extension-host/broker`

Cross-extension calls. An extension can call another extension through the
broker rather than depending on it directly.

```wit
interface broker {
  call-extension: func(
    kind:      string,     // "design" | "bundle" | "deploy"
    target-id: string,     // e.g. "greentic.adaptive-cards"
    function:  string,     // function to call, e.g. "validate-content"
    args-json: string,     // JSON-encoded arguments
  ) -> result<string, string>;  // JSON result or error message
}
```

**`call-extension`** — Dispatch a call to another installed extension. The
host:

1. Checks that the caller's `runtime.permissions.callExtensionKinds` includes
   the target kind.
2. Resolves the target extension by id.
3. Checks the max call depth (default 8).
4. Dispatches the call and returns the result.

Returns `Err` if any check fails. Callers should handle errors gracefully
rather than propagating them as hard failures.

See [cross-extension-communication.md](./cross-extension-communication.md)
for usage patterns.

---

### `greentic:extension-host/http`

Outbound HTTP. Access is gated by the extension's
`runtime.permissions.network` origin allowlist.

```wit
interface http {
  record request {
    method:  string,
    url:     string,
    headers: list<tuple<string, string>>,
    body:    option<list<u8>>,
  }

  record response {
    status:  u16,
    headers: list<tuple<string, string>>,
    body:    list<u8>,
  }

  fetch: func(req: request) -> result<response, string>;
}
```

**`fetch`** — Send an HTTP request. Returns `Err` if the URL's origin is not
in the allowlist or if a network error occurs. Only HTTPS is permitted.

**Redirects.** The host follows up to 10 redirects itself and re-checks the
allowlist before every hop; a hop off the list fails the call with `Err` and
the off-list host is never contacted. What each hop sends:

| Redirect | Method and body on the next hop |
|---|---|
| 301, 302, 303 after a method other than GET/HEAD | becomes `GET` with no body; `Content-Type`, `Content-Length`, `Content-Encoding`, `Content-Language` are dropped |
| 301, 302, 303 after GET/HEAD | unchanged |
| 307, 308 | method, body and body headers kept |

When a hop goes to a different **origin** (scheme, host or port differs from
the hop before it), the credential headers are dropped and stay dropped for
the rest of the chain, even if a later hop returns to the first origin:
`Authorization`, `Proxy-Authorization`, `Cookie`, `Cookie2`,
`WWW-Authenticate`, `X-Api-Key`, `Api-Key`, `X-Auth-Token`,
`X-Goog-Api-Key` (names matched case-insensitively). A same-origin redirect
keeps them. Other guest-set headers are kept on every hop. A guest whose API
redirects to another origin that genuinely needs the credential must call that
URL itself with the header set.

### `greentic:extension-host/artifact`

Store a file the extension produced (image, PDF, CSV, ...) and get back an
opaque id. **Bytes in, id out: never put bytes in a tool result.** Return the
`artifact://` id in the result instead. Imported by the
`design-extension@0.4.0` world only.

```wit
interface artifact {
  variant artifact-error {
    unsupported,
    tenant-required,
    invalid-size,
    invalid-input(string),
    unsupported-media-type,
    quota-exceeded,
    unavailable,
  }
  put: func(bytes: list<u8>, mime-type: string, name: string)
    -> result<string, artifact-error>;
}
```

**`put`** — Store `bytes` for the calling tenant and return the `artifact://`
id. The tenant comes from the host call context, never from the guest.

| `artifact-error` | Meaning |
|---|---|
| `unsupported` | The host wires no artifact store (no port installed). |
| `tenant-required` | The call carried no tenant; nothing is stored without one. |
| `invalid-size` | Empty, or over 10 MiB (refused, never truncated). |
| `invalid-input(msg)` | `name` or `mime-type` failed validation. |
| `unsupported-media-type` | The store refused the media type. |
| `quota-exceeded` | The tenant's byte quota is exhausted. |
| `unavailable` | The store failed; detail is logged host-side only. |

The tenant and shape checks (size, `name`, `mime-type`) run BEFORE the port
lookup, so with no port installed a call with no tenant answers
`tenant-required` and one with a bad name answers `invalid-input`, not
`unsupported`. A port that returns an id not starting with `artifact://` is
reported as `unavailable`.

`name` must be non-blank, at most 255 bytes, not exactly `.` or `..`, with no
`/`, `\`, control characters, or invisible format/bidi characters (U+200B-U+200F,
U+202A-U+202E, U+2060-U+2064, U+2066-U+2069, U+FEFF). `mime-type` must be a bare `type/subtype` (at most 127 bytes; no
parameters, whitespace or control characters). A `name` is still guest-chosen
text: a consumer that uses it as a file name or in a `Content-Disposition`
header must still treat it as untrusted.

A component that actually imports `artifact` (calls `put`) fails to instantiate
on a host that predates the interface; one that does not import it is
unaffected.

---

## `greentic:extension-design@0.1.0`

Exported by `DesignExtension` components. All four interfaces must be
implemented.

### `greentic:extension-design/tools`

Exposes callable tools to the LLM and designer UI.

```wit
interface tools {
  use greentic:extension-base/types.{extension-error};

  record tool-definition {
    name:               string,
    description:        string,
    input-schema-json:  string,         // JSON Schema for input
    output-schema-json: option<string>, // JSON Schema for output (optional)
  }

  list-tools:  func() -> list<tool-definition>;
  invoke-tool: func(name: string, args-json: string)
                 -> result<string, extension-error>;
}
```

**`list-tools`** — Returns all tools the extension provides. Called once at
startup. The host merges these into the LLM tool manifest.

**`invoke-tool`** — Called when the LLM or UI invokes a named tool. `args-json`
is a JSON object that conforms to the tool's `input-schema-json`. Return
a JSON string on success.

---

### `greentic:extension-design/validation`

Validates designer content against the extension's schema.

```wit
interface validation {
  use greentic:extension-base/types.{diagnostic};

  record validate-result {
    valid:       bool,
    diagnostics: list<diagnostic>,
  }

  validate-content: func(content-type: string, content-json: string)
                      -> validate-result;
}
```

**`validate-content`** — Validate a piece of designer content. `content-type`
identifies the content kind (e.g. `"adaptive-card"`). `content-json` is the
JSON representation. Return `ValidateResult { valid: true, diagnostics: [] }`
on success or a list of diagnostics on failure.

Implementations should return `valid: false` only when there are `error`
severity diagnostics. Warnings and hints are allowed alongside `valid: true`.

---

### `greentic:extension-design/prompting`

Contributes text fragments to the LLM system prompt.

```wit
interface prompting {
  record prompt-fragment {
    section:          string,  // logical section name, e.g. "rules"
    content-markdown: string,  // the fragment text (Markdown)
    priority:         u32,     // higher = injected earlier
  }

  system-prompt-fragments: func() -> list<prompt-fragment>;
}
```

**`system-prompt-fragments`** — Called once at startup. The host merges
fragments from all loaded design-extensions, sorted by descending priority,
and injects them into the LLM system prompt.

Use high priority (100+) for hard rules, lower priority (50) for examples.

---

### `greentic:extension-design/knowledge`

Provides a searchable knowledge base for few-shot and RAG retrieval.

```wit
interface knowledge {
  use greentic:extension-base/types.{extension-error};

  record entry-summary {
    id:       string,
    title:    string,
    category: string,
    tags:     list<string>,
  }

  record entry {
    id:           string,
    title:        string,
    category:     string,
    tags:         list<string>,
    content-json: string,  // extension-defined JSON payload
  }

  list-entries:    func(category-filter: option<string>)
                     -> list<entry-summary>;
  get-entry:       func(id: string)
                     -> result<entry, extension-error>;
  suggest-entries: func(query: string, limit: u32)
                     -> list<entry-summary>;
}
```

**`list-entries`** — List all (or filtered) knowledge entries. Returns
summaries only (no content).

**`get-entry`** — Fetch one entry by id. Returns `Err(InvalidInput)` if not
found.

**`suggest-entries`** — Keyword or semantic search returning up to `limit`
summaries. The host calls this when the LLM needs few-shot examples.

---

## `greentic:extension-bundle@0.1.0`

Exported by `BundleExtension` components.

### `greentic:extension-bundle/recipes`

Describes the bundle recipes the extension offers.

```wit
interface recipes {
  use greentic:extension-base/types.{extension-error};

  record recipe-summary {
    id:           string,
    display-name: string,
    description:  string,
    icon-path:    option<string>,
  }

  list-recipes:          func() -> list<recipe-summary>;
  recipe-config-schema:  func(recipe-id: string)
                           -> result<string, extension-error>;
  supported-capabilities: func(recipe-id: string)
                            -> result<list<string>, extension-error>;
}
```

**`list-recipes`** — Returns available recipes shown in the designer's
"Next" wizard step.

**`recipe-config-schema`** — Returns a JSON Schema string for the config
wizard of the given recipe. Returns `Err` if `recipe-id` is unknown.

**`supported-capabilities`** — Returns the capability IDs the generated
pack will include for the given recipe. The designer uses this to verify
that required design extensions are active.

---

### `greentic:extension-bundle/bundling`

Runs the bundle build.

```wit
interface bundling {
  use greentic:extension-base/types.{diagnostic, extension-error};

  record designer-session {
    flows-json:        string,         // serialized flow graph
    contents-json:     string,         // serialized designer content
    assets:            list<tuple<string, list<u8>>>,  // (path, bytes)
    capabilities-used: list<string>,
  }

  record bundle-artifact {
    filename: string,
    bytes:    list<u8>,
    sha256:   string,
  }

  validate-config: func(recipe-id: string, config-json: string)
                     -> list<diagnostic>;
  render:          func(recipe-id: string, config-json: string,
                        session: designer-session)
                     -> result<bundle-artifact, extension-error>;
}
```

**`validate-config`** — Validate the wizard config for a recipe before
running `render`. Returns an empty list on success.

**`render`** — Build the Application Pack artifact. Returns a `bundle-artifact`
with file name, raw bytes, and SHA-256 checksum on success.

---

## `greentic:extension-deploy@0.1.0`

Exported by `DeployExtension` components.

### `greentic:extension-deploy/targets`

Describes available deployment targets.

```wit
interface targets {
  use greentic:extension-base/types.{diagnostic, extension-error};

  record target-summary {
    id:               string,
    display-name:     string,
    description:      string,
    icon-path:        option<string>,
    supports-rollback: bool,
  }

  list-targets:          func() -> list<target-summary>;
  credential-schema:     func(target-id: string)
                           -> result<string, extension-error>;
  config-schema:         func(target-id: string)
                           -> result<string, extension-error>;
  validate-credentials:  func(target-id: string, credentials-json: string)
                           -> list<diagnostic>;
}
```

**`list-targets`** — Returns all targets shown in the deploy wizard.

**`credential-schema`** — Returns JSON Schema for the credential form.

**`config-schema`** — Returns JSON Schema for the deployment configuration
form.

**`validate-credentials`** — Pre-validates credentials before attempting
deployment. Called when the user submits the credential form.

---

### `greentic:extension-deploy/deployment`

Runs deployments and tracks status.

```wit
interface deployment {
  use greentic:extension-base/types.{extension-error};

  record deploy-request {
    target-id:       string,
    artifact-bytes:  list<u8>,
    credentials-json: string,
    config-json:     string,
    deployment-name: string,
  }

  enum deploy-status {
    pending,
    provisioning,
    configuring,
    starting,
    running,
    failed,
    rolled-back,
  }

  record deploy-job {
    id:        string,
    status:    deploy-status,
    message:   string,
    endpoints: list<string>,  // live URLs once running
  }

  deploy:   func(req: deploy-request) -> result<deploy-job, extension-error>;
  poll:     func(job-id: string)      -> result<deploy-job, extension-error>;
  rollback: func(job-id: string)      -> result<_, extension-error>;
}
```

**`deploy`** — Start a deployment. Returns immediately with a `deploy-job`
in `pending` or `provisioning` state.

**`poll`** — Query the current status of a running deployment job.

**`rollback`** — Attempt to roll back a deployment. Only valid when the
target's `supports-rollback` is `true`.

---

## Worked Call Example

This traces a complete LLM tool call through the runtime to the AC
extension:

1. User asks the designer: "Validate this card for me."
2. The LLM chooses the `validate_card` tool and emits:
   ```json
   { "name": "validate_card", "arguments": { "card": { ... } } }
   ```
3. The designer host resolves `validate_card` to
   `greentic:extension-design/validation.validate-content` via the tool
   mapping in `describe.json`.
4. The runtime calls:
   ```
   validate-content("adaptive-card", "{...card json...}")
   ```
   on the loaded `greentic.adaptive-cards` WASM component.
5. The extension parses the card JSON, runs structural checks, and returns:
   ```wit
   ValidateResult {
     valid: true,
     diagnostics: []
   }
   ```
6. The host serializes the result to JSON and returns it to the LLM as a
   tool result.
7. The LLM formats the result for the user.

For broker-mediated cross-extension calls, see
[cross-extension-communication.md](./cross-extension-communication.md).
