// Everything below is `wasmtime::component::bindgen!` output. Generated code is
// not held to this crate's lint bar, but the suppression is enumerated rather
// than a blanket `allow(warnings)` so a *new* class of warning here still
// surfaces instead of being pre-silenced.
#![allow(clippy::all, clippy::pedantic, dead_code, unused_imports, missing_docs)]

// Bind against the design-extension world from the component's perspective.
// wasmtime bindgen! generates:
//   - add_to_linker() for `import` items (host implements these for the component)
//   - typed export accessors for `export` items (host calls these on the component)
//
// NOTE: wasmtime appends a version suffix to package module names when multiple
// versions of the same package namespace coexist in wit/deps (required for v2
// dual-support). The unversioned paths that existed before Task 1 become:
//   greentic::extension_design  ->  exports::greentic::extension_design0_2_0
//   greentic::extension_base    ->  greentic::extension_base0_1_0
// Callers in runtime*.rs use these versioned paths directly.
wasmtime::component::bindgen!({
    path: "wit",
    world: "greentic:extension-design/design-extension@0.2.0",
});

// ---------------------------------------------------------------------------
// Deploy-extension bindings
//
// Generated in a sibling `mod deploy` to keep the type namespace isolated
// from the design-extension bindings above. Both worlds share
// `greentic:extension-base` + `greentic:extension-host/*`, so generating
// them in the root module would cause duplicate-type errors.
// ---------------------------------------------------------------------------
pub mod deploy {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:extension-deploy/deploy-extension@0.1.0",
    });
}

// ---------------------------------------------------------------------------
// Bundle-extension bindings
//
// Same pattern as deploy: isolated submodule because all three worlds share
// `extension-base` + `extension-host` types and re-binding them at the root
// would conflict. The bundle world exports `recipes` and `bundling` (the
// host calls `bundling.render(...)` in `runtime::render_bundle`); it imports
// the standard host triplet (logging / i18n / broker), wired through the
// shared `add_to_linker` helpers.
// ---------------------------------------------------------------------------
pub mod bundle {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:extension-bundle/bundle-extension@0.1.0",
    });
}

// ---------------------------------------------------------------------------
// DW-Composer-extension bindings
//
// Isolated submodule for the `greentic:dw-composer/dw-composer-extension`
// world. Composer extensions export a domain-specific `composer` interface
// (`greentic:dw-composer/composer@0.1.0`) instead of the generic
// `greentic:extension-design/tools` interface. Keeping them in their own
// submodule avoids duplicate-type conflicts with the design-extension
// bindings above.
// ---------------------------------------------------------------------------
pub mod dw_composer {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:dw-composer/dw-composer-extension@0.1.0",
    });
}

// ---------------------------------------------------------------------------
// v2-contract bindings (unified 6-variant extension-error, spec
// 2026-06-07-extension-response-envelope-design.md). Old-world modules above
// stay for extensions built against the previous WIT; the runtime resolves
// per-extension at dispatch time (see runtime::resolve_iface_versions).
// ---------------------------------------------------------------------------
pub mod design_v03 {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:extension-design/design-extension@0.3.0",
    });
}

// ---------------------------------------------------------------------------
// design-extension @0.4.0 bindings.
//
// Identical to the @0.3.0 world plus one additive import:
// `greentic:oauth-broker/broker-v1@1.0.0`. The version bump (rather than an
// in-place edit of @0.3.0) keeps the world signature versioned, so a component
// compiled against the broker-capable world is distinguishable from one that is
// not. This is the only world that generates the oauth-broker host bindings;
// the broker `Host` impl (host_state.rs) and linker wiring (loaded.rs) target
// this module. Registering broker-v1 once in the shared linker covers every
// instantiated component regardless of the world version it targets.
// ---------------------------------------------------------------------------
pub mod design_v04 {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:extension-design/design-extension@0.4.0",
    });
}

pub mod deploy_v02 {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:extension-deploy/deploy-extension@0.2.0",
    });
}

pub mod bundle_v02 {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:extension-bundle/bundle-extension@0.2.0",
    });
}

pub mod dw_composer_v02 {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:dw-composer/dw-composer-extension@0.2.0",
    });
}

// ---------------------------------------------------------------------------
// SoRX runtime-extension bindings
//
// Isolated submodule (same reason as deploy/bundle): the world shares
// `greentic:extension-host/*` types, so binding at the root would conflict.
// The world exports `control` and `observe` (the host calls them in
// `runtime_sorx::{control,observe}`); it imports only `greentic:extension-host/logging`.
// ---------------------------------------------------------------------------
pub mod sorx {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "greentic:extension-sorx/sorx-runtime-extension",
    });
}
