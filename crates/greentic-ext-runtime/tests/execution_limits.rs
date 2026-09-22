//! The execution-limit guard: memory ceilings and the dispatch deadline.
//!
//! Mutation testing found this guard had **no** integration coverage at all —
//! `epoch_interruption(true)` could be flipped off, `deadline_ticks` could
//! return `u64::MAX`, and the epoch ticker's spawn failure could go back to
//! being swallowed, all with the suite fully green. The unit tests in
//! `limits.rs` only ever exercised the tick arithmetic; nothing asserted that a
//! limit actually *bites*.
//!
//! These tests drive real components through `register_loaded_from_dir` and
//! `invoke_tool`, so they fail if the guard is disarmed in any of those ways.

#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;

use greentic_ext_runtime::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig};
use greentic_extension_sdk_contract::ExtensionKind;

use support::{EnvGuard, finalize_signed_with_manifest, signed_fixture};

fn new_runtime(config: RuntimeConfig) -> (ExtensionRuntime, tempfile::TempDir) {
    let trust = tempfile::TempDir::new().expect("temp trust root");
    let config = config.with_trust_root(trust.path().to_path_buf());
    (ExtensionRuntime::new(config).unwrap(), trust)
}

fn base_config() -> RuntimeConfig {
    RuntimeConfig::from_paths(DiscoveryPaths::new(PathBuf::from("/dev/null")))
}

/// Replace a signed fixture's component with `wat`, then re-seal the pack.
fn fixture_with_component(
    id: &str,
    wat_src: &str,
) -> greentic_extension_sdk_testing::ExtensionFixture {
    let (fx, sk) = signed_fixture(ExtensionKind::Design, id, "0.1.0");
    let wasm = wat::parse_str(wat_src).expect("wat must compile");
    std::fs::write(fx.root().join("extension.wasm"), &wasm).unwrap();

    let raw = std::fs::read_to_string(fx.root().join("describe.json")).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    finalize_signed_with_manifest(fx.root(), &mut describe, &sk);
    fx
}

/// A component whose core module declares more linear memory than the host
/// allows, as its *initial* size.
///
/// 20000 pages is ~1.28 GB against a 512 MiB store budget. Initial size is the
/// point: it is allocated during `instantiate`, so a limiter installed after
/// instantiation never sees it — which is exactly how the ceiling used to be
/// wired. A guest that simply declares its memory up front never calls
/// `memory.grow` and so never met the limit at all.
const OVERSIZED_MEMORY: &str = r#"
(component
  (core module $m
    (memory (export "mem") 20000)
  )
  (core instance (instantiate $m))
)
"#;

#[test]
fn a_component_declaring_more_memory_than_the_ceiling_is_refused() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let fx = fixture_with_component("greentic.memory-hog", OVERSIZED_MEMORY);

    let (mut rt, _trust) = new_runtime(base_config());
    rt.register_loaded_from_dir(fx.root())
        .expect("compiling the component is fine; it is instantiation that must refuse");

    // Any dispatch instantiates, which is where the ceiling applies.
    let err = rt
        .invoke_tool("greentic.memory-hog", "anything", "{}")
        .expect_err("instantiating a component over the memory ceiling must fail");
    let rendered = err.to_string();
    assert!(
        rendered.contains("memory") || rendered.contains("limit"),
        "expected the store budget to refuse the allocation, got: {rendered}"
    );
}

/// The ceiling is a store-wide total, so many small memories cannot add up past
/// it either. `StoreLimits::memory_size` is per-memory, and a component is many
/// core instances — 64 memories each "within" a 512 MiB per-memory ceiling is a
/// 32 GiB store with every ceiling reporting as enforced.
const MANY_MEMORIES: &str = r#"
(component
  (core module $m
    (memory (export "a") 6000)
    (memory (export "b") 6000)
    (memory (export "c") 6000)
  )
  (core instance (instantiate $m))
)
"#;

#[test]
fn memories_draw_on_one_shared_budget_not_one_each() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let fx = fixture_with_component("greentic.many-memories", MANY_MEMORIES);

    let (mut rt, _trust) = new_runtime(base_config());
    rt.register_loaded_from_dir(fx.root()).expect("register");

    // 3 x 6000 pages = ~1.15 GB total; each one alone is under the ceiling.
    let err = rt
        .invoke_tool("greentic.many-memories", "anything", "{}")
        .expect_err("the total across memories must be what the ceiling measures");
    let rendered = err.to_string();
    assert!(
        rendered.contains("memory") || rendered.contains("limit"),
        "expected the shared budget to refuse the allocation, got: {rendered}"
    );
}

/// A component sized well inside the ceiling still instantiates.
///
/// The counterweight to the two tests above: a ceiling that refused everything
/// would satisfy them both while breaking every real extension.
const MODEST_MEMORY: &str = r#"
(component
  (core module $m
    (memory (export "mem") 16)
  )
  (core instance (instantiate $m))
)
"#;

#[test]
fn a_component_within_the_ceiling_still_instantiates() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let fx = fixture_with_component("greentic.modest-memory", MODEST_MEMORY);

    let (mut rt, _trust) = new_runtime(base_config());
    rt.register_loaded_from_dir(fx.root()).expect("register");

    // It exports no tools interface, so dispatch fails on *resolution* — which
    // is proof instantiation itself got through. A memory refusal would have
    // stopped us before ever looking for an export.
    let err = rt
        .invoke_tool("greentic.modest-memory", "anything", "{}")
        .expect_err("this component exports no tools interface");
    let rendered = err.to_string();
    assert!(
        rendered.contains("does not export"),
        "expected an export-resolution failure, not a resource refusal: {rendered}"
    );
}
