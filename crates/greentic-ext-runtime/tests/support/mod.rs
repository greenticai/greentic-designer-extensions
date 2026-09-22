//! Shared test helpers for runtime integration tests.
//!
//! Tests must not run in parallel when mutating process environment.
//! The `EnvGuard::set` guard serializes via a global Mutex.
#![allow(dead_code)]

use std::sync::{Mutex, MutexGuard, OnceLock};

fn env_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub struct EnvGuard {
    key: String,
    prev: Option<String>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub fn set(key: &str, value: &str) -> Self {
        let lock = env_mutex()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var(key).ok();
        // SAFETY: serialized via global mutex; we hold the lock for guard lifetime.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(key, value);
        }
        EnvGuard {
            key: key.to_string(),
            prev,
            _lock: lock,
        }
    }

    /// Remove an env var for the lifetime of the guard, holding the global
    /// mutex for exclusive access. On drop, restore the previous value (if any).
    pub fn remove(key: &str) -> Self {
        let lock = env_mutex()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var(key).ok();
        // SAFETY: serialized via global mutex; we hold the lock for guard lifetime.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(key);
        }
        EnvGuard {
            key: key.to_string(),
            prev,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}

/// `ExtensionFixtureBuilder` (sdk-testing 1.2.0-research) emits each
/// `runtime.components` entry with `gtpack: None` and only `oci_ref` set.
/// Source-dir loading needs `gtpack.file` to resolve the wasm path, so this
/// helper rewrites every component to point at `extension.wasm` (the file
/// the fixture writes alongside describe.json). Call before signing —
/// otherwise the signature would cover the original (gtpack-less) bytes.
pub fn populate_gtpack_for_local_load(
    describe: &mut greentic_extension_sdk_contract::DescribeJson,
) {
    use greentic_extension_sdk_contract::describe::provider::RuntimeGtpack;

    for component in describe.runtime.components.values_mut() {
        if component.gtpack.is_none() {
            component.gtpack = Some(RuntimeGtpack {
                file: "extension.wasm".to_string(),
                sha256: "0".repeat(64),
                pack_id: describe.metadata.id.clone(),
                component_version: describe.metadata.version.clone(),
            });
        }
    }
}

/// Recursively list every file under `dir`.
fn walk_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for ent in std::fs::read_dir(dir).unwrap().flatten() {
        let path = ent.path();
        if path.is_dir() {
            out.extend(walk_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Build the whole-archive manifest bytes over the files in `dir`.
/// `build_manifest` excludes `describe.json` and `manifest.json` itself, so the
/// ledger covers exactly the integrity-relevant payload (wasm + assets).
pub fn build_dir_manifest_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for path in walk_files(dir) {
        let rel = path
            .strip_prefix(dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel == greentic_extension_sdk_contract::MANIFEST_ENTRY_NAME || rel.is_empty() {
            continue;
        }
        entries.push((rel, std::fs::read(&path).unwrap()));
    }
    let manifest = greentic_extension_sdk_contract::build_manifest(
        entries.iter().map(|(p, b)| (p.as_str(), b.as_slice())),
    );
    serde_jcs::to_vec(&manifest).unwrap()
}

/// Finalize a fixture into a real signed pack, mirroring the SDK producer:
/// build the whole-archive manifest over `dir`, write `manifest.json`, bind it
/// into the describe (`manifestSha256`), sign, and write the signed
/// `describe.json`. Binding happens BEFORE signing so the signature transitively
/// covers the ledger (audit C2). `describe.json` is excluded from the manifest,
/// so overwriting it with the signed bytes does not invalidate the ledger.
pub fn finalize_signed_with_manifest(
    dir: &std::path::Path,
    describe: &mut greentic_extension_sdk_contract::DescribeJson,
    sk: &ed25519_dalek::SigningKey,
) {
    let manifest_bytes = build_dir_manifest_bytes(dir);
    std::fs::write(
        dir.join(greentic_extension_sdk_contract::MANIFEST_ENTRY_NAME),
        &manifest_bytes,
    )
    .unwrap();
    greentic_extension_sdk_contract::bind_manifest(describe, &manifest_bytes);
    greentic_extension_sdk_contract::sign_describe(describe, sk).expect("sign");
    std::fs::write(
        dir.join("describe.json"),
        serde_json::to_string_pretty(describe).unwrap(),
    )
    .unwrap();
}

/// Like [`signed_fixture`] but signs with a caller-supplied key.
///
/// Needed wherever a test has to produce a second pack that the trust store
/// will accept for an id already pinned — a downgrade, say. A fresh key would
/// be rejected as `PublisherKeyChanged` long before the case under test.
pub fn signed_fixture_with_key(
    kind: greentic_extension_sdk_contract::ExtensionKind,
    id: &str,
    version: &str,
    sk: &ed25519_dalek::SigningKey,
) -> greentic_extension_sdk_testing::ExtensionFixture {
    let minimal_wasm = wat::parse_str(r"(component)").expect("wat component must compile");
    let fixture = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(kind, id, version)
        .offer("greentic:test/ping", "1.0.0")
        .with_wasm(minimal_wasm)
        .build()
        .expect("fixture build");

    let describe_path = fixture.root().join("describe.json");
    let raw = std::fs::read_to_string(&describe_path).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    populate_gtpack_for_local_load(&mut describe);
    finalize_signed_with_manifest(fixture.root(), &mut describe, sk);

    fixture
}

/// Build a signed extension fixture using the `ExtensionFixtureBuilder`
/// from `greentic-extension-sdk-testing`, then sign its describe.json with a fresh
/// ed25519 key. Returns the fixture and the signing key used.
pub fn signed_fixture(
    kind: greentic_extension_sdk_contract::ExtensionKind,
    id: &str,
    version: &str,
) -> (
    greentic_extension_sdk_testing::ExtensionFixture,
    ed25519_dalek::SigningKey,
) {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let minimal_wasm = wat::parse_str(r"(component)").expect("wat component must compile");
    let fixture = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(kind, id, version)
        .offer("greentic:test/ping", "1.0.0")
        .with_wasm(minimal_wasm)
        .build()
        .expect("fixture build");

    // Read, patch gtpack, sign, write back. Patch must run before sign.
    let describe_path = fixture.root().join("describe.json");
    let raw = std::fs::read_to_string(&describe_path).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    populate_gtpack_for_local_load(&mut describe);
    let sk = SigningKey::generate(&mut OsRng);
    finalize_signed_with_manifest(fixture.root(), &mut describe, &sk);

    (fixture, sk)
}

/// Build a signed `ProviderExtension` fixture whose `describe.json` points
/// `runtime.components[stub].gtpack.file` at `"runtime/provider.gtpack"` (a
/// text placeholder — intentionally NOT parseable as a WASM component), while
/// the real design-side `extension.wasm` sits at the directory root.
///
/// This mirrors the dual-component layout used by real provider extensions
/// (e.g. `greentic.provider.telegram-1.3.1-research`):
/// - `extension.wasm` — design-side WebAssembly (metadata, icons, i18n).
/// - `runtime/provider.gtpack` — intentional placeholder; runner-host fetches
///   the real runtime lazily; designer must never try to parse it as WASM.
pub fn signed_provider_fixture_with_placeholder_gtpack(
    id: &str,
    version: &str,
) -> (
    greentic_extension_sdk_testing::ExtensionFixture,
    ed25519_dalek::SigningKey,
) {
    use ed25519_dalek::SigningKey;
    use greentic_extension_sdk_contract::describe::provider::RuntimeGtpack;
    use rand::rngs::OsRng;

    let minimal_wasm = wat::parse_str(r"(component)").expect("wat component must compile");
    // ExtensionFixtureBuilder writes `extension.wasm` at root automatically.
    let fixture = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(
        greentic_extension_sdk_contract::ExtensionKind::Provider,
        id,
        version,
    )
    .offer("greentic:test/ping", "1.0.0")
    .with_wasm(minimal_wasm)
    .build()
    .expect("fixture build");

    // Create the placeholder `runtime/provider.gtpack` (text, not valid WASM).
    let runtime_dir = fixture.root().join("runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::write(
        runtime_dir.join("provider.gtpack"),
        b"placeholder - not valid WASM; runner-host fetches the real pack",
    )
    .unwrap();

    // Patch describe.json to point at `runtime/provider.gtpack`, NOT at
    // `extension.wasm`. This is the layout that was breaking the loader.
    let describe_path = fixture.root().join("describe.json");
    let raw = std::fs::read_to_string(&describe_path).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    for component in describe.runtime.components.values_mut() {
        component.gtpack = Some(RuntimeGtpack {
            file: "runtime/provider.gtpack".to_string(),
            sha256: "0".repeat(64),
            pack_id: describe.metadata.id.clone(),
            component_version: describe.metadata.version.clone(),
        });
    }

    // Build manifest + bind + sign over the final (patched) describe so the
    // pack passes the runtime's hardened verify chain.
    let sk = SigningKey::generate(&mut OsRng);
    finalize_signed_with_manifest(fixture.root(), &mut describe, &sk);

    (fixture, sk)
}

/// Build a signed extension fixture that has **no** `extension.wasm` at its
/// source-dir root. The fixture is created normally (the builder always writes
/// `extension.wasm`), then the root WASM is removed so the loader must fall
/// back to `describe.runtime.components[X].gtpack.file`.
///
/// `gtpack.file` is patched to point at an internal WASM that DOES exist — the
/// fixture builder writes the component bytes to `extension.wasm`, which we
/// rename to `inner.wasm` before signing, then update `gtpack.file` accordingly.
/// This gives the loader a valid path to resolve via the fallback branch.
pub fn signed_fixture_without_root_wasm(
    kind: greentic_extension_sdk_contract::ExtensionKind,
    id: &str,
    version: &str,
) -> (
    greentic_extension_sdk_testing::ExtensionFixture,
    ed25519_dalek::SigningKey,
) {
    use ed25519_dalek::SigningKey;
    use greentic_extension_sdk_contract::describe::provider::RuntimeGtpack;
    use rand::rngs::OsRng;

    let minimal_wasm = wat::parse_str(r"(component)").expect("wat component must compile");
    let fixture = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(kind, id, version)
        .offer("greentic:test/ping", "1.0.0")
        .with_wasm(minimal_wasm)
        .build()
        .expect("fixture build");

    // Move extension.wasm → inner.wasm so there is no root `extension.wasm`.
    // The loader's unconditional check will not find one and will fall back to
    // the describe.runtime.components path.
    let root_wasm = fixture.root().join("extension.wasm");
    let inner_wasm = fixture.root().join("inner.wasm");
    std::fs::rename(&root_wasm, &inner_wasm).expect("rename extension.wasm → inner.wasm");

    // Patch describe.json: point gtpack.file at "inner.wasm" (the actual WASM).
    let describe_path = fixture.root().join("describe.json");
    let raw = std::fs::read_to_string(&describe_path).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    for component in describe.runtime.components.values_mut() {
        component.gtpack = Some(RuntimeGtpack {
            file: "inner.wasm".to_string(),
            sha256: "0".repeat(64),
            pack_id: describe.metadata.id.clone(),
            component_version: describe.metadata.version.clone(),
        });
    }

    // Build manifest + bind + sign over the final (patched) describe so the
    // pack passes the runtime's hardened verify chain.
    let sk = SigningKey::generate(&mut OsRng);
    finalize_signed_with_manifest(fixture.root(), &mut describe, &sk);

    (fixture, sk)
}

/// Build a signed fixture with a dual-component layout for a non-Provider kind.
/// The design-side `extension.wasm` sits at root AND `describe.json` points
/// `gtpack.file` at a placeholder that is intentionally NOT valid WASM.
///
/// This mirrors the layout used by e.g. `greentic.llm-openai-1.3.1-research`
/// (`DesignExtension`) and `greentic.bundle-standard-1.3.0-research`
/// (`BundleExtension`): a real `extension.wasm` at root, while `describe.json`
/// names a runtime gtpack that runner-host uses for flow-execution but that
/// wasmtime cannot parse as a raw component.
pub fn signed_fixture_with_placeholder_gtpack(
    kind: greentic_extension_sdk_contract::ExtensionKind,
    id: &str,
    version: &str,
) -> (
    greentic_extension_sdk_testing::ExtensionFixture,
    ed25519_dalek::SigningKey,
) {
    use ed25519_dalek::SigningKey;
    use greentic_extension_sdk_contract::describe::provider::RuntimeGtpack;
    use rand::rngs::OsRng;

    let minimal_wasm = wat::parse_str(r"(component)").expect("wat component must compile");
    // Builder writes extension.wasm at root automatically.
    let fixture = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(kind, id, version)
        .offer("greentic:test/ping", "1.0.0")
        .with_wasm(minimal_wasm)
        .build()
        .expect("fixture build");

    // Create a placeholder runtime gtpack (text, not valid WASM).
    let runtime_dir = fixture.root().join("runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::write(
        runtime_dir.join("component.gtpack"),
        b"placeholder - not valid WASM; runner-host fetches the real pack",
    )
    .unwrap();

    // Patch describe.json to point at the placeholder, NOT at extension.wasm.
    let describe_path = fixture.root().join("describe.json");
    let raw = std::fs::read_to_string(&describe_path).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    for component in describe.runtime.components.values_mut() {
        component.gtpack = Some(RuntimeGtpack {
            file: "runtime/component.gtpack".to_string(),
            sha256: "0".repeat(64),
            pack_id: describe.metadata.id.clone(),
            component_version: describe.metadata.version.clone(),
        });
    }

    // Build manifest + bind + sign over the final (patched) describe so the
    // pack passes the runtime's hardened verify chain.
    let sk = SigningKey::generate(&mut OsRng);
    finalize_signed_with_manifest(fixture.root(), &mut describe, &sk);

    (fixture, sk)
}

/// Mutate an installed fixture's describe.json to invalidate its signature.
pub fn tamper_fixture(fixture: &greentic_extension_sdk_testing::ExtensionFixture) {
    let path = fixture.root().join("describe.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    describe.metadata.version = "99.99.99".into();
    std::fs::write(&path, serde_json::to_string_pretty(&describe).unwrap()).unwrap();
}

/// Build an **unsigned** fixture (no .signature field). Mirrors existing
/// `ExtensionFixtureBuilder` default output, but also patches gtpack so
/// source-dir loads can resolve the wasm path (sdk-testing 1.2.0-research
/// leaves gtpack unset on every component).
pub fn unsigned_fixture(
    kind: greentic_extension_sdk_contract::ExtensionKind,
    id: &str,
    version: &str,
) -> greentic_extension_sdk_testing::ExtensionFixture {
    let minimal_wasm = wat::parse_str(r"(component)").expect("wat component must compile");
    let fixture = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(kind, id, version)
        .offer("greentic:test/ping", "1.0.0")
        .with_wasm(minimal_wasm)
        .build()
        .expect("fixture build");

    let describe_path = fixture.root().join("describe.json");
    let raw = std::fs::read_to_string(&describe_path).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    populate_gtpack_for_local_load(&mut describe);
    std::fs::write(
        &describe_path,
        serde_json::to_string_pretty(&describe).unwrap(),
    )
    .unwrap();

    fixture
}
