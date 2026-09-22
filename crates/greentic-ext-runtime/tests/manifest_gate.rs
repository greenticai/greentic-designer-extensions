//! Audit P5 (consumer hardening): ext-runtime now **fails closed** on the
//! whole-archive integrity ledger. A pack with no `manifest.json` is rejected
//! (only the `dev-allow-unsigned` escape loads it); a present manifest must be
//! bound into the signed describe (`manifestSha256`) AND every listed file must
//! hash-match. The fixtures here are produced bind→sign→manifest, exactly like
//! the SDK producer.

#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;

use greentic_ext_runtime::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig, RuntimeError};
use greentic_extension_sdk_contract::ExtensionKind;

use support::{EnvGuard, signed_fixture};

/// The returned `TempDir` is the trust root and must be held for the test's
/// lifetime. It is not optional: the default root is the developer's real
/// `~/.greentic`, and `signed_fixture` mints a fresh key per call, so a
/// default-rooted test pins junk on its first run and then fails every later
/// run with `PublisherKeyChanged`.
fn new_runtime() -> (ExtensionRuntime, tempfile::TempDir) {
    let trust = tempfile::TempDir::new().expect("temp trust root");
    let config = RuntimeConfig::from_paths(DiscoveryPaths::new(PathBuf::from("/dev/null")))
        .with_trust_root(trust.path().to_path_buf());
    (ExtensionRuntime::new(config).unwrap(), trust)
}

fn manifest_path(dir: &std::path::Path) -> PathBuf {
    dir.join(greentic_extension_sdk_contract::MANIFEST_ENTRY_NAME)
}

#[test]
fn pack_without_manifest_is_rejected() {
    // Fail-closed: removing the ledger from an otherwise-valid signed pack must
    // refuse to load (audit P5 — was previously fail-open).
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.no-manifest", "0.1.0");
    std::fs::remove_file(manifest_path(fx.root())).unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("manifest.json absent"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn pack_with_intact_manifest_loads() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.with-manifest", "0.1.0");
    let (mut rt, trust) = new_runtime();
    rt.register_loaded_from_dir(fx.root())
        .expect("a bound, intact manifest must verify");

    // Positive control for `valid_signature_with_broken_manifest_pins_nothing`,
    // which proves the anchor was NOT reached by asserting this directory is
    // absent. That assertion is only meaningful if a *successful* load does
    // create it — otherwise an SDK change that relocates the store would
    // silently disarm the ordering guard with nothing turning red.
    assert!(
        trust.path().join("trust").exists(),
        "a successful load must reach the trust store, or the ordering guard proves nothing"
    );
}

#[test]
fn pack_with_tampered_wasm_after_manifest_is_rejected() {
    // Manifest stays intact (so the binding still matches), but the wasm it
    // lists is mutated — caught by the per-entry hash check.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.tampered-wasm", "0.1.0");
    let wasm_path = fx.root().join("extension.wasm");
    let mut bytes = std::fs::read(&wasm_path).unwrap();
    bytes.push(0xff);
    std::fs::write(&wasm_path, bytes).unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("manifest sha256 mismatch"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn pack_with_manifest_listing_missing_file_is_rejected() {
    // Manifest (bound) lists extension.wasm, but the file is removed from disk —
    // caught by the per-entry existence check, binding still intact.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.missing-file", "0.1.0");
    std::fs::remove_file(fx.root().join("extension.wasm")).unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("manifest lists missing file"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn tampered_manifest_breaks_binding() {
    // Any post-sign mutation of manifest.json breaks the describe's manifestSha256
    // binding — the signature transitively covers the ledger (audit C2). This is
    // the dominant protection: it fires before the per-entry / schema checks,
    // regardless of what the tampered manifest claims (bad schema, phantom
    // entries, swapped hashes).
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.tampered-manifest", "0.1.0");
    let bogus = serde_json::json!({
        "schema": "greentic.gtxpack.manifest/v999",
        "entries": [],
    });
    std::fs::write(
        manifest_path(fx.root()),
        serde_json::to_vec(&bogus).unwrap(),
    )
    .unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("manifest binding"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn valid_signature_with_broken_manifest_pins_nothing() {
    // Ordering gate: the anchor must not be written until the artifact's
    // integrity ledger has passed. The signature here is genuinely valid — only
    // the ledger is broken — so steps 1 and 2 accept and the pin is the next
    // thing that would run.
    //
    // The trust store is deliberately the same one gtdx writes. A pin from a
    // *rejected* load is therefore not a local mistake: it permanently blocks
    // the real publisher for this id, in both tools, until someone hand-edits
    // publishers.json. An attacker who cannot complete a load must not be able
    // to squat an id this way.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.guardrail-pii", "0.1.0");
    std::fs::remove_file(manifest_path(fx.root())).unwrap();

    let (mut rt, trust) = new_runtime();
    rt.register_loaded_from_dir(fx.root())
        .expect_err("a pack with no manifest must be rejected");

    // Asserted one level above publishers.json: `pin_or_verify` creates the
    // trust dir and its lockfile before inserting, so the directory existing at
    // all proves the store was reached.
    assert!(
        !trust.path().join("trust").exists(),
        "a rejected load touched the shared trust store"
    );
}

#[test]
fn pack_carrying_a_file_the_ledger_does_not_list_is_rejected() {
    // Coverage gate. An install unpacks an archive whose contents the SDK's
    // archive verifier already requires to match the ledger exactly, so a file
    // on disk that the ledger never mentions is by definition not part of the
    // signed pack.
    //
    // The concrete attack this closes: `wasm_component_path` prefers a root
    // `extension.wasm` unconditionally, so on a pack that ships none (the
    // gtpack-fallback layout) an attacker who can write into the extension
    // directory could drop one in. Every listed entry would still hash-match,
    // the describe signature and manifest binding would both still verify — and
    // the component the runtime instantiated would be entirely theirs.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.smuggled-file", "0.1.0");
    std::fs::write(fx.root().join("smuggled.wasm"), b"\0asm\x01\0\0\0").unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("smuggled.wasm") && reason.contains("absent from manifest.json"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn a_smuggled_file_in_a_subdirectory_is_rejected_too() {
    // The coverage walk has to recurse; a nested drop site is the obvious way
    // around a root-only check.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.smuggled-nested", "0.1.0");
    let nested = fx.root().join("assets").join("deep");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("payload.bin"), b"x").unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("assets/deep/payload.bin"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_ledger_entry_replaced_by_a_symlink_is_rejected() {
    // Swapping a listed file for a symlink pointing at identical bytes outside
    // the pack would hash-match if the check followed the link. It must not:
    // what the ledger commits to is the file *in the pack*, and the link target
    // is mutable by anyone who can write where it points.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.symlinked-wasm", "0.1.0");

    let wasm = fx.root().join("extension.wasm");
    let outside = tempfile::TempDir::new().unwrap();
    let target = outside.path().join("extension.wasm");
    std::fs::copy(&wasm, &target).unwrap();
    std::fs::remove_file(&wasm).unwrap();
    std::os::unix::fs::symlink(&target, &wasm).unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("not a regular file"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

/// Rewrite `manifest.json` with `mutate` applied to the parsed ledger, then
/// re-bind and re-sign so the pack is internally consistent again.
///
/// Without the re-bind the describe's `manifestSha256` no longer matches and
/// the *binding* check rejects first — which is what made it possible for the
/// path rules to look covered while never actually running.
fn reseal_with_manifest<F>(
    fx: &greentic_extension_sdk_testing::ExtensionFixture,
    sk: &ed25519_dalek::SigningKey,
    mutate: F,
) where
    F: FnOnce(&mut greentic_extension_sdk_contract::Manifest),
{
    let raw = std::fs::read(manifest_path(fx.root())).unwrap();
    let mut manifest: greentic_extension_sdk_contract::Manifest =
        serde_json::from_slice(&raw).unwrap();
    mutate(&mut manifest);

    let bytes = serde_jcs::to_vec(&manifest).unwrap();
    std::fs::write(manifest_path(fx.root()), &bytes).unwrap();

    let describe_raw = std::fs::read_to_string(fx.root().join("describe.json")).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&describe_raw).unwrap();
    greentic_extension_sdk_contract::bind_manifest(&mut describe, &bytes);
    greentic_extension_sdk_contract::sign_describe(&mut describe, sk).expect("re-sign");
    std::fs::write(
        fx.root().join("describe.json"),
        serde_json::to_string_pretty(&describe).unwrap(),
    )
    .unwrap();
}

#[test]
fn a_bound_ledger_that_traverses_out_of_the_pack_is_rejected() {
    // The malicious-publisher case: the attacker controls the ledger AND the
    // signing key, so binding and signature both verify. `dir.join("../x")`
    // walks out of the pack, so without the path rule the ledger could commit
    // to bytes that are not in the artifact at all.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, sk) = signed_fixture(ExtensionKind::Design, "greentic.traversing-ledger", "0.1.0");
    reseal_with_manifest(&fx, &sk, |m| {
        m.entries[0].path = "../escaped.wasm".to_string();
    });

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("not a plain relative path"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn a_bound_ledger_with_an_absolute_path_is_rejected() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, sk) = signed_fixture(ExtensionKind::Design, "greentic.absolute-ledger", "0.1.0");
    reseal_with_manifest(&fx, &sk, |m| {
        m.entries[0].path = "/etc/hostname".to_string();
    });

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("not a plain relative path"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn a_pack_nested_past_the_depth_cap_is_refused() {
    // The coverage walk runs over an unverified directory, so its shape is
    // attacker-controlled at that moment; an unbounded recursive walk over a
    // deliberately deep tree aborts the process instead of rejecting the pack.
    // Empty directories carry no files, so the signed ledger stays intact and
    // the walk is genuinely what trips.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.deep-pack", "0.1.0");
    let mut deep = fx.root().to_path_buf();
    for i in 0..40 {
        deep = deep.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&deep).unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    let rendered = err.to_string();
    assert!(
        rendered.contains("nests deeper than"),
        "expected the depth cap to trip, got: {rendered}"
    );
}

#[cfg(unix)]
#[test]
fn a_backslash_name_cannot_impersonate_a_nested_ledger_entry() {
    // On Linux a backslash is an ordinary filename byte. The coverage walk used
    // to lower every on-disk name through `to_string_lossy().replace('\\', "/")`
    // before comparing, so a root file literally named `a\b.txt` rendered as
    // `a/b.txt` and matched the ledger entry for a *different* file — an
    // unlisted, unhashed file present in a pack the gate called intact.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, sk) = signed_fixture(ExtensionKind::Design, "greentic.backslash", "0.1.0");

    // A genuine nested entry for the impostor to collide with.
    std::fs::create_dir_all(fx.root().join("a")).unwrap();
    std::fs::write(fx.root().join("a").join("b.txt"), b"real").unwrap();
    let raw = std::fs::read_to_string(fx.root().join("describe.json")).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    support::finalize_signed_with_manifest(fx.root(), &mut describe, &sk);

    // Now drop the impostor in, after the pack was sealed.
    std::fs::write(fx.root().join(r"a\b.txt"), b"smuggled").unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("absent from manifest.json"),
            "unexpected reason: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_directory_is_reported_as_one_unlisted_entry() {
    // The walk uses `symlink_metadata`, so a symlink-to-dir is not descended
    // into — it shows up as a single unlisted entry and the pack is refused.
    // With plain `metadata` it would be followed and its contents walked as if
    // they were part of the pack.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.symlinked-dir", "0.1.0");

    let outside = tempfile::TempDir::new().unwrap();
    std::fs::write(outside.path().join("payload.wasm"), b"x").unwrap();
    std::os::unix::fs::symlink(outside.path(), fx.root().join("vendor")).unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt.register_loaded_from_dir(fx.root()).unwrap_err();
    match err {
        RuntimeError::SignatureInvalid { reason, .. } => assert!(
            reason.contains("vendor") && reason.contains("absent from manifest.json"),
            "the symlink itself must be the unlisted entry, not its contents: {reason}",
        ),
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn the_component_must_still_match_the_ledger_when_it_is_read() {
    // The check-to-use window. The gate walks the directory, but the loader
    // then re-decided *which* file to compile with a fresh `exists()` stat —
    // and `wasm_component_path` prefers a root `extension.wasm` unconditionally.
    // For a pack that ships none, a file created after the walk won outright,
    // never having been hashed by anything.
    //
    // Simulated by sealing a pack without a root component and dropping one in
    // afterwards, which is the same state the race produces.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, sk) = signed_fixture(ExtensionKind::Design, "greentic.late-component", "0.1.0");

    std::fs::remove_file(fx.root().join("extension.wasm")).unwrap();
    std::fs::create_dir_all(fx.root().join("runtime")).unwrap();
    let real = wat::parse_str("(component)").unwrap();
    std::fs::write(fx.root().join("runtime").join("pack.wasm"), &real).unwrap();

    let raw = std::fs::read_to_string(fx.root().join("describe.json")).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    for component in describe.runtime.components.values_mut() {
        if let Some(gtpack) = component.gtpack.as_mut() {
            gtpack.file = "runtime/pack.wasm".to_string();
        }
    }
    support::finalize_signed_with_manifest(fx.root(), &mut describe, &sk);

    // The pack is sealed and valid. Now the attacker's file appears.
    std::fs::write(fx.root().join("extension.wasm"), &real).unwrap();

    let (mut rt, _trust) = new_runtime();
    let err = rt
        .register_loaded_from_dir(fx.root())
        .expect_err("a component the ledger never covered must not be compiled");
    let rendered = err.to_string();
    assert!(
        rendered.contains("not covered by the signed manifest")
            || rendered.contains("absent from manifest.json"),
        "unexpected reason: {rendered}"
    );
}
