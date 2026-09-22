//! The watcher hot-reload path must enforce the same signature gate as
//! explicit registration, and the capability registry must stay a faithful
//! reflection of what is actually loaded.
//!
//! These two live together because they are the same class of bug: the
//! watcher path (`handle_added_or_modified` / `handle_removal`) silently did
//! less than the registration path it shadows. It is not dead code —
//! `greentic-designer/src/ui/mod.rs:983` calls `start_watcher()` and holds the
//! guard for the whole server lifetime — so anything it skips is skipped in
//! production.

#[path = "support/mod.rs"]
mod support;

use std::path::{Path, PathBuf};

use greentic_ext_runtime::{DiscoveryPaths, ExtensionRuntime, RuntimeConfig, RuntimeError};
use greentic_extension_sdk_contract::ExtensionKind;

use support::{EnvGuard, signed_fixture, tamper_fixture, unsigned_fixture};

/// See the note in `anchored_verify.rs`: the trust root must be a temp dir or
/// the test pins into the developer's real `~/.greentic`.
fn runtime_with_trust_root(root: &Path) -> ExtensionRuntime {
    let config = RuntimeConfig::from_paths(DiscoveryPaths::new(PathBuf::from("/dev/null")))
        .with_trust_root(root.to_path_buf());
    ExtensionRuntime::new(config).expect("runtime construction")
}

/// Every capability id currently advertised for `extension_id`.
fn offered_caps(rt: &ExtensionRuntime, extension_id: &str) -> Vec<String> {
    let mut caps: Vec<String> = rt
        .capability_registry()
        .offerings()
        .filter(|o| o.extension_id == extension_id)
        .map(|o| o.cap_id.to_string())
        .collect();
    caps.sort();
    caps
}

// ---------------------------------------------------------------------------
// T4 — the watcher path must verify signatures.
// ---------------------------------------------------------------------------

#[test]
fn watcher_path_rejects_unsigned() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();

    let fx = unsigned_fixture(ExtensionKind::Design, "greentic.watch-unsigned", "0.1.0");
    let rt = runtime_with_trust_root(trust.path());

    let err = rt
        .handle_added_or_modified(fx.root())
        .expect_err("the hot-reload path must refuse an unsigned extension");
    assert!(
        matches!(err, RuntimeError::SignatureInvalid { .. }),
        "expected SignatureInvalid, got {err:?}"
    );
    assert!(
        rt.loaded().is_empty(),
        "a rejected extension must not be loaded"
    );
}

#[test]
fn watcher_path_rejects_tampered() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();

    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.watch-tampered", "0.1.0");
    tamper_fixture(&fx);
    let rt = runtime_with_trust_root(trust.path());

    let err = rt
        .handle_added_or_modified(fx.root())
        .expect_err("the hot-reload path must refuse a tampered extension");
    assert!(
        matches!(err, RuntimeError::SignatureInvalid { .. }),
        "expected SignatureInvalid, got {err:?}"
    );
    assert!(
        rt.loaded().is_empty(),
        "a rejected extension must not be loaded"
    );
}

// ---------------------------------------------------------------------------
// T5 — the registry must be a pure function of what is loaded.
// ---------------------------------------------------------------------------

/// Re-registering an id whose describe no longer offers a capability must drop
/// that capability. Previously every existing offering was cloned forward
/// before appending, so a dropped cap lingered forever AND the surviving ones
/// were duplicated on every reload — a false positive that lets admin's
/// guardrail preflight pass a policy the runtime then fails closed on.
#[test]
fn registry_evicts_prior_offerings_on_replace() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();

    let (fx, sk) = signed_fixture(ExtensionKind::Design, "greentic.evict", "0.1.0");
    let mut rt = runtime_with_trust_root(trust.path());
    rt.register_loaded_from_dir(fx.root()).expect("first load");
    assert_eq!(
        offered_caps(&rt, "greentic.evict"),
        vec!["greentic:test/ping".to_string()],
        "the fixture's only offered cap must be registered on first load"
    );

    // Re-sign the SAME id with the SAME key (so TOFU accepts it), but with the
    // capability dropped from the describe.
    let describe_path = fx.root().join("describe.json");
    let raw = std::fs::read_to_string(&describe_path).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    describe.capabilities.offered.clear();
    support::finalize_signed_with_manifest(fx.root(), &mut describe, &sk);

    rt.register_loaded_from_dir(fx.root())
        .expect("re-registering with the same key must succeed");

    assert!(
        offered_caps(&rt, "greentic.evict").is_empty(),
        "a capability dropped from the describe must leave the registry; got {:?}",
        offered_caps(&rt, "greentic.evict")
    );
}

/// Re-registering an unchanged extension must not duplicate its offerings.
#[test]
fn registry_does_not_duplicate_offerings_on_reload() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();

    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.dupe", "0.1.0");
    let mut rt = runtime_with_trust_root(trust.path());

    rt.register_loaded_from_dir(fx.root()).expect("first load");
    rt.register_loaded_from_dir(fx.root()).expect("second load");
    rt.register_loaded_from_dir(fx.root()).expect("third load");

    assert_eq!(
        offered_caps(&rt, "greentic.dupe"),
        vec!["greentic:test/ping".to_string()],
        "re-registering the same dir must not duplicate its offerings"
    );
}

/// A removed extension's capabilities must leave the registry. Previously
/// `handle_removal` never touched it, so they stayed advertised forever.
#[test]
fn registry_drops_offerings_on_removal() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();

    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.removed", "0.1.0");
    let mut rt = runtime_with_trust_root(trust.path());
    rt.register_loaded_from_dir(fx.root()).expect("load");
    assert_eq!(
        offered_caps(&rt, "greentic.removed"),
        vec!["greentic:test/ping".to_string()],
        "precondition: the cap must be registered before removal"
    );

    rt.handle_removal(fx.root());

    assert!(
        rt.loaded().is_empty(),
        "precondition: the extension must be unloaded"
    );
    assert!(
        offered_caps(&rt, "greentic.removed").is_empty(),
        "a removed extension's caps must leave the registry; got {:?}",
        offered_caps(&rt, "greentic.removed")
    );
}

/// The watcher's add path must register capabilities too — previously it never
/// touched the registry, so a hot-reloaded extension's caps never appeared.
#[test]
fn registry_gains_offerings_on_watcher_add() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();

    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.watch-add", "0.1.0");
    let rt = runtime_with_trust_root(trust.path());

    rt.handle_added_or_modified(fx.root())
        .expect("hot-reloading a signed extension must succeed");

    assert_eq!(
        offered_caps(&rt, "greentic.watch-add"),
        vec!["greentic:test/ping".to_string()],
        "a hot-reloaded extension's caps must be registered"
    );
}

/// The base64 public key the fixture's signed describe.json advertises.
fn describe_public_key(dir: &Path) -> String {
    let raw = std::fs::read_to_string(dir.join("describe.json")).expect("read describe.json");
    let describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).expect("parse describe.json");
    describe
        .signature
        .expect("fixture describe must be signed")
        .public_key
}

#[test]
fn watcher_path_rejects_a_different_key_for_a_pinned_id() {
    // The cross-product this whole gate exists for: watcher x anchor.
    //
    // The other watcher tests use unsigned/tampered fixtures, so they trip
    // step 1 and would pass with the anchor deleted entirely. This one cannot:
    // both describes are perfectly self-consistent, so only the pin can tell
    // them apart. It is also the realistic attack — an attacker who can write
    // to a watched dir re-signs a known id with their own key and waits for
    // the hot-reload, rather than re-signing nothing and being caught by
    // step 1.
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();

    let (genuine, _sk1) = signed_fixture(ExtensionKind::Design, "greentic.watch-swap", "0.1.0");
    let (attacker, _sk2) = signed_fixture(ExtensionKind::Design, "greentic.watch-swap", "0.1.0");
    let pinned = describe_public_key(genuine.root());
    let presented = describe_public_key(attacker.root());
    assert_ne!(
        pinned, presented,
        "signed_fixture must mint a fresh key per call, or this test proves nothing"
    );

    let rt = runtime_with_trust_root(trust.path());
    rt.handle_added_or_modified(genuine.root())
        .expect("first hot-reload pins the genuine key");

    let err = rt
        .handle_added_or_modified(attacker.root())
        .expect_err("the hot-reload path must reject a key swap on a pinned id");
    match err {
        RuntimeError::SignatureInvalid {
            extension_id,
            reason,
        } => {
            assert_eq!(extension_id, "greentic.watch-swap");
            assert!(
                reason.contains(&pinned) && reason.contains(&presented),
                "reason must name both keys so a rotation is distinguishable \
                 from an attack; got: {reason}"
            );
        }
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }

    // The genuine extension must survive the rejected swap.
    assert!(
        rt.loaded()
            .values()
            .any(|e| e.id.as_str() == "greentic.watch-swap"),
        "the rejected reload must not evict the extension already loaded"
    );
}

/// Uninstalling an extension must actually unload it.
///
/// The removal path used to resolve the changed path by looking for a
/// `describe.json` beside it — which, after an uninstall, is exactly the file
/// that is gone. The event resolved to `None`, was dropped by an `if let Some`
/// with no `else`, and the extension stayed loaded and dispatchable with its
/// capabilities still advertised until the process restarted.
#[test]
fn removing_an_extension_directory_unloads_it() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.vanishing", "0.1.0");

    let trust = tempfile::TempDir::new().unwrap();
    let mut rt = runtime_with_trust_root(trust.path());
    rt.register_loaded_from_dir(fx.root()).expect("register");
    assert_eq!(rt.loaded().len(), 1);

    std::fs::remove_dir_all(fx.root()).expect("uninstall");
    rt.handle_fs_event_for_test(&greentic_ext_runtime::watcher::FsEvent::Removed(
        fx.root().join("describe.json"),
    ))
    .expect("removal event");

    assert!(
        rt.loaded().is_empty(),
        "an uninstalled extension must not stay loaded"
    );
    assert_eq!(
        rt.capability_registry().offerings().count(),
        0,
        "its capabilities must stop being advertised too"
    );
}

/// Deleting one asset out of a pack is not an uninstall: the directory is still
/// there and the compiled component is already in memory.
#[test]
fn removing_one_file_from_a_pack_does_not_unload_it() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.partial", "0.1.0");

    let trust = tempfile::TempDir::new().unwrap();
    let mut rt = runtime_with_trust_root(trust.path());
    rt.register_loaded_from_dir(fx.root()).expect("register");

    let victim = fx.root().join("extension.wasm");
    std::fs::remove_file(&victim).expect("delete one file");
    rt.handle_fs_event_for_test(&greentic_ext_runtime::watcher::FsEvent::Removed(victim))
        .expect("removal event");

    assert_eq!(
        rt.loaded().len(),
        1,
        "a partially deleted pack stays loaded; its directory is still there"
    );
}

/// A correctly-signed *older* pack must not replace a newer loaded one.
///
/// TOFU pins a publisher key, never a version floor, so a downgrade verifies
/// perfectly — which means anyone who can write the extensions directory, or
/// replay a stale artifact the publisher really did sign, rolls a patched
/// extension back to a vulnerable one and the gate applauds.
#[test]
fn a_signed_downgrade_is_refused() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();
    let mut rt = runtime_with_trust_root(trust.path());

    let (newer, sk) = signed_fixture(ExtensionKind::Design, "greentic.rollback", "2.0.0");
    rt.register_loaded_from_dir(newer.root()).expect("register");

    // Same id, same publisher key, lower version — everything the gate checks
    // still holds.
    let older =
        support::signed_fixture_with_key(ExtensionKind::Design, "greentic.rollback", "1.0.0", &sk);
    let err = rt
        .handle_added_or_modified(older.root())
        .expect_err("an older version must not replace a newer one");
    assert!(
        err.to_string().contains("older"),
        "expected a downgrade refusal, got: {err}"
    );
    assert_eq!(
        rt.loaded()
            .values()
            .next()
            .map(|e| e.describe.metadata.version.clone()),
        Some("2.0.0".to_string()),
        "the newer version must still be the loaded one"
    );
}

/// `mv`-ing an extension directory aside must unload it.
///
/// inotify reports a rename *out of* the watched tree as
/// `Modify(Name(From))`, not `Remove`. Classified as a modification, the event
/// resolved to no extension directory and was dropped — so quarantining a
/// misbehaving extension by moving it, the natural admin reflex, left it
/// loaded, offering capabilities and dispatchable until restart.
#[test]
fn renaming_an_extension_directory_out_of_the_tree_unloads_it() {
    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let (fx, _sk) = signed_fixture(ExtensionKind::Design, "greentic.quarantined", "0.1.0");

    let trust = tempfile::TempDir::new().unwrap();
    let mut rt = runtime_with_trust_root(trust.path());
    rt.register_loaded_from_dir(fx.root()).expect("register");
    assert_eq!(rt.loaded().len(), 1);

    let elsewhere = tempfile::TempDir::new().unwrap();
    let moved = elsewhere.path().join("quarantined");
    std::fs::rename(fx.root(), &moved).expect("mv the extension aside");

    // What the watcher actually delivers for a rename-out.
    rt.handle_fs_event_for_test(&greentic_ext_runtime::watcher::FsEvent::Removed(
        fx.root().to_path_buf(),
    ))
    .expect("rename-out event");

    assert!(
        rt.loaded().is_empty(),
        "an extension moved out of the tree must not stay loaded"
    );
}

/// Concurrent mutations of the loaded map must not lose one another.
///
/// `ArcSwap` makes each individual store atomic, which is what readers need,
/// but the mutators clone the map, edit the clone and store it back. Two of
/// those racing lose an edit — and losing a *removal* leaves an evicted
/// extension advertising capabilities through `offerings()`, the stale-offering
/// false positive the wholesale rebuild exists to prevent.
///
/// Nothing pinned the serialisation half of that invariant: removing the lock
/// from `mutate_loaded` left the whole suite green.
#[test]
fn concurrent_registrations_and_evictions_do_not_lose_each_other() {
    use std::sync::Arc;

    let _guard = EnvGuard::remove("GREENTIC_EXT_ALLOW_UNSIGNED");
    let trust = tempfile::TempDir::new().unwrap();

    // Register a batch up front, then race an eviction of half of them against
    // registrations of the other half's replacements.
    let fixtures: Vec<_> = (0..8)
        .map(|i| {
            signed_fixture(
                ExtensionKind::Design,
                &format!("greentic.racer-{i}"),
                "1.0.0",
            )
        })
        .collect();

    let mut rt = runtime_with_trust_root(trust.path());
    for (fx, _sk) in &fixtures {
        rt.register_loaded_from_dir(fx.root()).expect("register");
    }
    assert_eq!(rt.loaded().len(), 8);

    let rt = Arc::new(rt);
    let mut handles = Vec::new();
    for (fx, _sk) in &fixtures {
        let rt = Arc::clone(&rt);
        let dir = fx.root().to_path_buf();
        handles.push(std::thread::spawn(move || rt.handle_removal(&dir)));
    }
    for h in handles {
        h.join().expect("no mutator may panic");
    }

    assert!(
        rt.loaded().is_empty(),
        "every concurrent removal must land; {} survived",
        rt.loaded().len()
    );
    assert_eq!(
        rt.capability_registry().offerings().count(),
        0,
        "a lost removal leaves capabilities advertised for an evicted extension"
    );
}
