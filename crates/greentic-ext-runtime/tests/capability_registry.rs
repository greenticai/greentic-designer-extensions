use greentic_ext_runtime::{CapabilityRegistry, OfferedBinding};
use greentic_extension_sdk_contract::{CapabilityRef, ExtensionKind};

fn cap_ref(id: &str, v: &str) -> CapabilityRef {
    CapabilityRef {
        id: id.parse().unwrap(),
        version: v.to_string(),
        deprecated: None,
    }
}

#[test]
fn matches_caret_version() {
    let mut r = CapabilityRegistry::new();
    r.add_offering(OfferedBinding {
        extension_id: "x.offerer".into(),
        cap_id: "greentic:x/y".parse().unwrap(),
        version: "1.2.5".parse().unwrap(),
        kind: ExtensionKind::Design,
        export_path: "ext/y.func".into(),
    });
    let plan = r.resolve("x.consumer", &[cap_ref("greentic:x/y", "^1.0")]);
    assert!(plan.unresolved.is_empty());
    assert_eq!(plan.resolved.len(), 1);
}

#[test]
fn degrades_on_missing_cap() {
    let r = CapabilityRegistry::new();
    let plan = r.resolve("x.consumer", &[cap_ref("greentic:nope/here", "^1.0")]);
    assert_eq!(plan.unresolved.len(), 1);
    assert!(plan.resolved.is_empty());
}

#[test]
fn picks_highest_compatible_semver() {
    let mut r = CapabilityRegistry::new();
    for v in ["1.0.0", "1.2.0", "1.5.0", "2.0.0"] {
        r.add_offering(OfferedBinding {
            extension_id: format!("x.offer-{v}"),
            cap_id: "greentic:x/y".parse().unwrap(),
            version: v.parse().unwrap(),
            kind: ExtensionKind::Design,
            export_path: "e".into(),
        });
    }
    let plan = r.resolve("x.consumer", &[cap_ref("greentic:x/y", "^1.0")]);
    let picked = plan.resolved.values().next().unwrap();
    assert_eq!(picked.version.to_string(), "1.5.0");
}

#[test]
fn an_unparseable_requirement_resolves_to_nothing() {
    // Fail closed. The previous fallback was `VersionReq::STAR`, which turned
    // the narrowest possible input — a requirement nobody can even parse —
    // into the widest possible grant, and handed the consumer a binding it
    // never asked for. An undeclarable dependency is an unmet dependency.
    let mut r = CapabilityRegistry::new();
    r.add_offering(OfferedBinding {
        extension_id: "x.offerer".into(),
        cap_id: "greentic:x/y".parse().unwrap(),
        version: "9.9.9".parse().unwrap(),
        kind: ExtensionKind::Design,
        export_path: "e".into(),
    });

    let plan = r.resolve(
        "x.consumer",
        &[cap_ref("greentic:x/y", "not-a-version-req")],
    );

    assert!(
        plan.resolved.is_empty(),
        "a garbage requirement must not resolve to an arbitrary offering"
    );
    assert_eq!(plan.unresolved.len(), 1);
}

#[test]
fn an_unparseable_requirement_introduces_no_dependency_edge() {
    // Same fallback, seen from the cycle detector: `STAR` made every malformed
    // requirement match every offering, so one typo could manufacture a cycle
    // that does not exist and take otherwise-loadable extensions offline.
    let mut r = CapabilityRegistry::new();
    r.add_offering(OfferedBinding {
        extension_id: "x.a".into(),
        cap_id: "greentic:x/y".parse().unwrap(),
        version: "1.0.0".parse().unwrap(),
        kind: ExtensionKind::Design,
        export_path: "e".into(),
    });

    let cycles = r.detect_cycle(&[("x.a".to_string(), vec![cap_ref("greentic:x/y", "@@@")])]);

    assert!(
        cycles.is_empty(),
        "an unparseable requirement must not be treated as a self-edge: {cycles:?}"
    );
}
