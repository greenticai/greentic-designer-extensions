//! Fixtures for the hosting-provider world: the real test guest component,
//! built on demand, wrapped in a signed `DeployExtension` pack that offers
//! `greentic:hosting/provider`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use greentic_ext_runtime::hosting::audit::MemoryAuditSink;
use greentic_ext_runtime::hosting::mock::MockHostingPort;
use greentic_ext_runtime::hosting::{HOSTING_PROVIDER_CAPABILITY, TargetContext, TargetPolicy};
use greentic_ext_runtime::{DiscoveryPaths, ExtensionRuntime, HostingContext, RuntimeConfig};
use greentic_extension_sdk_contract::ExtensionKind;

use super::finalize_signed_with_manifest;

/// A credential-shaped value assembled at runtime so no literal in the source
/// looks like one.
pub fn fake_credential() -> String {
    ["cred", "0123456789", "abcdef"].join("-")
}

fn guest_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../hosting-test-guest/Cargo.toml")
}

/// Build the test guest (`sleeper` selects the variant that reads the clock)
/// for wasm32-wasip2 and return its bytes. Needs the `wasm32-wasip2` target,
/// which `rust-toolchain.toml` installs.
pub fn guest_wasm(sleeper: bool) -> Vec<u8> {
    static CACHE: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    let _g = CACHE
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(if sleeper {
        "hosting-guest-sleeper"
    } else {
        "hosting-guest"
    });
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.args([
        "build",
        "--release",
        "--locked",
        "--target",
        "wasm32-wasip2",
        "--manifest-path",
    ])
    .arg(guest_manifest())
    .env("CARGO_TARGET_DIR", &dir)
    .env_remove("CARGO_BUILD_BUILD_DIR");
    if sleeper {
        cmd.args(["--features", "sleeper"]);
    }
    let out = cmd
        .output()
        .expect("run cargo to build the hosting test guest");
    assert!(
        out.status.success(),
        "building the hosting test guest failed (is the wasm32-wasip2 target installed?):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(dir.join("wasm32-wasip2/release/hosting_test_guest.wasm"))
        .expect("guest wasm exists after a successful build")
}

/// Sign `wasm` into a pack of `kind` that offers the hosting capability when
/// `hosting` is set.
pub fn pack(
    kind: ExtensionKind,
    id: &str,
    wasm: Vec<u8>,
    hosting: bool,
) -> greentic_extension_sdk_testing::ExtensionFixture {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let mut b = greentic_extension_sdk_testing::ExtensionFixtureBuilder::new(kind, id, "0.1.0")
        .with_wasm(wasm);
    b = if hosting {
        b.offer(HOSTING_PROVIDER_CAPABILITY, "1.0.0")
    } else {
        b.offer("greentic:test/ping", "1.0.0")
    };
    let fx = b.build().expect("fixture build");
    let raw = std::fs::read_to_string(fx.root().join("describe.json")).unwrap();
    let mut describe: greentic_extension_sdk_contract::DescribeJson =
        serde_json::from_str(&raw).unwrap();
    super::populate_gtpack_for_local_load(&mut describe);
    finalize_signed_with_manifest(fx.root(), &mut describe, &SigningKey::generate(&mut OsRng));
    fx
}

pub struct Harness {
    pub rt: ExtensionRuntime,
    pub fx: greentic_extension_sdk_testing::ExtensionFixture,
    pub id: String,
    _trust: tempfile::TempDir,
}

pub fn harness(
    kind: ExtensionKind,
    id: &str,
    wasm: Vec<u8>,
    hosting: bool,
    timeout: Option<Duration>,
) -> Harness {
    let trust = tempfile::TempDir::new().expect("trust root");
    let mut cfg = RuntimeConfig::from_paths(DiscoveryPaths::new(PathBuf::from("/dev/null")))
        .with_trust_root(trust.path().to_path_buf());
    if let Some(t) = timeout {
        cfg = cfg.with_dispatch_timeout(Some(t));
    }
    let mut rt = ExtensionRuntime::new(cfg).expect("runtime");
    let fx = pack(kind, id, wasm, hosting);
    rt.register_loaded_from_dir(fx.root()).expect("register");
    Harness {
        rt,
        fx,
        id: id.to_string(),
        _trust: trust,
    }
}

/// A port with a plausible target and the fake credential.
pub fn port() -> MockHostingPort {
    MockHostingPort::new()
        .setting("region", "eu-west-1")
        .credential(&fake_credential())
        .context(TargetContext {
            installation_id: "inst-1".into(),
            owner_tags: vec![("greentic:installation".into(), "inst-1".into())],
            credential_fingerprint: Some("fp-abc".into()),
        })
}

pub fn policy() -> TargetPolicy {
    TargetPolicy::new(
        vec!["*.amazonaws.com".into()],
        vec!["infra.example.com".into()],
    )
}

pub fn ctx(
    port: Arc<MockHostingPort>,
    policy: TargetPolicy,
    audit: Arc<MemoryAuditSink>,
) -> HostingContext {
    HostingContext {
        target_id: "t1".into(),
        port,
        policy,
        audit,
    }
}

/// A target that makes the guest run `scenario`.
pub fn scenario_port(scenario: &str) -> MockHostingPort {
    port().setting("scenario", scenario)
}
