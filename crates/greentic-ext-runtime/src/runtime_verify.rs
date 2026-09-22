//! The load gate: signature integrity, whole-archive ledger, and the TOFU
//! publisher-key anchor.
//!
//! Split out of [`crate::runtime`] so the gate reads as one piece. Every load
//! path — [`crate::ExtensionRuntime::register_loaded_from_dir`] and the
//! watcher's `handle_added_or_modified` — funnels through
//! [`ExtensionRuntime::verify_dir_signature`] here, in that order and no other.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use greentic_extension_sdk_contract::DescribeJson;

use crate::error::RuntimeError;
use crate::runtime::ExtensionRuntime;

/// Entries the ledger deliberately excludes, so the on-disk coverage check
/// must not treat them as smuggled files.
///
/// `describe.json` carries its own JCS publisher signature and binds the
/// manifest via `manifestSha256`; listing it in the manifest would be circular.
/// `manifest.json` cannot list itself. Both are therefore covered by step 1 +
/// step 2 of the gate rather than by a ledger row. Mirrors the exclusion in the
/// SDK's `build_manifest` / `verify_archive_against_manifest`.
const LEDGER_EXEMPT: [&str; 2] = [
    greentic_extension_sdk_contract::MANIFEST_ENTRY_NAME,
    greentic_extension_sdk_contract::DESCRIBE_ENTRY_NAME,
];

impl ExtensionRuntime {
    /// Verify an unpacked extension directory before anything is loaded from it.
    ///
    /// Three steps, and the order is the security property (see `CLAUDE.md`):
    /// integrity → artifact ledger → anchor. The anchor is a *write* into the
    /// store `gtdx` shares, so it must never run for a load that then fails.
    ///
    /// # Known residual: check-to-use gap on the component bytes
    ///
    /// The verified [`DescribeJson`] is returned and handed to
    /// [`crate::loaded::LoadedExtension::from_verified`], so nothing downstream
    /// re-reads it: the extension id this pins under and the permissions it
    /// runs with are the ones this function checked, not whatever is on disk a
    /// moment later.
    ///
    /// The **component bytes** are still opened by path afterwards, so a writer
    /// who lands between the ledger check and `Component::from_file` can still
    /// substitute the wasm. Closing that means threading the bytes read here
    /// through to `Component::from_binary` — worth doing, and deliberately not
    /// bundled into this gate. Note the window is reachable through the
    /// watcher, not only by a privileged process: writing into a watched
    /// directory is what schedules the load in the first place.
    pub(crate) fn verify_dir_signature(
        &self,
        dir: &Path,
    ) -> Result<(DescribeJson, VerifiedLedger), RuntimeError> {
        let describe = read_describe(dir)?;

        #[cfg(feature = "dev-allow-unsigned")]
        if std::env::var("GREENTIC_EXT_ALLOW_UNSIGNED").is_ok() {
            tracing::warn!(
                extension_dir = %dir.display(),
                "GREENTIC_EXT_ALLOW_UNSIGNED is set — signature verification skipped"
            );
            return Ok((describe, VerifiedLedger::unchecked()));
        }
        // Step 1 — integrity: the describe is unmodified since signing. This is
        // NOT authenticity: it proves nothing about *who* signed, because an
        // attacker can re-sign their own describe with their own key and pass
        // this check trivially. Steps 2 and 3 below supply authenticity.
        greentic_extension_sdk_contract::verify_describe_self_consistent(&describe).map_err(
            |e| RuntimeError::SignatureInvalid {
                extension_id: describe.metadata.id.clone(),
                reason: e.to_string(),
            },
        )?;

        let invalid = |reason: String| RuntimeError::SignatureInvalid {
            extension_id: describe.metadata.id.clone(),
            reason,
        };
        // `verify_describe_self_consistent` already rejects an unsigned
        // describe, so this is belt-and-braces rather than a live path — but
        // failing closed here keeps the invariant local and obvious.
        let key_b64 = describe
            .signature
            .as_ref()
            .map(|s| s.public_key.clone())
            .ok_or_else(|| invalid("unsigned describe cannot be anchored".to_string()))?;

        // Step 2 — integrity of the artifact itself, not just of the describe.
        // This must run BEFORE the anchor below, because pinning is a *write*
        // into a store shared with `gtdx`: a pin left behind by a load that
        // then fails would permanently block the genuine publisher for this id
        // in both tools, recoverable only by hand-editing publishers.json.
        //
        // `gtdx` orders it the same way, one level up — see
        // `sdk-registry/src/lifecycle.rs`, `verify_integrity` then
        // `verify_authenticity`. The ordering rule inside
        // `sdk-registry/src/verify.rs` covers only signature-then-anchor
        // because integrity is already done by the time it is called; reading
        // that rule without its caller is what put the pin ahead of the ledger
        // here.
        let ledger = verify_dir_manifest(dir, &describe)?;

        // Step 3 — anchor (TOFU): the key that signed this describe must be the
        // one pinned for this extension id on first load. Step 1 proved the
        // signature verifies against `key_b64`; pinning `key_b64` is therefore
        // what turns integrity into authenticity. There is no separate
        // `verify_describe_with_key` step: passing it a key read out of the
        // describe compares that key against itself, which is a tautology the
        // SDK's own doc warns against ("the key must come from a trust anchor
        // ... never from the artifact alone"). The anchor IS the trust anchor.
        let trust_root = self.config().resolve_trust_root()?;
        greentic_extension_sdk_registry::trust_store::TrustStore::new(&trust_root)
            .pin_or_verify(&describe.metadata.id, &key_b64)
            .map_err(|e| invalid(e.to_string()))?;

        let pub_prefix = key_b64.chars().take(16).collect::<String>();
        tracing::info!(
            extension_id = %describe.metadata.id,
            key_prefix = %pub_prefix,
            "extension signature verified and anchored to the pinned publisher key"
        );
        Ok((describe, ledger))
    }
}

/// The sha256 the signed ledger records for each file in a verified pack.
///
/// Handed to the loader so the component it compiles is checked against the
/// ledger *at the moment it is read*, rather than re-selected by a fresh
/// `exists()` stat some time after the directory was walked.
#[derive(Debug, Default)]
pub(crate) struct VerifiedLedger {
    /// `None` under `dev-allow-unsigned`, where no ledger was checked at all.
    entries: Option<BTreeMap<PathBuf, String>>,
}

impl VerifiedLedger {
    /// A ledger that checks nothing — the `dev-allow-unsigned` escape only.
    ///
    /// Gated on the feature, so a production build has no way to construct one
    /// and the "no ledger to check against" branch is not even compiled.
    #[cfg(feature = "dev-allow-unsigned")]
    const fn unchecked() -> Self {
        Self { entries: None }
    }

    /// Read `path` and confirm it hashes to what the ledger recorded.
    ///
    /// This is what closes the check-to-use window on the component bytes. The
    /// gate verified the directory, but the loader then re-decided *which* file
    /// to compile with a fresh stat — and `wasm_component_path` prefers a root
    /// `extension.wasm` unconditionally, so for a pack that ships none, a file
    /// created after the walk won outright. It was never in the ledger, so
    /// requiring a ledger entry refuses it; and hashing the bytes we are about
    /// to compile, rather than the path, leaves nothing to swap in between.
    pub(crate) fn read_verified(&self, path: &Path) -> anyhow::Result<Vec<u8>> {
        let bytes = std::fs::read(path)?;

        let Some(entries) = &self.entries else {
            return Ok(bytes);
        };
        let expected = entries.get(path).ok_or_else(|| {
            anyhow::anyhow!(
                "{} is not covered by the signed manifest; refusing to load it",
                path.display()
            )
        })?;
        let computed = format!("{:x}", Sha256::digest(&bytes));
        anyhow::ensure!(
            &computed == expected,
            "{} changed after verification: manifest recorded {expected}, read {computed}",
            path.display()
        );
        Ok(bytes)
    }
}

/// Read and schema-validate `describe.json`, once.
///
/// The parsed value is handed back to the caller so nothing downstream re-reads
/// the file — see the check-to-use note on
/// [`ExtensionRuntime::verify_dir_signature`] for why that matters.
fn read_describe(dir: &Path) -> Result<DescribeJson, RuntimeError> {
    let path = dir.join(greentic_extension_sdk_contract::DESCRIBE_ENTRY_NAME);
    let raw = std::fs::read(&path)?;
    let value: serde_json::Value = serde_json::from_slice(&raw)?;
    greentic_extension_sdk_contract::schema::validate_describe_json(&value)
        .map_err(|e| RuntimeError::Wasmtime(anyhow::anyhow!("invalid {}: {e}", path.display())))?;
    serde_json::from_value(value).map_err(RuntimeError::Json)
}

/// Verify the unpacked extension dir against its `manifest.json`
/// (whole-archive integrity ledger).
///
/// Audit P5 hardening — fail **closed**:
/// - A missing `manifest.json` is a hard error. Pre-ledger packs only load
///   under the `dev-allow-unsigned` escape (checked upstream in
///   [`ExtensionRuntime::verify_dir_signature`]); production refuses an
///   unverifiable pack.
/// - The describe's manifest binding (`manifestSha256`) must match the on-disk
///   `manifest.json`, so the (signed) describe transitively commits to the
///   ledger — an attacker cannot swap the manifest without breaking the
///   describe signature.
/// - Every file the manifest lists must hash to the recorded sha256.
/// - **Every file on disk must be listed.** An install produces a directory
///   whose contents are exactly the archive's, and the SDK's archive verifier
///   already rejects a smuggled entry (`ManifestError::UnexpectedEntry`).
///   Without the same rule here the directory gate was strictly weaker than the
///   archive gate it stands in for: `wasm_component_path` prefers a root
///   `extension.wasm` unconditionally, so dropping one into a pack that ships
///   none (the gtpack-fallback layout) left every listed entry hash-matching
///   while the component actually instantiated was attacker-supplied.
/// - Ledger paths must be **relative and free of traversal**, and must resolve
///   to regular files. `dir.join(entry.path)` honours an absolute path by
///   discarding `dir` outright, and follows a symlink out of the pack; either
///   lets a ledger "verify" against bytes that are not in the pack at all.
fn verify_dir_manifest(
    dir: &Path,
    describe: &DescribeJson,
) -> Result<VerifiedLedger, RuntimeError> {
    let extension_id = describe.metadata.id.as_str();
    let invalid = |reason: String| RuntimeError::SignatureInvalid {
        extension_id: extension_id.to_string(),
        reason,
    };

    let manifest_path = dir.join(greentic_extension_sdk_contract::MANIFEST_ENTRY_NAME);
    let raw = match std::fs::read(&manifest_path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(invalid(
                "manifest.json absent — refusing to load an extension without a whole-archive \
                 integrity ledger (set GREENTIC_EXT_ALLOW_UNSIGNED with the dev-allow-unsigned \
                 build for local dev)"
                    .to_string(),
            ));
        }
        Err(e) => return Err(RuntimeError::Io(e)),
    };

    // Binding: the signed describe commits to exactly this manifest, so the
    // signature transitively covers the ledger. Rejects both a swapped manifest
    // and an unbound (legacy) describe carrying a manifest.
    greentic_extension_sdk_contract::verify_manifest_binding(describe, &raw)
        .map_err(|e| invalid(format!("manifest binding: {e}")))?;

    let manifest: greentic_extension_sdk_contract::Manifest =
        serde_json::from_slice(&raw).map_err(|e| invalid(format!("manifest.json parse: {e}")))?;
    if manifest.schema != greentic_extension_sdk_contract::MANIFEST_SCHEMA_V1 {
        return Err(invalid(format!(
            "manifest schema unsupported: {}",
            manifest.schema
        )));
    }

    // Keyed by resolved `PathBuf`, not by the raw string. Comparing rendered
    // strings made the check evadable: the walk lowered every on-disk name
    // through `to_string_lossy().replace('\\', "/")`, so on Linux — where a
    // backslash is an ordinary filename byte — a file literally named `a\b.txt`
    // rendered as `a/b.txt` and matched a ledger entry for a different file,
    // and any non-UTF-8 name rendered as U+FFFD and collided with any entry
    // containing it. Comparing paths removes both mappings.
    let mut listed: BTreeMap<PathBuf, String> = BTreeMap::new();
    for entry in &manifest.entries {
        let path = pack_relative_path(dir, &entry.path).map_err(&invalid)?;
        // `symlink_metadata` does not follow the final component, so a symlink
        // is rejected here rather than silently hashing whatever it points at.
        //
        // A missing file keeps its own wording: "the pack is incomplete" and
        // "the pack is unreadable" are different diagnoses for whoever has to
        // act on the rejection.
        let meta = std::fs::symlink_metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                invalid(format!("manifest lists missing file: {}", entry.path))
            } else {
                invalid(format!(
                    "manifest lists unreadable file {}: {e}",
                    entry.path
                ))
            }
        })?;
        if !meta.is_file() {
            return Err(invalid(format!(
                "manifest entry {} is not a regular file",
                entry.path
            )));
        }
        let bytes = std::fs::read(&path)?;
        let computed = format!("{:x}", Sha256::digest(&bytes));
        if computed != entry.sha256 {
            return Err(invalid(format!(
                "manifest sha256 mismatch for {}: expected {} got {}",
                entry.path, entry.sha256, computed
            )));
        }
        listed.insert(path, entry.sha256.clone());
    }

    // Coverage: nothing on disk may sit outside the ledger.
    let exempt: Vec<PathBuf> = LEDGER_EXEMPT.iter().map(|n| dir.join(n)).collect();
    for present in collect_pack_files(dir)? {
        if exempt.contains(&present) || listed.contains_key(&present) {
            continue;
        }
        return Err(invalid(format!(
            "{} is present in the extension directory but absent from manifest.json — \
             refusing to load a pack carrying files the signed ledger does not cover",
            present.strip_prefix(dir).unwrap_or(&present).display()
        )));
    }

    tracing::info!(
        extension_id = %extension_id,
        entries = manifest.entries.len(),
        "whole-archive manifest verified"
    );
    Ok(VerifiedLedger {
        entries: Some(listed),
    })
}

/// Resolve a ledger path against the pack root, refusing anything that could
/// address bytes outside it.
///
/// Only `Component::Normal` segments are accepted: that rules out an absolute
/// path (`RootDir`/`Prefix`, which `Path::join` honours by *replacing* the
/// base), `..` (`ParentDir`), and a bare `.` (`CurDir`). The final-component
/// symlink case is handled by the caller's `symlink_metadata` check; an
/// intermediate symlinked directory cannot exist in a verified pack because
/// [`collect_pack_files`] refuses to descend into one.
pub(crate) fn pack_relative_path(dir: &Path, rel: &str) -> Result<PathBuf, String> {
    if rel.is_empty() {
        return Err("manifest lists an empty path".to_string());
    }
    let candidate = Path::new(rel);
    for component in candidate.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(format!(
                "manifest path {rel} is not a plain relative path (absolute paths and `..` \
                 segments can address bytes outside the pack)"
            ));
        }
    }
    Ok(dir.join(candidate))
}

/// Deepest directory nesting the coverage walk will descend.
///
/// This walk runs over an *unverified* directory — establishing that it matches
/// the ledger is the whole point — so its shape is attacker-controlled at this
/// moment. An unbounded recursive walk over a deliberately deep tree overflows
/// the stack, which aborts the process rather than rejecting the pack. Real
/// packs nest a handful of levels (`runtime/`, `assets/…`); anything past this
/// is refused, and refusal is the safe answer either way.
const MAX_PACK_DEPTH: usize = 32;

/// Every regular file under `dir`, as absolute paths.
///
/// Paths, not rendered strings: the caller compares these against ledger
/// entries resolved through [`pack_relative_path`], and any lossy rendering in
/// between is a way to make two different files compare equal.
///
/// Uses `symlink_metadata`, so a symlink — to a file or to a directory — is
/// reported as itself and never followed. A symlinked directory therefore shows
/// up as one unlisted entry instead of silently expanding into whatever it
/// points at, and the caller's coverage check rejects the pack.
fn collect_pack_files(dir: &Path) -> Result<Vec<PathBuf>, RuntimeError> {
    let mut out = Vec::new();
    collect_into(dir, 0, &mut out)?;
    Ok(out)
}

fn collect_into(current: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), RuntimeError> {
    if depth > MAX_PACK_DEPTH {
        return Err(RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "extension directory nests deeper than {MAX_PACK_DEPTH} levels; refusing to walk it"
            ),
        )));
    }
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            collect_into(&path, depth + 1, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_relative_path_resolves_under_the_pack_root() {
        let root = Path::new("/packs/demo");
        assert_eq!(
            pack_relative_path(root, "runtime/component.wasm").unwrap(),
            Path::new("/packs/demo/runtime/component.wasm")
        );
    }

    #[test]
    fn an_absolute_ledger_path_is_refused() {
        // `Path::join` replaces the base with an absolute argument, so without
        // this check the ledger would verify `/etc/passwd` and call the pack
        // intact.
        let err = pack_relative_path(Path::new("/packs/demo"), "/etc/passwd").unwrap_err();
        assert!(err.contains("not a plain relative path"), "{err}");
    }

    #[test]
    fn a_traversing_ledger_path_is_refused() {
        let err =
            pack_relative_path(Path::new("/packs/demo"), "../other/extension.wasm").unwrap_err();
        assert!(err.contains("not a plain relative path"), "{err}");
    }

    #[test]
    fn an_empty_ledger_path_is_refused() {
        let err = pack_relative_path(Path::new("/packs/demo"), "").unwrap_err();
        assert!(err.contains("empty path"), "{err}");
    }

    #[test]
    fn nested_files_are_collected_as_paths_under_the_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("extension.wasm"), b"a").unwrap();
        std::fs::create_dir(tmp.path().join("runtime")).unwrap();
        std::fs::write(tmp.path().join("runtime").join("pack.gtpack"), b"b").unwrap();

        let mut found = collect_pack_files(tmp.path()).unwrap();
        found.sort();
        assert_eq!(
            found,
            [
                tmp.path().join("extension.wasm"),
                tmp.path().join("runtime").join("pack.gtpack"),
            ]
        );
    }
}
