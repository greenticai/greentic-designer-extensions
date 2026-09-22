use std::collections::HashMap;

use greentic_extension_sdk_contract::{CapabilityId, CapabilityRef, ExtensionKind};
use semver::{Version, VersionReq};

#[derive(Debug, Clone)]
pub struct OfferedBinding {
    pub extension_id: String,
    pub cap_id: CapabilityId,
    pub version: Version,
    pub kind: ExtensionKind,
    pub export_path: String,
}

#[derive(Debug, Clone, Default)]
pub struct ResolutionPlan {
    pub consumer: String,
    pub resolved: HashMap<CapabilityId, OfferedBinding>,
    pub unresolved: Vec<CapabilityRef>,
}

#[derive(Debug, Default)]
pub struct CapabilityRegistry {
    offerings: HashMap<CapabilityId, Vec<OfferedBinding>>,
}

impl CapabilityRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_offering(&mut self, offering: OfferedBinding) {
        self.offerings
            .entry(offering.cap_id.clone())
            .or_default()
            .push(offering);
    }

    #[must_use]
    pub fn resolve(&self, consumer: &str, required: &[CapabilityRef]) -> ResolutionPlan {
        let mut resolved = HashMap::new();
        let mut unresolved = Vec::new();
        for req in required {
            let Some(vr) = parse_requirement(&req.id, &req.version) else {
                unresolved.push(req.clone());
                continue;
            };
            let best = self
                .offerings
                .get(&req.id)
                .and_then(|offers| {
                    offers
                        .iter()
                        .filter(|o| vr.matches(&o.version))
                        .max_by(|a, b| a.version.cmp(&b.version))
                })
                .cloned();
            match best {
                Some(o) => {
                    resolved.insert(req.id.clone(), o);
                }
                None => unresolved.push(req.clone()),
            }
        }
        ResolutionPlan {
            consumer: consumer.to_string(),
            resolved,
            unresolved,
        }
    }

    pub fn offerings(&self) -> impl Iterator<Item = &OfferedBinding> {
        self.offerings.values().flat_map(|v| v.iter())
    }

    /// Returns the extension IDs whose dependency graph reaches a cycle.
    ///
    /// This is deliberately "reaches", not "participates in": an extension
    /// that merely depends on a cyclic pair is just as unresolvable as the pair
    /// itself, and callers use this list to refuse to activate. Empty vec means
    /// every listed extension resolves acyclically.
    #[must_use]
    pub fn detect_cycle(&self, extensions: &[(String, Vec<CapabilityRef>)]) -> Vec<String> {
        let ext_map: HashMap<&str, &Vec<CapabilityRef>> = extensions
            .iter()
            .map(|(id, reqs)| (id.as_str(), reqs))
            .collect();

        let mut in_cycle = Vec::new();
        for (id, _) in extensions {
            let mut visited = std::collections::HashSet::new();
            if self.dfs_has_cycle(id, &ext_map, &mut visited) {
                in_cycle.push(id.clone());
            }
        }
        in_cycle
    }

    fn dfs_has_cycle(
        &self,
        ext_id: &str,
        ext_map: &HashMap<&str, &Vec<CapabilityRef>>,
        visited: &mut std::collections::HashSet<String>,
    ) -> bool {
        if !visited.insert(ext_id.to_string()) {
            return true;
        }
        let Some(reqs) = ext_map.get(ext_id) else {
            visited.remove(ext_id);
            return false;
        };
        for req in *reqs {
            // A requirement that does not parse resolves to nothing (see
            // `parse_requirement`), so it can introduce no edge and therefore
            // no cycle.
            let Some(vr) = parse_requirement(&req.id, &req.version) else {
                continue;
            };
            let Some(offers) = self.offerings.get(&req.id) else {
                continue;
            };
            for o in offers.iter().filter(|o| vr.matches(&o.version)) {
                if self.dfs_has_cycle(&o.extension_id, ext_map, visited) {
                    return true;
                }
            }
        }
        visited.remove(ext_id);
        false
    }
}

/// Parse a capability version requirement, or reject it.
///
/// A malformed requirement previously fell back to [`VersionReq::STAR`], which
/// silently turned "I need exactly this" into "anything will do" — the widest
/// possible resolution from the narrowest possible input, and the resolver
/// would then hand back a binding the extension never asked for. Failing the
/// requirement instead surfaces it as unresolved, which is the outcome an
/// undeclarable dependency should have.
fn parse_requirement(cap_id: &CapabilityId, raw: &str) -> Option<VersionReq> {
    match VersionReq::parse(raw) {
        Ok(vr) => Some(vr),
        Err(e) => {
            tracing::warn!(
                capability = ?cap_id,
                requirement = %raw,
                error = %e,
                "unparseable capability version requirement; treating it as unresolvable"
            );
            None
        }
    }
}
