/// Health of a loaded extension.
///
/// **This runtime only ever produces [`ExtensionHealth::Healthy`].** Loading
/// fails closed — a bad signature, an unverifiable ledger, or an unparseable
/// describe all reject the extension outright rather than admitting it in a
/// degraded state — so nothing is left to mark. `Degraded` exists for the
/// planned soft-failure path (a required capability that resolves at load but
/// disappears when its provider is evicted); until that lands, do not read
/// `Healthy` as evidence that anything was checked at dispatch time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionHealth {
    Healthy,
    Degraded(HealthReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthReason {
    MissingRequiredCap(String),
    SignatureInvalid,
    LoadFailed(String),
    CycleDetected,
}

impl ExtensionHealth {
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}
