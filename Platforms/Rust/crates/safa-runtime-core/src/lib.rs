//! Platform-neutral vocabulary for native SAFA runtimes.
//!
//! This crate deliberately contains no credential values, operating-system APIs, or remote
//! execution. Public Agent contracts remain canonical in `juju-w/safa`.

/// The current external Agent-facing schema understood by runtime implementations.
pub const CLI_SCHEMA_V1: &str = "dev.safa.cli/v1";

/// Security capabilities that every supported platform runtime must implement without a plaintext
/// fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityCapability {
    CredentialStorage,
    PeerIdentity,
    UserAuthorization,
    ServiceLifecycle,
}

/// Whether a platform adapter can safely provide a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityStatus {
    Available,
    Unavailable,
}

/// Minimal boundary implemented by an operating-system adapter.
///
/// Capability discovery is intentionally non-secret and side-effect free. Concrete credential and
/// authorization operations will use separate narrow traits after their contracts are reviewed.
pub trait PlatformSecurity {
    fn capability_status(&self, capability: SecurityCapability) -> CapabilityStatus;
}

#[cfg(test)]
mod tests {
    use super::CLI_SCHEMA_V1;

    #[test]
    fn schema_identifier_stays_explicitly_versioned() {
        assert_eq!(CLI_SCHEMA_V1, "dev.safa.cli/v1");
    }
}
