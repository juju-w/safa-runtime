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

impl SecurityCapability {
    /// Every capability required before a protected platform backend may report ready.
    pub const ALL: [Self; 4] = [
        Self::CredentialStorage,
        Self::PeerIdentity,
        Self::UserAuthorization,
        Self::ServiceLifecycle,
    ];

    /// Stable machine-readable name used by local readiness diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialStorage => "credential_storage",
            Self::PeerIdentity => "peer_identity",
            Self::UserAuthorization => "user_authorization",
            Self::ServiceLifecycle => "service_lifecycle",
        }
    }
}

/// Whether a platform adapter can safely provide a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityStatus {
    Available,
    Unavailable,
}

impl CapabilityStatus {
    /// Stable machine-readable representation for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
        }
    }
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
    use super::{CapabilityStatus, SecurityCapability, CLI_SCHEMA_V1};

    #[test]
    fn schema_identifier_stays_explicitly_versioned() {
        assert_eq!(CLI_SCHEMA_V1, "dev.safa.cli/v1");
    }

    #[test]
    fn readiness_vocabulary_is_stable() {
        assert_eq!(SecurityCapability::ALL.len(), 4);
        assert_eq!(SecurityCapability::PeerIdentity.as_str(), "peer_identity");
        assert_eq!(CapabilityStatus::Unavailable.as_str(), "unavailable");
    }
}
