//! Linux security adapter boundary.
//!
//! No Linux capability is implemented yet. Reporting `Unavailable` prevents scaffolding from being
//! mistaken for a working or safe runtime.

use safa_runtime_core::{CapabilityStatus, PlatformSecurity, SecurityCapability};

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxPlatformSecurity;

impl PlatformSecurity for LinuxPlatformSecurity {
    fn capability_status(&self, _capability: SecurityCapability) -> CapabilityStatus {
        CapabilityStatus::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use safa_runtime_core::{CapabilityStatus, PlatformSecurity, SecurityCapability};

    use super::LinuxPlatformSecurity;

    #[test]
    fn scaffold_never_claims_a_protected_capability() {
        let platform = LinuxPlatformSecurity;
        let capabilities = [
            SecurityCapability::CredentialStorage,
            SecurityCapability::PeerIdentity,
            SecurityCapability::UserAuthorization,
            SecurityCapability::ServiceLifecycle,
        ];

        for capability in capabilities {
            assert_eq!(
                platform.capability_status(capability),
                CapabilityStatus::Unavailable
            );
        }
    }
}
