//! Service-level access policies.
//!
//! Defines the minimum access level required to invoke each management
//! service. This is the first line of defense — checked *before*
//! dispatching to any handler. Individual handlers may perform additional
//! fine-grained checks (e.g., per-property access levels).
//!
//! The policy table is intentionally kept simple for legacy 4-level auth.
//! When KNX Secure is added, this module will be extended with
//! security-mode-aware policies (None/Auth/AuthConf) and role-based
//! access (Tool/Unlisted).

use crate::messages::knx::ApciCode;
use crate::AccessContext;

/// Result of a service-level access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AccessDecision {
    /// Service is allowed.
    Allowed,
    /// Service is denied — caller lacks sufficient access.
    Denied,
    /// No service-level policy — handler does its own checks.
    ///
    /// Used for services where access control is more granular than
    /// service-level (e.g., per-property levels, per-memory-region,
    /// or erase-code-dependent restart checks).
    Defer,
}

/// Check whether the given service is allowed under the given access context.
///
/// Returns [`AccessDecision::Allowed`] if the caller meets the minimum
/// access level, [`AccessDecision::Denied`] if not, or
/// [`AccessDecision::Defer`] if the service handles access checks
/// internally.
pub const fn check_service_access(apci: ApciCode, ctx: &AccessContext) -> AccessDecision {
    match required_access_level(apci) {
        Some(required) => {
            if ctx.access_level <= required {
                AccessDecision::Allowed
            } else {
                AccessDecision::Denied
            }
        }
        None => AccessDecision::Defer,
    }
}

/// Minimum access level required for a service, or `None` if the service
/// handles access checks internally.
const fn required_access_level(apci: ApciCode) -> Option<u8> {
    match apci {
        // Group communication: governed by comm object flags, not auth level.
        ApciCode::GroupValueRead
        | ApciCode::GroupValueWrite
        | ApciCode::GroupValueResponse => Some(3),

        // Device discovery: unrestricted.
        ApciCode::IndividualAddressRead
        | ApciCode::IndividualAddressSerialNumberRead
        | ApciCode::DeviceDescriptorRead
        | ApciCode::AdcRead
        | ApciCode::UserManufacturerInfoRead => Some(3),

        // Address write: unrestricted at service level. Protection comes from
        // the handler layer — IndividualAddressWrite requires programming mode,
        // IndividualAddressSerialNumberWrite requires serial number match.
        // In KNX Secure mode these will be tightened to Tool-only access.
        ApciCode::IndividualAddressWrite
        | ApciCode::IndividualAddressSerialNumberWrite => Some(3),

        // Property services: per-property read/write level checks in handler.
        ApciCode::PropertyDescriptionRead
        | ApciCode::PropertyValueRead
        | ApciCode::PropertyValueWrite => None,

        // Memory services: per-region checks in the memory map.
        ApciCode::MemoryRead
        | ApciCode::MemoryWrite
        | ApciCode::MemoryBitWrite
        | ApciCode::UserMemoryRead
        | ApciCode::UserMemoryWrite => None,

        // Auth services must be callable to gain access. KeyWrite checks
        // the caller's current level internally.
        ApciCode::AuthorizeRequest | ApciCode::KeyWrite => None,

        // Restart: erase-code-specific checks in handler (basic restart is
        // unrestricted, master reset requires level 0).
        ApciCode::Restart => None,

        // Unknown/unhandled services: deny by default (conservative).
        _ => Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_services_allowed_at_min_access() {
        let ctx = AccessContext::MIN_ACCESS;
        assert_eq!(
            check_service_access(ApciCode::GroupValueRead, &ctx),
            AccessDecision::Allowed
        );
        assert_eq!(
            check_service_access(ApciCode::DeviceDescriptorRead, &ctx),
            AccessDecision::Allowed
        );
        assert_eq!(
            check_service_access(ApciCode::IndividualAddressRead, &ctx),
            AccessDecision::Allowed
        );
        assert_eq!(
            check_service_access(ApciCode::AdcRead, &ctx),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn address_write_unrestricted_at_service_level() {
        // Address write services are unrestricted at the service level.
        // Protection comes from the handler: programming mode (for
        // IndividualAddressWrite) or serial number match (for
        // IndividualAddressSerialNumberWrite).
        let ctx = AccessContext::MIN_ACCESS;
        assert_eq!(
            check_service_access(ApciCode::IndividualAddressWrite, &ctx),
            AccessDecision::Allowed
        );
        assert_eq!(
            check_service_access(ApciCode::IndividualAddressSerialNumberWrite, &ctx),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn deferred_services_always_defer() {
        let ctx = AccessContext::MIN_ACCESS;
        assert_eq!(
            check_service_access(ApciCode::PropertyValueRead, &ctx),
            AccessDecision::Defer
        );
        assert_eq!(
            check_service_access(ApciCode::MemoryRead, &ctx),
            AccessDecision::Defer
        );
        assert_eq!(
            check_service_access(ApciCode::Restart, &ctx),
            AccessDecision::Defer
        );
        assert_eq!(
            check_service_access(ApciCode::AuthorizeRequest, &ctx),
            AccessDecision::Defer
        );
    }

    #[test]
    fn unknown_service_denied_without_max_access() {
        let min = AccessContext::MIN_ACCESS;
        // SystemNetworkParameterRead is not in our handled set, falls to `_ => Some(0)`
        assert_eq!(
            check_service_access(ApciCode::SystemNetworkParameterRead, &min),
            AccessDecision::Denied
        );

        let max = AccessContext::MAX_ACCESS;
        assert_eq!(
            check_service_access(ApciCode::SystemNetworkParameterRead, &max),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn has_level_semantics() {
        let ctx = AccessContext::new(2);
        assert!(ctx.has_level(2));  // exactly meets requirement
        assert!(ctx.has_level(3));  // exceeds requirement
        assert!(!ctx.has_level(1)); // insufficient
        assert!(!ctx.has_level(0)); // way insufficient
    }
}
