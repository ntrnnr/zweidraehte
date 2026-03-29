//! Service-level access policies.
//!
//! Defines the minimum access level required to invoke each management
//! service. This is the first line of defense — checked *before*
//! dispatching to any handler. Individual handlers may perform additional
//! fine-grained checks (e.g., per-property access levels, access policies).
//!
//! ## Two-Layer Access Control
//!
//! 1. **Service level** (this module): Coarse check based on legacy access
//!    levels. Determines whether a service APCI is allowed at all.
//! 2. **Data level** (per-property [`AccessPolicy`]): Fine-grained check
//!    considering KNX Data Secure roles, security mode, and per-property
//!    permission matrices.
//!
//! [`AccessPolicy`]: crate::access::AccessPolicy

use crate::access::AccessPolicy;
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

        // Domain address services: unrestricted at service level. Protection
        // via serial number match (for SerialNumber variants) or programming
        // mode (for plain DomainAddress variants) in the handler.
        ApciCode::DomainAddressRead
        | ApciCode::DomainAddressWrite
        | ApciCode::DomainAddressResponse
        | ApciCode::DomainAddressSerialNumberRead
        | ApciCode::DomainAddressSerialNumberWrite => Some(3),

        // Property services: per-property read/write level checks in handler.
        ApciCode::PropertyDescriptionRead
        | ApciCode::PropertyValueRead
        | ApciCode::PropertyValueWrite => None,

        // Function property services: per-property checks in handler.
        ApciCode::FunctionPropertyCommand
        | ApciCode::FunctionPropertyStateRead => None,

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

// ============================================================================
// Restart Access Policies (KNX spec 03/04/01, Table 8)
// ============================================================================

/// Get the access policy for a restart with the given erase code.
///
/// Per KNX spec 03/04/01 Table 8, different restart/reset types have
/// different access requirements:
///
/// | Erase Code | Description | Policy |
/// |------------|-------------|--------|
/// | 0x00 | Basic restart (type=0) | 3FF / 0CC |
/// | 0x01 | Confirmed restart | 3FF / 0CC |
/// | 0x02 | Reset to default state | 3FF / 00C |
/// | 0x03 | Master reset | 3FF / 000 |
/// | 0x05 | Reset parameters | 3FF / 00C |
/// | 0x06 | Reset links | 3FF / 00C |
/// | 0x07 | Reset to default w/o IA | 3FF / 00C |
/// | 0x08 | Local reset to defaults | 3FF / 00C |
///
/// Note: Erase code 0x03 (master reset) has policy `3FF / 000`, meaning
/// no remote write access is possible — it can only be triggered locally.
pub const fn restart_access_policy(erase_code: u8) -> AccessPolicy {
    match erase_code {
        0x00 | 0x01 => AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF / 0CC
        0x02 => AccessPolicy::TOOL_ONLY, // 3FF / 00C
        0x03 => AccessPolicy::READ_ONLY_NO_REMOTE_WRITE, // 3FF / 000
        0x05 | 0x06 | 0x07 | 0x08 => AccessPolicy::TOOL_ONLY, // 3FF / 00C
        _ => AccessPolicy::TOOL_ONLY, // Unknown: conservative default
    }
}

/// Get the required legacy access level for a restart erase code.
///
/// This provides backward compatibility for devices without Data Secure.
/// The level check is a simplified version of the full access policy.
pub const fn restart_required_level(erase_code: u8) -> u8 {
    match erase_code {
        0x00 | 0x01 => 3, // Basic/confirmed restart: anyone
        0x02 => 0,        // Reset to default: level 0
        0x03 => 0,        // Master reset: level 0 (and even then, policy says no remote)
        0x05 | 0x06 | 0x07 | 0x08 => 0, // All resets: level 0
        _ => 0,           // Unknown: conservative
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
        assert_eq!(
            check_service_access(ApciCode::FunctionPropertyCommand, &ctx),
            AccessDecision::Defer
        );
        assert_eq!(
            check_service_access(ApciCode::FunctionPropertyStateRead, &ctx),
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

    #[test]
    fn restart_policies_match_spec() {
        use crate::access::SecurityMode;
        use crate::access::ClientRole;

        // Basic restart: unlisted plain can trigger (sec off, 3FF bits 9,8 set)
        let unlisted = AccessContext::new(3);
        let policy = restart_access_policy(0x00);
        assert!(policy.can_write(&unlisted, false));

        // Master reset (0x03): nobody can write remotely (000)
        let tool = AccessContext::with_security(0, SecurityMode::AuthConf, ClientRole::Tool);
        let policy = restart_access_policy(0x03);
        assert!(!policy.can_write(&tool, false));
        assert!(!policy.can_write(&tool, true));

        // Reset to default (0x02): only Tool can write
        let policy = restart_access_policy(0x02);
        assert!(policy.can_write(&tool, false)); // Tool A+C, sec off: bits 3,2 of 00C → bit 3 set
        assert!(!policy.can_write(&unlisted, false));
    }
}
