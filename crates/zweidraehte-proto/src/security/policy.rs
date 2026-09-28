//! GO security flag matching — the one admission rule worth sharing.
//!
//! Every other S-AL decision (`tables_evaluable`, `tool_access_allowed`,
//! `received_security_bits`) is a single boolean expression that reads
//! clearer inline at the call site than as a named function here. The GO
//! flag check is different: the exact-match rule across multiple associated
//! objects is genuinely non-obvious, and the two stacks must agree on it.

use crate::access::{AccessLevel, AccessPolicy, SecurityMode};
use crate::messages::apdu::restart::{EraseCode, RestartType};

/// Mask selecting the security requirement from a `PID_GO_SECURITY_FLAGS` byte.
pub const GO_FLAG_SECURITY_MASK: u8 = 0x03;

/// Whether every group object associated with one group address accepts a
/// frame arriving at `received_bits`.
///
/// `required` yields the flag byte of each associated object, in any order,
/// with `None` for an object the flag table does not cover. When several
/// objects share the group address they must *all* accept — the weakest one
/// does not win.
///
/// The rule is **exact match**, not "at least as strong": a plain-configured
/// object rejects an authenticated frame just as an authenticated one rejects
/// a plain frame. An object with no flag entry has no requirement and accepts
/// anything.
pub fn go_flags_accept(required: impl IntoIterator<Item = Option<u8>>, received_bits: u8) -> bool {
    required.into_iter().all(|flag| match flag {
        Some(f) => f & GO_FLAG_SECURITY_MASK == received_bits,
        None => true,
    })
}

/// The security bits (`PID_GO_SECURITY_FLAGS` coding) a request of
/// `security` carries: none, authentication, or authentication and
/// confidentiality.
pub const fn security_bits(security: SecurityMode) -> u8 {
    match security {
        SecurityMode::Plain => 0x00,
        SecurityMode::AuthOnly => 0x01,
        SecurityMode::AuthConf => 0x03,
    }
}

/// Whether a caller of `security` may reach, through Group Object
/// Diagnostics, what requires the security bits `required`.
///
/// GO Diagnostics "shall not have lower security access conditions to a
/// GO than the access through the group services" (03/05/01 §4.8.1): a GO
/// the group services admit only with A+C is not reached with less through
/// its diagnostics either. Unlike [`go_flags_accept`], this is a floor, not
/// an exact match — management may exceed the object's requirement. `None`
/// is an object without a flag entry.
pub const fn go_diagnostics_accept(required: Option<u8>, security: SecurityMode) -> bool {
    let Some(required) = required else {
        return true;
    };
    let required = required & GO_FLAG_SECURITY_MASK;
    let offered = security_bits(security);
    // Confidentiality implies authentication, so the offered bits must
    // cover every required bit; an invalid `10b` demands A+C.
    required & !offered == 0 && (required & 0x02 == 0 || offered == 0x03)
}

/// Data Secure access policy of one `A_Restart` (AN193 v04 §2.2.4.3).
///
/// AN193 omits ResetAP (04h); it gets the other erasing codes' `3FF/00C`.
/// Codes a server does not implement are answered "Unsupported Erase
/// Code" before any policy applies, so their `00C/00C` is never consulted.
pub const fn restart_access_policy(restart: RestartType) -> AccessPolicy {
    match restart {
        RestartType::Basic | RestartType::MasterReset(EraseCode::Confirmed) => AccessPolicy::READ_OPEN_WRITE_TOOL,
        RestartType::MasterReset(EraseCode::ResetIA) => AccessPolicy::OPEN_OFF_DENY_ON,
        RestartType::MasterReset(
            EraseCode::FactoryReset
            | EraseCode::ResetAP
            | EraseCode::ResetParam
            | EraseCode::ResetLinks
            | EraseCode::FactoryResetKeepIA,
        ) => AccessPolicy::OPEN_OFF_TOOL_ON,
        RestartType::MasterReset(EraseCode::Other(_)) => AccessPolicy::TOOL_ONLY,
    }
}

/// Legacy authorisation audience required by one `A_Restart`.
///
/// A restart that erases nothing (basic, or the confirmed restart 01h) is
/// free to everyone; every master reset that erases needs level 0.
/// 03/05/02 §3.7 Table 5 leaves the protection of Master Reset to the
/// device ("protected by authorization"), so level 0 is our choice.
///
/// An audience rather than a number: "free" is level 3 on a 4-level
/// profile and level 15 on a 16-level one, so the caller resolves it with
/// [`AccessLevel::for_levels`].
pub const fn restart_required_level(restart: RestartType) -> AccessLevel {
    match restart {
        RestartType::Basic | RestartType::MasterReset(EraseCode::Confirmed) => AccessLevel::Runtime,
        RestartType::MasterReset(_) => AccessLevel::SystemManufacturer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_in_both_directions() {
        assert!(!go_flags_accept([Some(0x03)], 0x01), "auth-only rejected by auth+conf");
        assert!(!go_flags_accept([Some(0x01)], 0x03), "auth+conf rejected by auth-only");
        assert!(!go_flags_accept([Some(0x00)], 0x01), "secured rejected by plain");
        assert!(!go_flags_accept([Some(0x01)], 0x00), "plain rejected by auth-only");
    }

    #[test]
    fn upper_bits_ignored() {
        assert!(go_flags_accept([Some(0xFC | 0x01)], 0x01));
    }

    #[test]
    fn no_entry_means_no_requirement() {
        assert!(go_flags_accept([None], 0x00));
        assert!(go_flags_accept([None], 0x03));
    }

    #[test]
    fn shared_addresses_take_strictest() {
        assert!(!go_flags_accept([Some(0x01), Some(0x03)], 0x01));
        assert!(go_flags_accept([Some(0x01), Some(0x01)], 0x01));
    }

    #[test]
    fn empty_means_nothing_to_object() {
        assert!(go_flags_accept(core::iter::empty(), 0x00));
    }

    /// GO Diagnostics access is a floor: at least what the group services
    /// require, and more is fine.
    #[test]
    fn diagnostics_need_at_least_the_group_security() {
        use SecurityMode::{AuthConf, AuthOnly, Plain};

        for security in [Plain, AuthOnly, AuthConf] {
            assert!(go_diagnostics_accept(None, security), "no entry, {security:?}");
            assert!(go_diagnostics_accept(Some(0x00), security), "plain object, {security:?}");
        }
        assert!(!go_diagnostics_accept(Some(0x01), Plain));
        assert!(go_diagnostics_accept(Some(0x01), AuthOnly));
        assert!(go_diagnostics_accept(Some(0x01), AuthConf));
        assert!(!go_diagnostics_accept(Some(0x03), Plain));
        assert!(!go_diagnostics_accept(Some(0x03), AuthOnly));
        assert!(go_diagnostics_accept(Some(0x03), AuthConf));
        // The invalid confidentiality-only coding demands A+C.
        assert!(!go_diagnostics_accept(Some(0x02), AuthOnly));
        assert!(go_diagnostics_accept(Some(0x02), AuthConf));
        // Bits above the security field are not requirements.
        assert!(go_diagnostics_accept(Some(0x90), Plain));
    }
}
