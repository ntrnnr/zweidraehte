//! GO security flag matching — the one admission rule worth sharing.
//!
//! Every other S-AL decision (`tables_evaluable`, `tool_access_allowed`,
//! `received_security_bits`) is a single boolean expression that reads
//! clearer inline at the call site than as a named function here. The GO
//! flag check is different: the exact-match rule across multiple associated
//! objects is genuinely non-obvious, and the two stacks must agree on it.

use crate::access::AccessPolicy;

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

/// Data Secure access policy for one `A_Restart` erase code.
pub const fn restart_access_policy(erase_code: u8) -> AccessPolicy {
    match erase_code {
        0x00 | 0x01 => AccessPolicy::READ_OPEN_WRITE_TOOL,
        0x02 | 0x04..=0x07 => AccessPolicy::OPEN_OFF_TOOL_ON,
        0x03 => AccessPolicy::OPEN_OFF_DENY_ON,
        _ => AccessPolicy::TOOL_ONLY,
    }
}

/// Legacy authorisation level required by one restart erase code.
pub const fn restart_required_level(erase_code: u8) -> u8 {
    match erase_code {
        0x00 | 0x01 => 3,
        _ => 0,
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
}
