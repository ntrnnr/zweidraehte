//! Security test variables and key definitions.
//!
//! Matches the variable definitions in
//! `KnxConformanceTestTemplate-DataSecurity.xml`.

use std::collections::BTreeMap;

use super::context::SecurityTestContext;
use crate::TestVariable;

// ============================================================================
// Test Key Definitions
// ============================================================================

/// Tool Key 1 — primary tool key used for most security tests.
pub const TK1: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

/// Tool Key 2 — alternate tool key for key-switch tests.
pub const TK2: [u8; 16] =
    [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

/// Group Key 1 — for group address index of GA 1/1/1.
pub const GK1: [u8; 16] =
    [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];

/// Group Key 2 — for group address index of GA 2/2/2.
pub const GK2: [u8; 16] =
    [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

/// Group Key 3 — for group address index of GA 3/3/3.
pub const GK3: [u8; 16] =
    [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F];

/// Group Key 4 — for group address index of GA 4/4/4.
pub const GK4: [u8; 16] =
    [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F];

/// Group Key 5 — for group address index of GA 6/6/6.
pub const GK5: [u8; 16] =
    [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F];

/// FDSK — Factory Default Setup Key (same as TK1 for testing convenience).
pub const FDSK: [u8; 16] = TK1;

// ============================================================================
// P2P Key Definitions (Section 3.6 — Roles)
// ============================================================================

/// P2P Key 1 — for peer IA 1.1.1 (0x1101), Role 0 (A, R+W).
pub const P2PK1: [u8; 16] = [0x22; 16];

/// P2P Key 2 — for peer IA 1.1.2 (0x1102), Role 1 (A+C, R+W).
pub const P2PK2: [u8; 16] = [0x33; 16];

/// P2P Key 3 — for peer IA 1.1.3 (0x1103), Role 2 (A, R only).
pub const P2PK3: [u8; 16] = [0x44; 16];

/// P2P Key 4 — for peer IA 1.1.4 (0x1104), Role 3 (A+C, R only).
pub const P2PK4: [u8; 16] = [0x55; 16];

/// P2P Key 5 — for peer IA 1.1.5 (0x1105), Role 4 (A, W only).
pub const P2PK5: [u8; 16] = [0x66; 16];

/// P2P Key 6 — for peer IA 1.1.6 (0x1106), Role 5 (A+C, W only).
pub const P2PK6: [u8; 16] = [0x77; 16];

/// P2P Key 7 — for peer IA 1.1.7 (0x1107), no role.
pub const P2PK7: [u8; 16] = [0x88; 16];

/// P2P Key 8 — for peer IA 1.1.8 (0x1108), Roles 3+4.
pub const P2PK8: [u8; 16] = [0x99; 16];

// ============================================================================
// Test Variables
// ============================================================================

/// Create the standard security test variables.
///
/// These match the XML Fields section: BDUT_ADDR=11 01, EDI=AF FE,
/// SER_NUM=FE ED BA BE CA FE, etc.
pub fn create_security_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();

    // Addresses.
    vars.insert("BDUT_ADDR".into(), TestVariable::Bytes(vec![0x11, 0x01]));
    vars.insert("EDI".into(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("ALT_SRC_ADDR".into(), TestVariable::Bytes(vec![0xAF, 0xFD]));
    vars.insert("SER_NUM".into(), TestVariable::Bytes(vec![0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE]));

    // Alternate BDUT address: 2.2.2 = 0x1202 (used by Section 3.6 where
    // the normal BDUT address conflicts with P2P peer IAs).
    vars.insert("ALT_BDUT_ADDR".into(), TestVariable::Bytes(vec![0x12, 0x02]));

    // Security Interface Object index.
    vars.insert("SEC_INTF_OBJ_INDEX".into(), TestVariable::Bytes(vec![0x06]));

    // Domain address.
    vars.insert("DOM_ADDR".into(), TestVariable::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));

    // Device Descriptor Type 0 response (System B TP1 = 0x07B0).
    vars.insert("DD0_RESPONSE".into(), TestVariable::Bytes(vec![0x07, 0xB0]));

    // Access passwords.
    vars.insert("L2_PWD".into(), TestVariable::Bytes(vec![0x11, 0x22, 0x33, 0x44]));
    vars.insert("L3_PWD".into(), TestVariable::Bytes(vec![0x12, 0x34, 0x56, 0x78]));

    // User-defined Interface Object: for our DUT, this is the Security IO.
    vars.insert("USER_OBJ_TYPE1".into(), TestVariable::Bytes(vec![0x00, 0x11]));

    // Certification Object (IOT 0xC351) — used for Section 3.6 role tests.
    vars.insert("CERT_OBJ_TYPE".into(), TestVariable::Bytes(vec![0xC3, 0x51]));

    // Property used for role-based access testing (PID 51 = 0x33).
    vars.insert("ROLES_PROPERTY".into(), TestVariable::Bytes(vec![0x33]));

    // Accessible properties on USER_OBJ_TYPE1 (Security IO):
    // PROP1: PDT_GENERIC_20 ReadWrite (PID_P2P_KEY_TABLE = 0x34)
    vars.insert("ACCESSIBLE_PROP1".into(), TestVariable::Bytes(vec![0x34]));
    // PROP3: PDT_FUNCTION (PID_SECURITY_MODE = 0x33)
    vars.insert("ACCESSIBLE_PROP3".into(), TestVariable::Bytes(vec![0x33]));
    // PROP4: PDT_GENERIC_01 ReadWrite (PID_SECURITY_REPORT = 0x39)
    vars.insert("ACCESSIBLE_PROP4".into(), TestVariable::Bytes(vec![0x39]));

    // Property indices within the Device Object for description-by-index tests.
    // These are 0-based indices into our DUT's Device Object property table.
    vars.insert("INDX_PID_SERIAL_NO".into(), TestVariable::Bytes(vec![0x08]));
    vars.insert("INDX_PID_DEVICE_CTRL".into(), TestVariable::Bytes(vec![0x01]));

    vars
}

/// Create the security test context with all named keys.
pub fn create_security_context() -> SecurityTestContext {
    let mut keys = BTreeMap::new();
    keys.insert("TK1".into(), TK1);
    keys.insert("TK2".into(), TK2);
    keys.insert("GK1".into(), GK1);
    keys.insert("GK2".into(), GK2);
    keys.insert("GK3".into(), GK3);
    keys.insert("GK4".into(), GK4);
    keys.insert("GK5".into(), GK5);
    keys.insert("FDSK".into(), FDSK);
    keys.insert("ZERO_KEY".into(), [0u8; 16]);
    keys.insert("P2PK1".into(), P2PK1);
    keys.insert("P2PK2".into(), P2PK2);
    keys.insert("P2PK3".into(), P2PK3);
    keys.insert("P2PK4".into(), P2PK4);
    keys.insert("P2PK5".into(), P2PK5);
    keys.insert("P2PK6".into(), P2PK6);
    keys.insert("P2PK7".into(), P2PK7);
    keys.insert("P2PK8".into(), P2PK8);
    SecurityTestContext::new(keys)
}
