//! Security test variables and key definitions.
//!
//! Matches the variable definitions in
//! `KnxConformanceTestTemplate-DataSecurity.xml`.

use std::collections::BTreeMap;

use crate::TestVariable;
use super::context::SecurityTestContext;

// ============================================================================
// Test Key Definitions
// ============================================================================

/// Tool Key 1 — primary tool key used for most security tests.
pub const TK1: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];

/// Tool Key 2 — alternate tool key for key-switch tests.
pub const TK2: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

/// Group Key 1.
pub const GK1: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

/// FDSK — Factory Default Setup Key (same as TK1 for testing convenience).
pub const FDSK: [u8; 16] = TK1;

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
    keys.insert("FDSK".into(), FDSK);
    SecurityTestContext::new(keys)
}
