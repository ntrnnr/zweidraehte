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
//
// These are the values in the EITT data-security template's own Security
// Configuration Table, `supportfiles/TSSJ_SCT.csv`. They have to be: the
// template provisions keys by *value*, not by name — its preparation
// writes `PID_TOOL_KEY` with the sixteen octets 00…01 encrypted under
// FDSK — so a harness holding different bytes ends up with a device
// keyed one way and a runner expecting the other, and every secure
// exchange after it times out.
//
// The hand-written suites name their keys and do not care what the bytes
// are, with two exceptions that write them literally: section 3.8.8 and
// section 3.8.13.

/// Tool Key 1 — primary tool key used for most security tests.
pub const TK1: [u8; 16] =
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Tool Key 2 — alternate tool key for key-switch tests.
pub const TK2: [u8; 16] =
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Group Key 1 — for group address index of GA 1/1/1.
pub const GK1: [u8; 16] =
    [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];

/// Group Key 2 — for group address index of GA 2/2/2.
pub const GK2: [u8; 16] =
    [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB];

/// Group Key 3 — for group address index of GA 3/3/3.
pub const GK3: [u8; 16] =
    [0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC];

/// Group Key 4 — for group address index of GA 4/4/4.
pub const GK4: [u8; 16] =
    [0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD];

/// Group Key 5 — for group address index of GA 6/6/6.
pub const GK5: [u8; 16] =
    [0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE];

/// Group Key 6 — for group address index of GA 3/1/6 (used by Section 6.2
/// PID_GO_DIAGNOSTICS secure bus telegram tests).
pub const GK6: [u8; 16] =
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// FDSK — Factory Default Setup Key.
///
/// Must match `SECURE_FDSK` in [`crate::harness::secure_stack`]. Distinct
/// from TK1 so tests that factory-reset the DUT can observe the tool
/// key reverting to FDSK and re-provision TK1 via an FDSK-encrypted
/// `PID_TOOL_KEY` write, per the reference XML (see 3.8.13.1/8).
pub const FDSK: [u8; 16] =
    [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];

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
    vars.insert("BDUT_ADDR".into(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars.insert("EDI".into(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("ALT_SRC_ADDR".into(), TestVariable::Bytes(vec![0xAF, 0xFD]));
    vars.insert("SER_NUM".into(), TestVariable::Bytes(vec![0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE]));

    // Alternate BDUT address: 2.2.2 = 0x1202 (used by Section 3.6 where
    // the normal BDUT address conflicts with P2P peer IAs).
    vars.insert("ALT_BDUT_ADDR".into(), TestVariable::Bytes(vec![0x12, 0x02]));

    // BDUT address after a factory reset wipes the IA. The XML uses
    // `#BDUT_ADDR_RESET` for telegrams sent to the DUT before the IA
    // has been re-programmed — the DUT answers on the broadcast address
    // `FF FF` until then.
    vars.insert("BDUT_ADDR_RESET".into(), TestVariable::Bytes(vec![0xFF, 0xFF]));

    // Security Interface Object index.
    vars.insert("SEC_INTF_OBJ_INDEX".into(), TestVariable::Bytes(vec![0x06]));

    // Domain address.
    vars.insert("DOM_ADDR".into(), TestVariable::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));

    // Device Descriptor Type 0 response (System B TP1 = 0x07B0).
    vars.insert("DD0_RESPONSE".into(), TestVariable::Bytes(vec![0x07, 0xB0]));

    // Access passwords.
    vars.insert("L2_PWD".into(), TestVariable::Bytes(vec![0x11, 0x22, 0x33, 0x44]));
    vars.insert("L3_PWD".into(), TestVariable::Bytes(vec![0x12, 0x34, 0x56, 0x78]));

    // The template's "User Interface Object (IO1)", which for us is the
    // Certification Object at 0xC351 — the same object `CERT_OBJ_TYPE`
    // names, kept as a separate variable because the reference XML uses
    // both spellings.
    //
    // This used to point at the Security IO (0x0011) and the four
    // accessible properties at whatever Security IO properties happened
    // to have roughly the right shape. That was the only option before
    // the Certification Object carried properties of its own; it also
    // meant the extended-addressing tests never addressed anything
    // outside the standard object range, which is the one thing AN163
    // exists to cover.
    vars.insert("USER_OBJ_TYPE1".into(), TestVariable::Bytes(vec![0xC3, 0x51]));

    // Certification Object (IOT 0xC351) — used for Section 3.6 role tests.
    vars.insert("CERT_OBJ_TYPE".into(), TestVariable::Bytes(vec![0xC3, 0x51]));

    // Property used for role-based access testing (PID 51 = 0x33).
    vars.insert("ROLES_PROPERTY".into(), TestVariable::Bytes(vec![0x33]));

    // The four accessible properties the reference XML expects on IO1.
    // Their shapes come from its own field comments; see
    // `cert_pid` in `harness::secure_stack` for the implementations.
    // PROP1: PDT_GENERIC_02 ReadWrite, restricted write level (PID 52).
    vars.insert("ACCESSIBLE_PROP1".into(), TestVariable::Bytes(vec![0x34]));
    // PROP2: PDT_GENERIC_01 ReadWrite with a validated range (PID 201).
    vars.insert("ACCESSIBLE_PROP2".into(), TestVariable::Bytes(vec![0xC9]));
    // PROP3: PDT_FUNCTION (PID 54).
    vars.insert("ACCESSIBLE_PROP3".into(), TestVariable::Bytes(vec![0x36]));
    // PROP4: PDT_GENERIC_01 ReadWrite, long enough to fill an APDU (PID 55).
    vars.insert("ACCESSIBLE_PROP4".into(), TestVariable::Bytes(vec![0x37]));

    // Manufacturer-specific overflow-test PID exposed by our DUT for
    // conformance test 3.8.12.6: a writable view of the four 16-bit
    // failure counters in `PID_SECURITY_FAILURES_LOG`. The reference
    // XML names this `#OVERFLOW_PROPERTY` and suggests PID 203 (0xCB).
    vars.insert("OVERFLOW_PROPERTY".into(), TestVariable::Bytes(vec![0xCB]));

    // Start address of the DUT's read-only memory region for tests
    // 5.1.4 / 5.2.3. Three octets, big-endian.
    // Maps to `ConformanceMemoryMap::READONLY_MEMORY_BASE` (0x000500).
    vars.insert("READONLY_MEM_START".into(), TestVariable::Bytes(vec![0x00, 0x05, 0x00]));
    // Start address of the DUT's write-only memory region for test 5.2.3.
    // Maps to `ConformanceMemoryMap::WRITEONLY_MEMORY_BASE` (0x000510).
    vars.insert("WRITEONLY_MEM_START".into(), TestVariable::Bytes(vec![0x00, 0x05, 0x10]));

    // Memory addresses for security-aware sub-region tests (3.7.2.8).
    // 3-byte MemoryExtended addresses within Level 2 memory (0x0300-0x03FF).
    vars.insert("MEM_AP_000_000".into(), TestVariable::Bytes(vec![0x00, 0x03, 0xD0]));
    vars.insert("MEM_AP_3FF_00C".into(), TestVariable::Bytes(vec![0x00, 0x03, 0xE0]));

    // Property indices within the Device Object for description-by-index tests.
    // These are 0-based indices into our DUT's Device Object property table.
    vars.insert("INDX_PID_SERIAL_NO".into(), TestVariable::Bytes(vec![0x08]));
    vars.insert("INDX_PID_DEVICE_CTRL".into(), TestVariable::Bytes(vec![0x01]));

    // Group addresses for Section 6.2 PID_GO_DIAGNOSTICS tests.
    // GO_1 = 3/1/7 (no security key) — used for plain bus telegrams.
    vars.insert("GO_1".into(), TestVariable::Bytes(vec![0x19, 0x07]));
    // GO_2 = 3/1/6 (with security key GK6) — used for secure bus telegrams.
    vars.insert("GO_2".into(), TestVariable::Bytes(vec![0x19, 0x06]));

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
    keys.insert("GK6".into(), GK6);
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
