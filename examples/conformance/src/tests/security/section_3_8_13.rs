//! Section 3.8.13 — `PID_TOOL_KEY` access policy `008/008` (4 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.13 PID_TOOL_KEY".
//!
//! Tests PID 0x38 (PID_TOOL_KEY, i.e. PID 56) on the Security Interface
//! Object (IOT=0x0011, instance=0x0010). Access policy is `008/008`: requires
//! Tool A+C for writing. The property is **write-only** — all read attempts
//! are denied with E_ACCESS_DENIED (0xFC).
//!
//! The tool key value is PDT_GENERIC_16 (16 bytes).
//!
//! Skipped test cases:
//! - 3.8.13.1 — writes an actual key and uses it for authentication
//!   (complex key-switch scenario with SyncReq).
//! - 3.8.13.2 — unloads/reloads Security IO and switches from TK1 to TK2;
//!   requires LoadStateControl support not exercised elsewhere.
//! - 3.8.13.6 — uses T_Connect (connection-oriented), not yet implemented.
//! - 3.8.13.8 — uses FDSK key setup, not yet implemented.
//!
//! Note: The XML test template uses TK2 for tests 3.8.13.3–5 because it
//! assumes 3.8.13.2 already switched the tool key. Since we skip 3.8.13.2,
//! we use TK1 (the default tool key) instead.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Security Mode Toggle Templates
// ============================================================================

const ENABLE_SECURITY_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

const ENABLE_SECURITY_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

const DISABLE_SECURITY_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const DISABLE_SECURITY_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// ============================================================================
// PropertyExtValueWriteCon templates for PID 0x38 on Security IO
// ============================================================================

// Secure write: count=1, start=1, data=16 bytes (all-zero key + 0x01).
// The last byte 0x01 is part of the 16-byte key value.
// APDU: 01 CE + 00 11 + 00 10 + 38 + 01 + 00 01 + 16 data = 26 bytes → len = 0x19
const SECURE_WRITE_TOOL_KEY: &str =
    "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";

// Write success: count=1, start=1, return_code=0x00.
// APDU: 01 CF + 00 11 + 00 10 + 38 + 01 + 00 01 + 00 = 11 bytes → len = 0x0A
#[allow(dead_code)] // Not used since we skip 3.8.13.1 and 3.8.13.2.
const SECURE_WRITE_TOOL_KEY_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 01 00 01 00";

// Write denied: count=0, start=1, return_code=0xFC (E_ACCESS_DENIED).
const SECURE_WRITE_TOOL_KEY_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 00 00 01 FC";

// Plain write denied response: standard frame.
const PLAIN_WRITE_TOOL_KEY_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 38 00 00 01 FC";

// ============================================================================
// PropertyExtValueRead templates for PID 0x38 on Security IO (write-only)
// ============================================================================

// Secure A_PropertyExtValueRead: count=1, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 38 + 01 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ_TOOL_KEY: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 38 01 00 01";

// Secure read denied: count=0, start=1, return_code=0xFC (E_ACCESS_DENIED).
// All reads are denied because PID_TOOL_KEY is write-only.
const SECURE_READ_TOOL_KEY_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 38 00 00 01 FC";

// Plain extended read (extended frame for oversize APDU).
const PLAIN_EXT_READ_TOOL_KEY: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 38 01 00 01";

// Plain extended read denied.
const PLAIN_EXT_READ_TOOL_KEY_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 38 00 00 01 FC";

// ============================================================================
// Standard PropertyValueRead templates (03 D5/D6) for PID 0x38
// ============================================================================
//
// The XML also tests the old-style A_PropertyValue_Read service to verify
// that reads are denied through both API paths.

// Plain standard read: obj_index=#SEC_INTF_OBJ_INDEX, PID=0x38, count=1, start=1.
// APDU: 03 D5 + OBJ_INDEX(1) + PID(1) + count_start(2) = 6 bytes → TP1 len = 0x65
const PLAIN_STD_READ_TOOL_KEY: &str =
    "BC #EDI #BDUT_ADDR 65 03 D5 #SEC_INTF_OBJ_INDEX 38 10 01";

// Plain standard read denied: count=0, start=1.
// In standard property read, count=0 indicates an error/denied response.
const PLAIN_STD_READ_TOOL_KEY_DENIED: &str =
    "BC #BDUT_ADDR #EDI 65 03 D6 #SEC_INTF_OBJ_INDEX 38 00 01";

// Secure standard read (extended frame).
// APDU: 03 D5 + OBJ_INDEX(1) + PID(1) + count_start(2) = 6 bytes → len = 0x05
const SECURE_STD_READ_TOOL_KEY: &str =
    "3C 60 #EDI #BDUT_ADDR 05 03 D5 #SEC_INTF_OBJ_INDEX 38 10 01";

// Secure standard read denied: count=0, start=1.
const SECURE_STD_READ_TOOL_KEY_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 05 03 D6 #SEC_INTF_OBJ_INDEX 38 00 01";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x38 on Security IO
// ============================================================================

// Secure A+C A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x38, description index=0x00, property index=0x00.
// APDU: 01 D2 + 00 11 + 00 10 + 38 + 00 + 00 = 8 bytes → len = 0x08
const SECURE_DESC_READ_PID38: &str =
    "3C 60 #EDI #BDUT_ADDR 08 01 D2 00 11 00 10 38 00 00";

// Secure A+C success response: valid descriptor (wildcard data bytes).
// APDU: 01 D3 + 00 11 + 00 10 + 38 + ?? x10 = 16 bytes → len = 0x10
const SECURE_DESC_READ_PID38_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Plain A_PropertyExtDescription_Read for PID 0x38.
const PLAIN_DESC_READ_PID38: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 38 00 00";

// Plain all-zero descriptor response (access denied for 00C/00C — plain NEVER allowed).
const PLAIN_DESC_READ_PID38_ZERO: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 38 00 00 00 00 00 00 00 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_13_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.13 PID_TOOL_KEY (Security IO, access 008/008, write-only)", variables)
        .secure()
        .with_cases(vec![
            // Skipped: 3.8.13.1 — writes actual key and uses it for authentication.
            // Skipped: 3.8.13.2 — unloads/reloads Security IO and switches tool key.
            test_3_8_13_3(),
            test_3_8_13_4(),
            test_3_8_13_5(),
            // Skipped: 3.8.13.6 — uses T_Connect (connection-oriented).
            test_3_8_13_7(),
            // Skipped: 3.8.13.8 — uses FDSK key setup.
        ])
}

// ============================================================================
// 3.8.13.3 Secured PropertyValueWrite sent only authenticated
// ============================================================================
//
// Auth-only write is insufficient for 008/008 policy — it requires A+C.
// Write is denied in both security modes.

fn test_3_8_13_3() -> TestCase {
    TestCase::new("3.8.13.3 Secured PropertyValueWrite sent only authenticated").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only write tool key → E_ACCESS_DENIED (008 requires A+C)"),
        inject_secure_ao(SECURE_WRITE_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_WRITE_TOOL_KEY_DENIED, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only write tool key → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_WRITE_TOOL_KEY_DENIED, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.13.4 Unsecure PropertyValueWrite
// ============================================================================
//
// Plain (non-secure) write is always denied under 008/008 policy.

fn test_3_8_13_4() -> TestCase {
    TestCase::new("3.8.13.4 Unsecure PropertyValueWrite").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write tool key → E_ACCESS_DENIED"),
        inject(SECURE_WRITE_TOOL_KEY),
        expect(PLAIN_WRITE_TOOL_KEY_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write tool key → E_ACCESS_DENIED"),
        inject(SECURE_WRITE_TOOL_KEY),
        expect(PLAIN_WRITE_TOOL_KEY_DENIED, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.13.5 Secure Property(Ext)ValueRead
// ============================================================================
//
// PID_TOOL_KEY is write-only: all reads are denied with E_ACCESS_DENIED (0xFC)
// regardless of access mode (plain, auth-only, A+C) and regardless of which
// property read service is used (standard 03 D5 or extended 01 CC).
//
// Tests both security mode ON and OFF phases.

fn test_3_8_13_5() -> TestCase {
    TestCase::new("3.8.13.5 Secure Property(Ext)ValueRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // -- Standard property read (03 D5) --
        comment("Plain standard read → denied (write-only)"),
        inject(PLAIN_STD_READ_TOOL_KEY),
        expect(PLAIN_STD_READ_TOOL_KEY_DENIED, TIMEOUT),

        comment("Auth-only standard read → denied"),
        inject_secure_ao(SECURE_STD_READ_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_STD_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),

        comment("A+C standard read → denied"),
        inject_secure_ac(SECURE_STD_READ_TOOL_KEY, "TK1"),
        expect_secure_ac(SECURE_STD_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),

        // -- Extended property read (01 CC) --
        comment("Plain extended read → E_ACCESS_DENIED"),
        inject(PLAIN_EXT_READ_TOOL_KEY),
        expect(PLAIN_EXT_READ_TOOL_KEY_DENIED, TIMEOUT),

        comment("Auth-only extended read → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),

        comment("A+C extended read → E_ACCESS_DENIED"),
        inject_secure_ac(SECURE_READ_TOOL_KEY, "TK1"),
        expect_secure_ac(SECURE_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // -- Standard property read (03 D5) --
        comment("Plain standard read → denied"),
        inject(PLAIN_STD_READ_TOOL_KEY),
        expect(PLAIN_STD_READ_TOOL_KEY_DENIED, TIMEOUT),

        comment("Auth-only standard read → denied"),
        inject_secure_ao(SECURE_STD_READ_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_STD_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),

        comment("A+C standard read → denied"),
        inject_secure_ac(SECURE_STD_READ_TOOL_KEY, "TK1"),
        expect_secure_ac(SECURE_STD_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),

        // -- Extended property read (01 CC) --
        comment("Plain extended read → E_ACCESS_DENIED"),
        inject(PLAIN_EXT_READ_TOOL_KEY),
        expect(PLAIN_EXT_READ_TOOL_KEY_DENIED, TIMEOUT),

        comment("Auth-only extended read → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),

        comment("A+C extended read → E_ACCESS_DENIED"),
        inject_secure_ac(SECURE_READ_TOOL_KEY, "TK1"),
        expect_secure_ac(SECURE_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.13.7 PropertyDescriptionRead
// ============================================================================
//
// Access policy 008/008: A+C secure description read succeeds (A+C is always
// allowed). Plain description read returns all-zero (plain NEVER allowed for
// 008/008, regardless of security mode).

fn test_3_8_13_7() -> TestCase {
    TestCase::new("3.8.13.7 PropertyDescriptionRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Secure A+C description read → success (valid descriptor)"),
        inject_secure_ac(SECURE_DESC_READ_PID38, "TK1"),
        expect_secure_ac(SECURE_DESC_READ_PID38_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → all-zero (plain never allowed for 008/008)"),
        inject(PLAIN_DESC_READ_PID38),
        expect(PLAIN_DESC_READ_PID38_ZERO, TIMEOUT),
    ])
}
