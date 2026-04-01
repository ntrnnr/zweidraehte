//! Section 3.8.17 — `PID_GO_SECURITY_FLAGS` access policy `00C/00C` (2 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.17 PID_GO_SECURITY_FLAGS".
//!
//! Tests PID 0x3D (PID_GO_SECURITY_FLAGS, i.e. PID 61) on the Security
//! Interface Object (IOT=0x0011, instance=0x0010). Access policy is `00C/00C`:
//! requires Tool A+C for both read and write in both security modes — plain and
//! auth-only access is always denied.
//!
//! Each entry is PDT_GENERIC_01 × count (3 GO flags bytes for 3 group objects).
//!
//! Skipped test cases:
//! - 3.8.17.1 — writes actual GO flag data and verifies group object behavior;
//!   needs a fully populated GO_FLAGS table and group communication setup.
//! - 3.8.17.5 — uses T_Connect (connection-oriented power-down test), not yet
//!   implemented.

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
    "3C 60 #BDUT_ADDR #EDI 07 01 D6 00 11 00 10 33 00";

const DISABLE_SECURITY_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const DISABLE_SECURITY_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 07 01 D6 00 11 00 10 33 00";

// ============================================================================
// PropertyExtValueRead / Response templates for PID 0x3D on Security IO
// ============================================================================

// Plain A_PropertyExtValueRead: IOT=0x0011, instance=0x0010,
// PID=0x3D (GO_SECURITY_FLAGS), count=3, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 3D + 03 + 00 01 = 10 bytes → TP1 len = 0x69
const PLAIN_READ: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 3D 03 00 01";

// Plain read error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
// APDU: 01 CD + 00 11 + 00 10 + 3D + 00 + 00 01 + FC = 11 bytes → len = 0x6A
const PLAIN_READ_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 3D 00 00 01 FC";

// Plain A_PropertyExtValueWriteCon: count=3, start=1, data=3 zero bytes.
// APDU: 01 CE + 00 11 + 00 10 + 3D + 03 + 00 01 + 00 00 00 = 13 bytes → len = 0x6C
const PLAIN_WRITE: &str =
    "BC #EDI #BDUT_ADDR 6C 01 CE 00 11 00 10 3D 03 00 01 00 00 00";

// Plain write error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
const PLAIN_WRITE_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 3D 00 00 01 FC";

// ============================================================================
// Secure (auth-only) templates for PID 0x3D on Security IO
// ============================================================================

// Secure A_PropertyExtValueRead (carried in extended frame for secure wrapping).
// APDU: 01 CC + 00 11 + 00 10 + 3D + 03 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ: &str =
    "30 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3D 03 00 01";

// Secure read error response: count=0, return_code=0xFC.
// APDU: 01 CD + 00 11 + 00 10 + 3D + 00 + 00 01 + FC = 11 bytes → len = 0x0A
const SECURE_READ_DENIED: &str =
    "30 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 3D 00 00 01 FC";

// Secure A_PropertyExtValueWriteCon: count=3, start=1, data=3 zero bytes.
// APDU: 01 CE + 00 11 + 00 10 + 3D + 03 + 00 01 + 00 00 00 = 13 bytes → len = 0x0C
const SECURE_WRITE: &str =
    "30 60 #EDI #BDUT_ADDR 0C 01 CE 00 11 00 10 3D 03 00 01 00 00 00";

// Secure write error response: count=0, return_code=0xFC.
const SECURE_WRITE_DENIED: &str =
    "30 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3D 00 00 01 FC";

// ============================================================================
// Verification read — A+C secure read to confirm current state at end of test
// ============================================================================

// A+C secure element count query: count=1, start=0.
const VERIFY_READ: &str =
    "30 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3D 01 00 00";

// Response: count=1, start=0, 2-byte element count.
const VERIFY_READ_OK: &str =
    "30 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 3D 01 00 00 ?? ??";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x3D on Security IO
// ============================================================================

// Secure A+C A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x3D, description index=0x00, property index=0x00.
// APDU: 01 D2 + 00 11 + 00 10 + 3D + 00 + 00 = 8 bytes → len = 0x08
const SECURE_DESC_READ_PID3D: &str =
    "3C 60 #EDI #BDUT_ADDR 08 01 D2 00 11 00 10 3D 00 00";

// Secure A+C success response: valid descriptor (wildcard data bytes).
// APDU: 01 D3 + 00 11 + 00 10 + 3D + ?? x10 = 16 bytes → len = 0x10
const SECURE_DESC_READ_PID3D_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 3D ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Plain A_PropertyExtDescription_Read for PID 0x3D.
const PLAIN_DESC_READ_PID3D: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 3D 00 00";

// Plain all-zero descriptor response (access denied for 00C/00C — plain NEVER allowed).
const PLAIN_DESC_READ_PID3D_ZERO: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 3D 00 00 00 00 00 00 00 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_17_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.17 PID_GO_SECURITY_FLAGS (Security IO, access 00C/00C)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_17_2(),
            test_3_8_17_3(),
            test_3_8_17_4(),
            // Skipped: 3.8.17.1 — writes actual GO flag data and verifies group
            //   object behavior; needs fully populated GO_FLAGS table.
            // Skipped: 3.8.17.5 — uses T_Connect (connection-oriented),
            //   not yet implemented.
        ])
}

// ============================================================================
// 3.8.17.2 Unsecure PropertyValueWrite/Read
// ============================================================================
//
// Plain (non-secure) write and read are always denied under 00C/00C policy,
// regardless of security mode. Ends with a verification A+C read to confirm
// the flags are unchanged.

fn test_3_8_17_2() -> TestCase {
    TestCase::new("3.8.17.2 Unsecure PropertyValueWrite/Read").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED (00C requires A+C)"),
        inject(PLAIN_READ),
        expect(PLAIN_READ_DENIED, TIMEOUT),

        comment("Plain write → E_ACCESS_DENIED"),
        inject(PLAIN_WRITE),
        expect(PLAIN_WRITE_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED (still denied, 00C policy)"),
        inject(PLAIN_READ),
        expect(PLAIN_READ_DENIED, TIMEOUT),

        comment("Plain write → E_ACCESS_DENIED"),
        inject(PLAIN_WRITE),
        expect(PLAIN_WRITE_DENIED, TIMEOUT),

        // Verification: A+C read to confirm flags unchanged.
        comment("A+C secure read → success (verify flags unchanged)"),
        inject_secure_ac(VERIFY_READ, "TK1"),
        expect_secure_ac(VERIFY_READ_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.17.3 Auth. Secured PropertyValueRead/Write
// ============================================================================
//
// Auth-only (without confidentiality) is insufficient for 00C/00C policy —
// both write and read are denied in both security modes. Ends with a
// verification A+C read to confirm the flags are unchanged.

fn test_3_8_17_3() -> TestCase {
    TestCase::new("3.8.17.3 Auth. Secured PropertyValueRead/Write").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only read → E_ACCESS_DENIED (00C requires A+C, not just A)"),
        inject_secure_ao(SECURE_READ, "TK1"),
        expect_secure_ao(SECURE_READ_DENIED, "TK1", TIMEOUT),

        comment("Auth-only write → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE, "TK1"),
        expect_secure_ao(SECURE_WRITE_DENIED, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only read → E_ACCESS_DENIED (still denied)"),
        inject_secure_ao(SECURE_READ, "TK1"),
        expect_secure_ao(SECURE_READ_DENIED, "TK1", TIMEOUT),

        comment("Auth-only write → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE, "TK1"),
        expect_secure_ao(SECURE_WRITE_DENIED, "TK1", TIMEOUT),

        // Verification: A+C read to confirm flags unchanged.
        comment("A+C secure read → success (verify flags unchanged)"),
        inject_secure_ac(VERIFY_READ, "TK1"),
        expect_secure_ac(VERIFY_READ_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.17.4 PropertyDescriptionRead
// ============================================================================
//
// Access policy 00C/00C: A+C secure description read succeeds (A+C is always
// allowed). Plain description read returns all-zero (plain NEVER allowed for
// 00C/00C, regardless of security mode).

fn test_3_8_17_4() -> TestCase {
    TestCase::new("3.8.17.4 PropertyDescriptionRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Secure A+C description read → success (valid descriptor)"),
        inject_secure_ac(SECURE_DESC_READ_PID3D, "TK1"),
        expect_secure_ac(SECURE_DESC_READ_PID3D_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → all-zero (plain never allowed for 00C/00C)"),
        inject(PLAIN_DESC_READ_PID3D),
        expect(PLAIN_DESC_READ_PID3D_ZERO, TIMEOUT),
    ])
}
