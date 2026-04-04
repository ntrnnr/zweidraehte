//! Section 3.8.8 — `PID_SECURITY_MODE` access policy `15F/04C` (5 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.8 PID_SECURITY_MODE".
//!
//! Tests PID 0x33 (PID_SECURITY_MODE) on the Security Interface Object
//! (IOT=0x0011, instance=0x0010) using `A_FunctionPropertyExtCommand`
//! (0x01D4), `A_FunctionPropertyExtState_Read` (0x01D5), and
//! `A_FunctionPropertyExtState_Response` (0x01D6).
//!
//! Access policy is `15F/04C`:
//! - Security Mode OFF: Command/StateRead allowed with A+C and auth-only;
//!   plain Command is denied but plain StateRead succeeds.
//! - Security Mode ON: Command/StateRead require A+C; auth-only and plain
//!   are denied.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// FunctionPropertyExtCommand / Response templates for PID 0x33
// ============================================================================

// A_FunctionPropertyExtCommand (0x01D4) on Security IO (0x0011, instance 0x0010),
// PID_SECURITY_MODE (0x33): reserved=0x00, ServiceID=0x00 (Write Security Mode),
// ServiceInfo=0x01 (Enable).
// APDU: 01 D4 + 00 11 + 00 10 + 33 + 00 + 00 + 01 = 10 bytes → TP1 len = 0x09
const COMMAND_ENABLE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

// A_FunctionPropertyExtCommand: ServiceInfo=0x00 (Disable).
const COMMAND_DISABLE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

// A_FunctionPropertyExtState_Response (0x01D6): return_code=0x00 (success).
// APDU: 01 D6 + 00 11 + 00 10 + 33 + 00 = 8 bytes → TP1 len = 0x07
const COMMAND_RESP_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// A_FunctionPropertyExtState_Response: return_code=0xF8 (invalid service info).
const COMMAND_RESP_F8: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 F8 00";

// A_FunctionPropertyExtState_Response: return_code=0xFC (access denied).
const COMMAND_RESP_FC: &str =
    "3C 60 #BDUT_ADDR #EDI 07 01 D6 00 11 00 10 33 FC";

// ============================================================================
// FunctionPropertyExtCommand with invalid ServiceID / ServiceInfo
// ============================================================================

// Command with ServiceInfo=0x03 (invalid — only 0x00 and 0x01 are valid).
// APDU: 01 D4 + 00 11 + 00 10 + 33 + 00 + 00 + 03 = 10 bytes → TP1 len = 0x09
const COMMAND_INVALID_SERVICE_INFO: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 03";

// ============================================================================
// FunctionPropertyExtState_Read / Response templates for PID 0x33
// ============================================================================

// A_FunctionPropertyExtState_Read (0x01D5): reserved=0x00, ServiceID=0x00.
// APDU: 01 D5 + 00 11 + 00 10 + 33 + 00 + 00 = 9 bytes → TP1 len = 0x08
const STATE_READ: &str =
    "3C 60 #EDI #BDUT_ADDR 08 01 D5 00 11 00 10 33 00 00";

// State_Read response: return_code=0x00, mode=0x01 (sec ON).
// APDU: 01 D6 + 00 11 + 00 10 + 33 + 00 + 00 + 01 = 10 bytes → TP1 len = 0x09
const STATE_READ_RESP_ON: &str =
    "3C 60 #BDUT_ADDR #EDI 09 01 D6 00 11 00 10 33 00 00 01";

// State_Read response: return_code=0x00, mode=0x00 (sec OFF).
const STATE_READ_RESP_OFF: &str =
    "3C 60 #BDUT_ADDR #EDI 09 01 D6 00 11 00 10 33 00 00 00";

// State_Read response: return_code=0xFC (access denied).
const STATE_READ_RESP_FC: &str =
    "3C 60 #BDUT_ADDR #EDI 07 01 D6 00 11 00 10 33 FC";

// State_Read with invalid ServiceID=0x01 (only 0x00 is valid for StateRead).
const STATE_READ_INVALID_SERVICE_ID: &str =
    "3C 60 #EDI #BDUT_ADDR 08 01 D5 00 11 00 10 33 00 01";

// State_Read response: return_code=0xF2 (invalid service ID), echoed ServiceID=0x01.
// APDU: 01 D6 + 00 11 + 00 10 + 33 + F2 + 01 = 9 bytes → TP1 len = 0x08
const STATE_READ_RESP_F2: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 F2 01";

// ============================================================================
// Plain (non-secure) FunctionPropertyExt templates
// ============================================================================

// Plain A_FunctionPropertyExtCommand: enable.
// APDU: 10 bytes → TP1 standard frame len = 0x69
const PLAIN_COMMAND_ENABLE: &str =
    "BC #EDI #BDUT_ADDR 69 01 D4 00 11 00 10 33 00 00 01";

// Plain A_FunctionPropertyExtCommand: disable.
const PLAIN_COMMAND_DISABLE: &str =
    "BC #EDI #BDUT_ADDR 69 01 D4 00 11 00 10 33 00 00 00";

// Plain Command response: return_code=0xFC (access denied).
// APDU: 01 D6 + 00 11 + 00 10 + 33 + FC = 8 bytes → TP1 len = 0x67
const PLAIN_COMMAND_RESP_FC: &str =
    "BC #BDUT_ADDR #EDI 67 01 D6 00 11 00 10 33 FC";

// Plain A_FunctionPropertyExtState_Read.
// APDU: 9 bytes → TP1 standard frame len = 0x68
const PLAIN_STATE_READ: &str =
    "BC #EDI #BDUT_ADDR 68 01 D5 00 11 00 10 33 00 00";

// Plain State_Read response: mode=0x00 (sec OFF).
// APDU: 01 D6 + 00 11 + 00 10 + 33 + 00 + 00 + 00 = 10 bytes → TP1 len = 0x69
const PLAIN_STATE_READ_RESP_OFF: &str =
    "BC #BDUT_ADDR #EDI 69 01 D6 00 11 00 10 33 00 00 00";

// Plain State_Read response: return_code=0xFC (access denied).
// APDU: 01 D6 + 00 11 + 00 10 + 33 + FC = 8 bytes → TP1 len = 0x67
const PLAIN_STATE_READ_RESP_FC: &str =
    "BC #BDUT_ADDR #EDI 67 01 D6 00 11 00 10 33 FC";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x33
// ============================================================================

// Plain A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x33, description index=0x00, property index=0x00.
const PLAIN_DESC_READ: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 33 00 00";

// Plain all-zero descriptor response (access denied when sec ON).
const PLAIN_DESC_READ_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 33 00 00 00 00 00 00 00 00 00 00";

// Plain success response: valid descriptor (wildcard data bytes).
const PLAIN_DESC_READ_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_8_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.8 PID_SECURITY_MODE (Security IO, access 15F/04C)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_8_1(),
            test_3_8_8_2(),
            test_3_8_8_3(),
            test_3_8_8_4(),
            test_3_8_8_5(),
        ])
}

// ============================================================================
// 3.8.8.1 Activate/deactivate + read state (A+C)
// ============================================================================
//
// Verifies the basic activate/deactivate cycle via FunctionPropertyExtCommand
// and reads back the current state via FunctionPropertyExtState_Read. All
// interactions use A+C secure wrapping.

fn test_3_8_8_1() -> TestCase {
    TestCase::new("3.8.8.1 Activate/deactivate + read state (A+C)").with_steps(vec![
        // Enable security mode.
        comment("A+C Command: enable security mode"),
        inject_secure_ac(COMMAND_ENABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),

        // Read back — expect mode=1 (ON).
        comment("A+C StateRead → mode=1 (security ON)"),
        inject_secure_ac(STATE_READ, "TK1"),
        expect_secure_ac(STATE_READ_RESP_ON, "TK1", TIMEOUT),

        // Disable security mode.
        comment("A+C Command: disable security mode"),
        inject_secure_ac(COMMAND_DISABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),

        // Read back — expect mode=0 (OFF).
        comment("A+C StateRead → mode=0 (security OFF)"),
        inject_secure_ac(STATE_READ, "TK1"),
        expect_secure_ac(STATE_READ_RESP_OFF, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.8.2 Invalid Service IDs
// ============================================================================
//
// Verifies that the DUT rejects FunctionPropertyExtCommand with an invalid
// ServiceInfo value (0x03) and FunctionPropertyExtState_Read with an invalid
// ServiceID (0x01). Neither should change the security mode.

fn test_3_8_8_2() -> TestCase {
    TestCase::new("3.8.8.2 Invalid Service IDs").with_steps(vec![
        // Command with invalid ServiceInfo=0x03 → return_code=0xF8.
        comment("A+C Command with ServiceInfo=0x03 (invalid) → RC=0xF8"),
        inject_secure_ac(COMMAND_INVALID_SERVICE_INFO, "TK1"),
        expect_secure_ac(COMMAND_RESP_F8, "TK1", TIMEOUT),

        // Verify mode unchanged (should still be OFF from previous test or initial state).
        comment("A+C StateRead → mode=0 (unchanged)"),
        inject_secure_ac(STATE_READ, "TK1"),
        expect_secure_ac(STATE_READ_RESP_OFF, "TK1", TIMEOUT),

        // StateRead with invalid ServiceID=0x01 → return_code=0xF2.
        comment("A+C StateRead with ServiceID=0x01 (invalid) → RC=0xF2"),
        inject_secure_ac(STATE_READ_INVALID_SERVICE_ID, "TK1"),
        expect_secure_ac(STATE_READ_RESP_F2, "TK1", TIMEOUT),

        // Verify mode still unchanged.
        comment("A+C StateRead → mode=0 (still unchanged)"),
        inject_secure_ac(STATE_READ, "TK1"),
        expect_secure_ac(STATE_READ_RESP_OFF, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.8.3 Auth-only access
// ============================================================================
//
// Access policy 15F/04C: when security mode is OFF, auth-only access is
// sufficient for both Command and StateRead. When security mode is ON,
// auth-only is insufficient — A+C is required.

fn test_3_8_8_3() -> TestCase {
    TestCase::new("3.8.8.3 Auth-only access").with_steps(vec![
        // Ensure security mode is OFF.
        comment("A+C Command: disable security mode (ensure OFF)"),
        inject_secure_ac(COMMAND_DISABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),

        // Auth-only StateRead when sec OFF → succeeds.
        comment("Auth-only StateRead → mode=0 (succeeds when sec OFF)"),
        inject_secure_ao(STATE_READ, "TK1"),
        expect_secure_ao(STATE_READ_RESP_OFF, "TK1", TIMEOUT),

        // Auth-only Command enable when sec OFF → succeeds.
        comment("Auth-only Command: enable security mode (succeeds when sec OFF)"),
        inject_secure_ao(COMMAND_ENABLE, "TK1"),
        expect_secure_ao(COMMAND_RESP_OK, "TK1", TIMEOUT),

        // Auth-only Command disable when sec ON → denied (04C requires A+C).
        comment("Auth-only Command: disable → RC=0xFC (denied when sec ON)"),
        inject_secure_ao(COMMAND_DISABLE, "TK1"),
        expect_secure_ao(COMMAND_RESP_FC, "TK1", TIMEOUT),

        // Auth-only StateRead when sec ON → denied.
        comment("Auth-only StateRead → RC=0xFC (denied when sec ON)"),
        inject_secure_ao(STATE_READ, "TK1"),
        expect_secure_ao(STATE_READ_RESP_FC, "TK1", TIMEOUT),

        // Clean up: disable security mode via A+C.
        comment("A+C Command: disable security mode (cleanup)"),
        inject_secure_ac(COMMAND_DISABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.8.4 Plain access
// ============================================================================
//
// PID_SECURITY_MODE Command always requires secure access — plain Command
// is denied regardless of security mode. Plain StateRead is allowed when
// security mode is OFF (15F policy) but denied when ON (04C policy).

fn test_3_8_8_4() -> TestCase {
    TestCase::new("3.8.8.4 Plain access").with_steps(vec![
        // ==== Security Mode OFF ====
        comment("A+C Command: disable security mode (ensure OFF)"),
        inject_secure_ac(COMMAND_DISABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),

        comment("Plain Command enable → RC=0xFC (plain Command always denied)"),
        inject(PLAIN_COMMAND_ENABLE),
        expect(PLAIN_COMMAND_RESP_FC, TIMEOUT),

        comment("Plain Command disable → RC=0xFC"),
        inject(PLAIN_COMMAND_DISABLE),
        expect(PLAIN_COMMAND_RESP_FC, TIMEOUT),

        comment("Plain StateRead → mode=0 (allowed when sec OFF, 15F policy)"),
        inject(PLAIN_STATE_READ),
        expect(PLAIN_STATE_READ_RESP_OFF, TIMEOUT),

        // ==== Security Mode ON ====
        comment("A+C Command: enable security mode"),
        inject_secure_ac(COMMAND_ENABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),

        comment("Plain Command enable → RC=0xFC (still denied)"),
        inject(PLAIN_COMMAND_ENABLE),
        expect(PLAIN_COMMAND_RESP_FC, TIMEOUT),

        comment("Plain Command disable → RC=0xFC"),
        inject(PLAIN_COMMAND_DISABLE),
        expect(PLAIN_COMMAND_RESP_FC, TIMEOUT),

        comment("Plain StateRead → RC=0xFC (denied when sec ON)"),
        inject(PLAIN_STATE_READ),
        expect(PLAIN_STATE_READ_RESP_FC, TIMEOUT),

        // Clean up: disable security mode via A+C.
        comment("A+C Command: disable security mode (cleanup)"),
        inject_secure_ac(COMMAND_DISABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.8.5 PropertyDescriptionRead plain
// ============================================================================
//
// Plain description read returns all-zero when security mode is ON (access
// denied) and a valid descriptor when security mode is OFF.

fn test_3_8_8_5() -> TestCase {
    TestCase::new("3.8.8.5 PropertyDescriptionRead plain").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(COMMAND_ENABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),

        comment("Plain description read → all-zero response (access denied)"),
        inject(PLAIN_DESC_READ),
        expect(PLAIN_DESC_READ_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(COMMAND_DISABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),

        comment("Plain description read → valid descriptor"),
        inject(PLAIN_DESC_READ),
        expect(PLAIN_DESC_READ_OK, TIMEOUT),
    ])
}
