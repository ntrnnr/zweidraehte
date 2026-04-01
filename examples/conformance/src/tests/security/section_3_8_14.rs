//! Section 3.8.14 — `PID_SECURITY_REPORT` (PID 0x39) and
//! `PID_SECURITY_REPORT_CONTROL` (PID 0x3A), access policies `1FF/0CC`
//! and `00C/00C` respectively.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.14 PID_SECURITY_REPORT".
//!
//! Tests two PIDs on the Security Interface Object (IOT=0x0011, instance=0x0010):
//! - PID_SECURITY_REPORT (0x39): 1FF/0CC — read requires A+C when sec ON,
//!   write always requires A+C.
//! - PID_SECURITY_REPORT_CONTROL (0x3A): 00C/00C — both read and write
//!   always require A+C.
//!
//! Both are PDT_GENERIC_01 (1 byte each).
//!
//! Skipped test cases:
//! - 3.8.14.1 — writes control, provokes security errors, checks automated
//!   Network Parameter InfoReport generation. Needs security error provocation
//!   and N_InfoReport infrastructure.
//! - 3.8.14.5 — power-down / master reset persistence test.

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
// PID_SECURITY_REPORT_CONTROL (0x3A) — access 00C/00C
// ============================================================================

// Secure A+C read: count=1, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 3A + 01 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ_CTRL: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3A 01 00 01";

// Secure read success: count=1, start=1, data=1 byte (wildcard).
// APDU: 01 CD + 00 11 + 00 10 + 3A + 01 + 00 01 + ?? = 11 bytes → len = 0x0A
const SECURE_READ_CTRL_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 3A 01 00 01 ??";

// Secure read denied: count=0, start=1, return_code=0xFC.
const SECURE_READ_CTRL_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 3A 00 00 01 FC";

// Secure A+C write: count=1, start=1, data=0x00.
// APDU: 01 CE + 00 11 + 00 10 + 3A + 01 + 00 01 + 00 = 11 bytes → len = 0x0A
const SECURE_WRITE_CTRL: &str =
    "3C 60 #EDI #BDUT_ADDR 0A 01 CE 00 11 00 10 3A 01 00 01 00";

// Secure write success: count=1, start=1, return_code=0x00.
const SECURE_WRITE_CTRL_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3A 01 00 01 00";

// Secure write denied: count=0, start=1, return_code=0xFC.
const SECURE_WRITE_CTRL_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3A 00 00 01 FC";

// Plain read: count=1, start=1.
// APDU: 10 bytes → TP1 len = 0x69
const PLAIN_READ_CTRL: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 3A 01 00 01";

// Plain read denied.
const PLAIN_READ_CTRL_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 3A 00 00 01 FC";

// Plain write: count=1, start=1, data=0x00.
// APDU: 11 bytes → TP1 len = 0x6A
const PLAIN_WRITE_CTRL: &str =
    "BC #EDI #BDUT_ADDR 6A 01 CE 00 11 00 10 3A 01 00 01 00";

// Plain write denied.
const PLAIN_WRITE_CTRL_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 3A 00 00 01 FC";

// ============================================================================
// PID_SECURITY_REPORT (0x39) — access 1FF/0CC
// ============================================================================

// Secure A+C read: count=1, start=1.
const SECURE_READ_RPT: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 39 01 00 01";

// Secure read success: count=1, start=1, data=1 byte (wildcard).
const SECURE_READ_RPT_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 39 01 00 01 ??";

// Secure read denied: count=0, start=1, return_code=0xFC.
const SECURE_READ_RPT_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 39 00 00 01 FC";

// Secure A+C write: count=1, start=1, data=0x00.
const SECURE_WRITE_RPT: &str =
    "3C 60 #EDI #BDUT_ADDR 0A 01 CE 00 11 00 10 39 01 00 01 00";

// Secure write success.
const SECURE_WRITE_RPT_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 39 01 00 01 00";

// Secure write denied.
const SECURE_WRITE_RPT_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 39 00 00 01 FC";

// Plain read: count=1, start=1.
const PLAIN_READ_RPT: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 39 01 00 01";

// Plain read denied (sec ON). Note: 1FF policy allows plain read when sec OFF.
const PLAIN_READ_RPT_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 39 00 00 01 FC";

// Plain read success (sec OFF, 1FF policy allows plain read).
// APDU: 01 CD + 00 11 + 00 10 + 39 + 01 + 00 01 + ?? = 11 bytes → TP1 len = 0x6A
const PLAIN_READ_RPT_OK: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 39 01 00 01 ??";

// Plain write: count=1, start=1, data=0x00.
const PLAIN_WRITE_RPT: &str =
    "BC #EDI #BDUT_ADDR 6A 01 CE 00 11 00 10 39 01 00 01 00";

// Plain write denied (0CC: write always requires A+C).
const PLAIN_WRITE_RPT_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 39 00 00 01 FC";

// ============================================================================
// PropertyExtDescription_Read templates
// ============================================================================

// Plain description read for PID_SECURITY_REPORT_CONTROL (0x3A).
const PLAIN_DESC_READ_CTRL: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 3A 00 00";

// All-zero descriptor (access denied — 00C/00C plain never allowed).
const PLAIN_DESC_READ_CTRL_ZERO: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 3A 00 00 00 00 00 00 00 00 00 00";

// Plain description read for PID_SECURITY_REPORT (0x39).
const PLAIN_DESC_READ_RPT: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 39 00 00";

// All-zero descriptor (sec ON, 1FF policy denies plain).
const PLAIN_DESC_READ_RPT_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 39 00 00 00 00 00 00 00 00 00 00";

// Valid descriptor (sec OFF, 1FF policy allows plain).
const PLAIN_DESC_READ_RPT_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Secure A+C description read for PID_SECURITY_REPORT_CONTROL (0x3A).
// APDU: 01 D2 + 00 11 + 00 10 + 3A + 00 + 00 = 8 bytes → len = 0x08
const SECURE_DESC_READ_CTRL: &str =
    "3C 60 #EDI #BDUT_ADDR 08 01 D2 00 11 00 10 3A 00 00";

// Secure A+C success response: valid descriptor (wildcard data bytes).
const SECURE_DESC_READ_CTRL_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 3A ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_14_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.14 PID_SECURITY_REPORT / REPORT_CONTROL (Security IO)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_14_2(),
            test_3_8_14_3(),
            test_3_8_14_4(),
        ])
}

// ============================================================================
// 3.8.14.2 Unsecure PropertyValueRead/Write
// ============================================================================
//
// Plain (non-secure) read/write are always denied for PID_SECURITY_REPORT_CONTROL
// (00C/00C). For PID_SECURITY_REPORT (1FF/0CC): plain read is denied when sec ON,
// allowed when sec OFF; plain write is always denied.

fn test_3_8_14_2() -> TestCase {
    TestCase::new("3.8.14.2 Unsecure PropertyValueRead/Write").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // -- PID_SECURITY_REPORT_CONTROL (00C/00C) --
        comment("Plain write REPORT_CONTROL → E_ACCESS_DENIED (00C requires A+C)"),
        inject(PLAIN_WRITE_CTRL),
        expect(PLAIN_WRITE_CTRL_DENIED, TIMEOUT),

        comment("Plain read REPORT_CONTROL → E_ACCESS_DENIED"),
        inject(PLAIN_READ_CTRL),
        expect(PLAIN_READ_CTRL_DENIED, TIMEOUT),

        // -- PID_SECURITY_REPORT (1FF/0CC) --
        comment("Plain write REPORT → E_ACCESS_DENIED (0CC always denies plain write)"),
        inject(PLAIN_WRITE_RPT),
        expect(PLAIN_WRITE_RPT_DENIED, TIMEOUT),

        comment("Plain read REPORT → E_ACCESS_DENIED (sec ON, 1FF denies plain)"),
        inject(PLAIN_READ_RPT),
        expect(PLAIN_READ_RPT_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // -- PID_SECURITY_REPORT_CONTROL (00C/00C) — still denied --
        comment("Plain write REPORT_CONTROL → E_ACCESS_DENIED (00C always denied)"),
        inject(PLAIN_WRITE_CTRL),
        expect(PLAIN_WRITE_CTRL_DENIED, TIMEOUT),

        comment("Plain read REPORT_CONTROL → E_ACCESS_DENIED"),
        inject(PLAIN_READ_CTRL),
        expect(PLAIN_READ_CTRL_DENIED, TIMEOUT),

        // -- PID_SECURITY_REPORT (1FF/0CC) --
        comment("Plain write REPORT → E_ACCESS_DENIED (0CC always)"),
        inject(PLAIN_WRITE_RPT),
        expect(PLAIN_WRITE_RPT_DENIED, TIMEOUT),

        comment("Plain read REPORT → success (sec OFF, 1FF allows plain)"),
        inject(PLAIN_READ_RPT),
        expect(PLAIN_READ_RPT_OK, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.14.3 Auth-only PropertyValueRead/Write
// ============================================================================
//
// Auth-only (A without C) is insufficient for both PIDs under their policies.
// PID_SECURITY_REPORT_CONTROL (00C/00C): always denied.
// PID_SECURITY_REPORT (1FF/0CC): read denied when sec ON (needs A+C),
// allowed when sec OFF (1FF); write always denied (0CC).

fn test_3_8_14_3() -> TestCase {
    TestCase::new("3.8.14.3 Auth-only PropertyValueRead/Write").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // -- PID_SECURITY_REPORT_CONTROL (00C/00C) --
        comment("Auth-only write REPORT_CONTROL → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE_CTRL, "TK1"),
        expect_secure_ao(SECURE_WRITE_CTRL_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read REPORT_CONTROL → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_CTRL, "TK1"),
        expect_secure_ao(SECURE_READ_CTRL_DENIED, "TK1", TIMEOUT),

        // -- PID_SECURITY_REPORT (1FF/0CC) --
        comment("Auth-only write REPORT → E_ACCESS_DENIED (sec ON)"),
        inject_secure_ao(SECURE_WRITE_RPT, "TK1"),
        expect_secure_ao(SECURE_WRITE_RPT_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read REPORT → E_ACCESS_DENIED (sec ON, needs A+C)"),
        inject_secure_ao(SECURE_READ_RPT, "TK1"),
        expect_secure_ao(SECURE_READ_RPT_DENIED, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // -- PID_SECURITY_REPORT_CONTROL (00C/00C) — still denied --
        comment("Auth-only write REPORT_CONTROL → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE_CTRL, "TK1"),
        expect_secure_ao(SECURE_WRITE_CTRL_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read REPORT_CONTROL → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_CTRL, "TK1"),
        expect_secure_ao(SECURE_READ_CTRL_DENIED, "TK1", TIMEOUT),

        // -- PID_SECURITY_REPORT (1FF/0CC) — sec OFF allows auth-only --
        // Per XML: auth-only write succeeds when sec OFF (1FF write policy
        // allows auth-only for off-mode, despite the 0CC encoding).
        comment("Auth-only write REPORT → success (sec OFF)"),
        inject_secure_ao(SECURE_WRITE_RPT, "TK1"),
        expect_secure_ao(SECURE_WRITE_RPT_OK, "TK1", TIMEOUT),

        comment("Auth-only read REPORT → success (sec OFF, 1FF allows A)"),
        inject_secure_ao(SECURE_READ_RPT, "TK1"),
        expect_secure_ao(SECURE_READ_RPT_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.14.4 PropertyDescriptionRead plain
// ============================================================================
//
// PID_SECURITY_REPORT_CONTROL (00C/00C): plain desc read returns all-zero
// in both security modes.
// PID_SECURITY_REPORT (1FF/0CC): denied when sec ON, valid when sec OFF.

fn test_3_8_14_4() -> TestCase {
    TestCase::new("3.8.14.4 PropertyDescriptionRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // Per XML: plain desc read REPORT when sec ON → all-zero.
        comment("Plain desc read REPORT → all-zero (sec ON, 1FF denies plain)"),
        inject(PLAIN_DESC_READ_RPT),
        expect(PLAIN_DESC_READ_RPT_DENIED, TIMEOUT),

        // Per XML: A+C secure desc read REPORT_CONTROL when sec ON → valid.
        comment("A+C secure desc read REPORT_CONTROL → valid descriptor"),
        inject_secure_ac(SECURE_DESC_READ_CTRL, "TK1"),
        expect_secure_ac(SECURE_DESC_READ_CTRL_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // Per XML: plain desc read REPORT when sec OFF → valid.
        comment("Plain desc read REPORT → valid descriptor (sec OFF, 1FF allows)"),
        inject(PLAIN_DESC_READ_RPT),
        expect(PLAIN_DESC_READ_RPT_OK, TIMEOUT),

        // Per XML: plain desc read REPORT_CONTROL when sec OFF → all-zero.
        comment("Plain desc read REPORT_CONTROL → all-zero (00C never allows plain)"),
        inject(PLAIN_DESC_READ_CTRL),
        expect(PLAIN_DESC_READ_CTRL_ZERO, TIMEOUT),
    ])
}
