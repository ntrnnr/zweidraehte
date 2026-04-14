//! Section 3.8.18 — `PID_SUBNET_ADDR` / `PID_DEVICE_ADDRESS` access policy
//! `3FF/00C` (2 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.18 PID_SUBNET_ADDR / PID_DEVICE_ADDRESS".
//!
//! Tests PID 0x39 (PID_SUBNET_ADDR, i.e. PID 57) and PID 0x3A
//! (PID_DEVICE_ADDRESS, i.e. PID 58) on the Device Object (IOT=0x0000,
//! instance=0x0010). Both are read-only 1-byte properties.
//!
//! Access policy is `3FF/00C`:
//! - Security OFF: everyone (3FF) can read/write → reads succeed, writes return
//!   0xFB (read-only).
//! - Security ON: only Tool A+C (00C) can read/write → plain and auth-only reads
//!   are denied (0xFC), writes still return 0xFB (read-only error takes priority).
//!
//! PID_SUBNET_ADDR returns 1 byte = high byte of the individual address.
//! PID_DEVICE_ADDRESS returns 1 byte = low byte of the individual address.
//!
//! Skipped test cases:
//! - 3.8.18.2 — uses P2P key infrastructure and alternative individual address
//!   (0x2202), not yet implemented.

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
// PID_SUBNET_ADDR (0x39) — Secure templates on Device Object
// ============================================================================

// Secure A_PropertyExtValueWriteCon: IOT=0x0000, instance=0x0010,
// PID=0x39 (SUBNET_ADDR), count=1, start=1, data=0x72 (arbitrary write value).
// APDU: 01 CE + 00 00 + 00 10 + 39 + 01 + 00 01 + 72 = 11 bytes → len = 0x0A
const SECURE_WRITE_SUBNET: &str =
    "3C 60 #EDI #BDUT_ADDR 0A 01 CE 00 00 00 10 39 01 00 01 72";

// Secure write error response: count=0, return_code=0xFB (E_ACCESS_READ_ONLY).
// APDU: 01 CF + 00 00 + 00 10 + 39 + 00 + 00 01 + FB = 11 bytes → len = 0x0A
const SECURE_WRITE_SUBNET_RO: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 00 00 10 39 00 00 01 FB";

// Secure A_PropertyExtValueRead: count=1, start=1.
// APDU: 01 CC + 00 00 + 00 10 + 39 + 01 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ_SUBNET: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 00 00 10 39 01 00 01";

// Secure read success: count=1, data=high byte of BDUT address.
// APDU: 01 CD + 00 00 + 00 10 + 39 + 01 + 00 01 + ?? = 11 bytes → len = 0x0A
const SECURE_READ_SUBNET_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 00 00 10 39 01 00 01 ??";

// Secure read error: count=0, return_code=0xFC (E_ACCESS_DENIED).
const SECURE_READ_SUBNET_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 00 00 10 39 00 00 01 FC";

// ============================================================================
// PID_DEVICE_ADDRESS (0x3A) — Secure templates on Device Object
// ============================================================================

// Secure write: data=0x8A (arbitrary).
const SECURE_WRITE_DEVADDR: &str =
    "3C 60 #EDI #BDUT_ADDR 0A 01 CE 00 00 00 10 3A 01 00 01 8A";

const SECURE_WRITE_DEVADDR_RO: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 00 00 10 3A 00 00 01 FB";

const SECURE_READ_DEVADDR: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 00 00 10 3A 01 00 01";

// Secure read success: count=1, data=low byte of BDUT address.
const SECURE_READ_DEVADDR_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 00 00 10 3A 01 00 01 ??";

const SECURE_READ_DEVADDR_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 00 00 10 3A 00 00 01 FC";

// ============================================================================
// PID_SUBNET_ADDR (0x39) — Plain templates on Device Object
// ============================================================================

// Plain A_PropertyExtValueWriteCon: data=0x72.
// APDU: 01 CE + 00 00 + 00 10 + 39 + 01 + 00 01 + 72 = 11 bytes → TP1 len = 0x6A
const PLAIN_WRITE_SUBNET: &str =
    "BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 39 01 00 01 72";

// Plain write error: count=0, return_code=0xFB (E_ACCESS_READ_ONLY).
const PLAIN_WRITE_SUBNET_RO: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 39 00 00 01 FB";

// Plain A_PropertyExtValueRead.
// APDU: 01 CC + 00 00 + 00 10 + 39 + 01 + 00 01 = 10 bytes → TP1 len = 0x69
const PLAIN_READ_SUBNET: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 39 01 00 01";

// Plain read success: count=1, data=high byte of BDUT address.
const PLAIN_READ_SUBNET_OK: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 39 01 00 01 ??";

// Plain read error: count=0, return_code=0xFC (E_ACCESS_DENIED).
const PLAIN_READ_SUBNET_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 39 00 00 01 FC";

// ============================================================================
// PID_DEVICE_ADDRESS (0x3A) — Plain templates on Device Object
// ============================================================================

const PLAIN_WRITE_DEVADDR: &str =
    "BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 3A 01 00 01 8A";

const PLAIN_WRITE_DEVADDR_RO: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 3A 00 00 01 FB";

const PLAIN_READ_DEVADDR: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 3A 01 00 01";

const PLAIN_READ_DEVADDR_OK: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 3A 01 00 01 ??";

const PLAIN_READ_DEVADDR_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 3A 00 00 01 FC";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_18_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new(
        "3.8.18 PID_SUBNET_ADDR / PID_DEVICE_ADDRESS (Device Object, access 3FF/00C)",
        variables,
    )
    .secure()
    .with_cases(vec![
        test_3_8_18_1(),
        test_3_8_18_2(),
        test_3_8_18_3(),
    ])
}

fn test_3_8_18_2() -> TestCase {
    TestCase::new("3.8.18.2 Secured S-A_Data, P2P Key").with_steps(vec![
        comment("Placeholder: requires P2P-key infrastructure and alternative individual address (0x2202); not yet supported by the harness."),
    ])
}

// ============================================================================
// 3.8.18.1 Secured S-A_Data, toolkey
// ============================================================================
//
// Access policy 3FF/00C: with security ON, only Tool A+C can read;
// with security OFF, everyone can read. Writes always fail as read-only.
//
// Tests both PID_SUBNET_ADDR and PID_DEVICE_ADDRESS with A+C and auth-only
// in both security modes.

fn test_3_8_18_1() -> TestCase {
    TestCase::new("3.8.18.1 Secured S-A_Data, toolkey").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // ---- PID_SUBNET_ADDR (0x39) with A+C ----
        comment("A+C write SUBNET_ADDR → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_SUBNET, "TK1"),
        expect_secure_ac(SECURE_WRITE_SUBNET_RO, "TK1", TIMEOUT),

        comment("A+C read SUBNET_ADDR → success"),
        inject_secure_ac(SECURE_READ_SUBNET, "TK1"),
        expect_secure_ac(SECURE_READ_SUBNET_OK, "TK1", TIMEOUT),

        // ---- PID_DEVICE_ADDRESS (0x3A) with A+C ----
        comment("A+C write DEVICE_ADDRESS → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_DEVADDR, "TK1"),
        expect_secure_ac(SECURE_WRITE_DEVADDR_RO, "TK1", TIMEOUT),

        comment("A+C read DEVICE_ADDRESS → success"),
        inject_secure_ac(SECURE_READ_DEVADDR, "TK1"),
        expect_secure_ac(SECURE_READ_DEVADDR_OK, "TK1", TIMEOUT),

        // ---- PID_SUBNET_ADDR (0x39) with auth-only ----
        comment("Auth-only write SUBNET_ADDR → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_SUBNET, "TK1"),
        expect_secure_ao(SECURE_WRITE_SUBNET_RO, "TK1", TIMEOUT),

        comment("Auth-only read SUBNET_ADDR → E_ACCESS_DENIED (sec ON, needs A+C)"),
        inject_secure_ao(SECURE_READ_SUBNET, "TK1"),
        expect_secure_ao(SECURE_READ_SUBNET_DENIED, "TK1", TIMEOUT),

        // ---- PID_DEVICE_ADDRESS (0x3A) with auth-only ----
        comment("Auth-only write DEVICE_ADDRESS → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_DEVADDR, "TK1"),
        expect_secure_ao(SECURE_WRITE_DEVADDR_RO, "TK1", TIMEOUT),

        comment("Auth-only read DEVICE_ADDRESS → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_DEVADDR, "TK1"),
        expect_secure_ao(SECURE_READ_DEVADDR_DENIED, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // ---- PID_SUBNET_ADDR (0x39) with A+C ----
        comment("A+C write SUBNET_ADDR → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_SUBNET, "TK1"),
        expect_secure_ac(SECURE_WRITE_SUBNET_RO, "TK1", TIMEOUT),

        comment("A+C read SUBNET_ADDR → success"),
        inject_secure_ac(SECURE_READ_SUBNET, "TK1"),
        expect_secure_ac(SECURE_READ_SUBNET_OK, "TK1", TIMEOUT),

        // ---- PID_DEVICE_ADDRESS (0x3A) with A+C ----
        comment("A+C write DEVICE_ADDRESS → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_DEVADDR, "TK1"),
        expect_secure_ac(SECURE_WRITE_DEVADDR_RO, "TK1", TIMEOUT),

        comment("A+C read DEVICE_ADDRESS → success"),
        inject_secure_ac(SECURE_READ_DEVADDR, "TK1"),
        expect_secure_ac(SECURE_READ_DEVADDR_OK, "TK1", TIMEOUT),

        // ---- PID_SUBNET_ADDR (0x39) with auth-only ----
        comment("Auth-only write SUBNET_ADDR → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_SUBNET, "TK1"),
        expect_secure_ao(SECURE_WRITE_SUBNET_RO, "TK1", TIMEOUT),

        comment("Auth-only read SUBNET_ADDR → success (sec OFF, 3FF allows all)"),
        inject_secure_ao(SECURE_READ_SUBNET, "TK1"),
        expect_secure_ao(SECURE_READ_SUBNET_OK, "TK1", TIMEOUT),

        // ---- PID_DEVICE_ADDRESS (0x3A) with auth-only ----
        comment("Auth-only write DEVICE_ADDRESS → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_DEVADDR, "TK1"),
        expect_secure_ao(SECURE_WRITE_DEVADDR_RO, "TK1", TIMEOUT),

        comment("Auth-only read DEVICE_ADDRESS → success"),
        inject_secure_ao(SECURE_READ_DEVADDR, "TK1"),
        expect_secure_ao(SECURE_READ_DEVADDR_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.18.3 Write and read PID_SUBNET_ADDR and PID_DEVICE_ADDRESS unsecured
// ============================================================================
//
// Plain write always returns 0xFB (read-only). Plain read: denied when
// security is ON (00C policy), succeeds when security is OFF (3FF policy).
// Ends with a redundant disable to leave security mode OFF.

fn test_3_8_18_3() -> TestCase {
    TestCase::new("3.8.18.3 Write and read PID_SUBNET_ADDR/PID_DEVICE_ADDRESS unsecured")
        .with_steps(vec![
            // ==== Security Mode ON ====
            comment("Enable Security Mode"),
            inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
            expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

            // ---- PID_SUBNET_ADDR (0x39) plain ----
            comment("Plain write SUBNET_ADDR → E_ACCESS_READ_ONLY"),
            inject(PLAIN_WRITE_SUBNET),
            expect(PLAIN_WRITE_SUBNET_RO, TIMEOUT),

            comment("Plain read SUBNET_ADDR → E_ACCESS_DENIED (sec ON)"),
            inject(PLAIN_READ_SUBNET),
            expect(PLAIN_READ_SUBNET_DENIED, TIMEOUT),

            // ---- PID_DEVICE_ADDRESS (0x3A) plain ----
            comment("Plain write DEVICE_ADDRESS → E_ACCESS_READ_ONLY"),
            inject(PLAIN_WRITE_DEVADDR),
            expect(PLAIN_WRITE_DEVADDR_RO, TIMEOUT),

            comment("Plain read DEVICE_ADDRESS → E_ACCESS_DENIED (sec ON)"),
            inject(PLAIN_READ_DEVADDR),
            expect(PLAIN_READ_DEVADDR_DENIED, TIMEOUT),

            // ==== Security Mode OFF ====
            comment("Disable Security Mode"),
            inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
            expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

            // ---- PID_SUBNET_ADDR (0x39) plain ----
            comment("Plain write SUBNET_ADDR → E_ACCESS_READ_ONLY"),
            inject(PLAIN_WRITE_SUBNET),
            expect(PLAIN_WRITE_SUBNET_RO, TIMEOUT),

            comment("Plain read SUBNET_ADDR → success (sec OFF, 3FF allows all)"),
            inject(PLAIN_READ_SUBNET),
            expect(PLAIN_READ_SUBNET_OK, TIMEOUT),

            // ---- PID_DEVICE_ADDRESS (0x3A) plain ----
            comment("Plain write DEVICE_ADDRESS → E_ACCESS_READ_ONLY"),
            inject(PLAIN_WRITE_DEVADDR),
            expect(PLAIN_WRITE_DEVADDR_RO, TIMEOUT),

            comment("Plain read DEVICE_ADDRESS → success"),
            inject(PLAIN_READ_DEVADDR),
            expect(PLAIN_READ_DEVADDR_OK, TIMEOUT),

            // The XML ends with a redundant disable — include it for parity.
            comment("Disable Security Mode (cleanup)"),
            inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
            expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        ])
}
