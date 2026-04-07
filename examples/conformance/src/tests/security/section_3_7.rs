//! Section 3.7 -- Access Policies at Service Level (TP1-applicable tests).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.7 Access Policies - Service Level".
//!
//! Tests that AL device management services correctly enforce access policies
//! when security mode is activated. Each test sends the same service request
//! three ways (plain, auth-only, A+C) and checks the DUT response:
//!
//! - `3FF/3FF` services: DUT responds identically regardless of security level.
//! - `3FF/0CC` services: plain/auth-only get masked or denied; A+C succeeds.
//! - `3FF/00C` services: only A+C can write when security mode is on.
//!
//! Skipped (not TP1):
//! - 3.7.2.3-5: DomainAddress services (open media only)
//! - 3.7.2.10: KeyWrite (requires T-Connect)
//! - 3.7.2.11-12: DomainAddress write (open media)

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Security Mode activation/deactivation templates
// ============================================================================

// A_FunctionPropertyExtCommand on Security IO (0x0011, instance 0x0010),
// PID_SECURITY_MODE (0x33): enable (ServiceInfo=0x01).
const ENABLE_SEC_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

// Disable security mode (ServiceInfo=0x00).
const DISABLE_SEC_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

// FunctionPropertyExtState_Response: success.
const SEC_MODE_RESP_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// ============================================================================
// Programming Mode templates (PID_DEVICE_CONTROL = 0x36, IOT=0x0000, inst=0x0010)
// ============================================================================

// PropertyExtValue_WriteCon: set bit 0 of PID_DEVICE_CONTROL to 1 (prog mode on).
const ENABLE_PROG_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 06 03 D7 00 36 10 01 01";

const ENABLE_PROG_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 06 03 D6 00 36 10 01 01";

// Disable programming mode.
const DISABLE_PROG_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 06 03 D7 00 36 10 01 00";

const DISABLE_PROG_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 06 03 D6 00 36 10 01 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_7_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.7 Access Policies - Service Level", variables)
        .secure()
        .with_cases(vec![
            test_3_7_2_1(),
            test_3_7_2_2(),
            test_3_7_2_6(),
            test_3_7_2_13(),
            test_3_7_2_14(),
        ])
}

// ============================================================================
// 3.7.2.1 A_IndividualAddress_Read (3FF/3FF) -- Plain/A/A+C -- Security Mode on
// ============================================================================
//
// Access policy 3FF/3FF: DUT responds to all access types, even plain, when
// security mode is on. The service itself is unconditionally allowed.

fn test_3_7_2_1() -> TestCase {
    TestCase::new("3.7.2.1 IndividualAddressRead (3FF/3FF) -- Plain/A/A+C -- SM on")
        .with_steps(vec![
            // Setup: enable security mode.
            comment("Enable Security Mode"),
            inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),

            // Enable programming mode (required for IndAddrRead to respond).
            comment("Enable Programming Mode"),
            inject_secure_ac(ENABLE_PROG_MODE, "TK1"),
            expect_secure_ac(ENABLE_PROG_MODE_RESP, "TK1", TIMEOUT),

            // Plain IndividualAddressRead -> DUT responds.
            comment("Plain IndividualAddressRead"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT_ADDR 00 00 E1 01 40", TIMEOUT),

            // Auth-only IndividualAddressRead -> DUT responds.
            comment("Auth-only IndividualAddressRead"),
            inject_secure_ao("BC #EDI 00 00 E1 01 00", "TK1"),
            expect_secure_ao("BC #BDUT_ADDR 00 00 E1 01 40", "TK1", TIMEOUT),

            // A+C IndividualAddressRead -> DUT responds.
            comment("A+C IndividualAddressRead"),
            inject_secure_ac("BC #EDI 00 00 E1 01 00", "TK1"),
            expect_secure_ac("BC #BDUT_ADDR 00 00 E1 01 40", "TK1", TIMEOUT),

            // Cleanup: disable programming mode, disable security mode.
            comment("Disable Programming Mode"),
            inject_secure_ac(DISABLE_PROG_MODE, "TK1"),
            expect_secure_ac(DISABLE_PROG_MODE_RESP, "TK1", TIMEOUT),

            comment("Disable Security Mode"),
            inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        ])
}

// ============================================================================
// 3.7.2.2 A_IndividualAddressSerialNumber_Read (3FF/3FF) -- Plain/A/A+C -- SM on
// ============================================================================
//
// Like 3.7.2.1 but with serial-number-based address read. Access policy 3FF/3FF
// means all access types succeed. No programming mode required.

fn test_3_7_2_2() -> TestCase {
    TestCase::new("3.7.2.2 IndAddrSerNoRead (3FF/3FF) -- Plain/A/A+C -- SM on")
        .with_steps(vec![
            // Setup: enable security mode.
            comment("Enable Security Mode"),
            inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),

            // Plain IndividualAddressSerialNumberRead.
            // APCI 0xDC, payload = serial number (6 bytes).
            // Normal frame: BC src dst len_hi APCI_byte SER_NUM
            comment("Plain IndAddrSerNoRead"),
            inject("BC #EDI 00 00 E7 03 DC #SER_NUM"),
            expect("BC #BDUT_ADDR 00 00 EB 03 DD #SER_NUM 00 00 00 00", TIMEOUT),

            // Auth-only IndAddrSerNoRead.
            comment("Auth-only IndAddrSerNoRead"),
            inject_secure_ao("3C E0 #EDI 00 00 07 03 DC #SER_NUM", "TK1"),
            expect_secure_ao("3C E0 #BDUT_ADDR 00 00 0B 03 DD #SER_NUM 00 00 00 00", "TK1", TIMEOUT),

            // A+C IndAddrSerNoRead.
            comment("A+C IndAddrSerNoRead"),
            inject_secure_ac("3C E0 #EDI 00 00 07 03 DC #SER_NUM", "TK1"),
            expect_secure_ac("3C E0 #BDUT_ADDR 00 00 0B 03 DD #SER_NUM 00 00 00 00", "TK1", TIMEOUT),

            // Cleanup.
            comment("Disable Security Mode"),
            inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        ])
}

// ============================================================================
// 3.7.2.6 A_DeviceDescriptor_Read (3FF/0CC at data level) -- SM on
// ============================================================================
//
// Access policy 3FF/0CC: when security mode is on, only Tool A+C gets the real
// device descriptor. Plain and auth-only get masked data (FF FF). Unsupported
// descriptor types get an error response (type 3F) regardless. We use type 3
// since our DUT supports DD type 2.

fn test_3_7_2_6() -> TestCase {
    TestCase::new("3.7.2.6 DeviceDescriptorRead (3FF/0CC) -- Plain/A/A+C -- SM on")
        .with_steps(vec![
            // Setup: enable security mode.
            comment("Enable Security Mode"),
            inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),

            // --------------------------------------------------------
            // DD type 0: real data only with A+C
            // --------------------------------------------------------

            // Plain DD0 read -> masked response (FF FF).
            comment("Plain DD0 read -> masked FF FF"),
            inject("BC #EDI #BDUT_ADDR 61 03 00"),
            expect("BC #BDUT_ADDR #EDI 63 03 40 FF FF", TIMEOUT),

            // Auth-only DD0 read -> masked response (FF FF).
            comment("Auth-only DD0 read -> masked FF FF"),
            inject_secure_ao("BC #EDI #BDUT_ADDR 61 03 00", "TK1"),
            expect_secure_ao("3C 60 #BDUT_ADDR #EDI 03 03 40 FF FF", "TK1", TIMEOUT),

            // A+C DD0 read -> real device descriptor.
            comment("A+C DD0 read -> real descriptor"),
            inject_secure_ac("BC #EDI #BDUT_ADDR 61 03 00", "TK1"),
            expect_secure_ac("3C 60 #BDUT_ADDR #EDI 03 03 40 ?? ??", "TK1", TIMEOUT),

            // --------------------------------------------------------
            // Unsupported DD type 2: error (3F) for all access levels
            // --------------------------------------------------------

            // Plain unsupported DD -> error.
            comment("Plain DD3 (unsupported) -> error 3F"),
            inject("BC #EDI #BDUT_ADDR 61 03 03"),
            expect("BC #BDUT_ADDR #EDI 61 03 7F", TIMEOUT),

            // Auth-only unsupported DD -> error.
            comment("Auth-only DD3 (unsupported) -> error 3F"),
            inject_secure_ao("BC #EDI #BDUT_ADDR 61 03 03", "TK1"),
            expect_secure_ao("BC #BDUT_ADDR #EDI 61 03 7F", "TK1", TIMEOUT),

            // A+C unsupported DD -> error.
            comment("A+C DD3 (unsupported) -> error 3F"),
            inject_secure_ac("BC #EDI #BDUT_ADDR 61 03 03", "TK1"),
            expect_secure_ac("BC #BDUT_ADDR #EDI 61 03 7F", "TK1", TIMEOUT),

            // Cleanup.
            comment("Disable Security Mode"),
            inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        ])
}

// ============================================================================
// 3.7.2.13 A_IndividualAddress_Write (3FF/00C) + PID_PROG_Mode (3FF/0CC) -- SM on
// ============================================================================
//
// Access policy for IndividualAddressWrite is 3FF/00C: when security mode is
// on, only Tool A+C can write. Plain is silently rejected.
//
// Additionally tests PID_DEVICE_CONTROL (programming mode) access policy
// 3FF/0CC: plain PropertyExtValue_WriteCon is denied when SM is on.

fn test_3_7_2_13() -> TestCase {
    TestCase::new("3.7.2.13 IndAddrWrite (3FF/00C) + ProgMode (3FF/0CC) -- SM on")
        .with_steps(vec![
            // Setup: enable security mode.
            comment("Enable Security Mode"),
            inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),

            // --------------------------------------------------------
            // PID_DEVICE_CONTROL (prog mode) plain write denied
            // --------------------------------------------------------

            // Plain PropertyExtValue_WriteCon for PID_DEVICE_CONTROL -> FC (access denied).
            // IOT=0x0000, inst=0x0010, PID=0x36, count=1, start=1, data=0x01
            comment("Plain prog mode write -> access denied (FC)"),
            inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 36 01 00 01 01"),
            expect("BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 36 00 00 01 FC", TIMEOUT),

            // A+C PropertyExtValue_WriteCon for PID_DEVICE_CONTROL -> success.
            comment("A+C prog mode write -> success"),
            inject_secure_ac("3C 60 #EDI #BDUT_ADDR 0A 01 CE 00 00 00 10 36 01 00 01 01", "TK1"),
            expect_secure_ac("3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 00 00 10 36 01 00 01 00", "TK1", TIMEOUT),

            // --------------------------------------------------------
            // IndividualAddressWrite: plain rejected, A+C succeeds
            // --------------------------------------------------------

            // Plain IndividualAddressWrite (set IA to 1.2.52 = 0x1234) -> silently rejected.
            comment("Plain IndAddrWrite -> silently rejected"),
            inject("BC #EDI 00 00 E3 00 C0 12 34"),
            expect_none(1500),

            // A+C IndividualAddressWrite -> success (address changes).
            comment("A+C IndAddrWrite to 1.2.52"),
            inject_secure_ac("3C E0 #EDI 00 00 03 00 C0 12 34", "TK1"),
            // IndividualAddressWrite has no response — verify by reading back.

            // Verify: plain IndividualAddressRead should respond from new address.
            comment("Verify: plain IndAddrRead from new address"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC 12 34 00 00 E1 01 40", TIMEOUT),

            // Restore: A+C IndividualAddressWrite back to original.
            comment("Restore: A+C IndAddrWrite to original address"),
            inject_secure_ac("3C E0 #EDI 00 00 03 00 C0 #BDUT_ADDR", "TK1"),

            // Verify: read back original address.
            comment("Verify: IndAddrRead from original address"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT_ADDR 00 00 E1 01 40", TIMEOUT),

            // Disable programming mode.
            comment("Disable Programming Mode"),
            inject_secure_ac(DISABLE_PROG_MODE, "TK1"),
            expect_secure_ac(DISABLE_PROG_MODE_RESP, "TK1", TIMEOUT),

            // Cleanup.
            comment("Disable Security Mode"),
            inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        ])
}

// ============================================================================
// 3.7.2.14 A_IndividualAddressSerialNumber_Write (3FF/00C) -- SM on
// ============================================================================
//
// Access policy 3FF/00C: when security mode is on, only Tool A+C can write
// the individual address via serial number. Plain and auth-only are silently
// rejected (no response for a write service).

fn test_3_7_2_14() -> TestCase {
    TestCase::new("3.7.2.14 IndAddrSerNoWrite (3FF/00C) -- Plain/A/A+C -- SM on")
        .with_steps(vec![
            // Setup: enable security mode + programming mode.
            comment("Enable Security Mode"),
            inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),

            comment("Enable Programming Mode"),
            inject_secure_ac(ENABLE_PROG_MODE, "TK1"),
            expect_secure_ac(ENABLE_PROG_MODE_RESP, "TK1", TIMEOUT),

            // --------------------------------------------------------
            // Plain IndAddrSerNoWrite -> silently rejected
            // --------------------------------------------------------
            comment("Plain IndAddrSerNoWrite -> silently rejected"),
            inject("BC #EDI 00 00 ED 03 DE #SER_NUM 12 34 00 00 00 00"),
            expect_none(1500),

            // Verify address unchanged via plain IndAddrRead.
            comment("Verify: address unchanged"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT_ADDR 00 00 E1 01 40", TIMEOUT),

            // --------------------------------------------------------
            // Auth-only IndAddrSerNoWrite -> silently rejected
            // --------------------------------------------------------
            comment("Auth-only IndAddrSerNoWrite -> silently rejected"),
            inject_secure_ao("3C E0 #EDI 00 00 0D 03 DE #SER_NUM 12 34 00 00 00 00", "TK1"),
            expect_none(1500),

            // Verify address unchanged.
            comment("Verify: address still unchanged"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT_ADDR 00 00 E1 01 40", TIMEOUT),

            // --------------------------------------------------------
            // A+C IndAddrSerNoWrite -> success
            // --------------------------------------------------------
            comment("A+C IndAddrSerNoWrite to 1.2.52"),
            inject_secure_ac("3C E0 #EDI 00 00 0D 03 DE #SER_NUM 12 34 00 00 00 00", "TK1"),
            // No response for write service -- verify by reading back.

            // Verify: address changed to 1.2.52 (0x1234).
            comment("Verify: address changed to 1.2.52"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC 12 34 00 00 E1 01 40", TIMEOUT),

            // Restore original address.
            comment("Restore: A+C IndAddrSerNoWrite to original"),
            inject_secure_ac("3C E0 #EDI 00 00 0D 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00", "TK1"),

            // Verify restoration.
            comment("Verify: address restored"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT_ADDR 00 00 E1 01 40", TIMEOUT),

            // Cleanup.
            comment("Disable Programming Mode"),
            inject_secure_ac(DISABLE_PROG_MODE, "TK1"),
            expect_secure_ac(DISABLE_PROG_MODE_RESP, "TK1", TIMEOUT),

            comment("Disable Security Mode"),
            inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
            expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        ])
}
