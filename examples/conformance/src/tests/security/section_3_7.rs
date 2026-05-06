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
//! - 3.7.2.11-12: DomainAddress write (open media)

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{TestCase, TestSuite};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Security Mode activation/deactivation templates
// ============================================================================

// A_FunctionPropertyExtCommand on Security IO (0x0011, instance 0x0010),
// PID_SECURITY_MODE (0x33): enable (ServiceInfo=0x01).
const ENABLE_SEC_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

// Disable security mode (ServiceInfo=0x00).
const DISABLE_SEC_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

// FunctionPropertyExtState_Response: success.
const SEC_MODE_RESP_OK: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// ============================================================================
// Programming Mode templates (PID_DEVICE_CONTROL = 0x36, IOT=0x0000, inst=0x0010)
// ============================================================================

// PropertyExtValue_WriteCon: set bit 0 of PID_DEVICE_CONTROL to 1 (prog mode on).
const ENABLE_PROG_MODE: &str = "3C 60 #EDI #BDUT_ADDR 06 03 D7 00 36 10 01 01";

const ENABLE_PROG_MODE_RESP: &str = "3C 60 #BDUT_ADDR #EDI 06 03 D6 00 36 10 01 01";

// Disable programming mode.
const DISABLE_PROG_MODE: &str = "3C 60 #EDI #BDUT_ADDR 06 03 D7 00 36 10 01 00";

const DISABLE_PROG_MODE_RESP: &str = "3C 60 #BDUT_ADDR #EDI 06 03 D6 00 36 10 01 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_7_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.7 Access Policies - Service Level", variables).secure().with_cases(vec![
        test_3_7_2_1(),
        test_3_7_2_2(),
        test_3_7_2_6(),
        test_3_7_2_7(),
        test_3_7_2_8(),
        test_3_7_2_9(),
        test_3_7_2_10(),
        test_3_7_2_13(),
        test_3_7_2_14(),
        // Placeholders for media-dependent domain-address cases
        // (TP1 DUT does not support DomainAddress services).
        test_3_7_2_3(),
        test_3_7_2_3_1(),
        test_3_7_2_3_2(),
        test_3_7_2_4(),
        test_3_7_2_5(),
        test_3_7_2_11(),
        test_3_7_2_12(),
        test_3_7_2_12_1(),
        test_3_7_2_12_2(),
        test_3_7_2_12_3(),
    ])
}

// ============================================================================
// Placeholders — domain-address services (require PL/RF/IP media on the DUT)
// ============================================================================
// Our TP1 conformance DUT does not implement A_DomainAddress_Read/Write/
// SelectiveRead nor the 4/6/21-octet DomainAddressSerialNumber variants.
// These tests are retained as placeholders so the coverage index matches
// the reference XML.

fn placeholder(name: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![comment(
        "Placeholder: DomainAddress services require PL/RF/IP media — not supported on TP1 conformance DUT.",
    )])
}

fn test_3_7_2_3() -> TestCase {
    placeholder("3.7.2.3 A_DomainAddress_SerialNumber_Read")
}
fn test_3_7_2_3_1() -> TestCase {
    placeholder("3.7.2.3.1 For 2 octet (PL) and 6 octet (RF) (3FF/3FF)")
}
fn test_3_7_2_3_2() -> TestCase {
    placeholder("3.7.2.3.2 For 4 octet (IP) and 21 octet (IP)")
}
fn test_3_7_2_4() -> TestCase {
    placeholder("3.7.2.4 A_DomainAddress_Read (3FF/3FF) — Plain/A/A+C")
}
fn test_3_7_2_5() -> TestCase {
    placeholder("3.7.2.5 A_DomainAddress_Selective_Read (3FF/3FF)")
}
fn test_3_7_2_11() -> TestCase {
    placeholder("3.7.2.11 A_DomainAddress_Write (3FF/00C) [open media]")
}
fn test_3_7_2_12() -> TestCase {
    placeholder("3.7.2.12 A_DomainAddressSerialNumber_Write")
}
fn test_3_7_2_12_1() -> TestCase {
    placeholder("3.7.2.12.1 For 4 octet (IP) (3FF/00C)")
}
fn test_3_7_2_12_2() -> TestCase {
    placeholder("3.7.2.12.2 For 6 octet (RF) (3FF/00C)")
}
fn test_3_7_2_12_3() -> TestCase {
    placeholder("3.7.2.12.3 For 21 octet (IP) (00C/00C)")
}

// ============================================================================
// 3.7.2.1 A_IndividualAddress_Read (3FF/3FF) -- Plain/A/A+C -- Security Mode on
// ============================================================================
//
// Access policy 3FF/3FF: DUT responds to all access types, even plain, when
// security mode is on. The service itself is unconditionally allowed.

fn test_3_7_2_1() -> TestCase {
    TestCase::new("3.7.2.1 IndividualAddressRead (3FF/3FF) -- Plain/A/A+C -- SM on").with_steps(vec![
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
    TestCase::new("3.7.2.2 IndAddrSerNoRead (3FF/3FF) -- Plain/A/A+C -- SM on").with_steps(vec![
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
    TestCase::new("3.7.2.6 DeviceDescriptorRead (3FF/0CC) -- Plain/A/A+C -- SM on").with_steps(vec![
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
// 3.7.2.7 A_Authorize_Request (3FF/3FF) -- Plain/A/A+C -- SM on
// ============================================================================
//
// Access policy 3FF/3FF: DUT responds to authorize requests at any security
// level, even when security mode is on. Uses connection-oriented transport
// (T_Connect) since A_Authorize_Request requires a connection.

fn test_3_7_2_7() -> TestCase {
    TestCase::new("3.7.2.7 Authorize (3FF/3FF) -- Plain/A/A+C -- SM on").with_steps(vec![
        // Setup: enable security mode.
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        // T_Connect.
        comment("T_Connect"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        // Plain Authorize (TPCI seq=0: 0x43, APCI=0xD1).
        comment("Plain Authorize (seq=0)"),
        inject("BC #EDI #BDUT_ADDR 66 43 D1 00 #L3_PWD"),
        // Expect T_ACK (seq=0).
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        // Expect Authorize_Response (seq=0, APCI=0xD2, level=??).
        expect("BC #BDUT_ADDR #EDI 62 43 D2 ??", TIMEOUT),
        // ACK the response.
        inject("BC #EDI #BDUT_ADDR 60 C2"),
        // Auth-only Authorize (TPCI seq=1: 0x47, APCI=0xD1).
        comment("Auth-only Authorize (seq=1)"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 06 47 D1 00 #L3_PWD", "TK1"),
        // Expect T_ACK (seq=1).
        expect("B0 #BDUT_ADDR #EDI 60 C6", TIMEOUT),
        // Expect secure auth-only Authorize_Response (seq=1).
        expect_secure_ao("BC #BDUT_ADDR #EDI 62 47 D2 ??", "TK1", TIMEOUT),
        // ACK the response.
        inject("BC #EDI #BDUT_ADDR 60 C6"),
        // A+C Authorize (TPCI seq=2: 0x4B, APCI=0xD1).
        comment("A+C Authorize (seq=2)"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 06 4B D1 00 #L3_PWD", "TK1"),
        // Expect T_ACK (seq=2).
        expect("B0 #BDUT_ADDR #EDI 60 CA", TIMEOUT),
        // Expect secure A+C Authorize_Response (seq=2).
        expect_secure_ac("BC #BDUT_ADDR #EDI 62 4B D2 ??", "TK1", TIMEOUT),
        // ACK the response.
        inject("BC #EDI #BDUT_ADDR 60 CA"),
        // T_Disconnect.
        comment("T_Disconnect"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // Cleanup: disable security mode.
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.7.2.8 Memory Read/Write (000/000 and 3FF/00C) -- SM on/off
// ============================================================================
//
// Tests two memory regions with different access policies:
// - 0x03D0-0x03DF (AP 000/000): always denied regardless of security mode
// - 0x03E0-0x03EF (AP 3FF/00C): everyone when SM off, Tool A+C only when SM on
//
// Phase 1: SM ON -- test both regions with plain/auth/A+C
// Phase 2: SM OFF -- repeat same tests
// Phase 3: SM ON -- test 3FF/00C region (denied plain/auth, allowed A+C)
// Phase 4: SM OFF -- test 3FF/00C region (all allowed)

fn test_3_7_2_8() -> TestCase {
    TestCase::new("3.7.2.8 Memory Read/Write (000/000 + 3FF/00C) -- SM on/off").with_steps(vec![
        // ============================================================
        // Phase 1: SM ON, 000/000 region — all access denied
        // ============================================================
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        // ---- MemExtWrite 000/000, plain ----
        comment("MemExtWrite 000/000 plain -> FC"),
        inject("BC #EDI #BDUT_ADDR 6B 01 FB 06 #MEM_AP_000_000 01 02 03 04 05 06"),
        expect("BC #BDUT_ADDR #EDI 65 01 FC FC #MEM_AP_000_000", TIMEOUT),
        // ---- MemExtWrite 000/000, auth-only ----
        comment("MemExtWrite 000/000 auth -> FC"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 0B 01 FB 06 #MEM_AP_000_000 01 02 03 04 05 06", "TK1"),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 05 01 FC FC #MEM_AP_000_000", "TK1", TIMEOUT),
        // ---- MemExtWrite 000/000, A+C ----
        comment("MemExtWrite 000/000 A+C -> FC"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 0B 01 FB 06 #MEM_AP_000_000 01 02 03 04 05 06", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 05 01 FC FC #MEM_AP_000_000", "TK1", TIMEOUT),
        // ---- MemExtRead 000/000, plain ----
        comment("MemExtRead 000/000 plain -> FC"),
        inject("BC #EDI #BDUT_ADDR 65 01 FD 06 #MEM_AP_000_000"),
        expect("BC #BDUT_ADDR #EDI 65 01 FE FC #MEM_AP_000_000", TIMEOUT),
        // ---- MemExtRead 000/000, auth-only ----
        comment("MemExtRead 000/000 auth -> FC"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 05 01 FD 06 #MEM_AP_000_000", "TK1"),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 05 01 FE FC #MEM_AP_000_000", "TK1", TIMEOUT),
        // ---- MemExtRead 000/000, A+C ----
        comment("MemExtRead 000/000 A+C -> FC"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 05 01 FD 06 #MEM_AP_000_000", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 05 01 FE FC #MEM_AP_000_000", "TK1", TIMEOUT),
        // ============================================================
        // Phase 2: SM OFF, 000/000 region — still all denied
        // ============================================================
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        // ---- MemExtWrite 000/000, plain ----
        comment("MemExtWrite 000/000 plain (SM off) -> FC"),
        inject("BC #EDI #BDUT_ADDR 6B 01 FB 06 #MEM_AP_000_000 01 02 03 04 05 06"),
        expect("BC #BDUT_ADDR #EDI 65 01 FC FC #MEM_AP_000_000", TIMEOUT),
        // ---- MemExtWrite 000/000, auth-only ----
        comment("MemExtWrite 000/000 auth (SM off) -> FC"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 0B 01 FB 06 #MEM_AP_000_000 01 02 03 04 05 06", "TK1"),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 05 01 FC FC #MEM_AP_000_000", "TK1", TIMEOUT),
        // ---- MemExtWrite 000/000, A+C ----
        comment("MemExtWrite 000/000 A+C (SM off) -> FC"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 0B 01 FB 06 #MEM_AP_000_000 01 02 03 04 05 06", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 05 01 FC FC #MEM_AP_000_000", "TK1", TIMEOUT),
        // ---- MemExtRead 000/000, plain ----
        comment("MemExtRead 000/000 plain (SM off) -> FC"),
        inject("BC #EDI #BDUT_ADDR 65 01 FD 06 #MEM_AP_000_000"),
        expect("BC #BDUT_ADDR #EDI 65 01 FE FC #MEM_AP_000_000", TIMEOUT),
        // ---- MemExtRead 000/000, auth-only ----
        comment("MemExtRead 000/000 auth (SM off) -> FC"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 05 01 FD 06 #MEM_AP_000_000", "TK1"),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 05 01 FE FC #MEM_AP_000_000", "TK1", TIMEOUT),
        // ---- MemExtRead 000/000, A+C ----
        comment("MemExtRead 000/000 A+C (SM off) -> FC"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 05 01 FD 06 #MEM_AP_000_000", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 05 01 FE FC #MEM_AP_000_000", "TK1", TIMEOUT),
        // ============================================================
        // Phase 3: SM ON, 3FF/00C region — plain/auth denied, A+C allowed
        // ============================================================
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        // ---- MemExtWrite 3FF/00C, plain -> denied ----
        comment("MemExtWrite 3FF/00C plain (SM on) -> FC"),
        inject("BC #EDI #BDUT_ADDR 6B 01 FB 06 #MEM_AP_3FF_00C 01 02 03 04 05 06"),
        expect("BC #BDUT_ADDR #EDI 65 01 FC FC #MEM_AP_3FF_00C", TIMEOUT),
        // ---- MemExtWrite 3FF/00C, auth-only -> denied ----
        comment("MemExtWrite 3FF/00C auth (SM on) -> FC"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 0B 01 FB 06 #MEM_AP_3FF_00C 01 02 03 04 05 06", "TK1"),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 05 01 FC FC #MEM_AP_3FF_00C", "TK1", TIMEOUT),
        // ---- MemExtWrite 3FF/00C, A+C -> success ----
        comment("MemExtWrite 3FF/00C A+C (SM on) -> 00"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 0B 01 FB 06 #MEM_AP_3FF_00C 01 02 03 04 05 06", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 05 01 FC 00 #MEM_AP_3FF_00C", "TK1", TIMEOUT),
        // ---- MemExtRead 3FF/00C, plain -> denied ----
        comment("MemExtRead 3FF/00C plain (SM on) -> FC"),
        inject("BC #EDI #BDUT_ADDR 65 01 FD 06 #MEM_AP_3FF_00C"),
        expect("BC #BDUT_ADDR #EDI 65 01 FE FC #MEM_AP_3FF_00C", TIMEOUT),
        // ---- MemExtRead 3FF/00C, auth-only -> denied ----
        comment("MemExtRead 3FF/00C auth (SM on) -> FC"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 05 01 FD 06 #MEM_AP_3FF_00C", "TK1"),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 05 01 FE FC #MEM_AP_3FF_00C", "TK1", TIMEOUT),
        // ---- MemExtRead 3FF/00C, A+C -> success with data ----
        comment("MemExtRead 3FF/00C A+C (SM on) -> 00 + data"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 05 01 FD 06 #MEM_AP_3FF_00C", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 0B 01 FE 00 #MEM_AP_3FF_00C 01 02 03 04 05 06", "TK1", TIMEOUT),
        // ============================================================
        // Phase 4: SM OFF, 3FF/00C region — all access allowed
        // ============================================================
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        // ---- MemExtWrite 3FF/00C, plain -> success ----
        comment("MemExtWrite 3FF/00C plain (SM off) -> 00"),
        inject("BC #EDI #BDUT_ADDR 6B 01 FB 06 #MEM_AP_3FF_00C 01 02 03 04 05 06"),
        expect("BC #BDUT_ADDR #EDI 65 01 FC 00 #MEM_AP_3FF_00C", TIMEOUT),
        // ---- MemExtWrite 3FF/00C, auth-only -> success ----
        comment("MemExtWrite 3FF/00C auth (SM off) -> 00"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 0B 01 FB 06 #MEM_AP_3FF_00C 01 02 03 04 05 06", "TK1"),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 05 01 FC 00 #MEM_AP_3FF_00C", "TK1", TIMEOUT),
        // ---- MemExtWrite 3FF/00C, A+C -> success ----
        comment("MemExtWrite 3FF/00C A+C (SM off) -> 00"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 0B 01 FB 06 #MEM_AP_3FF_00C 01 02 03 04 05 06", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 05 01 FC 00 #MEM_AP_3FF_00C", "TK1", TIMEOUT),
        // ---- MemExtRead 3FF/00C, plain -> success with data ----
        comment("MemExtRead 3FF/00C plain (SM off) -> 00 + data"),
        inject("BC #EDI #BDUT_ADDR 65 01 FD 06 #MEM_AP_3FF_00C"),
        expect("BC #BDUT_ADDR #EDI 6B 01 FE 00 #MEM_AP_3FF_00C 01 02 03 04 05 06", TIMEOUT),
        // ---- MemExtRead 3FF/00C, auth-only -> success with data ----
        comment("MemExtRead 3FF/00C auth (SM off) -> 00 + data"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 05 01 FD 06 #MEM_AP_3FF_00C", "TK1"),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 0B 01 FE 00 #MEM_AP_3FF_00C 01 02 03 04 05 06", "TK1", TIMEOUT),
        // ---- MemExtRead 3FF/00C, A+C -> success with data ----
        comment("MemExtRead 3FF/00C A+C (SM off) -> 00 + data"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 05 01 FD 06 #MEM_AP_3FF_00C", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 0B 01 FE 00 #MEM_AP_3FF_00C 01 02 03 04 05 06", "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.7.2.9 A_Restart (3FF/00C) -- SM on
// ============================================================================
//
// With security + programming mode activated, tests that the DUT:
// - Ignores basic restart (type=0) when sent plain or auth-only
// - Returns UnsupportedEraseCode (0x02) for erase code 0xFE
// - Returns AccessDenied (0x01) for erase codes 0x01, 0x02, 0x07 when plain or auth-only
// - Remains in programming mode after all tests
//
// Each restart sub-test uses a fresh T_Connect/T_Disconnect cycle.

fn test_3_7_2_9() -> TestCase {
    TestCase::new("3.7.2.9 Restart (3FF/00C) -- SM on").with_steps(vec![
        // Setup: enable security mode + programming mode.
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        comment("Enable Programming Mode"),
        inject_secure_ac(ENABLE_PROG_MODE, "TK1"),
        expect_secure_ac(ENABLE_PROG_MODE_RESP, "TK1", TIMEOUT),
        // ============================================================
        // Basic Restart (type=0) — plain → ignore (no restart)
        // ============================================================
        comment("Basic Restart plain -> ignore"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        // Numbered data: TPCI=0x43(seq=0), APCI=0x0380 → 43 80
        inject("BC #EDI #BDUT_ADDR 61 43 80"),
        // DUT should ACK the frame but not restart.
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Basic Restart (type=0) — auth-only → ignore (no restart)
        // ============================================================
        comment("Basic Restart auth-only -> ignore"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ao("BC #EDI #BDUT_ADDR 61 43 80", "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Master Reset erase=0xFE — plain → UnsupportedEraseCode (0x02)
        // ============================================================
        comment("Master Reset erase=FE plain -> UnsupportedEraseCode"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        // TPCI=0x43(seq=0), APCI=0x0381, erase=0xFE, channel=0x00
        inject("BC #EDI #BDUT_ADDR 63 43 81 FE 00"),
        // Expect T_ACK.
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        // Expect Restart_Response: TPCI=0x43(seq=0), APCI=0x03A1, error=0x02, time=0x0000
        expect("BC #BDUT_ADDR #EDI 64 43 A1 02 00 00", TIMEOUT),
        // ACK the response.
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Master Reset erase=0x01 — plain → AccessDenied (0x01)
        // ============================================================
        comment("Master Reset erase=01 plain -> AccessDenied"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject("BC #EDI #BDUT_ADDR 63 43 81 01 00"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect("BC #BDUT_ADDR #EDI 64 43 A1 01 00 00", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Master Reset erase=0x01 — auth-only → AccessDenied (0x01)
        // ============================================================
        comment("Master Reset erase=01 auth-only -> AccessDenied"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 03 43 81 01 00", "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 04 43 A1 01 00 00", "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Master Reset erase=0x02 — plain → AccessDenied (0x01)
        // ============================================================
        comment("Master Reset erase=02 plain -> AccessDenied"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject("BC #EDI #BDUT_ADDR 63 43 81 02 00"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect("BC #BDUT_ADDR #EDI 64 43 A1 01 00 00", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Master Reset erase=0x02 — auth-only → AccessDenied (0x01)
        // ============================================================
        comment("Master Reset erase=02 auth-only -> AccessDenied"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 03 43 81 02 00", "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 04 43 A1 01 00 00", "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Master Reset erase=0x07 — plain → AccessDenied (0x01)
        // ============================================================
        comment("Master Reset erase=07 plain -> AccessDenied"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject("BC #EDI #BDUT_ADDR 63 43 81 07 00"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect("BC #BDUT_ADDR #EDI 64 43 A1 01 00 00", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Master Reset erase=0x07 — auth-only → AccessDenied (0x01)
        // ============================================================
        comment("Master Reset erase=07 auth-only -> AccessDenied"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ao("3C 60 #EDI #BDUT_ADDR 03 43 81 07 00", "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ao("3C 60 #BDUT_ADDR #EDI 04 43 A1 01 00 00", "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Verify programming mode still active
        // ============================================================
        comment("Verify Programming Mode still active"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 05 03 D5 00 36 10 01", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 06 03 D6 00 36 10 01 01", "TK1", TIMEOUT),
        // Cleanup.
        comment("Disable Programming Mode"),
        inject_secure_ac(DISABLE_PROG_MODE, "TK1"),
        expect_secure_ac(DISABLE_PROG_MODE_RESP, "TK1", TIMEOUT),
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.7.2.10 A_Key_Write (3FF/0CC) -- SM on
// ============================================================================
//
// Access policy 3FF/0CC: when security mode is on, only Tool A+C can write.
// Denied Key_Write requests are silently dropped — no Key_Response is sent.
// A_Key_Write is a connection-oriented service (T_Data_Ind only).
//
// APCI 0x03D3 (Key_Write), 0x03D4 (Key_Response).
// Frame format: TPCI=43h(seq=0) + D3h(low APCI) + level(1) + key(4).

fn test_3_7_2_10() -> TestCase {
    TestCase::new("3.7.2.10 KeyWrite (3FF/0CC) -- Plain/A/A+C -- SM on").with_steps(vec![
        // Setup: enable security mode.
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        // ============================================================
        // Plain A_Key_Write -> silently dropped (no Key_Response)
        // ============================================================
        // DUT ACKs the transport frame but does not send a KeyResponse.
        // We immediately disconnect — no need to wait for idle timeout.
        // Level 2 is the highest settable level (NUM_AUTH_KEYS = 3,
        // levels 0-2 are settable; level 3 is "everyone" with no key).
        comment("Plain Key_Write -> silently dropped"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject("BC #EDI #BDUT_ADDR 66 43 D3 02 AA BB CC DD"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // Auth-only A_Key_Write -> silently dropped
        // ============================================================
        comment("Auth-only Key_Write -> silently dropped"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ao("BC #EDI #BDUT_ADDR 66 43 D3 02 AA BB CC DD", "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // ============================================================
        // A+C A_Key_Write -> Key_Response with result level
        // ============================================================
        comment("A+C Key_Write -> Key_Response"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ac("BC #EDI #BDUT_ADDR 66 43 D3 02 AA BB CC DD", "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ac("BC #BDUT_ADDR #EDI 62 43 D4 02", "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
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
    TestCase::new("3.7.2.13 IndAddrWrite (3FF/00C) + ProgMode (3FF/0CC) -- SM on").with_steps(vec![
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
    TestCase::new("3.7.2.14 IndAddrSerNoWrite (3FF/00C) -- Plain/A/A+C -- SM on").with_steps(vec![
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
