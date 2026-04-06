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
//! - 3.8.17.5 — uses T_Connect (connection-oriented power-down test), not yet
//!   implemented.

use super::variables::create_security_variables;
#[allow(unused_imports)]
use crate::tests::helpers::*;
use crate::{TestCase, TestSuite};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Security Mode Toggle Templates
// ============================================================================

const ENABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

const ENABLE_SECURITY_MODE_RESP: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

const DISABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const DISABLE_SECURITY_MODE_RESP: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// ============================================================================
// PropertyExtValueRead / Response templates for PID 0x3D on Security IO
// ============================================================================

// Plain A_PropertyExtValueRead: IOT=0x0011, instance=0x0010,
// PID=0x3D (GO_SECURITY_FLAGS), count=3, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 3D + 03 + 00 01 = 10 bytes → TP1 len = 0x69
const PLAIN_READ: &str = "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 3D 03 00 01";

// Plain read error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
// APDU: 01 CD + 00 11 + 00 10 + 3D + 00 + 00 01 + FC = 11 bytes → len = 0x6A
const PLAIN_READ_DENIED: &str = "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 3D 00 00 01 FC";

// Plain A_PropertyExtValueWriteCon: count=3, start=1, data=3 zero bytes.
// APDU: 01 CE + 00 11 + 00 10 + 3D + 03 + 00 01 + 00 00 00 = 13 bytes → len = 0x6C
const PLAIN_WRITE: &str = "BC #EDI #BDUT_ADDR 6C 01 CE 00 11 00 10 3D 03 00 01 00 00 00";

// Plain write error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
const PLAIN_WRITE_DENIED: &str = "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 3D 00 00 01 FC";

// ============================================================================
// Secure (auth-only) templates for PID 0x3D on Security IO
// ============================================================================

// Secure A_PropertyExtValueRead (carried in extended frame for secure wrapping).
// APDU: 01 CC + 00 11 + 00 10 + 3D + 03 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ: &str = "30 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3D 03 00 01";

// Secure read error response: count=0, return_code=0xFC.
// APDU: 01 CD + 00 11 + 00 10 + 3D + 00 + 00 01 + FC = 11 bytes → len = 0x0A
const SECURE_READ_DENIED: &str = "30 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 3D 00 00 01 FC";

// Secure A_PropertyExtValueWriteCon: count=3, start=1, data=3 zero bytes.
// APDU: 01 CE + 00 11 + 00 10 + 3D + 03 + 00 01 + 00 00 00 = 13 bytes → len = 0x0C
const SECURE_WRITE: &str = "30 60 #EDI #BDUT_ADDR 0C 01 CE 00 11 00 10 3D 03 00 01 00 00 00";

// Secure write error response: count=0, return_code=0xFC.
const SECURE_WRITE_DENIED: &str = "30 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3D 00 00 01 FC";

// ============================================================================
// Verification read — A+C secure read to confirm current state at end of test
// ============================================================================

// A+C secure element count query: count=1, start=0.
const VERIFY_READ: &str = "30 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3D 01 00 00";

// Response: count=1, start=0, 2-byte element count.
const VERIFY_READ_OK: &str = "30 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 3D 01 00 00 ?? ??";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x3D on Security IO
// ============================================================================

// Secure A+C A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x3D, description index=0x00, property index=0x00.
// APDU: 01 D2 + 00 11 + 00 10 + 3D + 00 + 00 = 8 bytes → len = 0x08
const SECURE_DESC_READ_PID3D: &str = "3C 60 #EDI #BDUT_ADDR 08 01 D2 00 11 00 10 3D 00 00";

// Secure A+C success response: valid descriptor (wildcard data bytes).
// APDU: 01 D3 + 00 11 + 00 10 + 3D + ?? x10 = 16 bytes → len = 0x10
const SECURE_DESC_READ_PID3D_OK: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 3D ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Plain A_PropertyExtDescription_Read for PID 0x3D.
const PLAIN_DESC_READ_PID3D: &str = "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 3D 00 00";

// Plain all-zero descriptor response (access denied for 00C/00C — plain NEVER allowed).
const PLAIN_DESC_READ_PID3D_ZERO: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 3D 00 00 00 00 00 00 00 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_17_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.17 PID_GO_SECURITY_FLAGS (Security IO, access 00C/00C)", variables).secure().with_cases(vec![
        test_3_8_17_1(),
        test_3_8_17_2(),
        test_3_8_17_3(),
        test_3_8_17_4(),
        // Skipped: 3.8.17.5 — uses T_Connect (connection-oriented),
        //   not yet implemented.
    ])
}

// ============================================================================
// 3.8.17.1 Secure PropertyValueWrite and Read of GO Security Flags
// ============================================================================
//
// Writes GO security flags via secure A+C, then injects group telegrams
// (both plain and secured) to verify the DUT applies the flags correctly.
// The test does NOT expect the DUT to generate group responses — all group
// telegrams are injected by the test tool.
//
// Phases (repeated for SM=ON and SM=OFF):
// 1. Load Security IO (Loading → Loaded)
// 2. Write GO flags = 00 00 00 (all plain), inject plain group traffic
// 3. Write GO flags = 01 03 00 (mixed), read back, inject secured group traffic
// 4. Write GO flags = FD FF FC (max), inject secured group traffic

fn test_3_8_17_1() -> TestCase {
    // ---- Security IO Load State Control (PID 5) ----
    // Write PID 5 = 0x01 (Loaded) — 10-byte load procedure record.
    const LOAD_LOADED: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 01 00 00 00 00 00 00 00 00 00";
    const LOAD_LOADED_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";
    // Write PID 5 = 0x02 (Loading).
    const LOAD_LOADING: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 02 00 00 00 00 00 00 00 00 00";
    const LOAD_LOADING_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

    // ---- GO Flags Write/Read (PID 0x3D, count=3, start=1) ----
    // Write flags = 00 00 00 (all unsecured).
    const WRITE_FLAGS_PLAIN: &str = "30 60 #EDI #BDUT_ADDR 0C 01 CE 00 11 00 10 3D 03 00 01 00 00 00";
    // Write flags = 01 03 00 (GO0=auth-only, GO1=auth+conf, GO2=plain).
    const WRITE_FLAGS_MIXED: &str = "30 60 #EDI #BDUT_ADDR 0C 01 CE 00 11 00 10 3D 03 00 01 01 03 00";
    // Write flags = FD FF FC (all max).
    const WRITE_FLAGS_MAX: &str = "30 60 #EDI #BDUT_ADDR 0C 01 CE 00 11 00 10 3D 03 00 01 FD FF FC";
    // Write success: count=3, return_code=0x00.
    const WRITE_FLAGS_OK: &str = "30 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3D 03 00 01 00";
    // Read flags: count=3, start=1.
    const READ_FLAGS: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3D 03 00 01";
    // Read response: flags = 01 03 00.
    const READ_FLAGS_MIXED_OK: &str = "3C 60 #BDUT_ADDR #EDI 0C 01 CD 00 11 00 10 3D 03 00 01 01 03 00";

    // ---- Plain group telegrams ----
    // GroupValue_Write(0) to GA 5/5/5 (0x2D05) from EDI.
    const PLAIN_GW_555: &str = "BC #EDI 2D 05 E1 00 00";
    // GroupValue_Response(0x40) to GA 5/5/5 from BDUT_ADDR.
    const PLAIN_GR_555: &str = "BC #BDUT_ADDR 2D 05 E1 00 40";
    // GroupValue_Write(0) to GA 1/1/1 (0x0901) from EDI.
    const PLAIN_GW_111: &str = "BC #EDI 09 01 E1 00 00";
    // GroupValue_Response(0x40) to GA 2/2/2 (0x1202) from BDUT_ADDR.
    const PLAIN_GR_222: &str = "BC #BDUT_ADDR 12 02 E1 00 40";
    // GroupValue_Write(0) to GA 3/3/3 (0x1B03) from EDI.
    const PLAIN_GW_333: &str = "BC #EDI 1B 03 E1 00 00";
    // GroupValue_Response(0x40) to GA 4/4/4 (0x2404) from BDUT_ADDR.
    const PLAIN_GR_444: &str = "BC #BDUT_ADDR 24 04 E1 00 40";

    // ---- Secured group telegrams (same data, different security) ----
    // Auth-only GroupValue_Write(0) to 1/1/1 with GK1.
    const SEC_GW_111: &str = "BC #EDI 09 01 E1 00 00";
    // Auth+conf GroupValue_Response(0x40) to 2/2/2 with GK2.
    const SEC_GR_222: &str = "BC #BDUT_ADDR 12 02 E1 00 40";
    // Auth+conf GroupValue_Write(0) to 3/3/3 with GK3.
    const SEC_GW_333: &str = "BC #EDI 1B 03 E1 00 00";
    // Auth+conf GroupValue_Response(0x40) to 4/4/4 with GK4.
    const SEC_GR_444: &str = "BC #BDUT_ADDR 24 04 E1 00 40";

    TestCase::new("3.8.17.1 Secure PropertyValueWrite and Read of GO Security Flags").with_steps(vec![
        // ================================================================
        // Security Mode ON
        // ================================================================
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        // ---- Load Security IO ----
        comment("Security IO: Loading → Loaded"),
        inject_secure_ac(LOAD_LOADED, "TK1"),
        expect_secure_ac(LOAD_LOADED_OK, "TK1", TIMEOUT),
        inject_secure_ac(LOAD_LOADING, "TK1"),
        expect_secure_ac(LOAD_LOADING_OK, "TK1", TIMEOUT),
        // ---- Phase 1: GO flags = 00 00 00 (all plain) ----
        comment("Write GO flags = 00 00 00 (all unsecured)"),
        inject_secure_ac(WRITE_FLAGS_PLAIN, "TK1"),
        expect_secure_ac(WRITE_FLAGS_OK, "TK1", TIMEOUT),
        comment("Inject plain group traffic (all accepted when flags=00)"),
        inject(PLAIN_GW_555),
        inject(PLAIN_GR_555),
        inject(PLAIN_GW_111),
        inject(PLAIN_GR_222),
        inject(PLAIN_GW_333),
        inject(PLAIN_GR_444),
        // ---- Phase 2: GO flags = 01 03 00 (mixed) ----
        comment("Write GO flags = 01 03 00 (GO0=auth, GO1=auth+conf, GO2=plain)"),
        inject_secure_ac(WRITE_FLAGS_MIXED, "TK1"),
        expect_secure_ac(WRITE_FLAGS_OK, "TK1", TIMEOUT),
        comment("Read back GO flags → 01 03 00"),
        inject_secure_ac(READ_FLAGS, "TK1"),
        expect_secure_ac(READ_FLAGS_MIXED_OK, "TK1", TIMEOUT),
        comment("Inject plain group traffic on 5/5/5 (GO2=plain, accepted)"),
        inject(PLAIN_GW_555),
        inject(PLAIN_GR_555),
        comment("Inject secured group traffic on 1/1/1→2/2/2 (GO0=auth, GK1/GK2)"),
        inject_group_ao(SEC_GW_111, "GK1"),
        inject_group_ao(SEC_GR_222, "GK2"),
        comment("Inject secured group traffic on 3/3/3→4/4/4 (GO1=auth+conf, GK3/GK4)"),
        inject_group_ac(SEC_GW_333, "GK3"),
        inject_group_ac(SEC_GR_444, "GK4"),
        // ---- Phase 3: GO flags = FD FF FC (max flags) ----
        comment("Write GO flags = FD FF FC (max)"),
        inject_secure_ac(WRITE_FLAGS_MAX, "TK1"),
        expect_secure_ac(WRITE_FLAGS_OK, "TK1", TIMEOUT),
        comment("Inject plain 5/5/5 + secured group traffic (same as phase 2)"),
        inject(PLAIN_GW_555),
        inject(PLAIN_GR_555),
        inject_group_ao(SEC_GW_111, "GK1"),
        inject_group_ao(SEC_GR_222, "GK2"),
        inject_group_ac(SEC_GW_333, "GK3"),
        inject_group_ac(SEC_GR_444, "GK4"),
        // ================================================================
        // Security Mode OFF — repeat all phases
        // ================================================================
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        // ---- Phase 1 (SM OFF): GO flags = 00 00 00 ----
        comment("Write GO flags = 00 00 00"),
        inject_secure_ac(WRITE_FLAGS_PLAIN, "TK1"),
        expect_secure_ac(WRITE_FLAGS_OK, "TK1", TIMEOUT),
        comment("Inject plain group traffic"),
        inject(PLAIN_GW_555),
        inject(PLAIN_GR_555),
        inject(PLAIN_GW_111),
        inject(PLAIN_GR_222),
        inject(PLAIN_GW_333),
        inject(PLAIN_GR_444),
        // ---- Phase 2 (SM OFF): GO flags = 01 03 00 ----
        comment("Write GO flags = 01 03 00"),
        inject_secure_ac(WRITE_FLAGS_MIXED, "TK1"),
        expect_secure_ac(WRITE_FLAGS_OK, "TK1", TIMEOUT),
        comment("Read back GO flags → 01 03 00"),
        inject_secure_ac(READ_FLAGS, "TK1"),
        expect_secure_ac(READ_FLAGS_MIXED_OK, "TK1", TIMEOUT),
        comment("Inject plain 5/5/5 + secured group traffic"),
        inject(PLAIN_GW_555),
        inject(PLAIN_GR_555),
        inject_group_ao(SEC_GW_111, "GK1"),
        inject_group_ao(SEC_GR_222, "GK2"),
        inject_group_ac(SEC_GW_333, "GK3"),
        inject_group_ac(SEC_GR_444, "GK4"),
        // ---- Phase 3 (SM OFF): GO flags = FD FF FC ----
        comment("Write GO flags = FD FF FC"),
        inject_secure_ac(WRITE_FLAGS_MAX, "TK1"),
        expect_secure_ac(WRITE_FLAGS_OK, "TK1", TIMEOUT),
        comment("Inject plain 5/5/5 + secured group traffic"),
        inject(PLAIN_GW_555),
        inject(PLAIN_GR_555),
        inject_group_ao(SEC_GW_111, "GK1"),
        inject_group_ao(SEC_GR_222, "GK2"),
        inject_group_ac(SEC_GW_333, "GK3"),
        inject_group_ac(SEC_GR_444, "GK4"),
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
