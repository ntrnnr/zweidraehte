//! Section 3.8.7 — `PID_LOAD_STATE_CONTROL` on Security IO (4 cases).
//!
//! Tests PID 0x05 (PID_LOAD_STATE_CONTROL) on the Security Interface Object
//! (IOT=0x0011, instance=0x0010). Also tests SIAT write/read under load
//! state transitions and restart persistence.
//!
//! Skipped test cases:
//! - 3.8.7.1 — requires P2P key infrastructure (IA1 in SIAT + P2PK1 key).
//! - 3.8.7.2 — requires P2P key auth with non-tool key.

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
// PropertyExtDescription_Read / Response templates for PID 0x05 on Security IO
// ============================================================================

// Plain PropertyExtDescription read for PID 0x05 on Security IO.
// APDU: 01 D2 + 00 11 + 00 10 + 05 + 00 + 00 = 9 bytes → TP1 len = 0x68
const PLAIN_DESC_READ_PID05: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 05 00 00";

// Plain response: all-zero descriptor (denied when SM=ON, 00C policy for Security IO).
const PLAIN_DESC_READ_PID05_ZERO: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 05 00 00 00 00 00 00 00 00 00 00";

// Plain response: valid descriptor (allowed when SM=OFF for 15F policy).
// Wildcard bytes for the descriptor fields that vary by implementation.
// Valid descriptor response when SM=OFF. The descriptor index byte (00)
// and property index byte (01) are fixed; PDT and access fields use
// wildcards since they vary by implementation.
const PLAIN_DESC_READ_PID05_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 05 00 01 ?? ?? ?? ?? ?? ?? ?? ??";


// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_7_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new(
        "3.8.7 PID_LOAD_STATE_CONTROL / SIAT (Security IO)",
        variables,
    )
    .secure()
    .with_cases(vec![
        test_3_8_7_1(),
        test_3_8_7_2(),
        test_3_8_7_3(),
        test_3_8_7_4(),
    ])
}

fn placeholder(name: &'static str, reason: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![
        comment(reason),
    ])
}

fn test_3_8_7_1() -> TestCase {
    placeholder(
        "3.8.7.1 Secure Property Read and Write, Plain, with A only, with A+C",
        "Placeholder: requires P2P key infrastructure (non-tool key) not yet supported by the harness.",
    )
}

fn test_3_8_7_2() -> TestCase {
    placeholder(
        "3.8.7.2 Property Write and Read - A and A+C with other than Tool Key",
        "Placeholder: requires P2P key auth with non-tool key not yet supported by the harness.",
    )
}

fn test_3_8_7_4() -> TestCase {
    // 10-byte load-control writes: 1-byte event + 9-byte load-procedure
    // record (zero — System B ignores it). The System B load-state
    // machine only transitions `Loading → Loaded` on `LoadCompleted`,
    // so we drive `Unloaded → Loading → Loaded` with two writes
    // (StartLoading event = 0x01, then LoadCompleted event = 0x02)
    // before the test proper — this matches the transitions a real
    // commissioning flow would have already performed by the time
    // 3.8.7.4 runs.
    const START_LOADING: &str =
        "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 01 00 00 00 00 00 00 00 00 00";
    const LOAD_COMPLETED: &str =
        "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 02 00 00 00 00 00 00 00 00 00";
    const LOAD_CONTROL_OK: &str =
        "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

    const READ_LOAD_STATE: &str =
        "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 05 01 00 01";
    const READ_LOAD_STATE_LOADED: &str =
        "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 05 01 00 01 01";

    // Connection-oriented A_Restart variants from 3.8.9.5 / 3.8.12.2.
    const CONNECTED_RESTART_CONFIRMED: &str =
        "3C 60 #EDI #BDUT_ADDR 03 43 81 01 00";
    const CONNECTED_RESTART_CONFIRMED_RESP: &str =
        "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";
    // Plain numbered Basic Restart (TPCI 0x43 + APCI 0x80 single byte):
    // standard frame, len 0x61.
    const CONNECTED_BASIC_RESTART: &str =
        "BC #EDI #BDUT_ADDR 61 43 80";

    let steps = vec![
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // ==== Phase A: Confirmed Restart preserves load state ====
        comment("Drive Unloaded → Loading (event=0x01)"),
        inject_secure_ac(START_LOADING, "TK1"),
        expect_secure_ac(LOAD_CONTROL_OK, "TK1", TIMEOUT),

        comment("Drive Loading → Loaded (event=0x02)"),
        inject_secure_ac(LOAD_COMPLETED, "TK1"),
        expect_secure_ac(LOAD_CONTROL_OK, "TK1", TIMEOUT),

        comment("Read load state → expect Loaded (0x01)"),
        inject_secure_ac(READ_LOAD_STATE, "TK1"),
        expect_secure_ac(READ_LOAD_STATE_LOADED, "TK1", TIMEOUT),

        comment("T_Connect"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        comment("Secure A+C numbered A_Restart (Confirmed, erase=0x01)"),
        inject_secure_ac(CONNECTED_RESTART_CONFIRMED, "TK1"),
        comment("Expect T_ACK"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        comment("Expect A_Restart_Response"),
        expect_secure_ac(CONNECTED_RESTART_CONFIRMED_RESP, "TK1", TIMEOUT),
        comment("ACK + T_Disconnect"),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        comment("Wait for the DUT to auto-restart"),
        wait(500),

        comment("Read load state again → still Loaded (Confirmed Restart preserves)"),
        inject_secure_ac(READ_LOAD_STATE, "TK1"),
        expect_secure_ac(READ_LOAD_STATE_LOADED, "TK1", TIMEOUT),

        // ==== Phase B: Basic Restart preserves load state ====
        comment("Re-write Loaded (idempotent)"),
        inject_secure_ac(LOAD_COMPLETED, "TK1"),
        expect_secure_ac(LOAD_CONTROL_OK, "TK1", TIMEOUT),

        comment("Read load state → still Loaded"),
        inject_secure_ac(READ_LOAD_STATE, "TK1"),
        expect_secure_ac(READ_LOAD_STATE_LOADED, "TK1", TIMEOUT),

        comment("T_Connect"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        comment("Plain numbered Basic Restart (no encryption — APCI 0x80)"),
        inject(CONNECTED_BASIC_RESTART),
        comment("T_ACK only — Basic Restart does not produce an A_Restart_Response"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        comment("Wait for DUT auto-restart on Basic Restart"),
        wait(500),

        comment("Read load state after Basic Restart → still Loaded"),
        inject_secure_ac(READ_LOAD_STATE, "TK1"),
        expect_secure_ac(READ_LOAD_STATE_LOADED, "TK1", TIMEOUT),

        comment("Disable Security Mode (cleanup)"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
    ];

    TestCase::new("3.8.7.4 Secure PropertyValueRead after power down check value")
        .with_steps(steps)
}

// ============================================================================
// 3.8.7.3 Check Property description
// ============================================================================
//
// Plain PropertyDescription read for PID_LOAD_STATE_CONTROL on the Security
// IO. When Security Mode is ON, the DUT returns an all-zero descriptor
// (access denied). When SM is OFF, it returns a valid descriptor.

fn test_3_8_7_3() -> TestCase {
    TestCase::new("3.8.7.3 Check Property description").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → all-zero (denied when SM=ON)"),
        inject(PLAIN_DESC_READ_PID05),
        expect(PLAIN_DESC_READ_PID05_ZERO, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → valid descriptor (allowed when SM=OFF)"),
        inject(PLAIN_DESC_READ_PID05),
        expect(PLAIN_DESC_READ_PID05_OK, TIMEOUT),
    ])
}

// Tests 3.8.7.4 (restart persistence) is not implemented — the
// LOAD_STATE_CONTROL multi-byte write (load procedure control record)
// is rejected as E_DATA_TYPE_CONFLICT (0xFE) by the PropertyExt write
// path. Implementing it requires proper PDT_CONTROL handling.
