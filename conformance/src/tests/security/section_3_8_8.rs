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

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{TestCase, TestSuite};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// FunctionPropertyExtCommand / Response templates for PID 0x33
// ============================================================================

// A_FunctionPropertyExtCommand (0x01D4) on Security IO (0x0011, instance 0x0010),
// PID_SECURITY_MODE (0x33): reserved=0x00, ServiceID=0x00 (Write Security Mode),
// ServiceInfo=0x01 (Enable).
// APDU: 01 D4 + 00 11 + 00 10 + 33 + 00 + 00 + 01 = 10 bytes → TP1 len = 0x09
const COMMAND_ENABLE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

// A_FunctionPropertyExtCommand: ServiceInfo=0x00 (Disable).
const COMMAND_DISABLE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

// A_FunctionPropertyExtState_Response (0x01D6): return_code=0x00 (success),
// echoed ServiceID=0x00.
// APDU: 01 D6 + 00 11 + 00 10 + 33 + 00 + 00 = 9 bytes → TP1 len = 0x08
const COMMAND_RESP_OK: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// A_FunctionPropertyExtState_Response: return_code=0xF8 (invalid service info),
// echoed ServiceID=0x00.
const COMMAND_RESP_F8: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 F8 00";

// A_FunctionPropertyExtState_Response: return_code=0xFC (access denied),
// echoed ServiceID=0x00.
// APDU: 01 D6 + 00 11 + 00 10 + 33 + FC + 00 = 9 bytes → TP1 len = 0x08
const COMMAND_RESP_FC: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 FC 00";

// ============================================================================
// FunctionPropertyExtCommand with invalid ServiceID / ServiceInfo
// ============================================================================

// Command with ServiceInfo=0x03 (invalid — only 0x00 and 0x01 are valid).
// APDU: 01 D4 + 00 11 + 00 10 + 33 + 00 + 00 + 03 = 10 bytes → TP1 len = 0x09
const COMMAND_INVALID_SERVICE_INFO: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 03";

// Command with the Reserved octet = 0x01. 03/05/01 §6.3.5.1 fixes it at 00h,
// so the request data is not valid for this receiver → E_DATA_VOID (0xF8).
const COMMAND_RESERVED_NONZERO: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 01 00 01";

// ============================================================================
// FunctionPropertyExtState_Read / Response templates for PID 0x33
// ============================================================================

// A_FunctionPropertyExtState_Read (0x01D5): reserved=0x00, ServiceID=0x00.
// APDU: 01 D5 + 00 11 + 00 10 + 33 + 00 + 00 = 9 bytes → TP1 len = 0x08
const STATE_READ: &str = "3C 60 #EDI #BDUT_ADDR 08 01 D5 00 11 00 10 33 00 00";

// State_Read response: return_code=0x00, mode=0x01 (sec ON).
// APDU: 01 D6 + 00 11 + 00 10 + 33 + 00 + 00 + 01 = 10 bytes → TP1 len = 0x09
const STATE_READ_RESP_ON: &str = "3C 60 #BDUT_ADDR #EDI 09 01 D6 00 11 00 10 33 00 00 01";

// State_Read response: return_code=0x00, mode=0x00 (sec OFF).
const STATE_READ_RESP_OFF: &str = "3C 60 #BDUT_ADDR #EDI 09 01 D6 00 11 00 10 33 00 00 00";

// State_Read response: return_code=0xFC (access denied), echoed ServiceID=0x00.
// APDU: 01 D6 + 00 11 + 00 10 + 33 + FC + 00 = 9 bytes → TP1 len = 0x08
const STATE_READ_RESP_FC: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 FC 00";

// State_Read with invalid ServiceID=0x01 (only 0x00 is valid for StateRead).
const STATE_READ_INVALID_SERVICE_ID: &str = "3C 60 #EDI #BDUT_ADDR 08 01 D5 00 11 00 10 33 00 01";

// State_Read response: return_code=0xF2 (invalid service ID), echoed ServiceID=0x01.
// APDU: 01 D6 + 00 11 + 00 10 + 33 + F2 + 01 = 9 bytes → TP1 len = 0x08
const STATE_READ_RESP_F2: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 F2 01";

// State_Read with the Reserved octet = 0x01 (03/05/01 §6.3.5.2 fixes it at 00h).
const STATE_READ_RESERVED_NONZERO: &str = "3C 60 #EDI #BDUT_ADDR 08 01 D5 00 11 00 10 33 01 00";

// State_Read response: return_code=0xF8 (void request data), echoed ServiceID=0x00.
// APDU: 01 D6 + 00 11 + 00 10 + 33 + F8 + 00 = 9 bytes → TP1 len = 0x08
const STATE_READ_RESP_F8: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 F8 00";

// ============================================================================
// Plain (non-secure) FunctionPropertyExt templates
// ============================================================================

// Plain A_FunctionPropertyExtCommand: enable.
// APDU: 10 bytes → TP1 standard frame len = 0x69
const PLAIN_COMMAND_ENABLE: &str = "BC #EDI #BDUT_ADDR 69 01 D4 00 11 00 10 33 00 00 01";

// Plain A_FunctionPropertyExtCommand: disable.
const PLAIN_COMMAND_DISABLE: &str = "BC #EDI #BDUT_ADDR 69 01 D4 00 11 00 10 33 00 00 00";

// Plain Command response: return_code=0xFC (access denied), echoed ServiceID=0x00.
// APDU: 01 D6 + 00 11 + 00 10 + 33 + FC + 00 = 9 bytes → TP1 len = 0x68
const PLAIN_COMMAND_RESP_FC: &str = "BC #BDUT_ADDR #EDI 68 01 D6 00 11 00 10 33 FC 00";

// Plain A_FunctionPropertyExtState_Read.
// APDU: 9 bytes → TP1 standard frame len = 0x68
const PLAIN_STATE_READ: &str = "BC #EDI #BDUT_ADDR 68 01 D5 00 11 00 10 33 00 00";

// Plain State_Read response: mode=0x00 (sec OFF).
// APDU: 01 D6 + 00 11 + 00 10 + 33 + 00 + 00 + 00 = 10 bytes → TP1 len = 0x69
const PLAIN_STATE_READ_RESP_OFF: &str = "BC #BDUT_ADDR #EDI 69 01 D6 00 11 00 10 33 00 00 00";

// Plain State_Read response: return_code=0xFC (access denied), echoed ServiceID=0x00.
// APDU: 01 D6 + 00 11 + 00 10 + 33 + FC + 00 = 9 bytes → TP1 len = 0x68
const PLAIN_STATE_READ_RESP_FC: &str = "BC #BDUT_ADDR #EDI 68 01 D6 00 11 00 10 33 FC 00";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x33
// ============================================================================

// Plain A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x33, description index=0x00, property index=0x00.
const PLAIN_DESC_READ: &str = "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 33 00 00";

// Plain all-zero descriptor response (access denied when sec ON).
const PLAIN_DESC_READ_DENIED: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 33 00 00 00 00 00 00 00 00 00 00";

// Plain success response: valid descriptor (wildcard data bytes).
const PLAIN_DESC_READ_OK: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_8_suite() -> TestSuite {
    let variables = create_security_variables();

    // 3.8.8.7 performs two destructive factory resets (erase 0x02 and
    // local master_reset 0x02) that wipe address / association / GK
    // tables, then leaves Security Mode ON after the power-cycle phase.
    // Without a full reset, subsequent suites inherit an empty-tables
    // DUT with sec mode still active and cascade into failures.
    TestSuite::new("3.8.8 PID_SECURITY_MODE (Security IO, access 15F/04C)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_8_1(),
            test_3_8_8_2(),
            test_3_8_8_3(),
            test_3_8_8_4(),
            test_3_8_8_5(),
            test_3_8_8_6(),
            test_3_8_8_7(),
        ])
        .with_teardown(vec![
            comment("Teardown: rebuild default SHM + respawn to restore all DUT tables."),
            full_reset(2000),
            // Clear the `S-A_Sync_Req` rate-limit window so the next
            // suite's preparation SyncReq isn't throttled.
            wait(1500),
        ])
}

fn test_3_8_8_6() -> TestCase {
    TestCase::new("3.8.8.6 Secure FunctionPropertyStateRead").with_steps(vec![comment(
        "Placeholder: XML entry is comment-only (no active telegrams) — documentation-only cross-reference.",
    )])
}

fn test_3_8_8_7() -> TestCase {
    // Connection-oriented secure A+C `A_Restart` variants from the
    // established pattern (see 3.8.12.2/3.8.12.3/3.8.12.4).
    const CONNECTED_RESTART_CONFIRMED: &str = "3C 60 #EDI #BDUT_ADDR 03 43 81 01 00";
    const CONNECTED_RESTART_CONFIRMED_RESP: &str = "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";
    const CONNECTED_RESTART_FACTORY: &str = "3C 60 #EDI #BDUT_ADDR 03 43 81 02 00";
    const CONNECTED_RESTART_FACTORY_RESP: &str = "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";
    const CONNECTED_RESTART_FRWITHIA: &str = "3C 60 #EDI #BDUT_ADDR 03 43 81 07 00";
    const CONNECTED_RESTART_FRWITHIA_RESP: &str = "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    // PID_TOOL_KEY write: value = TK1 (`00 00 … 01`). Used after
    // each factory-reset phase to re-install TK1 so the next phase's
    // traffic can authenticate with TK1 again.
    const RESTORE_TOOL_KEY_TK1: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";
    const RESTORE_TOOL_KEY_TK1_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 01 00 01 00";

    const CHALLENGE_1: [u8; 6] = [0, 0, 0, 0, 0, 1];

    let steps = vec![
        // ==== Phase A: Confirmed Restart preserves PID_SECURITY_MODE ====
        comment("A. Activate Security Mode"),
        inject_secure_ac(COMMAND_ENABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),
        comment("A. Connection-oriented secure Confirmed Restart (erase=0x01)"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ac(CONNECTED_RESTART_CONFIRMED, "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ac(CONNECTED_RESTART_CONFIRMED_RESP, "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        // Wait for the child DUT to actually flush state and respawn
        // before the next phase starts. `wait(500)` only waits 10ms in
        // fast mode — short enough that Phase B's A_Restart lands in
        // the dying child's restart channel and gets silently dropped.
        wait_for_restart(2000),
        // Drop Read-On-Init frames the respawned child emits so they
        // don't collide with subsequent expects.
        drain(500),
        comment("A. Read Security Mode → still ON (Confirmed Restart preserves)"),
        inject_secure_ac(STATE_READ, "TK1"),
        expect_secure_ac(STATE_READ_RESP_ON, "TK1", TIMEOUT),
        // ==== Phase B: FactoryResetKeepIA clears PID_SECURITY_MODE ====
        comment("B. Re-activate Security Mode"),
        inject_secure_ac(COMMAND_ENABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),
        comment("B. FactoryResetKeepIA (erase=0x07)"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ac(CONNECTED_RESTART_FRWITHIA, "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ac(CONNECTED_RESTART_FRWITHIA_RESP, "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        wait_for_restart(2000),
        // Drop Read-On-Init frames the respawned child emits so they
        // don't collide with subsequent expects.
        drain(500),
        // 03/05/01 §6.3.5.4 and §6.3.10 both put "Reset to default
        // without IA" (07h) in the "not influenced" row: the Security
        // Mode stays on and the tool key stays TK1. The tables, the
        // failures log and the security report *are* cleared, and the IA
        // is kept, so there is nothing to re-program either.
        comment("B. Sync tool seq after FactoryResetKeepIA (tool key survives 07h)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
        comment("B. Read Security Mode → still ON (07h leaves it unchanged)"),
        inject_secure_ac(STATE_READ, "TK1"),
        expect_secure_ac(STATE_READ_RESP_ON, "TK1", TIMEOUT),
        // ==== Phase C: FactoryReset clears PID_SECURITY_MODE ====
        // Note: our DUT restored IA after the FactoryResetKeepIA (via
        // the preserved address), so step C still starts with a valid IA.
        comment("C. Security Mode is already on from phase B"),
        comment("C. FactoryReset (erase=0x02) — IA gets wiped"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ac(CONNECTED_RESTART_FACTORY, "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ac(CONNECTED_RESTART_FACTORY_RESP, "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI FF FF 60 81"),
        wait_for_restart(2000),
        // Drop Read-On-Init frames the respawned child emits so they
        // don't collide with subsequent expects.
        drain(500),
        comment("C. Re-program BDUT IA via A_IndividualAddressSerialNumber_Write"),
        inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
        wait(200),
        comment("C. Sync tool seq after FactoryReset (FDSK-encrypted)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, CHALLENGE_1),
        expect_sync_res_tool("FDSK", CHALLENGE_1, None, None, TIMEOUT),
        comment("C. Read Security Mode → OFF (factory reset cleared)"),
        inject_secure_ac(STATE_READ, "FDSK"),
        expect_secure_ac(STATE_READ_RESP_OFF, "FDSK", TIMEOUT),
        comment("C. Restore PID_TOOL_KEY = TK1 (auth with FDSK, response with TK1)"),
        inject_secure_ac(RESTORE_TOOL_KEY_TK1, "FDSK"),
        expect_secure_ac(RESTORE_TOOL_KEY_TK1_OK, "TK1", TIMEOUT),
        // ==== Phase D: Local Factory Reset clears PID_SECURITY_MODE ====
        comment("D. Re-activate Security Mode"),
        inject_secure_ac(COMMAND_ENABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),
        comment("D. Local Factory Reset via IPC (same effect as erase=0x02)"),
        master_reset(0x02, 2000),
        comment("D. Re-program BDUT IA"),
        inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
        wait(200),
        comment("D. Sync tool seq after Local Factory Reset (FDSK-encrypted)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, CHALLENGE_1),
        expect_sync_res_tool("FDSK", CHALLENGE_1, None, None, TIMEOUT),
        comment("D. Read Security Mode → OFF (local factory reset cleared)"),
        inject_secure_ac(STATE_READ, "FDSK"),
        expect_secure_ac(STATE_READ_RESP_OFF, "FDSK", TIMEOUT),
        comment("D. Restore PID_TOOL_KEY = TK1 (auth with FDSK, response with TK1)"),
        inject_secure_ac(RESTORE_TOOL_KEY_TK1, "FDSK"),
        expect_secure_ac(RESTORE_TOOL_KEY_TK1_OK, "TK1", TIMEOUT),
        // ==== Phase E: Power Down preserves PID_SECURITY_MODE ====
        comment("E. Activate Security Mode"),
        inject_secure_ac(COMMAND_ENABLE, "TK1"),
        expect_secure_ac(COMMAND_RESP_OK, "TK1", TIMEOUT),
        comment("E. Power cycle the DUT"),
        power_cycle(2000),
        comment("E. Sync tool seq after power cycle"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
        comment("E. Read Security Mode → still ON (power cycle preserves)"),
        inject_secure_ac(STATE_READ, "TK1"),
        expect_secure_ac(STATE_READ_RESP_ON, "TK1", TIMEOUT),
    ];

    TestCase::new("3.8.8.7 Secure FunctionPropertyStateRead after power down and master reset").with_steps(steps)
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
//
// The two Reserved-octet steps are not in the XML template; they are derived
// from 03/05/01 §6.3.5.3, which admits only FFh, FEh, F8h and the Table 102
// code F2h for this property. A malformed Reserved octet is void request
// data, so it must answer F8h — not a code from the specific-negative range
// A0h–DFh, where Table 102 defines nothing at all.

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
        // Reserved octet != 0x00 on the Command → RC=0xF8, ServiceID echoed,
        // and — critically — the enable must not take effect.
        comment("A+C Command with Reserved=0x01 → RC=0xF8"),
        inject_secure_ac(COMMAND_RESERVED_NONZERO, "TK1"),
        expect_secure_ac(COMMAND_RESP_F8, "TK1", TIMEOUT),
        comment("A+C StateRead → mode=0 (rejected Command did not enable)"),
        inject_secure_ac(STATE_READ, "TK1"),
        expect_secure_ac(STATE_READ_RESP_OFF, "TK1", TIMEOUT),
        // Reserved octet != 0x00 on the StateRead → RC=0xF8, ServiceID echoed.
        comment("A+C StateRead with Reserved=0x01 → RC=0xF8"),
        inject_secure_ac(STATE_READ_RESERVED_NONZERO, "TK1"),
        expect_secure_ac(STATE_READ_RESP_F8, "TK1", TIMEOUT),
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
