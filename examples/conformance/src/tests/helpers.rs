//! Shared helper functions for conformance test step definitions
//!
//! These helpers provide a concise DSL for defining test steps in EITT-style tests.

use crate::{InvalidSecurityParam, SecureParams, SeqSource, SyncReqParams, SyncResExpect, TestStep};

/// Helper to create an inject step from a template string
pub fn inject(template: &str) -> TestStep {
    TestStep::InjectTemplate { template: template.to_string(), delay_before_ms: 0 }
}

/// Helper to create an inject step with delay
pub fn inject_delay(template: &str, delay_ms: u32) -> TestStep {
    TestStep::InjectTemplate { template: template.to_string(), delay_before_ms: delay_ms }
}

/// Helper to create an expect step from a template string
pub fn expect(template: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectTemplate { template: template.to_string(), timeout_ms }
}

/// Helper to create a comment step
pub fn comment(text: &str) -> TestStep {
    TestStep::Comment(text.to_string())
}

/// Helper to set programming mode
pub fn set_programming_mode(enabled: bool) -> TestStep {
    TestStep::SetProgrammingMode(enabled)
}

/// Helper to trigger a GroupValue_Read for the given ASAP.
///
/// # BCU1/BCU2 Compatibility Note
///
/// Our stack does not automatically send GroupValue_Read when the ReadRequest
/// flag is set on a communication object. This differs from BCU1/BCU2 behavior
/// where setting the flag would automatically trigger the bus operation.
///
/// Use this helper after setting the ReadRequest flag via the shadow object (GO1)
/// to explicitly trigger the read operation that a BCU1/BCU2 would perform
/// automatically.
///
/// See `TestStep::TriggerRead` for more details on why we use explicit triggering.
pub fn trigger_read(asap: u16) -> TestStep {
    TestStep::TriggerRead { asap }
}

/// Helper to trigger a GroupValue_Write for the given ASAP.
///
/// # BCU1/BCU2 Compatibility Note
///
/// Our stack does not automatically send GroupValue_Write when the WriteRequest
/// flag is set on a communication object. This differs from BCU1/BCU2 behavior
/// where setting the flag would automatically trigger the bus operation.
///
/// Use this helper after setting the WriteRequest flag via the shadow object (GO1)
/// to explicitly trigger the write operation that a BCU1/BCU2 would perform
/// automatically.
///
/// See `TestStep::TriggerWrite` for more details on why we use explicit triggering.
pub fn trigger_write(asap: u16) -> TestStep {
    TestStep::TriggerWrite { asap }
}

/// Helper to expect no response within a timeout
///
/// This step passes if no message is received within the timeout period.
/// Use this when the test expects the device to remain silent.
pub fn expect_none(timeout_ms: u32) -> TestStep {
    TestStep::ExpectNone { timeout_ms }
}

/// Wait for a duration.
///
/// Used after connectionless restart injects to give the DUT child process
/// time to flush and exit before the next step runs.
pub fn wait(duration_ms: u32) -> TestStep {
    TestStep::Wait { duration_ms }
}

/// Drain all pending captured messages after waiting `settle_ms` for
/// in-flight messages to arrive.
///
/// Use after operations that produce side-effect messages (e.g., restart
/// triggers ROI reads) that would interfere with subsequent Expect steps.
#[allow(dead_code)]
pub fn drain(settle_ms: u32) -> TestStep {
    TestStep::Drain { settle_ms }
}

/// Wait for the DUT to exit (restart) and respawn it without draining
/// captured messages.
///
/// Use this after injecting an A_Restart telegram when the test needs to
/// observe automatic post-restart behavior such as Read-On-Init scans.
pub fn wait_for_restart(timeout_ms: u32) -> TestStep {
    TestStep::WaitForRestart { timeout_ms }
}

// ============================================================================
// KNX Data Secure helpers
// ============================================================================

/// Inject a secure telegram with authentication + confidentiality using
/// the tool key.
pub fn inject_secure_ac(template: &str, key: &str) -> TestStep {
    TestStep::InjectSecure {
        template: template.to_string(),
        sec_params: SecureParams::tool_auth_conf(key),
        delay_before_ms: 0,
    }
}

/// Inject a secure telegram with authentication only using the tool key.
pub fn inject_secure_ao(template: &str, key: &str) -> TestStep {
    TestStep::InjectSecure {
        template: template.to_string(),
        sec_params: SecureParams::tool_auth_only(key),
        delay_before_ms: 0,
    }
}

/// Inject a secure telegram with custom parameters.
pub fn inject_secure(template: &str, params: SecureParams) -> TestStep {
    TestStep::InjectSecure { template: template.to_string(), sec_params: params, delay_before_ms: 0 }
}

/// Inject a secure telegram with delay.
pub fn inject_secure_delay(template: &str, params: SecureParams, delay_ms: u32) -> TestStep {
    TestStep::InjectSecure { template: template.to_string(), sec_params: params, delay_before_ms: delay_ms }
}

/// Expect a secure response with authentication + confidentiality.
pub fn expect_secure_ac(template: &str, key: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectSecure { template: template.to_string(), sec_params: SecureParams::tool_auth_conf(key), timeout_ms }
}

/// Expect a secure response with authentication only.
pub fn expect_secure_ao(template: &str, key: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectSecure { template: template.to_string(), sec_params: SecureParams::tool_auth_only(key), timeout_ms }
}

/// Inject a group-key secure telegram with authentication + confidentiality.
pub fn inject_group_ac(template: &str, key: &str) -> TestStep {
    TestStep::InjectSecure {
        template: template.to_string(),
        sec_params: SecureParams::group_auth_conf(key),
        delay_before_ms: 0,
    }
}

/// Inject a group-key secure telegram with authentication only.
pub fn inject_group_ao(template: &str, key: &str) -> TestStep {
    TestStep::InjectSecure {
        template: template.to_string(),
        sec_params: SecureParams::group_auth_only(key),
        delay_before_ms: 0,
    }
}

/// Expect a group-key secure response with authentication + confidentiality.
pub fn expect_group_ac(template: &str, key: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectSecure {
        template: template.to_string(),
        sec_params: SecureParams::group_auth_conf(key),
        timeout_ms,
    }
}

/// Expect a group-key secure response with authentication only.
pub fn expect_group_ao(template: &str, key: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectSecure {
        template: template.to_string(),
        sec_params: SecureParams::group_auth_only(key),
        timeout_ms,
    }
}

/// Inject a secure A+C telegram using the all-zeros key. The DUT won't
/// be able to decrypt this (wrong key) and should silently drop it,
/// logging a CryptoError.
pub fn inject_secure_ac_wrongkey(template: &str) -> TestStep {
    inject_secure_ac(template, "ZERO_KEY")
}

/// Inject a secure A+C telegram with sequence number explicitly set to 0.
/// The DUT should reject this (seq=0 is invalid) and log a SeqNrError.
pub fn inject_secure_ac_seq0(template: &str, key: &str) -> TestStep {
    let mut params = SecureParams::tool_auth_conf(key);
    params.seq_source = SeqSource::Fixed(0);
    TestStep::InjectSecure { template: template.to_string(), sec_params: params, delay_before_ms: 0 }
}

/// Inject a secure telegram with an intentionally invalid field.
pub fn inject_secure_invalid(template: &str, params: SecureParams, invalid: InvalidSecurityParam) -> TestStep {
    TestStep::InjectSecureInvalid { template: template.to_string(), sec_params: params, invalid, delay_before_ms: 0 }
}

// ============================================================================
// S-A_Sync helpers
// ============================================================================

/// Inject a P2P sync request with tool key (connectionless).
pub fn inject_sync_req_tool(
    src: &str,
    dst: &str,
    key: &str,
    seq_nr_local: u64,
    challenge: [u8; 6],
) -> TestStep {
    TestStep::InjectSyncReq {
        sync_params: SyncReqParams {
            key_name: key.to_string(),
            tool_access: true,
            system_broadcast: false,
            src_template: src.to_string(),
            dst_template: dst.to_string(),
            npdu_byte: 0x60,
            ctrl_byte: 0x3C,
            seq_nr_local,
            serial_number: [0; 6],
            challenge,
            tpci_high: 0x00,
        },
        delay_before_ms: 0,
    }
}

/// Inject a broadcast sync request with tool key.
pub fn inject_sync_req_broadcast(
    src: &str,
    key: &str,
    seq_nr_local: u64,
    serial: [u8; 6],
    challenge: [u8; 6],
    system_broadcast: bool,
) -> TestStep {
    TestStep::InjectSyncReq {
        sync_params: SyncReqParams {
            key_name: key.to_string(),
            tool_access: true,
            system_broadcast,
            src_template: src.to_string(),
            dst_template: "00 00".to_string(),
            npdu_byte: 0xE0,
            ctrl_byte: 0x3C,
            seq_nr_local,
            serial_number: serial,
            challenge,
            tpci_high: 0x00,
        },
        delay_before_ms: 0,
    }
}

/// Expect a sync response from the DUT with tool key.
pub fn expect_sync_res_tool(
    key: &str,
    challenge: [u8; 6],
    expected_seq_remote: Option<u64>,
    expected_seq_local: Option<u64>,
    timeout_ms: u32,
) -> TestStep {
    TestStep::ExpectSyncRes {
        sync_expect: SyncResExpect {
            key_name: key.to_string(),
            tool_access: true,
            system_broadcast: false,
            expected_seq_remote,
            expected_seq_local,
            challenge,
            expected_src_template: "#BDUT_ADDR".to_string(),
        },
        timeout_ms,
    }
}

/// Inject a sync request with custom SyncReqParams.
pub fn inject_sync_req(params: SyncReqParams) -> TestStep {
    TestStep::InjectSyncReq { sync_params: params, delay_before_ms: 0 }
}

/// Inject a sync request with an intentionally invalid field.
pub fn inject_sync_req_invalid(params: SyncReqParams, invalid: InvalidSecurityParam) -> TestStep {
    TestStep::InjectSyncReqInvalid { sync_params: params, invalid, delay_before_ms: 0 }
}

/// Expect a sync response with custom SyncResExpect.
pub fn expect_sync_res(expect: SyncResExpect, timeout_ms: u32) -> TestStep {
    TestStep::ExpectSyncRes { sync_expect: expect, timeout_ms }
}
