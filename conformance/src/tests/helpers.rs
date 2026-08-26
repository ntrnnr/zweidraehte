//! Shared helper functions for conformance test step definitions
//!
//! These helpers provide a concise DSL for defining test steps in EITT-style tests.

use crate::{
    BlockExpectTemplate, InvalidSecurityParam, SecureParams, SeqSource, SyncReqParams, SyncResExpect,
    SyncResponseLocalSequence, TestStep,
};

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

/// Build an `ExpectBlockTemplate::Plain` element for use with
/// [`expect_block`].
pub fn block_plain(template: &str) -> BlockExpectTemplate {
    BlockExpectTemplate::Plain { template: template.to_string() }
}

/// Build an `ExpectBlockTemplate::Secure` element with group-key
/// auth-only semantics.
pub fn block_group_ao(template: &str, key: &str) -> BlockExpectTemplate {
    BlockExpectTemplate::Secure { template: template.to_string(), sec_params: SecureParams::group_auth_only(key) }
}

/// Build an `ExpectBlockTemplate::Secure` element with group-key
/// auth+conf semantics.
pub fn block_group_ac(template: &str, key: &str) -> BlockExpectTemplate {
    BlockExpectTemplate::Secure { template: template.to_string(), sec_params: SecureParams::group_auth_conf(key) }
}

/// Expect a set of telegrams in any order within `timeout_ms`.
///
/// EITT manual §11.2.3.6: consecutive `OUT` telegrams with
/// `TimeToNext = 0` form a block accepted in any order during the
/// time interval after the last telegram of the block. Use this for
/// the rare spec tests where the order of two outbound telegrams is
/// not constrained — today only GO-diagnostics tests 6.2.7 / 6.2.11
/// / 6.2.15. Ordinary sequencing should keep using [`expect`].
pub fn expect_block(elements: Vec<BlockExpectTemplate>, timeout_ms: u32) -> TestStep {
    TestStep::ExpectBlockTemplate { templates: elements, timeout_ms }
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

/// Helper to trigger an S-A_Sync_Req from the DUT to the specified peer.
pub fn trigger_sync(peer_ia: u16, tool_access: bool) -> TestStep {
    TestStep::TriggerSync { peer_ia, tool_access, is_broadcast: false }
}

/// Like [`trigger_sync`] but the DUT sends a broadcast sync request
/// (system broadcast flag set, dst = 0x0000).
pub fn trigger_sync_broadcast(peer_ia: u16, tool_access: bool) -> TestStep {
    TestStep::TriggerSync { peer_ia, tool_access, is_broadcast: true }
}

/// Helper to expect a DUT-initiated sync request and respond with a sync response.
pub fn expect_sync_req_then_respond(
    key: &str,
    tool_access: bool,
    seq_nr_remote: u64,
    seq_nr_local: u64,
    src_template: &str,
    timeout_ms: u32,
) -> TestStep {
    TestStep::ExpectSyncReqThenRespond {
        params: crate::SyncResponseParams {
            key_name: key.to_string(),
            tool_access,
            seq_nr_remote,
            seq_nr_local: SyncResponseLocalSequence::Fixed(seq_nr_local),
            system_broadcast: false,
            src_template: src_template.to_string(),
        },
        timeout_ms,
    }
}

/// Respond to a captured sync request with its advertised local sequence.
///
/// This is the exact "identical" case: the response value follows the DUT's
/// live request instead of relying on a fixture-order-dependent constant.
pub fn expect_sync_req_then_respond_matching_request(
    key: &str,
    tool_access: bool,
    seq_nr_remote: u64,
    src_template: &str,
    timeout_ms: u32,
) -> TestStep {
    TestStep::ExpectSyncReqThenRespond {
        params: crate::SyncResponseParams {
            key_name: key.to_string(),
            tool_access,
            seq_nr_remote,
            seq_nr_local: SyncResponseLocalSequence::Request,
            system_broadcast: false,
            src_template: src_template.to_string(),
        },
        timeout_ms,
    }
}

/// Like [`expect_sync_req_then_respond`] but the response is sent with
/// `system_broadcast = true` (SBC flag set in the response SCF, broadcast
/// dst address 0x0000). Used by test 3.4.5 (mismatch) and 3.4.9 (match).
pub fn expect_sync_req_then_respond_broadcast(
    key: &str,
    tool_access: bool,
    seq_nr_remote: u64,
    seq_nr_local: u64,
    src_template: &str,
    timeout_ms: u32,
) -> TestStep {
    TestStep::ExpectSyncReqThenRespond {
        params: crate::SyncResponseParams {
            key_name: key.to_string(),
            tool_access,
            seq_nr_remote,
            seq_nr_local: SyncResponseLocalSequence::Fixed(seq_nr_local),
            system_broadcast: true,
            src_template: src_template.to_string(),
        },
        timeout_ms,
    }
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

/// Wait for a real wall-clock duration, bypassing `KNX_TIME_DIVISOR`.
///
/// Use only when the test needs a true elapsed duration (e.g. a
/// device-side timer whose scale factor doesn't match the runner's).
/// Prefer `wait()` for everything else.
#[allow(dead_code)]
pub fn wall_clock_wait(duration_ms: u32) -> TestStep {
    TestStep::WallClockWait { duration_ms }
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

/// Simulate a power cycle: flushes persisted DUT state to the shared
/// memory region, exits the DUT child, and respawns it. Volatile state
/// (transport connections, programming mode, CO statuses) is cleared;
/// persisted state (Security IO properties, sequence numbers, tables)
/// survives — matching how a real device behaves across a power
/// interruption.
pub fn power_cycle(timeout_ms: u32) -> TestStep {
    TestStep::PowerCycle { timeout_ms }
}

/// Simulate a master reset: applies the given `A_Restart` erase code to
/// the DUT (e.g. `0x03` = FactoryReset, `0x08` = FactoryResetKeepIA),
/// flushes the updated state, and respawns. Unlike injecting an
/// `A_Restart` telegram, this does not generate an `A_Restart_Response`
/// on the bus — it represents a local reset (power-on while a service
/// button is held, for example).
pub fn master_reset(erase_code: u8, timeout_ms: u32) -> TestStep {
    TestStep::MasterReset { erase_code, timeout_ms }
}

/// Re-initialize the DUT to its factory-default conformance state by
/// overwriting shared memory with the default snapshot and respawning.
///
/// Use in teardown steps when a test case leaves the DUT in a
/// non-recoverable state (e.g. after a factory reset that wipes all
/// tables, keys, and associations).
pub fn full_reset(timeout_ms: u32) -> TestStep {
    TestStep::FullReset { timeout_ms }
}

// ============================================================================
// Tool-key provisioning helpers
// ============================================================================

/// Fixed challenge used by tool-key sync requests issued from the runner.
///
/// Any non-zero value works; pinning it to a constant keeps the wire
/// output deterministic.
const TOOL_KEY_SYNC_CHALLENGE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Build the steps needed to install `TK1` as the BDUT's active tool
/// key via an FDSK-encrypted `PID_TOOL_KEY` write.
///
/// Intended as a per-test `preparation` block: tests that assume the
/// device boots with `tool_key == TK1` but run after a case that left
/// `tool_key == FDSK` (factory reset) can invoke this to bring the
/// DUT back to the TK1 baseline without baking the handshake into
/// every test's step list.
///
/// Sequence (matches the `3.8.13.1` / `3.8.13.8` pattern in the
/// reference `KnxConformanceTestTemplate-DataSecurity.xml`):
///
/// 1. Sync the tool sequence counter using FDSK.
/// 2. Secure `A_PropertyExtValueWriteCon` on `PID_TOOL_KEY` with the
///    TK1 value, authenticated with FDSK.
/// 3. Expect the OK response encrypted with **TK1** (the newly-set
///    key) per TSSJ §3.8.13.1 — the WriteConRes for PID_TOOL_KEY is
///    authenticated and encrypted with the newly-set security tool
///    key, not the key used for the request.
pub fn provision_tk1_via_fdsk() -> Vec<TestStep> {
    // TK1 plaintext write of PID_TOOL_KEY. The sixteen octets are the
    // TK1 blob from `variables.rs`, which carries the value the EITT
    // data-security template's own Security Configuration Table uses.
    const WRITE_TK1_FDSK: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";
    const WRITE_TK1_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 01 00 01 00";
    vec![
        comment("provision TK1: sync tool seq (FDSK-encrypted)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, TOOL_KEY_SYNC_CHALLENGE),
        expect_sync_res_tool("FDSK", TOOL_KEY_SYNC_CHALLENGE, None, None, 3000),
        comment("provision TK1: write PID_TOOL_KEY = TK1 (auth with FDSK, response with TK1)"),
        inject_secure_ac(WRITE_TK1_FDSK, "FDSK"),
        expect_secure_ac(WRITE_TK1_OK, "TK1", 3000),
    ]
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

/// Expect a secure response with custom parameters.
///
/// The counterpart of [`inject_secure`], for callers that build the
/// parameters rather than picking one of the named shapes below — the
/// EITT lowering reads them off the telegram's attributes.
pub fn expect_secure(template: &str, params: SecureParams, timeout_ms: u32) -> TestStep {
    TestStep::ExpectSecure { template: template.to_string(), sec_params: params, timeout_ms }
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

/// Inject a P2P non-tool secure telegram with authentication + confidentiality.
pub fn inject_p2p_ac(template: &str, key: &str) -> TestStep {
    TestStep::InjectSecure {
        template: template.to_string(),
        sec_params: SecureParams::p2p_auth_conf(key),
        delay_before_ms: 0,
    }
}

/// Inject a P2P non-tool secure telegram with authentication only.
pub fn inject_p2p_ao(template: &str, key: &str) -> TestStep {
    TestStep::InjectSecure {
        template: template.to_string(),
        sec_params: SecureParams::p2p_auth_only(key),
        delay_before_ms: 0,
    }
}

/// Expect a P2P non-tool secure response with authentication + confidentiality.
pub fn expect_p2p_ac(template: &str, key: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectSecure { template: template.to_string(), sec_params: SecureParams::p2p_auth_conf(key), timeout_ms }
}

/// Expect a P2P non-tool secure response with authentication only.
pub fn expect_p2p_ao(template: &str, key: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectSecure { template: template.to_string(), sec_params: SecureParams::p2p_auth_only(key), timeout_ms }
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

/// Inject a secure A+C telegram with a specific sequence number (tool
/// access). Used for the XML transcripts that hard-code a 48-bit
/// counter value (e.g. 3.8.15.7's `SeqNum="280375465082876"`).
pub fn inject_secure_ac_seq(template: &str, key: &str, seq: u64) -> TestStep {
    let mut params = SecureParams::tool_auth_conf(key);
    params.seq_source = SeqSource::Fixed(seq);
    TestStep::InjectSecure { template: template.to_string(), sec_params: params, delay_before_ms: 0 }
}

/// Expect a secure A+C response with a specific sequence number.
pub fn expect_secure_ac_seq(template: &str, key: &str, seq: u64, timeout_ms: u32) -> TestStep {
    let mut params = SecureParams::tool_auth_conf(key);
    params.seq_source = SeqSource::Fixed(seq);
    TestStep::ExpectSecure { template: template.to_string(), sec_params: params, timeout_ms }
}

/// Inject a secure telegram with an intentionally invalid field.
pub fn inject_secure_invalid(template: &str, params: SecureParams, invalid: InvalidSecurityParam) -> TestStep {
    TestStep::InjectSecureInvalid { template: template.to_string(), sec_params: params, invalid, delay_before_ms: 0 }
}

// ============================================================================
// S-A_Sync helpers
// ============================================================================

/// Inject a P2P sync request with tool key (connectionless).
pub fn inject_sync_req_tool(src: &str, dst: &str, key: &str, seq_nr_local: u64, challenge: [u8; 6]) -> TestStep {
    TestStep::InjectSyncReq {
        sync_params: SyncReqParams {
            key_name: key.to_string(),
            tool_access: true,
            system_broadcast: false,
            src_template: src.to_string(),
            dst_template: dst.to_string(),
            npdu_byte: 0x60,
            ctrl_byte: 0x3C,
            seq_local: SeqSource::Fixed(seq_nr_local),
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
            seq_local: SeqSource::Fixed(seq_nr_local),
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
