#![feature(adt_const_params)]
#![feature(never_type)]

//! KNX Conformance Testing Framework
//!
//! This module provides a framework for running KNX conformance tests as defined
//! by the KNX Association. Tests target the full stack using MockLinkLayer.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       Test Runner (async)                       │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │   ┌──────────────┐                       ┌──────────────────┐   │
//! │   │ Test Harness │ ←─ inject/capture ──→ │  Full KNX Stack  │   │
//! │   │              │                       │ (MockLinkLayer)  │   │
//! │   └──────────────┘                       └──────────────────┘   │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Test Definition
//!
//! Tests are defined using the `TestCase` and `TestStep` types:
//!
//! ```ignore
//! let tests = vec![
//!     TestCase::new("3.1.1", "Group Read Response")
//!         .with_steps(vec![
//!             TestStep::Comment("Send GroupValue_Read to stack".to_string()),
//!             TestStep::Inject {
//!                 telegram: Telegram::from_bytes(&[0xBC, ...]),
//!                 delay_before_ms: 0,
//!             },
//!             TestStep::Expect {
//!                 matcher: TelegramMatcher::exact(&[0xBC, ...]),
//!                 timeout_ms: 200,
//!             },
//!         ]),
//! ];
//! ```

use std::{borrow::Cow, collections::BTreeMap};

pub mod dut_common;
pub mod eitt;
pub mod engine;
pub mod harness;
pub mod logger;
mod telegram;
pub mod tests;

pub use telegram::{Telegram, TelegramBuilder, TelegramMatcher};

// Re-export address types from the stack for convenience
pub use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

// ============================================================================
// Test Variables
// ============================================================================

/// A variable that can be substituted in telegram data
#[derive(Debug, Clone)]
pub enum TestVariable {
    /// Individual address (e.g., #EDI, #BDUT)
    IndividualAddr(IndividualAddress),
    /// Group address (e.g., #GO_ADDR)
    GroupAddr(GroupAddress),
    /// Raw bytes (e.g., custom data)
    Bytes(Vec<u8>),
}

impl TestVariable {
    /// Get the bytes representation of this variable
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            TestVariable::IndividualAddr(addr) => addr.as_bytes().to_vec(),
            TestVariable::GroupAddr(addr) => addr.as_bytes().to_vec(),
            TestVariable::Bytes(b) => b.clone(),
        }
    }
}

impl From<IndividualAddress> for TestVariable {
    fn from(addr: IndividualAddress) -> Self {
        TestVariable::IndividualAddr(addr)
    }
}

impl From<GroupAddress> for TestVariable {
    fn from(addr: GroupAddress) -> Self {
        TestVariable::GroupAddr(addr)
    }
}

impl From<Vec<u8>> for TestVariable {
    fn from(bytes: Vec<u8>) -> Self {
        TestVariable::Bytes(bytes)
    }
}

// ============================================================================
// Test Step
// ============================================================================

/// A single step in a test sequence
#[derive(Debug, Clone)]
pub enum TestStep {
    /// A comment/documentation for the test
    Comment(String),

    /// Inject a telegram into the stack (via MockLinkLayer) - already resolved
    Inject { telegram: Telegram, delay_before_ms: u32 },

    /// Inject a telegram using a template string with variable placeholders
    /// Format: "BC #EDI #GO_ADDR 81 00 00"
    InjectTemplate { template: String, delay_before_ms: u32 },

    /// Expect a telegram from the stack (captured from MockLinkLayer) - already resolved
    Expect { matcher: TelegramMatcher, timeout_ms: u32 },

    /// Expect a telegram using a template string with variable placeholders and wildcards
    /// Format: "BC #BDUT #GO_ADDR E2 00 40 ??"
    ExpectTemplate { template: String, timeout_ms: u32 },

    /// Expect a set of telegrams (plain and/or secure) within a single
    /// time window, **in any order**. Mirrors the EITT
    /// "block of OUT telegrams" semantics (manual §11.2.3.6):
    /// consecutive OUT telegrams with `TimeToNext = 0` are accepted in
    /// any order during the time interval after the last telegram of
    /// the block.
    ///
    /// Use this *only* for telegram pairs the spec explicitly treats
    /// as unordered — today: GO-diagnostics function-property tests
    /// 6.2.7 / 6.2.11 / 6.2.15, where the management response and the
    /// resulting bus telegram form one block. Ordinary sequencing
    /// should keep using [`Expect`](Self::Expect).
    ///
    /// Already resolved.
    ExpectBlock { matchers: Vec<BlockExpect>, timeout_ms: u32 },

    /// Template form of [`ExpectBlock`](Self::ExpectBlock); resolved at
    /// suite expansion time.
    ExpectBlockTemplate { templates: Vec<BlockExpectTemplate>, timeout_ms: u32 },

    /// Wait for a specific duration (scaled by `KNX_TIME_DIVISOR`).
    Wait { duration_ms: u32 },

    /// Wait for a real wall-clock duration, *not* scaled by
    /// `KNX_TIME_DIVISOR`. Use only when the test depends on a
    /// true elapsed duration (e.g. exercising a device-side timer
    /// whose scale factor doesn't match the runner's). Prefer
    /// `Wait` for everything else.
    WallClockWait { duration_ms: u32 },

    /// Set programming mode on the DUT
    /// When enabled, the device responds to A_IndividualAddress_Read broadcasts
    SetProgrammingMode(bool),

    /// Trigger a GroupValue_Read request for the given ASAP.
    ///
    /// # BCU1/BCU2 Compatibility Note
    ///
    /// In a real BCU1/BCU2, setting the ReadRequest flag on a communication object
    /// would automatically trigger the device to send a GroupValue_Read on the bus.
    /// Our stack does not implement this automatic behavior because:
    ///
    /// 1. Our architecture separates the comm object state from bus operations
    /// 2. Automatic triggering would require background scanning or event-driven
    ///    status monitoring, which adds complexity
    /// 3. Application code can explicitly call read/write methods when needed
    ///
    /// For conformance tests that expect BCU1-style behavior, use this step after
    /// setting the ReadRequest flag via the shadow object (GO1) to explicitly
    /// trigger the read operation.
    TriggerRead { asap: u16 },

    /// Trigger a GroupValue_Write request for the given ASAP.
    ///
    /// # BCU1/BCU2 Compatibility Note
    ///
    /// Similar to TriggerRead, this explicitly triggers a write operation that
    /// a BCU1/BCU2 would perform automatically when the WriteRequest flag is set.
    /// See TriggerRead documentation for why we use explicit triggering.
    TriggerWrite { asap: u16 },

    /// Expect no response within the timeout period.
    ///
    /// This step passes if no message is received within the specified timeout.
    /// Use this when the test expects the device to remain silent (e.g., when
    /// programming mode is off and an IndividualAddress_Read is sent).
    ExpectNone { timeout_ms: u32 },

    /// Wait for `settle_ms` then drain all pending captured messages.
    ///
    /// Use this after operations that produce "side-effect" messages (e.g.,
    /// restart triggers ROI GroupValue_Reads) that are correct behavior but
    /// would interfere with subsequent Expect steps.
    Drain { settle_ms: u32 },

    /// Wait for the DUT child process to exit (restart), then respawn it.
    ///
    /// Unlike the implicit respawn in `send_command()`, this does NOT drain
    /// ROI messages after respawn — they remain in the capture buffer for
    /// subsequent Expect steps. Use this when the test needs to observe
    /// automatic post-restart behavior (e.g., Read-On-Init scans).
    WaitForRestart { timeout_ms: u32 },

    /// Simulate a power cycle: tell the DUT to flush its current persisted
    /// state to the shared-memory region and exit, then respawn it. This
    /// resets volatile state (connections, programming mode, CO statuses)
    /// but preserves persisted state (Security IO properties, sequence
    /// numbers, loaded tables) — as a real device would after a power
    /// interruption.
    PowerCycle { timeout_ms: u32 },

    /// Simulate a master reset: apply the given `A_Restart` `EraseCode`
    /// to the DUT, flush the updated state, and respawn. Uses the same
    /// erase-code encoding as the bus-level `A_Restart` service (0x03 =
    /// FactoryReset, 0x08 = FactoryResetKeepIA, etc.). For the rare
    /// tests that need a factory reset without emitting an `A_Restart`
    /// response on the bus.
    MasterReset { erase_code: u8, timeout_ms: u32 },

    /// Re-initialize the DUT to factory-default state by overwriting
    /// shared memory with the default snapshot and respawning. Used in
    /// teardown steps to undo destructive operations (factory reset,
    /// table wipes) that would pollute subsequent suites.
    FullReset { timeout_ms: u32 },

    /// Custom action placeholder (for complex test scenarios)
    Custom,

    // ================================================================
    // KNX Data Secure steps
    // ================================================================
    /// Inject a secure telegram. The runner wraps the plaintext in a
    /// Secure APDU (SCF + SeqNr + encrypted payload + MAC) before
    /// injecting it into the DUT.
    InjectSecure {
        /// Plaintext telegram template (same format as InjectTemplate).
        template: String,
        /// Security parameters.
        sec_params: SecureParams,
        delay_before_ms: u32,
    },

    /// Expect a secure telegram from the DUT. The runner captures the
    /// raw frame, decrypts it, and matches the plaintext against the
    /// template.
    ExpectSecure {
        /// Expected plaintext telegram template.
        template: String,
        /// Security parameters for decryption.
        sec_params: SecureParams,
        timeout_ms: u32,
    },

    /// Inject a secure telegram with intentionally invalid security
    /// parameters (for negative tests that verify the DUT rejects
    /// malformed secure frames).
    InjectSecureInvalid {
        template: String,
        sec_params: SecureParams,
        /// Which field to corrupt.
        invalid: InvalidSecurityParam,
        delay_before_ms: u32,
    },

    // ================================================================
    // S-A_Sync steps
    // ================================================================
    /// Inject an S-A_Sync_Req frame. The frame is built from scratch
    /// (not wrapping a plaintext template like InjectSecure).
    InjectSyncReq {
        /// Sync request parameters.
        sync_params: SyncReqParams,
        delay_before_ms: u32,
    },

    /// Expect an S-A_Sync_Res frame from the DUT. Verifies the
    /// challenge/random, SeqNr_remote, and SeqNr_local fields.
    ExpectSyncRes {
        /// Expected sync response parameters.
        sync_expect: SyncResExpect,
        timeout_ms: u32,
    },

    /// Inject an S-A_Sync_Req with intentionally invalid fields.
    InjectSyncReqInvalid { sync_params: SyncReqParams, invalid: InvalidSecurityParam, delay_before_ms: u32 },

    /// Inject an S-A_Sync_Res nobody asked for.
    ///
    /// Distinct from [`ExpectSyncReqThenRespond`](Self::ExpectSyncReqThenRespond),
    /// which answers a request the device sent: here there is no
    /// request, and that is the test. Data security 3.4.3 is "correct
    /// S-A_Sync_Res without request before" — the device should ignore
    /// it, because a response it never solicited carries a challenge it
    /// never issued.
    InjectSyncRes { params: SyncResInject, delay_before_ms: u32 },

    /// Reset the runner's security sequence-number bookkeeping.
    ///
    /// The template's `@@[rn`: forget the tool and table counters and
    /// every per-peer one, as EITT does when a case wants to start
    /// counting from scratch. Touches only our side — the device keeps
    /// whatever it has stored, which is the point in 3.8.18.2, where the
    /// mismatch is the test.
    ResetSecuritySequences,

    /// Set one of the runner's security sequence counters.
    ///
    /// The template's `@@[sn"Tool;;;IN;;5000000000"`, used twice in
    /// 3.3.15 to put the counter somewhere a sync has to reconcile.
    SetSecuritySequence { counter: SecuritySeqCounter, value: u64 },

    /// Trigger the DUT to initiate an S-A_Sync_Req to the specified peer.
    ///
    /// The DUT builds and sends the sync request frame. The test runner
    /// should capture it with a subsequent Expect step.
    TriggerSync { peer_ia: u16, tool_access: bool, is_broadcast: bool },

    /// Capture the DUT's outgoing S-A_Sync_Req, verify it, then inject
    /// a valid S-A_Sync_Res back to the DUT.
    ///
    /// This compound step handles the full sync response flow:
    /// 1. Capture the DUT's outgoing sync request
    /// 2. Decrypt the challenge using the specified key
    /// 3. Build a sync response with the given sequence numbers
    /// 4. Inject the response
    ExpectSyncReqThenRespond { params: SyncResponseParams, timeout_ms: u32 },
}

// ============================================================================
// ExpectBlock element types
// ============================================================================

/// One element of an [`ExpectBlock`](TestStep::ExpectBlock) — a
/// telegram pattern the runner must match against one of the
/// frames it captures inside the block window. Either plain
/// (matched directly) or secure (decrypted with `sec_params`
/// before matching).
#[derive(Debug, Clone)]
pub enum BlockExpect {
    Plain { matcher: TelegramMatcher },
    Secure { matcher: TelegramMatcher, sec_params: SecureParams },
}

/// Template form of [`BlockExpect`]. Resolved at suite expansion.
#[derive(Debug, Clone)]
pub enum BlockExpectTemplate {
    Plain { template: String },
    Secure { template: String, sec_params: SecureParams },
}

// ============================================================================
// Security Types for Conformance Tests
// ============================================================================

/// Security parameters for a secure test step.
#[derive(Debug, Clone)]
pub struct SecureParams {
    /// Authentication mode.
    pub sec_type: SecType,
    /// Key name (e.g., "TK1", "GK1").
    pub key_name: String,
    /// Whether this is a tool access message (T flag in SCF).
    pub tool_access: bool,
    /// Sequence number source.
    pub seq_source: SeqSource,
    /// Signed offset applied to whatever [`SecureParams::seq_source`]
    /// produces.
    ///
    /// This is the EITT template's `SeqNumOfs`, and it is how the
    /// sequence-number tests are written: 3.1.9 replays with `-1` and
    /// `-2`, 3.1.10 and 3.1.11 jump forward with `+1` and `+2`. An
    /// offset rather than [`SeqSource::Fixed`] because the counter must
    /// still advance — a fixed value would leave every later telegram in
    /// the case numbered from the wrong place.
    pub seq_offset: i64,
    /// System broadcast flag.
    pub system_broadcast: bool,
}

impl SecureParams {
    /// Create params for tool-access A+C (most common for management).
    pub fn tool_auth_conf(key: &str) -> Self {
        Self {
            sec_type: SecType::AuthConf,
            key_name: key.to_string(),
            tool_access: true,
            seq_source: SeqSource::Tool,
            seq_offset: 0,
            system_broadcast: false,
        }
    }

    /// Create params for tool-access auth-only.
    pub fn tool_auth_only(key: &str) -> Self {
        Self {
            sec_type: SecType::AuthOnly,
            key_name: key.to_string(),
            tool_access: true,
            seq_source: SeqSource::Tool,
            seq_offset: 0,
            system_broadcast: false,
        }
    }

    /// Create params for group-key A+C (no tool access flag).
    pub fn group_auth_conf(key: &str) -> Self {
        Self {
            sec_type: SecType::AuthConf,
            key_name: key.to_string(),
            tool_access: false,
            seq_source: SeqSource::Tool,
            seq_offset: 0,
            system_broadcast: false,
        }
    }

    /// Create params for group-key auth-only (no tool access flag).
    pub fn group_auth_only(key: &str) -> Self {
        Self {
            sec_type: SecType::AuthOnly,
            key_name: key.to_string(),
            tool_access: false,
            seq_source: SeqSource::Tool,
            seq_offset: 0,
            system_broadcast: false,
        }
    }

    /// Create params for P2P non-tool A+C with per-peer sequence tracking.
    pub fn p2p_auth_conf(key: &str) -> Self {
        Self {
            sec_type: SecType::AuthConf,
            key_name: key.to_string(),
            tool_access: false,
            seq_source: SeqSource::Peer(key.to_string()),
            seq_offset: 0,
            system_broadcast: false,
        }
    }

    /// Create params for P2P non-tool auth-only with per-peer sequence tracking.
    pub fn p2p_auth_only(key: &str) -> Self {
        Self {
            sec_type: SecType::AuthOnly,
            key_name: key.to_string(),
            tool_access: false,
            seq_source: SeqSource::Peer(key.to_string()),
            seq_offset: 0,
            system_broadcast: false,
        }
    }
}

/// Parameters for an S-A_Sync_Res we send unprompted.
#[derive(Debug, Clone)]
pub struct SyncResInject {
    /// Key the response is protected with.
    pub key_name: String,
    /// Tool-access flag in the SCF.
    pub tool_access: bool,
    /// System-broadcast flag in the SCF.
    pub system_broadcast: bool,
    /// Source address template — us.
    pub src_template: String,
    /// Destination address template — the device.
    pub dst_template: String,
    /// The device's next sending number, as the response asserts it.
    pub seq_nr_remote: u64,
    /// Our next sending number, as the response asserts it.
    pub seq_nr_local: u64,
    /// Challenge the response answers. Unsolicited, so it answers one
    /// the device never issued, which is the point.
    pub challenge: [u8; 6],
    /// Control field, typically 3Ch for an extended frame.
    pub ctrl_byte: u8,
    /// NPDU octet: address type and hop count.
    pub npdu_byte: u8,
    /// TPCI octet.
    pub tpci_high: u8,
}

/// Which of the runner's security sequence counters a step addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuritySeqCounter {
    /// Our own sending counter — what we put in the telegrams we inject.
    Tool,
    /// What we believe the device will send next.
    Table,
}

/// Security algorithm mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecType {
    /// Authentication only (MAC appended, payload in clear).
    AuthOnly,
    /// Authentication + Confidentiality (payload encrypted + MAC).
    AuthConf,
}

/// Source for sequence number in a secure test step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeqSource {
    /// Use the EITT's (test tool's) sending sequence number.
    Tool,
    /// Use the DUT's expected sequence number.
    Table,
    /// Use a specific fixed sequence number (does not auto-increment).
    Fixed(u64),
    /// Use a per-peer sending sequence number, keyed by the P2P key name.
    Peer(String),
    /// Use the DUT's expected sequence number for a P2P peer.
    PeerTable(String),
    /// A template variable that pins nothing, carried only so the
    /// lowering can tell "unspecified" from "a number I could not
    /// read". Never reaches the engine.
    Unpinned(String),
}

/// Which security field to corrupt for negative tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidSecurityParam {
    /// Override the SCF byte with a specific value after wrapping.
    InvalidScf(u8),
    /// Replace the MAC with specific bytes.
    InvalidMac([u8; 4]),
    /// Corrupt the ciphertext after encryption (XOR first payload byte).
    InvalidCipher,
    /// Replace ciphertext with specific plaintext bytes (send unencrypted
    /// data in an A+C frame — the "plain APDU" attack from 3.1.24).
    PlainCipher(Vec<u8>),
    /// Use the wrong address type (group instead of individual) in CCM context.
    WrongAddressType,
    /// Append extra bytes after the MAC (frame too long).
    AppendBytes(Vec<u8>),
    /// Truncate N bytes from the end of the frame (frame too short).
    TruncateBytes(usize),
    /// Set reserved bits in the SCF on top of the computed value.
    ///
    /// Distinct from [`InvalidScf`](Self::InvalidScf), which replaces the
    /// whole byte: this ORs a bit into an otherwise correct SCF, which is
    /// what data-security 3.1.12 does six times over, once per reserved
    /// bit (01h, 02h, 04h, 08h, 10h, 20h).
    ScfReservedBits(u8),
    /// Rewrite the MAC field from a pattern.
    ///
    /// One entry per octet: `Some(b)` overrides, `None` keeps the byte
    /// the MAC computation produced. A pattern shorter or longer than the
    /// four-octet MAC shortens or lengthens the frame, which is how the
    /// template writes "one byte too short" (3.1.29, `?? ?? ??`) and "one
    /// byte too long" (3.1.28, `?? ?? ?? ?? 00`). A full-width pattern of
    /// all-`Some` is the plain replacement
    /// [`InvalidMac`](Self::InvalidMac) already does; the pattern form
    /// exists for the mixed cases like `FF ?? ?? ??`, where only the
    /// first octet is pinned.
    MacPattern(Vec<Option<u8>>),
}

/// Parameters for injecting an S-A_Sync_Req.
#[derive(Debug, Clone)]
pub struct SyncReqParams {
    /// Key name (e.g., "TK1", "P2PK1").
    pub key_name: String,
    /// Tool access flag (T in SCF).
    pub tool_access: bool,
    /// System broadcast flag (SBC in SCF).
    pub system_broadcast: bool,
    /// Source address template (e.g., "#EDI", "FF FE").
    pub src_template: String,
    /// Destination address template (e.g., "#BDUT_ADDR", "00 00").
    pub dst_template: String,
    /// NPDU byte (addr_type in bit 7 + hop count).
    /// Typically 0x60 for P2P, 0xE0 for broadcast.
    pub npdu_byte: u8,
    /// Control byte (typically 0x3C for extended frame).
    pub ctrl_byte: u8,
    /// SeqNr_local value to include in the request.
    pub seq_nr_local: u64,
    /// KNX Serial Number (6 bytes). Zero for P2P, device serial for broadcast.
    pub serial_number: [u8; 6],
    /// Challenge value (6 bytes).
    pub challenge: [u8; 6],
    /// TPCI high bits (e.g., 0x03 for connectionless, 0x43 for connection-oriented).
    pub tpci_high: u8,
}

/// Expected values for an S-A_Sync_Res from the DUT.
#[derive(Debug, Clone)]
pub struct SyncResExpect {
    /// Key name for decryption.
    pub key_name: String,
    /// Tool access flag expected in response SCF.
    pub tool_access: bool,
    /// System broadcast flag expected in response SCF.
    pub system_broadcast: bool,
    /// Expected SeqNr_remote value (the DUT's Sequence Number Sending).
    /// `None` means accept any value.
    pub expected_seq_remote: Option<u64>,
    /// Expected SeqNr_local value (what the DUT expects from us next).
    /// `None` means accept any value.
    pub expected_seq_local: Option<u64>,
    /// The challenge that was sent in the corresponding request
    /// (needed to recover the random value for decryption).
    pub challenge: [u8; 6],
    /// Expected source address of the response (typically #BDUT_ADDR).
    pub expected_src_template: String,
}

/// Parameters for the `ExpectSyncReqThenRespond` compound step.
#[derive(Debug, Clone)]
pub struct SyncResponseParams {
    /// Key name for decrypting the request and encrypting the response.
    pub key_name: String,
    /// Tool access flag (T in SCF).
    pub tool_access: bool,
    /// SeqNr_remote to include in the sync response (the EITT's
    /// "next sending sequence number" that the DUT should store).
    pub seq_nr_remote: u64,
    /// SeqNr_local to include in the sync response (what we think
    /// the DUT's next sending sequence number should be).
    pub seq_nr_local: u64,
    /// Whether the sync is broadcast (SBC flag).
    pub system_broadcast: bool,
    /// Source address template for the response (typically "#EDI").
    pub src_template: String,
}

impl TestStep {
    /// Resolve any template placeholders using the provided variables
    pub fn resolve(&self, variables: &std::collections::BTreeMap<String, TestVariable>) -> Result<TestStep, String> {
        match self {
            TestStep::InjectTemplate { template, delay_before_ms } => {
                let telegram = Telegram::parse(template, variables)?;
                Ok(TestStep::Inject { telegram, delay_before_ms: *delay_before_ms })
            }
            TestStep::ExpectTemplate { template, timeout_ms } => {
                let matcher = TelegramMatcher::parse(template, variables)?;
                Ok(TestStep::Expect { matcher, timeout_ms: *timeout_ms })
            }
            TestStep::ExpectBlockTemplate { templates, timeout_ms } => {
                let mut matchers = Vec::with_capacity(templates.len());
                for tpl in templates {
                    matchers.push(match tpl {
                        BlockExpectTemplate::Plain { template } => {
                            BlockExpect::Plain { matcher: TelegramMatcher::parse(template, variables)? }
                        }
                        BlockExpectTemplate::Secure { template, sec_params } => BlockExpect::Secure {
                            matcher: TelegramMatcher::parse(template, variables)?,
                            sec_params: sec_params.clone(),
                        },
                    });
                }
                Ok(TestStep::ExpectBlock { matchers, timeout_ms: *timeout_ms })
            }
            // Already resolved or doesn't need resolution
            other => Ok(other.clone()),
        }
    }
}

// ============================================================================
// Test Case
// ============================================================================

/// A single test case containing a sequence of steps
///
/// The name is a [`Cow`] rather than a `&'static str` because cases built
/// from an EITT XML template carry runtime-owned names; the hand-written
/// suites keep passing string literals.
#[derive(Debug, Clone, Default)]
pub struct TestCase {
    pub name: Cow<'static, str>,
    /// Steps run before [`Self::steps`]. Use to provision DUT state this
    /// case depends on (e.g. installing TK1 via an FDSK-encrypted
    /// `PID_TOOL_KEY` write after a factory reset) without baking the
    /// setup into every case's telegram list. A failed preparation
    /// step fails the whole case, but the `teardown` still runs so
    /// the DUT can be left in a known state for the next case.
    pub preparation: Vec<TestStep>,
    pub steps: Vec<TestStep>,
    /// Steps run after [`Self::steps`], regardless of whether the main
    /// steps passed. Use to restore DUT state this case mutated (e.g.
    /// re-install TK1 with the current tool key so the next case can
    /// still authenticate). Teardown failures are logged but do not
    /// affect the case's pass/fail result.
    pub teardown: Vec<TestStep>,
}

impl TestCase {
    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        Self { name: name.into(), preparation: Vec::new(), steps: Vec::new(), teardown: Vec::new() }
    }

    pub fn with_preparation(mut self, preparation: Vec<TestStep>) -> Self {
        self.preparation = preparation;
        self
    }

    pub fn with_steps(mut self, steps: Vec<TestStep>) -> Self {
        self.steps = steps;
        self
    }

    pub fn with_teardown(mut self, teardown: Vec<TestStep>) -> Self {
        self.teardown = teardown;
        self
    }
}

// ============================================================================
// Test Suite
// ============================================================================

/// A collection of related test cases with their variables
#[derive(Debug, Clone)]
pub struct TestSuite {
    pub name: Cow<'static, str>,
    pub variables: BTreeMap<String, TestVariable>,
    /// Optional preparation steps that run once before all test cases in the suite
    pub preparation: Vec<TestStep>,
    pub cases: Vec<TestCase>,
    /// Optional teardown steps that run once after all test cases in the suite
    pub teardown: Vec<TestStep>,
    /// Whether this suite requires the secure DUT (`conformance-dut-secure`).
    pub use_secure_dut: bool,
}

impl TestSuite {
    pub fn new(name: impl Into<Cow<'static, str>>, variables: BTreeMap<String, TestVariable>) -> Self {
        Self {
            name: name.into(),
            variables,
            preparation: Vec::new(),
            cases: Vec::new(),
            teardown: Vec::new(),
            use_secure_dut: false,
        }
    }

    pub fn with_preparation(mut self, preparation: Vec<TestStep>) -> Self {
        self.preparation = preparation;
        self
    }

    pub fn with_cases(mut self, cases: Vec<TestCase>) -> Self {
        self.cases = cases;
        self
    }

    pub fn with_teardown(mut self, teardown: Vec<TestStep>) -> Self {
        self.teardown = teardown;
        self
    }

    pub fn secure(mut self) -> Self {
        self.use_secure_dut = true;
        self
    }
}

// ============================================================================
// Test Collection
// ============================================================================

/// A collection of test suites (top-level grouping)
#[derive(Debug, Clone)]
pub struct TestCollection {
    pub name: &'static str,
    pub suites: Vec<TestSuite>,
}

impl TestCollection {
    pub const fn new(name: &'static str) -> Self {
        Self { name, suites: Vec::new() }
    }

    pub fn with_suites(mut self, suites: Vec<TestSuite>) -> Self {
        self.suites = suites;
        self
    }
}
