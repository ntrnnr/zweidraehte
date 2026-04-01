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

use std::collections::BTreeMap;

pub mod harness;
pub mod logger;
mod telegram;
pub mod tests;

pub use telegram::{Telegram, TelegramBuilder, TelegramMatcher};

// Re-export address types from the stack for convenience
pub use zweidraehte_device::address::{GroupAddress, IndividualAddress};

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

    /// Wait for a specific duration
    Wait { duration_ms: u32 },

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
            system_broadcast: false,
        }
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqSource {
    /// Use the EITT's (test tool's) sending sequence number.
    Tool,
    /// Use the DUT's expected sequence number.
    Table,
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
    /// Use the wrong address type (group instead of individual) in CCM context.
    WrongAddressType,
    /// Append extra bytes after the MAC (frame too long).
    AppendBytes(Vec<u8>),
    /// Truncate N bytes from the end of the frame (frame too short).
    TruncateBytes(usize),
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
            // Already resolved or doesn't need resolution
            other => Ok(other.clone()),
        }
    }
}

// ============================================================================
// Test Case
// ============================================================================

/// A single test case containing a sequence of steps
#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: &'static str,
    pub steps: Vec<TestStep>,
}

impl TestCase {
    pub const fn new(name: &'static str) -> Self {
        Self { name, steps: Vec::new() }
    }

    pub fn with_steps(mut self, steps: Vec<TestStep>) -> Self {
        self.steps = steps;
        self
    }
}

// ============================================================================
// Test Suite
// ============================================================================

/// A collection of related test cases with their variables
#[derive(Debug, Clone)]
pub struct TestSuite {
    pub name: &'static str,
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
    pub fn new(name: &'static str, variables: BTreeMap<String, TestVariable>) -> Self {
        Self {
            name,
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
