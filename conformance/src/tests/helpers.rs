//! Shared helper functions for conformance test step definitions
//!
//! These helpers provide a concise DSL for defining test steps in EITT-style tests.

use crate::TestStep;

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
