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
