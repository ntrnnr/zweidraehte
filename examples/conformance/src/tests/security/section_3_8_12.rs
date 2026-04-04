//! Section 3.8.12 — `PID_SECURITY_FAILURES_LOG` access policy `1FF/0CC`.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.12 PID_SECURITY_FAILURES_LOG".
//!
//! Tests PID 0x37 (PID_SECURITY_FAILURES_LOG, i.e. PID 55) on the Security
//! Interface Object (IOT=0x0011, instance=0x0010). Access policy is `1FF/0CC`:
//! - Security Mode OFF: read allowed with A, A+C, or plain; write requires A+C.
//! - Security Mode ON: read requires A+C; write requires A+C.
//!
//! This PID is `PDT_FUNCTION` — accessed via FunctionPropertyExtCommand
//! (0x01D4) and FunctionPropertyExtState_Read (0x01D5).
//!
//! Skipped test cases:
//! - 3.8.12.1–6 — power-down, restart, factory reset persistence and overflow
//!   tests. Need complex state management and restart infrastructure.
//! - 3.8.12.7 — complex FunctionPropertyStateRead with sub-indexes and invalid
//!   service IDs. Needs full failures log implementation.
//! - 3.8.12.8 — complex FunctionPropertyCommand with restart sequences.

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
// PropertyExtDescription_Read templates for PID 0x37
// ============================================================================

// Per XML 3.8.12.9: plain A_PropertyExtDescription_Read.
const PLAIN_DESC_READ: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 37 00 00";

// Per XML: all-zero descriptor (sec ON, 1FF denies plain desc when sec ON).
const PLAIN_DESC_READ_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 37 00 00 00 00 00 00 00 00 00 00";

// Per XML: valid descriptor (sec OFF, 1FF allows plain).
// XML response: `3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 37 0? ?? 00 00 00 00 BE 00 01 ??`
const PLAIN_DESC_READ_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_12_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.12 PID_SECURITY_FAILURES_LOG (Security IO, access 1FF/0CC)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_12_9(),
        ])
}

// ============================================================================
// 3.8.12.9 Unsecured PropDescrRead
// ============================================================================
//
// Per XML: sec ON first → plain desc read returns all-zero.
// Then sec OFF → plain desc read returns valid descriptor.

fn test_3_8_12_9() -> TestCase {
    TestCase::new("3.8.12.9 Unsecured PropDescrRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain desc read → all-zero (sec ON, 1FF denies plain)"),
        inject(PLAIN_DESC_READ),
        expect(PLAIN_DESC_READ_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain desc read → valid descriptor (sec OFF, 1FF allows)"),
        inject(PLAIN_DESC_READ),
        expect(PLAIN_DESC_READ_OK, TIMEOUT),
    ])
}
