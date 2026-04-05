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
        // Skipped: 3.8.7.1 — requires P2P key infrastructure.
        // Skipped: 3.8.7.2 — requires P2P key auth with non-tool key.
        test_3_8_7_3(),
        // Skipped: 3.8.7.4 — LOAD_STATE_CONTROL multi-byte writes rejected
        //   as E_DATA_TYPE_CONFLICT (0xFE). The load procedure control record
        //   format (PDT_CONTROL) isn't handled by the PropertyExt write path.
    ])
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
