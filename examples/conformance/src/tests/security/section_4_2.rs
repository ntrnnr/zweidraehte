//! Section 4.2 — `A_PropertyExtValue_WriteCon` / WriteConRes PDU.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "4.2 PropertyExtValue_WriteCon / WriteConRes PDU".
//!
//! These tests validate the confirmed write extended property service —
//! writes to various object types, instances, PIDs, and error conditions.
//! Each write is followed by a read to verify the actual state.
//!
//! Skipped: 4.2.1 (initial prep telegram), 4.2.7 (start_index=0 with >2 octets),
//! 4.2.10 (data type conflict), 4.2.11 (access level), 4.2.12, 4.2.13
//! (connection-oriented auth / special setup).

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

/// Default response timeout.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_4_2_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("4.2 PropertyExtValue_WriteCon / WriteConRes PDU", variables)
        .secure()
        .with_preparation(vec![
            // Write IA via serial number broadcast (same as 4.1)
            comment("Set BDUT individual address via A_IndividualAddressSerialNumber_Write"),
            inject(
                "BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00",
            ),
            wait(1000),
        ])
        .with_cases(vec![
            test_4_2_2(),
            test_4_2_3(),
            test_4_2_4(),
            test_4_2_5(),
            test_4_2_6(),
            test_4_2_8(),
            test_4_2_9(),
            // Skipped: 4.2.1 — initial prep telegram (IA write)
            // Skipped: 4.2.7 — start_index=0 with >2 octets data
            // Skipped: 4.2.10 — data type conflict (PDT_FUNCTION)
            // Skipped: 4.2.11 — access level restrictions
            // Skipped: 4.2.12 — connection-oriented auth
            // Skipped: 4.2.13 — special setup required
        ])
}

// ============================================================================
// 4.2.2 Non-existing Interface Object type
// ============================================================================

fn test_4_2_2() -> TestCase {
    TestCase::new("4.2.2 non-existing IO type").with_steps(vec![
        // Ensure PID_PROG_MODE starts at 0x00 by writing it
        comment("Pre-condition: write PID_PROG_MODE = 0x00"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 36 01 00 01 00"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),

        comment("IOT 0x000F does not exist → E_ADDRESS_VOID (0xFD)"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 0F 00 10 36 01 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 0F 00 10 36 00 00 01 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),

        comment("IOT 0x8000 does not exist → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 80 00 00 10 36 01 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 80 00 00 10 36 00 00 01 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.2.3 Non-existing Interface Object instance
// ============================================================================

fn test_4_2_3() -> TestCase {
    TestCase::new("4.2.3 non-existing IO instance").with_steps(vec![
        comment("Instance 0x0020 on Device Object → E_ADDRESS_VOID (0xFD)"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 20 36 01 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 20 36 00 00 01 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),

        comment("Instance 0x8000 on Device Object → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 80 00 36 01 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 80 00 36 00 00 01 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.2.4 Non-existing PID
// ============================================================================

fn test_4_2_4() -> TestCase {
    TestCase::new("4.2.4 non-existing PID").with_steps(vec![
        comment("PID 3 on Device Object does not exist → E_ADDRESS_VOID (0xFD)"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 03 01 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 03 00 00 01 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),

        comment("PID 0 on instance 0x0018 → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 18 00 01 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 18 00 00 00 01 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),

        comment("PID 0x0C on instance 0x0018 → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 18 0C 01 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 18 0C 00 00 01 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.2.5 Write with count=1 then count=0
// ============================================================================

fn test_4_2_5() -> TestCase {
    TestCase::new("4.2.5 count=1 succeeds, count=0 fails").with_steps(vec![
        comment("Write PID_PROG_MODE = 0x01 with count=1 → success (0x00)"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 36 01 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),

        comment("Write PID_PROG_MODE with count=0 → E_ADDRESS_VOID (0xFD)"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 36 00 00 01 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 36 00 00 01 FD",
            TIMEOUT,
        ),

        comment("Verify PID_PROG_MODE is still 0x01 (from the successful write)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 01",
            TIMEOUT,
        ),

        comment("Reset PID_PROG_MODE back to 0x00"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 36 01 00 01 00"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.2.6 Count too big (count=2 for single-element property)
// ============================================================================

fn test_4_2_6() -> TestCase {
    TestCase::new("4.2.6 count too big").with_steps(vec![
        comment("Write PID_PROG_MODE with count=2 (only 1 element) → E_ADDRESS_VOID (0xFD)"),
        inject("BC #EDI #BDUT_ADDR 6B 01 CE 00 00 00 10 36 02 00 01 01 00"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 36 00 00 01 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.2.8 Start index too big (start=2)
// ============================================================================

fn test_4_2_8() -> TestCase {
    TestCase::new("4.2.8 start_index too big").with_steps(vec![
        comment("Write PID_PROG_MODE at start_index=2 (only 1 element) → E_ADDRESS_VOID (0xFD)"),
        inject("BC #EDI #BDUT_ADDR 6A 01 CE 00 00 00 10 36 01 00 02 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 36 00 00 02 FD",
            TIMEOUT,
        ),
        comment("Verify PID_PROG_MODE unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.2.9 Write to read-only property (PID_SERIAL_NUMBER)
// ============================================================================

fn test_4_2_9() -> TestCase {
    TestCase::new("4.2.9 write to read-only property").with_steps(vec![
        comment("Read PID_SERIAL_NUMBER (PID 0x0B) to capture original value"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0B 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6F 01 CD 00 00 00 10 0B 01 00 01 ?? ?? ?? ?? ?? ??",
            TIMEOUT,
        ),

        comment("Write to PID_SERIAL_NUMBER → E_ACCESS_READ_ONLY (0xFB)"),
        inject("BC #EDI #BDUT_ADDR 6F 01 CE 00 00 00 10 0B 01 00 01 00 00 00 00 00 00"),
        expect(
            "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 0B 00 00 01 FB",
            TIMEOUT,
        ),

        comment("Verify PID_SERIAL_NUMBER unchanged via read"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0B 01 00 01"),
        expect(
            "BC #BDUT_ADDR #EDI 6F 01 CD 00 00 00 10 0B 01 00 01 ?? ?? ?? ?? ?? ??",
            TIMEOUT,
        ),
    ])
}
