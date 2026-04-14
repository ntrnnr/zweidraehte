//! Section 5 -- `A_MemoryExtended_Write` / `A_MemoryExtended_Read` PDUs.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suites
//! "5.1 MemoryExtended_Write / WriteRes PDU" and
//! "5.2 MemoryExtended_Read / ReadRes PDU".
//!
//! These tests validate:
//! - `A_MemoryExtended_Write`    (APCI 0x01FB)
//! - `A_MemoryExtended_WriteResponse` (APCI 0x01FC)
//! - `A_MemoryExtended_Read`     (APCI 0x01FD)
//! - `A_MemoryExtended_ReadResponse`  (APCI 0x01FE)
//!
//! Skipped:
//! - 5.1.2-5.1.5 — require connection-oriented auth or extended frames with
//!   huge payloads.
//! - 5.2.2-5.2.4 — require connection-oriented auth or extended frames with
//!   huge payloads.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

/// Default response timeout.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_5_suite() -> TestSuite {
    let mut variables = create_security_variables();

    // LINEAR_MEMORY_BASE = 0x0200 from the conformance stack.
    // A_MemoryExtended uses a 3-byte address: high byte 0x00, then the
    // 16-bit base as two bytes.
    variables.insert(
        "READWRITE_MEM_START".into(),
        crate::TestVariable::Bytes(vec![0x00, 0x02, 0x00]),
    );

    TestSuite::new("5 MemoryExtended_Write / Read PDUs", variables)
        .secure()
        .with_preparation(vec![
            // Set the DUT individual address.
            comment("Set BDUT individual address via A_IndividualAddressSerialNumber_Write"),
            inject(
                "BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00",
            ),
            wait(1000),
            // Seed 6 bytes so that later read tests have known data.
            comment("Write 6 bytes (01..06) to READWRITE_MEM_START for read tests"),
            inject(
                "BC #EDI #BDUT_ADDR 6B 01 FB 06 #READWRITE_MEM_START 01 02 03 04 05 06",
            ),
            expect(
                "BC #BDUT_ADDR #EDI 65 01 FC 00 #READWRITE_MEM_START",
                TIMEOUT,
            ),
        ])
        .with_cases(vec![
            test_5_1_1(),
            test_5_1_2(),
            test_5_1_3(),
            test_5_1_4(),
            test_5_1_5(),
            test_5_1_6(),
            test_5_1_7(),
            test_5_2_0(),
            test_5_2_1(),
            test_5_2_2(),
            test_5_2_3(),
            test_5_2_4(),
            test_5_2_5(),
            test_5_2_6(),
        ])
}

fn placeholder(name: &'static str, reason: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![comment(reason)])
}

fn test_5_1_3() -> TestCase {
    placeholder(
        "5.1.3 MemoryExtended_Write – not authorized (Conditional)",
        "Placeholder: requires connection-oriented A_Authorize key sequence not yet supported by the harness.",
    )
}

fn test_5_1_4() -> TestCase {
    // Per the reference XML: write 6 bytes to the start of the BDUT's
    // read-only memory region. The DUT must reject with return code
    // 0xFB (E_READ_ONLY); 0xFC (E_ILLEGAL_COMMAND) is also accepted.
    // Our DUT picks 0xFB; the response addr field echoes the request
    // address.
    TestCase::new("5.1.4 MemoryExtended_Write – read only memory").with_steps(vec![
        comment("Write 6 bytes to READONLY_MEM_START → expect E_READ_ONLY (0xFB)"),
        inject(
            "BC #EDI #BDUT_ADDR 6B 01 FB 06 #READONLY_MEM_START 01 02 03 04 05 06",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FC FB #READONLY_MEM_START",
            TIMEOUT,
        ),
    ])
}

fn test_5_1_5() -> TestCase {
    placeholder(
        "5.1.5 MemoryExtended_Write – partly read only memory",
        "Placeholder: requires a partly read-only memory region on the DUT; current DUT exposes no such region.",
    )
}

fn test_5_2_0() -> TestCase {
    placeholder(
        "5.2.0 Test Preparation",
        "Placeholder: documentation-only test-preparation entry (no active telegrams).",
    )
}

fn test_5_2_2() -> TestCase {
    placeholder(
        "5.2.2 MemoryExtended_Read – not authorized (Conditional)",
        "Placeholder: requires connection-oriented A_Authorize key sequence not yet supported by the harness.",
    )
}

fn test_5_2_3() -> TestCase {
    // The reference XML uses a connection-oriented variant (T_Connect +
    // numbered request) and accepts either return code 0xFA (E_WRITE_ONLY)
    // or 0xFC (E_ILLEGAL_COMMAND). Our DUT's AL maps `WriteProtected`
    // to 0xFA on reads so the unconnected version of the request is
    // sufficient — the spec invariant being checked is that the BDUT
    // refuses to read a write-only region with a recognisable error.
    TestCase::new("5.2.3 MemoryExtended_Read – write only memory").with_steps(vec![
        comment("Read 6 bytes from WRITEONLY_MEM_START → expect E_WRITE_ONLY (0xFA)"),
        inject(
            "BC #EDI #BDUT_ADDR 65 01 FD 06 #WRITEONLY_MEM_START",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FE FA #WRITEONLY_MEM_START",
            TIMEOUT,
        ),
    ])
}

fn test_5_2_4() -> TestCase {
    placeholder(
        "5.2.4 MemoryExtended_Read – partly write only memory (if available in BDUT)",
        "Placeholder: requires a partly write-only memory region on the DUT; current DUT exposes no such region.",
    )
}

// ============================================================================
// 5.1.1 Correct A_MemoryExtended_Write
// ============================================================================

fn test_5_1_1() -> TestCase {
    TestCase::new("5.1.1 correct MemoryExtended_Write").with_steps(vec![
        comment("Write 6 bytes to READWRITE_MEM_START"),
        inject(
            "BC #EDI #BDUT_ADDR 6B 01 FB 06 #READWRITE_MEM_START 01 02 03 04 05 06",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FC 00 #READWRITE_MEM_START",
            TIMEOUT,
        ),
        comment("Read back to verify written data"),
        inject(
            "BC #EDI #BDUT_ADDR 65 01 FD 06 #READWRITE_MEM_START",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 6B 01 FE 00 #READWRITE_MEM_START 01 02 03 04 05 06",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 5.1.2 A_MemoryExtended_Write up to MAX_APDU_LENGTH
// ============================================================================
//
// Write 249 bytes (the maximum for a 254-byte APDU: 2 APCI + 1 count +
// 3 address + 249 data = 256, but APDU length field is 254 = count + data).
// Uses an extended frame (3C 60 prefix).

fn test_5_1_2() -> TestCase {
    // 249 bytes: 01 02 03 ... F9
    let data_bytes: String = (1..=0xF9u8)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    let write_template = format!(
        "3C 60 #EDI #BDUT_ADDR FE 01 FB F9 #READWRITE_MEM_START {}",
        data_bytes
    );

    let read_response = format!(
        "3C 60 #BDUT_ADDR #EDI FE 01 FE 00 #READWRITE_MEM_START {}",
        data_bytes
    );

    TestCase::new("5.1.2 MemoryExtended_Write up to MAX_APDU_LENGTH").with_steps(vec![
        comment("Write 249 bytes (01..F9) to READWRITE_MEM_START"),
        inject(&write_template),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FC 00 #READWRITE_MEM_START",
            TIMEOUT,
        ),
        comment("Read back 249 bytes to verify"),
        inject(
            "BC #EDI #BDUT_ADDR 65 01 FD F9 #READWRITE_MEM_START",
        ),
        expect(&read_response, TIMEOUT),
    ])
}

// ============================================================================
// 5.1.6 A_MemoryExtended_Write -- invalid size
// ============================================================================

fn test_5_1_6() -> TestCase {
    TestCase::new("5.1.6 MemoryExtended_Write invalid size").with_steps(vec![
        // Count = 0 with 1 data byte.
        comment("Count=0 with 1 data byte -> error 0xFD"),
        inject(
            "BC #EDI #BDUT_ADDR 66 01 FB 00 #READWRITE_MEM_START 01",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FC FD #READWRITE_MEM_START",
            TIMEOUT,
        ),
        // Count = 5 but 6 data bytes (mismatch).
        comment("Count=5 with 6 data bytes (size mismatch) -> error 0xFE"),
        inject(
            "BC #EDI #BDUT_ADDR 6B 01 FB 05 #READWRITE_MEM_START 01 02 03 04 05 06",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FC FE #READWRITE_MEM_START",
            TIMEOUT,
        ),
        // Count = 7 but 6 data bytes (mismatch).
        comment("Count=7 with 6 data bytes (size mismatch) -> error 0xFE"),
        inject(
            "BC #EDI #BDUT_ADDR 6B 01 FB 07 #READWRITE_MEM_START 01 02 03 04 05 06",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FC FE #READWRITE_MEM_START",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 5.1.7 A_MemoryExtended_Write -- invalid memory address
// ============================================================================

fn test_5_1_7() -> TestCase {
    TestCase::new("5.1.7 MemoryExtended_Write invalid memory address").with_steps(vec![
        comment("Address 0x000000 (not accessible) -> error 0xFD"),
        inject(
            "BC #EDI #BDUT_ADDR 6B 01 FB 06 00 00 00 01 02 03 04 05 06",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FC FD 00 00 00",
            TIMEOUT,
        ),
        comment("Address 0x0FA000 (not accessible) -> error 0xFD"),
        inject(
            "BC #EDI #BDUT_ADDR 6B 01 FB 06 0F A0 00 01 02 03 04 05 06",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FC FD 0F A0 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 5.2.1 Correct A_MemoryExtended_Read
// ============================================================================

fn test_5_2_1() -> TestCase {
    TestCase::new("5.2.1 correct MemoryExtended_Read").with_steps(vec![
        comment("Read 6 bytes from READWRITE_MEM_START (seeded in preparation)"),
        inject(
            "BC #EDI #BDUT_ADDR 65 01 FD 06 #READWRITE_MEM_START",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 6B 01 FE 00 #READWRITE_MEM_START 01 02 03 04 05 06",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 5.2.5 A_MemoryExtended_Read -- invalid size (count=0)
// ============================================================================

fn test_5_2_5() -> TestCase {
    TestCase::new("5.2.5 MemoryExtended_Read invalid size").with_steps(vec![
        comment("Count=0 -> error 0xFD"),
        inject(
            "BC #EDI #BDUT_ADDR 65 01 FD 00 #READWRITE_MEM_START",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FE FD #READWRITE_MEM_START",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 5.2.6 A_MemoryExtended_Read -- invalid memory address
// ============================================================================

fn test_5_2_6() -> TestCase {
    TestCase::new("5.2.6 MemoryExtended_Read invalid memory address").with_steps(vec![
        comment("Address 0x000000 (not accessible) -> error 0xFD"),
        inject(
            "BC #EDI #BDUT_ADDR 65 01 FD 06 00 00 00",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FE FD 00 00 00",
            TIMEOUT,
        ),
        comment("Address 0x0FA000 (not accessible) -> error 0xFD"),
        inject(
            "BC #EDI #BDUT_ADDR 65 01 FD 06 0F A0 00",
        ),
        expect(
            "BC #BDUT_ADDR #EDI 65 01 FE FD 0F A0 00",
            TIMEOUT,
        ),
    ])
}
