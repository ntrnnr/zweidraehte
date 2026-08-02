//! System 7 DUT smoke suite.
//!
//! Not a transcription of a certification template — the generic EITT
//! templates run against this DUT through `conformance-eitt` with the
//! `tp1-system7.toml` profile. This suite drives the System 7 family's
//! own management surface end-to-end through the real engine and DUT
//! process:
//!
//! - DD0 answering mask 0705h
//! - the programming-mode byte at 0060h (memory ↔ property, one flag)
//! - OptionReg at 0100h
//! - the memory-mapped load-control window (write 0104h, status B6EAh;
//!   03/05/02 §3.31.2)
//! - the RT8 group address table fixed at 4000h, IA slot included
//! - group communication over the RT8 tables
//! - 16-level authorization
//!
//! Frame vocabulary matches the management suites (`#EDI` = tool at
//! 10.15.254, `#BDUT` = 1.0.1).

use std::collections::BTreeMap;

use crate::tests::helpers::{comment, expect, expect_none, inject, inject_delay};
use crate::{TestCase, TestSuite, TestVariable};

fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars
}

pub fn create_system7_smoke_suite() -> TestSuite {
    let vars = create_test_variables();

    let cases = vec![
        // ====================================================================
        // S7-1: Device Descriptor Type 0 answers the System 7 mask
        // ====================================================================
        TestCase::new("S7-1 DD0 reads 0705h").with_steps(vec![
            comment("The DUT identifies as System 7 TP1 (mask 0705h)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 61 43 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 63 43 40 07 05", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // S7-2: Programming mode via the memory byte at 0060h
        // ====================================================================
        TestCase::new("S7-2 Programming mode via memory 0060h").with_steps(vec![
            comment("Resources §4.26.3: bit 0 = prog_mode, bit 7 = parity"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Write 81h (mode on, parity consistent) to 0060h"),
            inject("BC #EDI #BDUT 64 42 81 00 60 81"),
            expect("B0 #BDUT #EDI 60 C2", 500),
            comment("The property view reflects it: IndividualAddress_Read answers"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT 00 00 E1 01 40", 400),
            comment("Read the byte back through memory"),
            inject("BC #EDI #BDUT 63 46 01 00 60"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            // The response carries the DUT's own send sequence (its first).
            expect("BC #BDUT #EDI 64 42 41 00 60 81", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Bad parity (01h) leaves the mode untouched"),
            inject("BC #EDI #BDUT 64 4A 81 00 60 01"),
            expect("B0 #BDUT #EDI 60 CA", 500),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT 00 00 E1 01 40", 400),
            comment("Write 00h: mode off, no more response"),
            inject("BC #EDI #BDUT 64 4E 81 00 60 00"),
            expect("B0 #BDUT #EDI 60 CE", 500),
            inject("BC #EDI 00 00 E1 01 00"),
            expect_none(300),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // S7-3: OptionReg at 0100h
        // ====================================================================
        TestCase::new("S7-3 OptionReg read/write at 0100h").with_steps(vec![
            comment("Resources §4.25: OptionReg is plain read/write memory"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 64 42 81 01 00 42"),
            expect("B0 #BDUT #EDI 60 C2", 500),
            inject("BC #EDI #BDUT 63 46 01 01 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 64 42 41 01 00 42", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Restore the factory value"),
            inject("BC #EDI #BDUT 64 4A 81 01 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 500),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // S7-4: Memory-mapped load-control window
        // ====================================================================
        TestCase::new("S7-4 Load control via 0104h, status at B6EAh").with_steps(vec![
            comment("03/05/02 §3.31.2: control at 0104h, ADT status at B6EAh"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("ADT is Loaded from the boot image"),
            inject("BC #EDI #BDUT 63 42 01 B6 EA"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 64 42 41 B6 EA 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Responses below advance the DUT's own send sequence.
            comment("Machine 1 (ADT), event StartLoading: control byte 11h"),
            inject("BC #EDI #BDUT 64 46 81 01 04 11"),
            expect("B0 #BDUT #EDI 60 C6", 500),
            inject("BC #EDI #BDUT 63 4A 01 B6 EA"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 64 46 41 B6 EA 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("LoadCompleted (12h) returns it to Loaded; AST untouched"),
            inject("BC #EDI #BDUT 64 4E 81 01 04 12"),
            expect("B0 #BDUT #EDI 60 CE", 500),
            inject("BC #EDI #BDUT 63 52 02 B6 EA"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 65 4A 42 B6 EA 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // S7-5: RT8 address table at 4000h carries the IA
        // ====================================================================
        TestCase::new("S7-5 RT8 table blob at 4000h").with_steps(vec![
            comment("Resources §4.16.9: [len][IA][GAs sorted], fixed at 4000h"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read the first 7 bytes: len=7, IA=1.0.1, GA 1/0/1, first octet of 2/0/0"),
            inject("BC #EDI #BDUT 63 42 07 40 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 6A 42 47 40 00 07 10 01 08 01 10 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // S7-6: Group communication over the RT8 tables
        // ====================================================================
        TestCase::new("S7-6 Group round trip").with_steps(vec![
            comment("GroupValue_Write to GO0 at 2/0/0, then read it back"),
            inject_delay("BC #EDI 10 00 E1 00 81", 100),
            inject("BC #EDI 10 00 E1 00 00"),
            expect("BC #BDUT 10 00 E1 00 41", 400),
            comment("GO6 at 5/5/5 is independent"),
            inject("BC #EDI 2D 05 E1 00 00"),
            expect("BC #BDUT 2D 05 E1 00 40", 400),
        ]),
        // ====================================================================
        // S7-7: 16-level authorization
        // ====================================================================
        TestCase::new("S7-7 Sixteen access levels").with_steps(vec![
            comment("Factory keys are all default: the default key grants level 0"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 66 43 D1 00 FF FF FF FF"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Set a key on level 14 — a slot System B does not have"),
            inject("BC #EDI #BDUT 66 47 D3 0E 0E 0E 0E 0E"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 62 47 D4 0E", 1000),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("An unknown key falls to level 15, the free level"),
            inject("BC #EDI #BDUT 66 4B D1 00 12 34 56 78"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 62 4B D2 0F", 1000),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("The level-14 key authorizes to level 14"),
            inject("BC #EDI #BDUT 66 4F D1 00 0E 0E 0E 0E"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 62 4F D2 0E", 1000),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Restore the default key on level 14 with level-0 access"),
            inject("BC #EDI #BDUT 66 53 D1 00 FF FF FF FF"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 62 53 D2 00", 1000),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            inject("BC #EDI #BDUT 66 57 D3 0E FF FF FF FF"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 62 57 D4 0E", 1000),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    TestSuite::new("S7 System 7 smoke", vars).with_cases(cases).system7()
}
