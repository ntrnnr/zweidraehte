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

use crate::tests::helpers::{comment, expect, expect_none, inject, inject_delay};
use crate::{TestCase, TestSuite};

use super::system7_contract;

pub fn create_system7_smoke_suite() -> TestSuite {
    let vars = system7_contract::variables();

    let cases = vec![
        // ====================================================================
        // S7-1: Device Descriptor Type 0 answers the System 7 mask
        // ====================================================================
        system7_contract::descriptor_type_0_case("S7-1 DD0 reads 0705h"),
        system7_contract::property_roster_case("S7-1a DeviceControl property contract"),
        // ====================================================================
        // S7-2: Programming mode via the memory byte at 0060h
        // ====================================================================
        system7_contract::programming_mode_case("S7-2 Programming mode via memory 0060h"),
        // ====================================================================
        // S7-3: OptionReg at 0100h
        // ====================================================================
        system7_contract::option_reg_case("S7-3 OptionReg read/write at 0100h"),
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
        // S7-5: the RT8 table at 4000h carries the IA
        // ====================================================================
        TestCase::new("S7-5 RT8 table blob at 4000h").with_steps(vec![
            comment("RT8: [len including IA][IA][GAs sorted], fixed at 4000h"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read the first 7 bytes: len=8, IA=1.0.1, GA 1/0/1, first octet of 2/0/0"),
            inject("BC #EDI #BDUT 63 42 07 40 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 6A 42 47 40 00 08 10 01 08 01 10 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // S7-6: Group communication over the RT8 tables
        // ====================================================================
        system7_contract::group_round_trip_case("S7-6 Group round trip"),
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
        // ====================================================================
        // S7-8: Unload preserves the ADT while disabling group communication
        // ====================================================================
        //
        // Unload declares the data invalid without requiring erasure
        // (03/05/01 §4.23.2.3.2). Partial ETS downloads rely on retaining
        // untouched table bytes, including the co-located IA. Load state
        // must gate group reads and writes even though the GAs still exist.
        TestCase::new("S7-8 ADT unload retains bytes and blocks group traffic").with_steps(vec![
            comment("Seed GO0 so the case also works without S7-6 preparation"),
            inject_delay("BC #EDI 10 00 E1 00 81", 100),
            inject("BC #EDI 10 00 E1 00 00"),
            expect("BC #BDUT 10 00 E1 00 41", 750),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Machine 1 (ADT), event Unload: control byte 14h"),
            inject("BC #EDI #BDUT 64 42 81 01 04 14"),
            expect("B0 #BDUT #EDI 60 C2", 500),
            comment("Load state is Unloaded"),
            inject("BC #EDI #BDUT 63 46 01 B6 EA"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 64 42 41 B6 EA 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("The boot table retains its length, IA and first group addresses"),
            inject("BC #EDI #BDUT 63 4A 07 40 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 6A 46 47 40 00 0F 10 01 08 01 10 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("An unloaded ADT accepts neither group writes nor group reads"),
            inject("BC #EDI 10 00 E1 00 80"),
            expect_none(750),
            inject("BC #EDI 10 00 E1 00 00"),
            expect_none(750),
            comment("Complete a partial download without rewriting the retained ADT"),
            inject("BC #EDI #BDUT 64 4E 81 01 04 11"),
            expect("B0 #BDUT #EDI 60 CE", 500),
            inject("BC #EDI #BDUT 64 52 81 01 04 12"),
            expect("B0 #BDUT #EDI 60 D2", 500),
            inject("BC #EDI #BDUT 63 56 01 B6 EA"),
            expect("B0 #BDUT #EDI 60 D6", 500),
            expect("BC #BDUT #EDI 64 4A 41 B6 EA 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Group traffic resumes; the write while unloaded did not change GO0"),
            inject("BC #EDI 10 00 E1 00 00"),
            expect("BC #BDUT 10 00 E1 00 41", 400),
        ]),
    ];

    TestSuite::new("S7 System 7 smoke", vars).with_cases(cases).system7()
}
