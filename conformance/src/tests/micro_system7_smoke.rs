//! Micro-System-7 DUT smoke suite.
//!
//! Drives the System 7 (mask 0705h) micro stack's management surface
//! end-to-end through the real engine and the blocking
//! `conformance-dut-micro-system7` process:
//!
//! - DD0 answering mask 0705h
//! - the plain (non-inverted) OptionReg at 0100h
//! - sixteen-level authorization (factory keys FFFFFFFFh → level 0,
//!   free access at 15, the free level unkeyable)
//! - the property-path load state machines (PID_LOAD_STATE_CONTROL on
//!   objects 1–4) *and* the memory-mapped window at 0104h with the
//!   read-only status bytes at B6EAh
//! - the §4.24 run state machine (Stop → Terminated, never HALTED)
//! - programming mode via the parity-guarded byte at 0060h
//! - group communication over the RT8/M112 tables at 4000h
//! - A_Restart
//!
//! Frame vocabulary matches the other suites (`#EDI` = tool at
//! 10.15.254, `#BDUT` = 1.0.1). TL style is 3, which is
//! indistinguishable from Style 1 for a device that only ever accepts
//! connections.

use crate::tests::helpers::{comment, expect, expect_none, inject, inject_delay, trigger_write, wait_for_restart};
use crate::{TestCase, TestSuite};

use super::system7_contract;

pub fn create_micro_system7_smoke_suite() -> TestSuite {
    let vars = system7_contract::variables();

    let cases = vec![
        // ====================================================================
        // MS7-1: Device Descriptor Type 0 answers the System 7 mask
        // ====================================================================
        system7_contract::descriptor_type_0_case("MS7-1 DD0 reads 0705h"),
        // ====================================================================
        // MS7-1b: The compact profile also defines unsupported DD behavior
        // ====================================================================
        TestCase::new("MS7-1b Unsupported DD type answers 3Fh").with_steps(vec![
            comment("An unsupported descriptor type answers 3Fh, no data"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 61 43 05"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 61 43 7F", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // MS7-2: OptionReg is plain and lives at 0100h
        // ====================================================================
        system7_contract::option_reg_case("MS7-2 OptionReg 0100h reads uninverted"),
        // ====================================================================
        // MS7-3: Sixteen-level authorization
        // ====================================================================
        TestCase::new("MS7-3 Authorize: 16 levels, free level 15 unkeyable").with_steps(vec![
            comment("Factory key FFFFFFFFh grants level 0"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 66 43 D1 00 FF FF FF FF"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("A_Key_Write to the free level answers FFh even at level 0"),
            inject("BC #EDI #BDUT 66 47 D3 0F 01 02 03 04"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 62 47 D4 FF", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("A wrong key falls back to free access (level 15)"),
            inject("BC #EDI #BDUT 66 4B D1 00 DE AD BE EF"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 62 4B D2 0F", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // MS7-4: Load state machine over the property path (App2)
        // ====================================================================
        TestCase::new("MS7-4 LSM cycle via PID_LOAD_STATE_CONTROL on object 4").with_steps(vec![
            comment("The second application program is the empty machine on a factory device"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("StartLoading (01h): readback answers Loading (02h)"),
            inject("BC #EDI #BDUT 6F 43 D7 04 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 04 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("AllocAbsDataSeg at 4300h inside the Loading window"),
            inject("BC #EDI #BDUT 6F 47 D7 04 05 10 01 03 00 43 00 00 40 FF 03 80 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 04 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("LoadCompleted (02h): Loaded (01h)"),
            inject("BC #EDI #BDUT 6F 4B D7 04 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 04 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("PID_TABLE_REFERENCE reads the allocated address back"),
            inject("BC #EDI #BDUT 65 4F D5 04 07 10 01"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 69 4F D6 04 07 10 01 00 00 43 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // MS7-5: The memory-mapped load-control window
        // ====================================================================
        TestCase::new("MS7-5a Load control via 0104h, status via B6EAh").with_steps(vec![
            comment("Unload machine 4 (App2) through the window: [4|4] to 0104h"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 64 42 81 01 04 44"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect_none(300),
            comment("Status bytes: ADT/AST/App Loaded (01h), App2 Unloaded (00h)"),
            inject("BC #EDI #BDUT 63 46 04 B6 EA"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 67 42 44 B6 EA 01 01 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("StartLoading through the window: [4|1]"),
            inject("BC #EDI #BDUT 64 4A 81 01 04 41"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect_none(300),
            inject("BC #EDI #BDUT 63 4E 04 B6 EA"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 67 46 44 B6 EA 01 01 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        TestCase::new("MS7-5b Memory-form allocation record and completion").with_steps(vec![
            comment("AllocAbsDataSeg in the memory spelling carries a segment ID octet"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 6E 42 8B 01 04 43 00 00 43 00 00 40 FF 03 80 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect_none(300),
            comment("LoadCompleted: [4|2]"),
            inject("BC #EDI #BDUT 64 46 81 01 04 42"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect_none(300),
            comment("All four machines Loaded"),
            inject("BC #EDI #BDUT 63 4A 04 B6 EA"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 67 42 44 B6 EA 01 01 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("The window fed the same machine the property path reads"),
            inject("BC #EDI #BDUT 65 4F D5 04 07 10 01"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 69 47 D6 04 07 10 01 00 00 43 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // MS7-6: Programming mode via memory 0060h
        // ====================================================================
        system7_contract::programming_mode_case("MS7-6 Programming mode via memory 0060h"),
        // ====================================================================
        // MS7-7: Run state machine — Stop terminates, never HALTED
        // ====================================================================
        TestCase::new("MS7-7 RUNCONTROL_STOP terminates the application").with_steps(vec![
            comment("A loaded application reads Running (01h)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 65 43 D5 03 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 03 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Stop (02h) → Terminated (03h) per 03/05/01 §4.24.2.3.3, and group reads go dark"),
            inject("BC #EDI #BDUT 66 47 D7 03 06 10 01 02"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 03 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            inject("BC #EDI 10 00 E1 00 00"),
            expect_none(300),
            comment("Restart (01h) revives it"),
            inject("BC #EDI #BDUT 66 4B D7 03 06 10 01 01"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 03 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // MS7-8: Group communication over the RT8/M112 tables
        // ====================================================================
        system7_contract::group_round_trip_case("MS7-8 Group communication over RT8 tables"),
        // ====================================================================
        // MS7-8b: Micro-DUT hooks beyond the bus-observable contract
        // ====================================================================
        TestCase::new("MS7-8b Group object fixture hooks").with_steps(vec![
            comment("GO1 (4 bit) answers short-form with its factory value"),
            inject("BC #EDI 10 01 E1 00 00"),
            expect("BC #BDUT 10 01 E1 00 40", 400),
            comment("A transmit request on GO6 sends its value on 5/5/5"),
            trigger_write(7),
            expect("BC #BDUT 2D 05 E1 00 80", 400),
        ]),
        // ====================================================================
        // MS7-9: A_Restart
        // ====================================================================
        TestCase::new("MS7-9 A_Restart is acknowledged and restarts").with_steps(vec![
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 61 43 80"),
            expect("B0 #BDUT #EDI 60 C2", 400),
            wait_for_restart(3000),
        ]),
    ];

    TestSuite::new("Micro System7 Smoke Tests", vars).with_cases(cases).micro_system7()
}
