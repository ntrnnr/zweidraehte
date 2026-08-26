//! BCU2 DUT smoke suite.
//!
//! Drives the BCU2 (mask 0020h) micro stack's management surface
//! end-to-end through the real engine and the blocking
//! `conformance-dut-bcu2` process:
//!
//! - DD0 answering mask 0020h
//! - the UsrSavPtr byte at 0115h (48h in the ETS mask fixture)
//! - OptionReg inversion at 0100h (factory-erased cell reads FFh)
//! - four-level authorization (factory keys FFFFFFFFh → level 0)
//! - the property-path load state machines (PID_LOAD_STATE_CONTROL
//!   on objects 1–3, 03/05/02 §3.31)
//! - verify mode (PID_DEVICE_CONTROL bit 2 → A_Memory_Response echo)
//! - programming mode via the parity-guarded byte at 0060h
//! - group communication over the RT2 tables at 0116h
//! - A_Restart
//!
//! Frame vocabulary matches the other suites (`#EDI` = tool at
//! 10.15.254, `#BDUT` = 1.0.1). TL style is 1: the device ACKs and
//! answers connection-oriented, control PDUs at system priority.

use std::collections::BTreeMap;

use crate::tests::helpers::{comment, expect, expect_none, inject, inject_delay, trigger_write, wait_for_restart};
use crate::{TestCase, TestSuite, TestVariable};

fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars
}

pub fn create_bcu2_smoke_suite() -> TestSuite {
    let vars = create_test_variables();

    let cases = vec![
        // ====================================================================
        // B2-1: Device Descriptor Type 0 answers the BCU2 mask
        // ====================================================================
        TestCase::new("B2-1 DD0 reads 0020h").with_steps(vec![
            comment("The DUT identifies as BCU2 TP1 (mask 0020h)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 61 43 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 63 43 40 00 20", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("An unsupported descriptor type answers 3Fh, no data"),
            inject("BC #EDI #BDUT 61 47 02"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 61 47 7F", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // B2-2: UsrSavPtr and OptionReg
        // ====================================================================
        TestCase::new("B2-2 UsrSavPtr 0115h and OptionReg 0100h").with_steps(vec![
            comment("Volume 9 names 0115h UsrSavPtr; the ETS mask fixture expects 48h"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 63 42 01 01 15"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 64 42 41 01 15 48", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("OptionReg reads inverted: the factory-erased cell shows FFh"),
            inject("BC #EDI #BDUT 63 46 01 01 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 64 46 41 01 00 FF", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // B2-3: Four-level authorization
        // ====================================================================
        TestCase::new("B2-3 Authorize: factory key grants level 0").with_steps(vec![
            comment("09_04_01 §5.1.2.14: level-0 key is FFFFFFFFh at delivery"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 66 43 D1 00 FF FF FF FF"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("A wrong key falls back to free access (level 3)"),
            inject("BC #EDI #BDUT 66 47 D1 00 DE AD BE EF"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 62 47 D2 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // B2-4: Load state machine over the property path
        // ====================================================================
        TestCase::new("B2-4 LSM cycle via PID_LOAD_STATE_CONTROL").with_steps(vec![
            comment("03/05/02 §3.31: records to PID 5 on object 3, 10 octets"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("StartLoading (01h): readback answers Loading (02h)"),
            inject("BC #EDI #BDUT 6F 43 D7 03 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 03 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("AllocAbsDataSeg at 011Eh inside the Loading window"),
            inject("BC #EDI #BDUT 6F 47 D7 03 05 10 01 03 00 01 1E 00 80 FF 03 80 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 03 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("LoadCompleted (02h): Loaded (01h)"),
            inject("BC #EDI #BDUT 6F 4B D7 03 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 03 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("PID_TABLE_REFERENCE reads the allocated address back"),
            inject("BC #EDI #BDUT 65 4F D5 03 07 10 01"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 69 4F D6 03 07 10 01 00 00 01 1E", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // B2-5: Verify mode
        // ====================================================================
        TestCase::new("B2-5 Verify mode echoes memory writes").with_steps(vec![
            comment("PID_DEVICE_CONTROL bit 2 on: every write answers"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("A verified write to user EEPROM echoes the stored bytes"),
            inject("BC #EDI #BDUT 64 46 81 01 D0 42"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 64 46 41 01 D0 42", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Closing the TL connection must clear Verify Mode"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("After reconnecting, the same write draws only the T_ACK"),
            inject("BC #EDI #BDUT 64 42 81 01 D0 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect_none(300),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // B2-6: Programming mode via memory 0060h
        // ====================================================================
        TestCase::new("B2-6 Programming mode via memory 0060h").with_steps(vec![
            comment("Bit 0 = mode, bit 7 = even parity over the octet"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 64 42 81 00 60 81"),
            expect("B0 #BDUT #EDI 60 C2", 500),
            comment("IndividualAddress_Read now answers"),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT 00 00 E1 01 40", 400),
            comment("Bad parity (01h) is dropped: mode stays on"),
            inject("BC #EDI #BDUT 64 46 81 00 60 01"),
            expect("B0 #BDUT #EDI 60 C6", 500),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT 00 00 E1 01 40", 400),
            comment("00h switches it off"),
            inject("BC #EDI #BDUT 64 4A 81 00 60 00"),
            expect("B0 #BDUT #EDI 60 CA", 500),
            inject("BC #EDI 00 00 E1 01 00"),
            expect_none(300),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // B2-7: Group communication over the RT2 tables
        // ====================================================================
        TestCase::new("B2-7 Group communication over RT2 tables").with_steps(vec![
            comment("A group write to 1000h lands in GO0 (1 bit, all flags)"),
            inject("BC #EDI 10 00 E1 00 81"),
            expect_none(200),
            comment("A group read of 1000h answers with the written value"),
            inject("BC #EDI 10 00 E1 00 00"),
            expect("BC #BDUT 10 00 E1 00 41", 400),
            comment("The independent network object answers long-form with its factory value"),
            inject("BC #EDI 08 01 E1 00 00"),
            expect("BC #BDUT 08 01 E2 00 40 00", 400),
            comment("A transmit request on the transport object sends its value on 5/5/5"),
            trigger_write(7),
            expect("BC #BDUT 2D 05 E1 00 80", 400),
        ]),
        // ====================================================================
        // B2-8: Detection of our own Individual Address on the bus
        // ====================================================================
        TestCase::new("B2-8 Own source address latches Device Control").with_steps(vec![
            comment("Volume 6 Profiles 2.3.2: seeing our IA as a source latches bit 1"),
            inject("BC #BDUT 10 00 E1 00 81"),
            expect_none(200),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 65 43 D5 00 0E 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("A management client may clear the latched value by writing zero"),
            inject("BC #EDI #BDUT 66 47 D7 00 0E 10 01 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 00 0E 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // B2-9: A_Restart
        // ====================================================================
        TestCase::new("B2-9 A_Restart is acknowledged and restarts").with_steps(vec![
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 61 43 80"),
            expect("B0 #BDUT #EDI 60 C2", 400),
            wait_for_restart(3000),
        ]),
    ];

    TestSuite::new("BCU2 Smoke Tests", vars).with_cases(cases).bcu2()
}
