//! Behavioral contracts shared by both System 7 device implementations.
//!
//! Keep only genuinely identical behavior here. Runtime-specific capabilities
//! and intentional differences belong in the full or micro smoke suite so this
//! module does not erase the boundary between the two stack designs.

use std::collections::BTreeMap;

use crate::tests::helpers::{comment, expect, expect_none, inject, inject_delay};
use crate::{TestCase, TestVariable};

pub(super) fn variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars
}

pub(super) fn descriptor_type_0_case(name: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![
        comment("The DUT identifies as System 7 TP1 (mask 0705h)"),
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        inject("BC #EDI #BDUT 61 43 00"),
        expect("B0 #BDUT #EDI 60 C2", 0),
        expect("BC #BDUT #EDI 63 43 40 07 05", 400),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ])
}

pub(super) fn programming_mode_case(name: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![
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
    ])
}

pub(super) fn option_reg_case(name: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![
        comment("Resources §4.25: OptionReg is plain read/write memory"),
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        comment("The factory value reads as 00h, without BCU2-style inversion"),
        inject("BC #EDI #BDUT 63 42 01 01 00"),
        expect("B0 #BDUT #EDI 60 C2", 0),
        expect("BC #BDUT #EDI 64 42 41 01 00 00", 400),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        comment("A write reads back as written"),
        inject("BC #EDI #BDUT 64 46 81 01 00 42"),
        expect("B0 #BDUT #EDI 60 C6", 500),
        inject("BC #EDI #BDUT 63 4A 01 01 00"),
        expect("B0 #BDUT #EDI 60 CA", 0),
        expect("BC #BDUT #EDI 64 46 41 01 00 42", 400),
        inject_delay("B0 #EDI #BDUT 60 C6", 200),
        comment("Restore and verify the factory value"),
        inject("BC #EDI #BDUT 64 4E 81 01 00 00"),
        expect("B0 #BDUT #EDI 60 CE", 500),
        inject("BC #EDI #BDUT 63 52 01 01 00"),
        expect("B0 #BDUT #EDI 60 D2", 0),
        expect("BC #BDUT #EDI 64 4A 41 01 00 00", 400),
        inject_delay("B0 #EDI #BDUT 60 CA", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ])
}

pub(super) fn group_round_trip_case(name: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![
        comment("GroupValue_Write to GO0 at 2/0/0, then read it back"),
        inject("BC #EDI 10 00 E1 00 81"),
        expect_none(200),
        inject("BC #EDI 10 00 E1 00 00"),
        expect("BC #BDUT 10 00 E1 00 41", 400),
        comment("GO6 at 5/5/5 is independent"),
        inject("BC #EDI 2D 05 E1 00 00"),
        expect("BC #BDUT 2D 05 E1 00 40", 400),
    ])
}
