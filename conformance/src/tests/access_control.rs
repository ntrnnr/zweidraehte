//! Access control over the bus, generated from the specification's tables.
//!
//! The device crate's `tests/access_control` checks every property of every
//! preset at the object dispatcher. What it cannot see is everything around
//! the dispatcher, which these cases drive through a real DUT:
//!
//! - **The Secure Application Layer's classification.** A caller here is a
//!   frame — plain, or secured with the Tool Key with authentication only
//!   or with confidentiality — and the S-AL decides who that is.
//! - **Service-level policies** (AN193 §2.2.3): a refused service is not
//!   answered at all (03/04/01 §6.2.2), which only the wire shows.
//! - **The application layer's own answers**: extended property services,
//!   the standard A_PropertyDescription_Read, the Device Descriptor.
//! - **Legacy authorisation**: A_Authorize and A_Key_Write over a
//!   transport connection, and what the granted level then permits.
//!
//! Every expectation is computed from the specification's Access Policy
//! notation (03/04/01 §6.2 Table 3), not written case by case, so each
//! property and service is exercised by every caller with Security Mode
//! off and on.

use std::collections::BTreeMap;

use crate::tests::helpers::*;
use crate::tests::management::create_test_variables;
use crate::tests::security::variables::create_security_variables;
use crate::{TestCase, TestStep, TestSuite, TestVariable};

const TIMEOUT: u32 = 3000;

/// How long a refused service must stay unanswered. A refusal at service
/// level is silence, so the wait is the only evidence.
const SILENCE: u32 = 400;

// ============================================================================
// Callers and the policy notation
// ============================================================================

/// A requester as the Secure Application Layer classifies it: plain
/// (Unlisted), or the Tool with authentication only or with
/// authentication and confidentiality.
#[derive(Clone, Copy, Debug)]
enum Caller {
    Plain,
    ToolAuth,
    ToolAuthConf,
}

const CALLERS: [Caller; 3] = [Caller::Plain, Caller::ToolAuth, Caller::ToolAuthConf];

impl Caller {
    fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::ToolAuth => "Tool A",
            Self::ToolAuthConf => "Tool A+C",
        }
    }

    fn send(self, frame: &str) -> TestStep {
        match self {
            Self::Plain => inject(frame),
            Self::ToolAuth => inject_secure_ao(frame, "TK1"),
            Self::ToolAuthConf => inject_secure_ac(frame, "TK1"),
        }
    }

    /// Expect the DUT's response carrying `apdu`. A secured response is
    /// compared under the control field of the secured frame on the wire:
    /// S-A_Data adds 13 octets (secure APCI, SCF, sequence number, MAC), so
    /// a plaintext APDU of up to three octets still travels in a standard
    /// frame and anything longer in an extended one.
    fn expect(self, apdu: &str) -> TestStep {
        let secured = if apdu.split_whitespace().count() <= 3 {
            frame("#BDUT_ADDR", "#EDI", apdu)
        } else {
            extended("#BDUT_ADDR", "#EDI", apdu)
        };
        match self {
            Self::Plain => expect(&frame("#BDUT_ADDR", "#EDI", apdu), TIMEOUT),
            Self::ToolAuth => expect_secure_ao(&secured, "TK1", TIMEOUT),
            Self::ToolAuthConf => expect_secure_ac(&secured, "TK1", TIMEOUT),
        }
    }

    /// Bit position of this caller's R permission in one half of an Access
    /// Policy: ten bits, most significant first, in the W/R pairs Unlisted,
    /// Role A+C, Role A, Tool A+C, Tool A (03/04/01 §6.2 Table 3).
    fn read_bit(self) -> u32 {
        match self {
            Self::Plain => 8,
            Self::ToolAuthConf => 2,
            Self::ToolAuth => 0,
        }
    }
}

/// Whether the policy `notation` ("3FF/0CC") grants `caller` reading
/// (`write == false`) or writing, with Security Mode `on` or off.
fn permits(notation: &str, caller: Caller, security_mode: bool, write: bool) -> bool {
    let (off, on) = notation.split_once('/').expect("notation is off/on");
    let half = u16::from_str_radix(if security_mode { on } else { off }, 16).expect("hex half");
    half & (1 << (caller.read_bit() + u32::from(write))) != 0
}

/// A frame from `src` to `dst` carrying `apdu` (TPCI octet first). The
/// length field counts tokens, so `apdu` may use one-octet variables only
/// (`#SEC_INTF_OBJ_INDEX`), never a wider one. A plain
/// frame is standard up to 15 length octets and extended beyond; a secured
/// one is wrapped by the engine, which chooses its own format.
fn frame(src: &str, dst: &str, apdu: &str) -> String {
    let length = apdu.split_whitespace().count() - 1;
    if length <= 15 {
        format!("BC {src} {dst} {:02X} {apdu}", 0x60 | length)
    } else {
        format!("3C 60 {src} {dst} {length:02X} {apdu}")
    }
}

/// An extended frame from `src` to `dst` carrying `apdu`.
fn extended(src: &str, dst: &str, apdu: &str) -> String {
    format!("3C 60 {src} {dst} {:02X} {apdu}", apdu.split_whitespace().count() - 1)
}

/// A comment built at generation time.
fn note(text: String) -> TestStep {
    TestStep::Comment(text)
}

fn request(apdu: &str) -> String {
    frame("#EDI", "#BDUT_ADDR", apdu)
}

// Security Mode is switched by the Tool with A+C through the function
// property (03/05/01 §6.3.5), never by the caller under test.
const ENABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";
const DISABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";
const SECURITY_MODE_SET: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

fn set_security_mode(on: bool) -> Vec<TestStep> {
    vec![
        comment(if on { "Security Mode on" } else { "Security Mode off" }),
        inject_secure_ac(if on { ENABLE_SECURITY_MODE } else { DISABLE_SECURITY_MODE }, "TK1"),
        expect_secure_ac(SECURITY_MODE_SET, "TK1", TIMEOUT),
    ]
}

/// One case per Security Mode, each restoring Security Mode off.
fn per_security_mode(name: &str, body: impl Fn(bool) -> Vec<TestStep>) -> Vec<TestCase> {
    [false, true]
        .into_iter()
        .map(|on| {
            let mut steps = set_security_mode(on);
            steps.extend(body(on));
            steps.extend(set_security_mode(false));
            TestCase::new(format!("{name} — Security Mode {}", if on { "on" } else { "off" })).with_steps(steps)
        })
        .collect()
}

// ============================================================================
// Service-level policies
// ============================================================================

/// One connection-oriented request by `caller` on a fresh connection,
/// answered with `response` when the service-level policy admits it. A
/// refused request is acknowledged by the transport layer and then not
/// answered (03/04/01 §6.2.2). Both PDUs are the connection's first, so
/// they carry sequence number 0.
fn connected_service(caller: Caller, apdu: &str, response: &str, admitted: bool) -> Vec<TestStep> {
    let mut steps = vec![
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        caller.send(&request(apdu)),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
    ];
    if admitted {
        steps.push(caller.expect(response));
        steps.push(inject("B0 #EDI #BDUT_ADDR 60 C2"));
    } else {
        steps.push(expect_none(SILENCE));
    }
    steps.push(inject("B0 #EDI #BDUT_ADDR 60 81"));
    steps
}

/// A connection-oriented service with a service-level `policy` (AN193
/// §2.2.3), requested by every caller.
fn service_level(name: &str, policy: &str, apdu: &str, response: &str, security_mode: bool) -> Vec<TestStep> {
    let mut steps = Vec::new();
    for caller in CALLERS {
        let admitted = permits(policy, caller, security_mode, false);
        steps.push(note(format!("{}: {name} {}", caller.label(), if admitted { "answered" } else { "ignored" })));
        steps.extend(connected_service(caller, apdu, response, admitted));
    }
    steps
}

/// A_ADC_Read: `3FF/00C`.
fn adc_read(security_mode: bool) -> Vec<TestStep> {
    service_level("A_ADC_Read channel 1", "3FF/00C", "41 81 01", "41 C1 01 ?? ??", security_mode)
}

/// A_Authorize_Request: `3FF/3FF`, answered for everyone. Secured or
/// plain, the key FFFFFFFFh opens level 0 of a DUT whose keys are all
/// unset.
fn authorize(security_mode: bool) -> Vec<TestStep> {
    service_level("A_Authorize_Request", "3FF/3FF", "43 D1 00 FF FF FF FF", "43 D2 00", security_mode)
}

/// A_Key_Write: `3FF/0CC`. The request rewrites the level-2 key with the
/// value it already has, so an admitted write changes nothing; the caller
/// is at level 0 whether plain (every key is FFFFFFFFh) or secured (the
/// Secure Application Layer grants level 0).
fn key_write(security_mode: bool) -> Vec<TestStep> {
    service_level("A_Key_Write level 2", "3FF/0CC", "43 D3 02 FF FF FF FF", "43 D4 02", security_mode)
}

/// A_DeviceDescriptor_Read: `3FF/0CC` at data level for every descriptor
/// type (AN193 §2.2.4.5). Refused, type 0 answers FFFFh and any other
/// type the 3Fh error, which is also the answer for an unsupported type.
fn device_descriptor(security_mode: bool, mask_version: &str) -> Vec<TestStep> {
    let mut steps = Vec::new();
    for caller in CALLERS {
        let admitted = permits("3FF/0CC", caller, security_mode, false);
        steps.push(note(format!(
            "{}: DD0, DD2, DD3 ({})",
            caller.label(),
            if admitted { "permitted" } else { "refused" }
        )));

        steps.push(caller.send(&request("03 00")));
        steps.push(caller.expect(&format!("03 40 {}", if admitted { mask_version } else { "FF FF" })));

        steps.push(caller.send(&request("03 02")));
        steps.push(caller.expect(if admitted { "03 42 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E" } else { "03 7F" }));

        steps.push(caller.send(&request("03 03")));
        steps.push(caller.expect("03 7F"));
    }
    steps
}

// ============================================================================
// Property services
// ============================================================================

/// A property addressed by object type, the way the extended services
/// reach it on either family.
struct Property {
    name: &'static str,
    object_type: u16,
    pid: u16,
    policy: &'static str,
    /// Octets of one element, for the read's wildcards.
    size: usize,
    /// A value to write back, when writing it changes nothing.
    write: Option<&'static str>,
}

/// One property per distinct Access Policy the stacks declare, on the
/// objects every secure DUT has.
const PROPERTIES: &[Property] = &[
    Property { name: "PID_SERIAL_NUMBER", object_type: 0x0000, pid: 11, policy: "3FF/0CC", size: 6, write: None },
    Property { name: "PID_MAX_APDU_LENGTH", object_type: 0x0000, pid: 56, policy: "3FF/1FF", size: 2, write: None },
    Property { name: "PID_SUBNET_ADDR", object_type: 0x0000, pid: 57, policy: "3FF/00C", size: 1, write: None },
    Property { name: "PID_PROGMODE", object_type: 0x0000, pid: 54, policy: "3FF/0CC", size: 1, write: Some("00") },
    Property { name: "PID_PROGRAM_VERSION", object_type: 0x0003, pid: 13, policy: "3FF/0CC", size: 5, write: None },
    Property {
        name: "PID_LOAD_STATE_CONTROL (Security)",
        object_type: 0x0011,
        pid: 5,
        policy: "15F/04C",
        size: 1,
        write: None,
    },
    Property { name: "PID_SECURITY_REPORT", object_type: 0x0011, pid: 57, policy: "1FF/0CC", size: 1, write: None },
    Property {
        name: "PID_SECURITY_REPORT_CONTROL",
        object_type: 0x0011,
        pid: 58,
        policy: "00C/00C",
        size: 1,
        write: Some("00"),
    },
    Property {
        name: "PID_SEQUENCE_NUMBER_SENDING",
        object_type: 0x0011,
        pid: 59,
        policy: "00C/00C",
        size: 6,
        write: None,
    },
];

/// `OT(2) instance+PID(3)` of an extended property service, instance 1.
fn ext_address(object_type: u16, pid: u16) -> String {
    let instance_pid = (1u32 << 12) | u32::from(pid);
    format!(
        "{:02X} {:02X} {:02X} {:02X} {:02X}",
        object_type >> 8,
        object_type & 0xFF,
        instance_pid >> 16,
        (instance_pid >> 8) & 0xFF,
        instance_pid & 0xFF
    )
}

/// A_PropertyExtValue_Read and _WriteCon of each property by each caller.
/// Refused, the response carries no element and E_ACCESS_DENIED (FCh).
fn property_ext_services(security_mode: bool) -> Vec<TestStep> {
    let mut steps = Vec::new();
    for property in PROPERTIES {
        let address = ext_address(property.object_type, property.pid);
        for caller in CALLERS {
            let readable = permits(property.policy, caller, security_mode, false);
            steps.push(note(format!(
                "{} {}: read {} ({})",
                caller.label(),
                property.name,
                if readable { "permitted" } else { "refused" },
                property.policy
            )));
            steps.push(caller.send(&request(&format!("01 CC {address} 01 00 01"))));
            steps.push(caller.expect(&if readable {
                format!("01 CD {address} 01 00 01{}", " ??".repeat(property.size))
            } else {
                format!("01 CD {address} 00 00 01 FC")
            }));

            if let Some(value) = property.write {
                let writable = permits(property.policy, caller, security_mode, true);
                steps.push(note(format!(
                    "{} {}: write {}",
                    caller.label(),
                    property.name,
                    if writable { "permitted" } else { "refused" }
                )));
                steps.push(caller.send(&request(&format!("01 CE {address} 01 00 01 {value}"))));
                steps.push(
                    caller.expect(&format!("01 CF {address} {}", if writable { "01 00 01 00" } else { "00 00 01 FC" })),
                );
            }
        }
    }
    steps
}

/// The standard A_PropertyDescription_Read of PID_TOOL_KEY (`008/008`,
/// write-only): visible to whoever may write it (AN193 §2.2.4.4,
/// Example 2), otherwise answered with its descriptor fields zeroed
/// (AN193 §2.2.1). Its description is `W, PDT_GENERIC_16, 1 element, 0/2`.
fn tool_key_description(security_mode: bool) -> Vec<TestStep> {
    let mut steps = Vec::new();
    for caller in CALLERS {
        let visible = permits("008/008", caller, security_mode, true);
        steps.push(note(format!(
            "{}: description of PID_TOOL_KEY {}",
            caller.label(),
            if visible { "visible" } else { "hidden" }
        )));
        steps.push(caller.send(&request("03 D8 #SEC_INTF_OBJ_INDEX 38 00")));
        steps.push(caller.expect(if visible {
            "03 D9 #SEC_INTF_OBJ_INDEX 38 ?? A0 00 01 02"
        } else {
            "03 D9 #SEC_INTF_OBJ_INDEX 38 00 00 00 00 00"
        }));
    }
    steps
}

// ============================================================================
// Legacy access levels
// ============================================================================
//
// Plain requests to the plain System B DUT, whose four levels are keyed by
// A_Key_Write and selected by A_Authorize_Request (03/03/07 §3.5.7-3.5.8).
// Two services draw the boundaries the cases probe:
//
// - A no-op write of the Address Table's PID_LOAD_STATE_CONTROL: read
//   level 3, write level 1 (06 Profiles Annex A.2.4 permits 0/1 there).
// - A_Memory_Read of the fixture's level-2 block at 0320h.
//
// Level 0 and 1 get their own keys in the suite preparation; level 2 keeps
// FFFFFFFFh, so an unauthorised connection starts at level 2.

const KEY_0: &str = "A0 A0 A0 A0";
const KEY_1: &str = "A1 A1 A1 A1";
const KEY_2: &str = "A2 A2 A2 A2";
const KEY_DEFAULT: &str = "FF FF FF FF";
const KEY_UNKNOWN: &str = "87 65 43 21";

/// A transport connection from the EDI. Each direction numbers its
/// T_Data_Connected PDUs on its own, so a request the DUT leaves
/// unanswered does not advance the DUT's number.
struct Connection {
    steps: Vec<TestStep>,
    sent: u8,
    received: u8,
}

impl Connection {
    fn open() -> Self {
        Self { steps: vec![inject_delay("B0 #EDI #BDUT 60 80", 200)], sent: 0, received: 0 }
    }

    /// The octets of `apdu` behind a numbered TPCI. Its first token holds
    /// the two APCI bits that share the TPCI octet.
    fn numbered(sequence: u8, apdu: &str) -> String {
        let (apci_bits, rest) = apdu.split_once(' ').expect("APDU has an APCI octet");
        let apci_bits = u8::from_str_radix(apci_bits, 16).expect("hex APCI bits");
        let length = rest.split_whitespace().count();
        format!("6{length:X} {:02X} {rest}", 0x40 | (sequence << 2) | apci_bits)
    }

    /// Send `apdu` and expect `response`, or nothing when it is `None`.
    fn request(&mut self, apdu: &str, response: Option<&str>) {
        self.steps.push(inject(&format!("BC #EDI #BDUT {}", Self::numbered(self.sent, apdu))));
        self.steps.push(expect(&format!("B0 #BDUT #EDI 60 {:02X}", 0xC2 | (self.sent << 2)), TIMEOUT));
        self.sent = (self.sent + 1) & 0x0F;

        match response {
            Some(response) => {
                self.steps.push(expect(&format!("BC #BDUT #EDI {}", Self::numbered(self.received, response)), TIMEOUT));
                self.steps.push(inject_delay(&format!("B0 #EDI #BDUT 60 {:02X}", 0xC2 | (self.received << 2)), 100));
                self.received = (self.received + 1) & 0x0F;
            }
            None => self.steps.push(expect_none(SILENCE)),
        }
    }

    fn note(&mut self, text: &str) {
        self.steps.push(comment(text));
    }

    /// A_Authorize_Request, answered with the level `granted`.
    fn authorize(&mut self, key: &str, granted: u8) {
        self.request(&format!("03 D1 00 {key}"), Some(&format!("03 D2 {granted:02X}")));
    }

    /// A_Key_Write, answered with the level set or FFh.
    fn key_write(&mut self, level: u8, key: &str, result: u8) {
        self.request(&format!("03 D3 {level:02X} {key}"), Some(&format!("03 D4 {result:02X}")));
    }

    /// Read and no-op write of the Address Table's load state (write
    /// level 1). A refused write answers with no element.
    fn load_state(&mut self, writable: bool) {
        self.request("03 D5 01 05 10 01", Some("03 D6 01 05 10 01 ??"));
        self.request(
            "03 D7 01 05 10 01 00 00 00 00 00 00 00 00 00 00",
            Some(if writable { "03 D6 01 05 10 01 ??" } else { "03 D6 01 05 00 01" }),
        );
    }

    /// A_Memory_Read of the level-2 block. A refused read answers with no
    /// octet.
    fn level_2_memory(&mut self, readable: bool) {
        self.request("02 01 03 20", Some(if readable { "02 41 03 20 ??" } else { "02 40 03 20" }));
    }

    /// Both boundaries at once, as they follow from `level`.
    fn probe(&mut self, level: u8) {
        self.load_state(level <= 1);
        self.level_2_memory(level <= 2);
    }

    fn close(mut self) -> Vec<TestStep> {
        self.steps.push(inject_delay("B0 #EDI #BDUT 60 81", 200));
        self.steps
    }
}

/// Key levels 0 and 1; level 2 keeps FFFFFFFFh.
fn legacy_preparation() -> Vec<TestStep> {
    let mut connection = Connection::open();
    connection.note("Every key is FFFFFFFFh: it opens level 0");
    connection.authorize(KEY_DEFAULT, 0);
    connection.key_write(0, KEY_0, 0);
    connection.key_write(1, KEY_1, 1);
    connection.close()
}

/// Every key back to FFFFFFFFh, whatever a failed case left behind.
fn legacy_teardown() -> Vec<TestStep> {
    let mut connection = Connection::open();
    connection.authorize(KEY_0, 0);
    for level in 0..3 {
        connection.key_write(level, KEY_DEFAULT, level);
    }
    connection.close()
}

fn legacy_cases() -> Vec<TestCase> {
    let mut cases = Vec::new();

    // Each key opens its own level, an unknown key the minimum (03/03/07
    // §3.5.7), and the level decides both boundaries.
    let mut steps = Vec::new();
    for (key, level) in [(KEY_0, 0), (KEY_1, 1), (KEY_DEFAULT, 2), (KEY_UNKNOWN, 3)] {
        let mut connection = Connection::open();
        connection.note(&format!("Key {key} opens level {level}"));
        connection.authorize(key, level);
        connection.probe(level);
        steps.extend(connection.close());
    }
    cases.push(TestCase::new("AC-L1 A_Authorize_Request grants the key's level").with_steps(steps));

    // Without A_Authorize_Request, the most privileged level keyed
    // FFFFFFFFh applies (03/03/07 §3.5.7), connectionless requests included.
    let mut connection = Connection::open();
    connection.note("Connection-oriented, unauthorised: level 2");
    connection.probe(2);
    let mut steps = connection.close();
    steps.extend([
        comment("Connectionless: level 2 as well"),
        inject("BC #EDI #BDUT 65 03 D5 01 05 10 01"),
        expect("BC #BDUT #EDI 66 03 D6 01 05 10 01 ??", TIMEOUT),
        inject("BC #EDI #BDUT 6F 03 D7 01 05 10 01 00 00 00 00 00 00 00 00 00 00"),
        expect("BC #BDUT #EDI 65 03 D6 01 05 00 01", TIMEOUT),
    ]);
    cases.push(TestCase::new("AC-L2 Unauthorised access gets the level keyed FFFFFFFFh").with_steps(steps));

    // "A current access level shall be valid until the connection is
    // released or a new key is indicated" (03/03/07 §3.5.7).
    let mut connection = Connection::open();
    connection.authorize(KEY_0, 0);
    connection.probe(0);
    connection.note("A new key replaces the level");
    connection.authorize(KEY_UNKNOWN, 3);
    connection.probe(3);
    connection.authorize(KEY_1, 1);
    connection.probe(1);
    let mut steps = connection.close();
    let mut connection = Connection::open();
    connection.note("A new connection starts unauthorised again");
    connection.probe(2);
    steps.extend(connection.close());
    cases.push(TestCase::new("AC-L3 A level lasts until a new key or the disconnect").with_steps(steps));

    // "The current access level shall be less or equal to the access level
    // indicated", otherwise FFh (03/03/07 §3.5.8). Level 3 is free access
    // and has no key (Figure 88).
    let mut connection = Connection::open();
    connection.authorize(KEY_1, 1);
    connection.note("Level 1 may not key level 0");
    connection.key_write(0, KEY_1, 0xFF);
    connection.note("Level 1 may key its own level and every less privileged one");
    connection.key_write(1, KEY_1, 1);
    connection.key_write(2, KEY_DEFAULT, 2);
    connection.note("Level 3 has no key");
    connection.key_write(3, KEY_1, 0xFF);
    connection.note("The refused write left the level-0 key alone");
    connection.authorize(KEY_0, 0);
    cases.push(TestCase::new("AC-L4 A_Key_Write stops at the caller's level").with_steps(connection.close()));

    // Once no level is keyed FFFFFFFFh, an unauthorised connection has
    // nothing to be granted; it gets the minimum level, as FFFFFFFFh is
    // then an invalid key (03/03/07 §3.5.7).
    let mut connection = Connection::open();
    connection.authorize(KEY_0, 0);
    connection.key_write(2, KEY_2, 2);
    let mut steps = connection.close();
    let mut connection = Connection::open();
    connection.note("No key is FFFFFFFFh: unauthorised access is level 3");
    connection.probe(3);
    connection.authorize(KEY_DEFAULT, 3);
    connection.authorize(KEY_2, 2);
    connection.probe(2);
    connection.note("Unkey level 2 again");
    connection.key_write(2, KEY_DEFAULT, 2);
    steps.extend(connection.close());
    let mut connection = Connection::open();
    connection.note("Unauthorised access is level 2 again");
    connection.probe(2);
    steps.extend(connection.close());
    cases.push(TestCase::new("AC-L5 Without an FFFFFFFFh key, unauthorised is the minimum").with_steps(steps));

    cases
}

// ============================================================================
// Suites
// ============================================================================

/// The cases for one secure DUT; `mask_version` is its DD0 as hex octets.
fn secure_cases(prefix: &str, mask_version: &'static str) -> Vec<TestCase> {
    let mut cases = Vec::new();
    cases.extend(per_security_mode(&format!("{prefix}-1 A_ADC_Read (3FF/00C, service level)"), adc_read));
    cases.extend(per_security_mode(&format!("{prefix}-2 A_DeviceDescriptor_Read (3FF/0CC)"), |on| {
        device_descriptor(on, mask_version)
    }));
    cases.extend(per_security_mode(&format!("{prefix}-3 Extended property services"), property_ext_services));
    cases.extend(per_security_mode(
        &format!("{prefix}-4 PropertyDescription_Read of PID_TOOL_KEY"),
        tool_key_description,
    ));
    cases.extend(per_security_mode(&format!("{prefix}-5 A_Authorize_Request (3FF/3FF, service level)"), authorize));
    cases.extend(per_security_mode(&format!("{prefix}-6 A_Key_Write (3FF/0CC, service level)"), key_write));
    cases
}

/// The generated access-control cases against the System B secure DUT.
pub fn create_access_control_suite() -> TestSuite {
    TestSuite::new("AC Access control (System B secure)", create_security_variables())
        .secure()
        .with_cases(secure_cases("AC", "07 B0"))
}

/// The same cases against the System 7 secure DUT, whose Security
/// Interface Object is at index 5.
pub fn create_system7_access_control_suite() -> TestSuite {
    let mut variables: BTreeMap<String, TestVariable> = create_security_variables();
    variables.insert("SEC_INTF_OBJ_INDEX".into(), TestVariable::Bytes(vec![0x05]));
    TestSuite::new("S7S-AC Access control (System 7 secure)", variables)
        .system7_secure()
        .with_cases(secure_cases("S7S-AC", "07 05"))
}

/// Legacy access levels on the plain System B DUT.
pub fn create_legacy_access_level_suite() -> TestSuite {
    TestSuite::new("AC-L Legacy access levels (System B)", create_test_variables())
        .with_preparation(legacy_preparation())
        .with_cases(legacy_cases())
        .with_teardown(legacy_teardown())
}
