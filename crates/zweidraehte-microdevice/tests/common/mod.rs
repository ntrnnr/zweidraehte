//! The client dialect every flow test speaks: open the transport
//! connection, run numbered exchanges with the T_ACK bookkeeping a
//! well-behaved client does, extract APDUs. Generic over the family so
//! the BCU1, BCU2 and System 7 flows drive their devices identically.

// Each integration test binary compiles its own copy and uses its own
// subset of these helpers; the unused remainder is expected.
#![allow(dead_code)]

use zweidraehte_microdevice::device::{Microdevice, PollInput};
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::frame::{ApciCode, FrameBuf, FrameView, Tpci, data_frame};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::encoding::tp1::{NPCI_HOP_COUNT_6, TP1_STD_CTRL_BASE};

pub const CLIENT: IndividualAddress = IndividualAddress::new(0, 0, 1);
pub const DUT: IndividualAddress = IndividualAddress::new(1, 1, 10);

/// One client→DUT transport control frame (T_Connect, T_ACK, ...).
fn control_frame(tpci: Tpci) -> [u8; 7] {
    let src = CLIENT.0;
    let dst = DUT.0;
    [TP1_STD_CTRL_BASE, src[0], src[1], dst[0], dst[1], NPCI_HOP_COUNT_6, tpci.octet()]
}

/// Drive one frame in and collect the response frames.
pub fn step<F: MicroDeviceFamily>(dev: &mut Microdevice<F>, frame: &[u8], now: u32) -> Vec<FrameBuf> {
    dev.poll(PollInput::Frame(frame), now).frames.into_iter().collect()
}

/// Open the transport connection. Every TL style this crate carries
/// accepts an incoming connect silently.
pub fn connect<F: MicroDeviceFamily>(dev: &mut Microdevice<F>) {
    let replies = step(dev, &control_frame(Tpci::Connect), 0);
    assert!(replies.is_empty(), "an incoming connect is accepted silently");
}

/// Send numbered data, expect T_ACK plus optionally a numbered reply;
/// acknowledge the reply like a well-behaved client. `None` means the
/// device sent only the T_ACK — how a device treats every service it
/// does not decode.
pub fn exchange<F: MicroDeviceFamily>(
    dev: &mut Microdevice<F>,
    seq: u8,
    apci: ApciCode,
    small6: u8,
    payload: &[u8],
    now: u32,
) -> Option<Vec<u8>> {
    let request = data_frame(0x00, CLIENT, DUT.0, false, Tpci::DataConnected(seq), apci, small6, payload);
    let replies = step(dev, &request, now);
    assert!(!replies.is_empty(), "expected at least a T_ACK");
    let ack = FrameView::parse(&replies[0]).expect("parsable ack");
    assert_eq!(ack.tpci(), Some(Tpci::Ack(seq)), "first reply is the T_ACK");

    let response = replies.get(1).map(|r| {
        let view = FrameView::parse(r).expect("parsable response");
        let Some(Tpci::DataConnected(rsp_seq)) = view.tpci() else {
            panic!("data response expected, got {:?}", view.tpci());
        };
        // Client acks the device's numbered response.
        let extra = step(dev, &control_frame(Tpci::Ack(rsp_seq)), now);
        assert!(extra.is_empty(), "T_ACK draws no further frames");
        r.to_vec()
    });
    assert!(replies.len() <= 2, "one request never yields more than ack + response");
    response
}

/// The response's APDU bytes: octet 6 onward.
pub fn apdu(frame: &[u8]) -> &[u8] {
    &frame[6..]
}
