use super::*;
use crate::families::{bcu1::Bcu1Family, bcu2::Bcu2Family, system7::System7Family};
use crate::frame::SECURE_EXTENDED_FRAME;
use crate::link::tpuart::{TpUart, TpUartEvent};
use zweidraehte_proto::encoding::tp1::calculate_tp1_checksum;

const OWN: [u8; 2] = [0x11, 0x0A];
const OTHER: [u8; 2] = [0x11, 0x0B];
const GROUP: [u8; 2] = [0x08, 0x01];
const OTHER_GROUP: [u8; 2] = [0x08, 0x02];
const WIRE_CAP: usize = SECURE_EXTENDED_FRAME + 1;
type Driver = TpUart<WIRE_CAP, { WIRE_CAP * 2 }>;
type System7 = System7Family<0x400, 0x4200, 0x0083, 0x0705, 1, 0>;

fn device<F: MicroDeviceFamily, const CAP: usize>() -> Microdevice<F, CAP> {
    let mut eeprom = F::blank_eeprom();
    eeprom.as_mut()[F::ADDR_TABLE_OFFSET..F::ADDR_TABLE_OFFSET + 5]
        .copy_from_slice(&[2, OWN[0], OWN[1], GROUP[0], GROUP[1]]);
    Microdevice::new(eeprom, DeviceIdentity { serial_number: [0; 6], order_info: [0; 10], hardware_type: [0; 6] }, 1)
}

fn wire(destination: [u8; 2], group: bool, extended: bool) -> WireBuf<SECURE_EXTENDED_FRAME> {
    let tpci = if group { Tpci::DataGroup } else { Tpci::DataIndividual };
    let mut plain = frame::data_frame::<SECURE_EXTENDED_FRAME>(
        0,
        IndividualAddress([0xAF, 0xFE]),
        destination,
        group,
        tpci,
        ApciCode::GroupValueWrite,
        0,
        &[],
    )
    .expect("short test frame fits");
    if extended {
        frame::force_extended(&mut plain);
    }
    frame::to_wire(&plain).expect("frame fits extended capacity")
}

/// Exercise the actual UART ACK window, not just the policy's return value.
/// Even an unaddressed frame must reach the stack: source-address collision
/// detection is independent of destination filtering.
fn receive<F: MicroDeviceFamily, const CAP: usize>(
    driver: &mut Driver,
    device: &Microdevice<F, CAP>,
    wire: &[u8],
    expected_ack: bool,
) {
    driver.clear_tx();
    let header_len = if Ctrl1Field::new(wire[0]).ft() == FrameType::Extended { 7 } else { 6 };
    for (index, &byte) in wire.iter().enumerate() {
        assert!(matches!(driver.push_byte(byte, 0, |header| device.should_ack(header)), TpUartEvent::None));
        assert_eq!(
            driver.pending_tx(),
            if expected_ack && index + 1 >= header_len { &[0x11][..] } else { &[] },
            "ACK must appear once, at the header boundary"
        );
    }
    let event = driver.push_byte(calculate_tp1_checksum(wire), 0, |header| device.should_ack(header));
    assert!(matches!(event, TpUartEvent::Frame(_)), "destination filtering must not discard captured frames");
}

fn live_policy<F: MicroDeviceFamily, const CAP: usize>() {
    let mut device = device::<F, CAP>();
    let mut driver = Driver::new_sized();
    for extended in [false, true] {
        if extended && !frame::is_extended(CAP) {
            let wire = wire(OWN, false, true);
            assert!(!device.should_ack(wire[..6].try_into().expect("six-byte header")));
            continue;
        }
        for (destination, group, accepted) in [
            (OWN, false, true),
            (OTHER, false, false),
            (GROUP, true, true),
            (OTHER_GROUP, true, false),
            (OWN, true, false),
            (GROUP, false, false),
            ([0, 0], true, true),
            ([0, 0], false, false),
        ] {
            receive(&mut driver, &device, &wire(destination, group, extended), accepted);
        }

        // The same live device and driver see changes through the EEPROM
        // write path used by management. No filter refresh is necessary.
        assert!(device.write_eeprom_bytes(F::ia_eeprom_offset(), &OTHER));
        assert!(device.write_eeprom_bytes(F::ADDR_TABLE_OFFSET + 3, &OTHER_GROUP));
        receive(&mut driver, &device, &wire(OWN, false, extended), false);
        receive(&mut driver, &device, &wire(OTHER, false, extended), true);
        receive(&mut driver, &device, &wire(GROUP, true, extended), false);
        receive(&mut driver, &device, &wire(OTHER_GROUP, true, extended), true);

        for length in [1, 0] {
            assert!(device.write_eeprom_bytes(F::ADDR_TABLE_OFFSET, &[length]));
            receive(&mut driver, &device, &wire(OTHER_GROUP, true, extended), length == 0);
            receive(&mut driver, &device, &wire(GROUP, true, extended), length == 0);
            receive(&mut driver, &device, &wire(OTHER, false, extended), true);
            receive(&mut driver, &device, &wire([0, 0], true, extended), true);
        }

        assert!(device.write_eeprom_bytes(F::ADDR_TABLE_OFFSET, &[2, OWN[0], OWN[1], GROUP[0], GROUP[1]]));
    }
}

#[test]
fn bcu1_ack_uses_the_live_rt1_address_table() {
    live_policy::<Bcu1Family, MAX_FRAME>();
}

#[test]
fn bcu2_ack_uses_the_live_rt2_address_table() {
    live_policy::<Bcu2Family, MAX_FRAME>();
    live_policy::<Bcu2Family, SECURE_EXTENDED_FRAME>();
}

#[test]
fn system7_ack_uses_the_live_rt8_address_table() {
    live_policy::<System7, MAX_FRAME>();
    live_policy::<System7, SECURE_EXTENDED_FRAME>();
}

fn unload_policy<F: MicroDeviceFamily>() {
    let mut device = device::<F, MAX_FRAME>();
    let mut driver = Driver::new_sized();
    receive(&mut driver, &device, &wire(GROUP, true, false), true);

    F::unload_side_effect(0, device.eeprom.as_mut(), &mut device.mgmt);

    receive(&mut driver, &device, &wire(GROUP, true, false), false);
    receive(&mut driver, &device, &wire(OWN, false, false), true);
    receive(&mut driver, &device, &wire([0, 0], true, false), true);
}

#[test]
fn table_unload_stops_group_acks_but_keeps_management_reachable() {
    unload_policy::<Bcu2Family>();
    unload_policy::<System7>();
}
