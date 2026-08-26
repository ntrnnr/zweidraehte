//! The family-specific surface of Data Secure composed onto micro System 7.
//!
//! The cryptographic and replay paths are exercised exhaustively by the BCU2
//! flow tests. These cases pin what changes with the base profile: sixteen-
//! level descriptors, the composed object roster, and RT8-backed identity.

use zweidraehte_microdevice::SecureSystem7;
use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice, PollInput};
use zweidraehte_microdevice::families::system7::{System7CoDescriptor, System7DeviceDefinition, System7Family};
use zweidraehte_microdevice::frame::{
    ApciCode, FrameView, SECURE_EXTENDED_FRAME, Tpci, data_frame, normalize, to_wire,
};
use zweidraehte_microdevice::security::{
    DataSecure, DataSecureState, MicroSecurityResources, SecurityModule, System7DataSecureProfile,
};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::encoding::tp1::{NPCI_HOP_COUNT_6, TP1_STD_CTRL_BASE};
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::pid;
use zweidraehte_proto::security::{DEFAULT_SENDING, SequenceNumberStorage, SiatAccess};

const CLIENT: IndividualAddress = IndividualAddress::new(0, 0, 1);
const DUT: IndividualAddress = IndividualAddress::new(1, 1, 10);
const FDSK: [u8; 16] = [0x11; 16];

static COS: &[System7CoDescriptor] = &[System7CoDescriptor { data_ptr: 0x00C6, config: 0x47, value_type: 0 }];
static GAS: &[GroupAddress] = &[GroupAddress::from_three_level(1, 0, 1)];

type Fam = System7Family<0x400, 0x4200, 0x0083, 0x0705, 1, 0>;
type Device = SecureSystem7<RamSeqStore, 4, 1, 0x400, 0x4200, 0x0083, 0x0705, 1, 0>;
type Module = DataSecure<RamSeqStore, 4, 1, System7DataSecureProfile>;

#[derive(Default, Clone)]
struct RamSeqStore {
    sending: Option<[u8; 6]>,
    tool: Option<[u8; 6]>,
    siat: std::vec::Vec<(u16, [u8; 6])>,
}

impl SequenceNumberStorage for RamSeqStore {
    type Error = ();

    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
        Ok(self.sending.unwrap_or(DEFAULT_SENDING))
    }

    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.sending = Some(*seq);
        Ok(())
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        Ok(self.siat.iter().find(|(ia, _)| *ia == peer_ia).map(|(_, seq)| *seq))
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        let Some((_, stored)) = self.siat.iter_mut().find(|(ia, _)| *ia == peer_ia) else { return Err(()) };
        *stored = *seq;
        Ok(())
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        Ok(self.tool)
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.tool = Some(*seq);
        Ok(())
    }
}

impl SiatAccess for RamSeqStore {
    type Error = ();

    fn siat_count(&self) -> u16 {
        self.siat.len() as u16
    }

    fn siat_index_of(&self, ia: u16) -> Option<u16> {
        self.siat.iter().position(|(entry, _)| *entry == ia).map(|index| index as u16 + 1)
    }

    fn siat_read_entry(&self, index: u16) -> Option<(u16, [u8; 6])> {
        self.siat.get(usize::from(index)).copied()
    }

    fn siat_write_entry(&mut self, index: u16, ia: u16, seq: [u8; 6]) -> Result<(), Self::Error> {
        let index = usize::from(index);
        if self.siat.len() <= index {
            self.siat.resize(index + 1, (0, [0; 6]));
        }
        self.siat[index] = (ia, seq);
        Ok(())
    }

    fn siat_set_count(&mut self, count: u16) -> Result<(), Self::Error> {
        self.siat.resize(usize::from(count), (0, [0; 6]));
        Ok(())
    }

    fn siat_clear(&mut self) -> Result<(), Self::Error> {
        self.siat.clear();
        Ok(())
    }
}

impl MicroSecurityResources for RamSeqStore {
    fn fill_random(&mut self, random: &mut [u8; 6]) {
        *random = [0xA5; 6];
    }
}

fn definition() -> System7DeviceDefinition {
    System7DeviceDefinition {
        manufacturer_id: 0x0083,
        device_type: 0x0705,
        version: 1,
        pei_type: 0,
        individual_address: DUT,
        max_group_addresses: 4,
        max_associations: 4,
        ram_flags_ptr: 0x00D0,
        comm_objects: COS,
        group_addresses: GAS,
        associations: &[(1, 0)],
        ast_offset: 0x100,
        app_offset: 0x300,
        app_params: &[],
    }
}

fn device() -> Device {
    let definition = definition();
    let identity = DeviceIdentity {
        serial_number: [0, 0x83, 0x07, 0x05, 0, 1],
        order_info: [0; 10],
        hardware_type: [0, 0x83, 0, 0, 0x07, 0x05],
    };
    let mut device = Microdevice::<Fam, SECURE_EXTENDED_FRAME, Module>::with_security(
        Fam::build_eeprom(&definition),
        identity,
        1,
        DataSecureState::new(FDSK, RamSeqStore::default()),
    );
    for (machine, table_ref) in Fam::factory_table_refs(&definition).into_iter().enumerate().take(3) {
        device.mgmt.lsm[machine].state = LoadState::Loaded;
        device.mgmt.lsm[machine].table_ref = table_ref;
    }
    device
}

fn exchange(device: &mut Device, sequence: u8, apci: ApciCode, payload: &[u8]) -> std::vec::Vec<u8> {
    if sequence == 0 {
        let connect =
            [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Connect.octet()];

        assert!(device.poll(PollInput::Frame(&connect), 0).frames.is_empty());
    }

    let request =
        data_frame::<SECURE_EXTENDED_FRAME>(0, CLIENT, DUT.0, false, Tpci::DataConnected(sequence), apci, 0, payload)
            .expect("test data frame fits its profile");
    let wire = to_wire::<SECURE_EXTENDED_FRAME>(&request).expect("test canonical frame fits its profile");

    let output = device.poll(PollInput::Frame(&wire), 10);

    assert_eq!(output.frames.len(), 2, "T_ACK plus property response");

    let response = normalize::<SECURE_EXTENDED_FRAME>(&output.frames[1]).expect("well-formed response");
    let view = FrameView::parse(&response).expect("parsable response");

    let Tpci::DataConnected(response_sequence) = view.tpci().expect("response TPCI") else {
        panic!("numbered response expected");
    };
    let ack = [
        TP1_STD_CTRL_BASE,
        CLIENT.0[0],
        CLIENT.0[1],
        DUT.0[0],
        DUT.0[1],
        NPCI_HOP_COUNT_6,
        Tpci::Ack(response_sequence).octet(),
    ];
    assert!(device.poll(PollInput::Frame(&ack), 11).frames.is_empty());
    view.payload().to_vec()
}

#[test]
fn system7_security_descriptors_use_sixteen_level_runtime_access() {
    let (_, descriptor) =
        <Module as SecurityModule>::property_descriptor(0, pid::OBJECT_TYPE).expect("Security IO has PID_OBJECT_TYPE");
    assert_eq!(descriptor.read_level, 15);
    assert_eq!(descriptor.write_level, 0);
}

#[test]
fn composition_exposes_security_and_group_object_table_objects() {
    let mut device = device();

    let security = exchange(&mut device, 0, ApciCode::PropertyValueRead, &[5, 1, 0x10, 0x01]);
    assert_eq!(security, &[5, 1, 0x10, 0x01, 0x00, 0x11]);

    let group_table = exchange(&mut device, 1, ApciCode::PropertyValueRead, &[6, 1, 0x10, 0x01]);
    assert_eq!(group_table, &[6, 1, 0x10, 0x01, 0x00, 0x09]);
}

#[test]
fn io_list_reports_the_complete_composed_roster() {
    let mut device = device();
    let response = exchange(&mut device, 0, ApciCode::PropertyValueRead, &[0, 71, 0x70, 0x01]);
    assert_eq!(&response[..4], &[0, 71, 0x70, 0x01]);
    assert_eq!(&response[4..], &[0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0x11, 0, 9]);
}

#[test]
fn data_secure_strengthens_existing_system7_programming_mode() {
    let mut device = device();
    let response = exchange(&mut device, 0, ApciCode::PropertyDescriptionRead, &[0, 54, 0]);
    assert_eq!(response[0], 0);
    assert_eq!(response[1], 54);
    assert_eq!(*response.last().expect("descriptor access octet"), 0x32, "read level 3, write level 2");
}
