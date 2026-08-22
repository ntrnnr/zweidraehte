//! Secure BCU2 (mask 0021h) micro-stack fixture.
//!
//! The security tables are deliberately small: this is a conformance and
//! commissioning fixture, not an attempt to mimic the bench product's 64-key
//! and 190-SIAT capacities. Product metadata is derived from these constants,
//! so ETS-style input cannot promise more storage than the firmware owns.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use zweidraehte_microdevice::SecureBcu2;
use zweidraehte_microdevice::security::MicroSecurityResources;
use zweidraehte_microdevice::snapshot::{MicroSnapshot, SecureMicroSnapshot};
use zweidraehte_proto::security::{SecurityConfig, SequenceNumberStorage, SiatAccess};

use super::bcu2_stack;
use super::fixture_common::{SECURE_FDSK, secure_seq_store};

pub const GROUP_KEY_CAPACITY: usize = 8;
pub const SIAT_CAPACITY: usize = 8;
pub const GROUP_OBJECT_CAPACITY: usize = 4;
pub const P2P_KEY_CAPACITY: usize = 0;

/// The micro module's handle onto the conformance harness's packed SHM store.
///
/// The handle is intentionally zero-sized. Sequence numbers are high-write
/// state in the dedicated SHM tail, while postcard snapshots contain only the
/// low-write security configuration. Serializing the handle as a unit keeps
/// that physical separation visible in the fixture.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bcu2SecureStore;

impl Serialize for Bcu2SecureStore {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for Bcu2SecureStore {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <()>::deserialize(deserializer)?;
        Ok(Self)
    }
}

impl SequenceNumberStorage for Bcu2SecureStore {
    type Error = ();

    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
        secure_seq_store().borrow().load_sending_seq().map_err(|_| ())
    }

    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        secure_seq_store().borrow_mut().save_sending_seq(seq).map_err(|_| ())
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        secure_seq_store().borrow().load_receiving_seq(peer_ia).map_err(|_| ())
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        secure_seq_store().borrow_mut().save_receiving_seq(peer_ia, seq).map_err(|_| ())
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        secure_seq_store().borrow().load_tool_receiving_seq().map_err(|_| ())
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        secure_seq_store().borrow_mut().save_tool_receiving_seq(seq).map_err(|_| ())
    }
}

impl SiatAccess for Bcu2SecureStore {
    type Error = ();

    fn siat_count(&self) -> u16 {
        secure_seq_store().borrow().siat_count()
    }

    fn siat_index_of(&self, ia: u16) -> Option<u16> {
        secure_seq_store().borrow().siat_index_of(ia)
    }

    fn siat_read_entry(&self, idx: u16) -> Option<(u16, [u8; 6])> {
        secure_seq_store().borrow().siat_read_entry(idx)
    }

    fn siat_write_entry(&mut self, idx: u16, ia: u16, seq: [u8; 6]) -> Result<(), Self::Error> {
        if usize::from(idx) >= SIAT_CAPACITY {
            return Err(());
        }
        secure_seq_store().borrow_mut().siat_write_entry(idx, ia, seq).map_err(|_| ())
    }

    fn siat_set_count(&mut self, count: u16) -> Result<(), Self::Error> {
        if usize::from(count) > SIAT_CAPACITY {
            return Err(());
        }
        secure_seq_store().borrow_mut().siat_set_count(count).map_err(|_| ())
    }

    fn siat_clear(&mut self) -> Result<(), Self::Error> {
        secure_seq_store().borrow_mut().siat_clear().map_err(|_| ())
    }
}

impl MicroSecurityResources for Bcu2SecureStore {
    fn fill_random(&mut self, random: &mut [u8; 6]) {
        getrandom::fill(random).expect("host entropy available");
    }
}

pub type Device = SecureBcu2<Bcu2SecureStore, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY>;
pub type Snapshot = SecureMicroSnapshot<Bcu2SecureStore, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY>;

/// The secure application uses a distinct identity but the same compact
/// communication-object roster as the plain fixture.
pub fn definition() -> zweidraehte_microdevice::Bcu2DeviceDefinition {
    let mut definition = bcu2_stack::definition();
    definition.device_type = 0x0B21;
    definition
}

pub fn factory_snapshot() -> Snapshot {
    let mut base: MicroSnapshot = bcu2_stack::factory_snapshot();
    base.eeprom = definition().build_eeprom_for_mask(0x0021).to_vec();

    let mut security: SecurityConfig<GROUP_KEY_CAPACITY, P2P_KEY_CAPACITY, GROUP_OBJECT_CAPACITY> =
        SecurityConfig::default();
    security.tool_key = SECURE_FDSK;

    Snapshot { base, security, sequence: Bcu2SecureStore, fdsk: SECURE_FDSK }
}

const _: () = assert!(GROUP_OBJECT_CAPACITY == 4);
const _: () = assert!(SIAT_CAPACITY <= super::fixture_common::sec_table_sizes::SIAT);
