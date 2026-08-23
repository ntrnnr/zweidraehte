//! Family-neutral secure-resource handle for polling micro DUTs.
//!
//! The full-stack fixtures receive the shared-memory sequence store through
//! their storage graph. A polling micro device instead owns this zero-sized
//! adapter. Keeping it outside the BCU2 fixture matters now that the same
//! Data Secure module is composed onto System 7.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use zweidraehte_microdevice::security::MicroSecurityResources;
use zweidraehte_proto::security::{SequenceNumberStorage, SiatAccess};

use super::fixture_common::{sec_table_sizes, secure_seq_store};

/// Handle onto the conformance harness's packed shared-memory store.
///
/// Serializing the handle as a unit keeps high-write sequence state out of
/// the postcard configuration snapshot. The shared-memory tail is persisted
/// and erased independently, like FRAM on the embedded targets.
#[derive(Debug, Clone, Copy, Default)]
pub struct MicroSecureStore;

impl Serialize for MicroSecureStore {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for MicroSecureStore {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <()>::deserialize(deserializer)?;
        Ok(Self)
    }
}

impl SequenceNumberStorage for MicroSecureStore {
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

impl SiatAccess for MicroSecureStore {
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
        if usize::from(idx) >= sec_table_sizes::SIAT {
            return Err(());
        }
        secure_seq_store().borrow_mut().siat_write_entry(idx, ia, seq).map_err(|_| ())
    }

    fn siat_set_count(&mut self, count: u16) -> Result<(), Self::Error> {
        if usize::from(count) > sec_table_sizes::SIAT {
            return Err(());
        }
        secure_seq_store().borrow_mut().siat_set_count(count).map_err(|_| ())
    }

    fn siat_clear(&mut self) -> Result<(), Self::Error> {
        secure_seq_store().borrow_mut().siat_clear().map_err(|_| ())
    }
}

impl MicroSecurityResources for MicroSecureStore {
    fn fill_random(&mut self, random: &mut [u8; 6]) {
        getrandom::fill(random).expect("host entropy available");
    }
}
