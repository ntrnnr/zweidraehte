//! Persistent-state snapshot for the conformance DUT.
//!
//! Captures exactly what survives a power cycle on real hardware: the
//! EEPROM image and the management state real firmware keeps in hidden
//! EEPROM (load states, table references, authorization keys). RAM —
//! group object values, flags, programming mode — is volatile and
//! deliberately absent, so a respawned DUT boots the way a re-powered
//! device does.

use serde::{Deserialize, Serialize};
use zweidraehte_proto::messages::apdu::load_control::LoadState;

use crate::device::{DeviceIdentity, EEPROM_SIZE, MAX_AUTH_LEVELS, MAX_LSM, Microdevice};
use crate::family::MicroDeviceFamily;
use crate::management::Lsm;

#[derive(Serialize, Deserialize, Clone)]
pub struct MicroSnapshot {
    pub eeprom: Vec<u8>,
    pub auth_keys: Vec<[u8; 4]>,
    pub lsm_states: [u8; MAX_LSM],
    pub table_refs: [u16; MAX_LSM],
    pub device_control: u8,
}

impl MicroSnapshot {
    pub fn capture<F: MicroDeviceFamily>(device: &Microdevice<F>) -> Self {
        Self {
            eeprom: device.eeprom.to_vec(),
            auth_keys: device.mgmt.auth_keys.to_vec(),
            lsm_states: device.mgmt.lsm.map(|l| l.state.into()),
            table_refs: device.mgmt.lsm.map(|l| l.table_ref),
            device_control: device.mgmt.device_control,
        }
    }

    /// Boot a device from this snapshot. A malformed snapshot (wrong
    /// lengths after a format change) falls back to zeroed regions
    /// rather than failing — the DUT would rather run blank than not
    /// at all, and the harness's full-reset path re-seeds it anyway.
    pub fn restore<F: MicroDeviceFamily>(&self, identity: DeviceIdentity, time_divisor: u32) -> Microdevice<F> {
        let mut eeprom = [0u8; EEPROM_SIZE];
        let n = self.eeprom.len().min(EEPROM_SIZE);
        eeprom[..n].copy_from_slice(&self.eeprom[..n]);
        let mut device = Microdevice::new(eeprom, identity, time_divisor);
        for (slot, key) in device.mgmt.auth_keys.iter_mut().zip(self.auth_keys.iter()) {
            *slot = *key;
        }
        for i in 0..MAX_LSM {
            device.mgmt.lsm[i] = Lsm {
                state: LoadState::try_from(self.lsm_states[i]).unwrap_or(LoadState::Unloaded),
                table_ref: self.table_refs[i],
            };
        }
        device.mgmt.device_control = self.device_control;
        device
    }
}

impl core::fmt::Debug for MicroSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MicroSnapshot")
            .field("eeprom_len", &self.eeprom.len())
            .field("lsm_states", &self.lsm_states)
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
fn assert_auth_capacity() {
    // MAX_AUTH_LEVELS keys are captured; a family with more would
    // silently truncate. Compile-time tripwire.
    const _: () = assert!(MAX_AUTH_LEVELS >= 16);
}
