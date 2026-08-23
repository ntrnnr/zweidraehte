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

use crate::device::{DeviceIdentity, MAX_AUTH_LEVELS, MAX_LSM, Microdevice};
use crate::family::MicroDeviceFamily;
use crate::management::Lsm;
use crate::security::{DataSecure, DataSecureState, MicroSecurityResources, SecurityModule};

#[derive(Serialize, Deserialize, Clone)]
pub struct MicroSnapshot {
    pub eeprom: Vec<u8>,
    pub auth_keys: Vec<[u8; 4]>,
    pub lsm_states: [u8; MAX_LSM],
    pub table_refs: [u16; MAX_LSM],
    /// Legacy serialized slot retained for snapshot compatibility.
    /// `PID_DEVICE_CONTROL` is volatile and this is always captured as zero.
    pub device_control: u8,
    /// Absent in snapshots taken before the System 7 family existed.
    #[serde(default)]
    pub option_reg: u8,
}

impl MicroSnapshot {
    pub fn capture<F: MicroDeviceFamily>(device: &Microdevice<F>) -> Self {
        Self::capture_common(device)
    }

    fn capture_common<F: MicroDeviceFamily, const N: usize, SEC: SecurityModule>(
        device: &Microdevice<F, N, SEC>,
    ) -> Self {
        Self {
            eeprom: device.eeprom.as_ref().to_vec(),
            auth_keys: device.mgmt.auth_keys.to_vec(),
            lsm_states: device.mgmt.lsm.map(|l| l.state.into()),
            table_refs: device.mgmt.lsm.map(|l| l.table_ref),
            device_control: 0,
            option_reg: device.mgmt.option_reg,
        }
    }

    /// Boot a device from this snapshot. A malformed snapshot (wrong
    /// lengths after a format change) falls back to zeroed regions
    /// rather than failing — the DUT would rather run blank than not
    /// at all, and the harness's full-reset path re-seeds it anyway.
    pub fn restore<F: MicroDeviceFamily>(&self, identity: DeviceIdentity, time_divisor: u32) -> Microdevice<F> {
        self.restore_with_security(identity, time_divisor, ())
    }

    fn restore_with_security<F: MicroDeviceFamily, const N: usize, SEC: SecurityModule>(
        &self,
        identity: DeviceIdentity,
        time_divisor: u32,
        security: SEC::State,
    ) -> Microdevice<F, N, SEC> {
        let mut eeprom = F::blank_eeprom();
        let n = self.eeprom.len().min(eeprom.as_ref().len());
        eeprom.as_mut()[..n].copy_from_slice(&self.eeprom[..n]);
        let mut device = Microdevice::with_security(eeprom, identity, time_divisor, security);
        for (slot, key) in device.mgmt.auth_keys.iter_mut().zip(self.auth_keys.iter()) {
            *slot = *key;
        }
        // `Microdevice::new` saw the factory-default key array. Resolve the
        // disconnected access level again after restoring the persisted keys.
        device.mgmt.reset_connection_auth::<F>();
        for i in 0..MAX_LSM {
            device.mgmt.lsm[i] = Lsm {
                state: LoadState::try_from(self.lsm_states[i]).unwrap_or(LoadState::Unloaded),
                table_ref: self.table_refs[i],
            };
        }
        // PID_DEVICE_CONTROL resets to zero at startup (03/05/01 §4.2.14.4).
        // Ignore the legacy snapshot slot, including values written by older
        // conformance binaries which incorrectly persisted it.
        let _ = self.device_control;
        device.mgmt.option_reg = self.option_reg;
        device
    }
}

/// Power-cycle snapshot for a Data Secure micro profile.
///
/// The low-frequency Security IO configuration and the high-frequency
/// sequence resource remain separate, matching their hardware persistence
/// seams. The derive serialises both for host fixtures; firmware may persist
/// them through different physical backends.
#[derive(Serialize, Deserialize, Clone)]
pub struct SecureMicroSnapshot<S, const GRP: usize, const GO: usize> {
    pub base: MicroSnapshot,
    pub security: zweidraehte_proto::security::SecurityConfig<GRP, 0, GO>,
    pub sequence: S,
    pub fdsk: [u8; 16],
}

impl<S: MicroSecurityResources + Clone + 'static, const GRP: usize, const GO: usize> SecureMicroSnapshot<S, GRP, GO> {
    pub fn capture<F: MicroDeviceFamily, const N: usize>(device: &Microdevice<F, N, DataSecure<S, GRP, GO>>) -> Self {
        Self {
            base: MicroSnapshot::capture_common(device),
            security: device.sec.to_config(),
            sequence: device.sec.seq.clone(),
            fdsk: device.sec.fdsk,
        }
    }

    pub fn restore<F: MicroDeviceFamily, const N: usize>(
        &self,
        identity: DeviceIdentity,
        time_divisor: u32,
    ) -> Microdevice<F, N, DataSecure<S, GRP, GO>> {
        self.base.restore_with_security(
            identity,
            time_divisor,
            DataSecureState::from_config(self.fdsk, self.sequence.clone(), self.security.clone()),
        )
    }
}

impl<S, const GRP: usize, const GO: usize> core::fmt::Debug for SecureMicroSnapshot<S, GRP, GO> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureMicroSnapshot")
            .field("base", &self.base)
            .field("security", &self.security)
            .field("sequence", &"[SEPARATE PERSISTENCE RESOURCE]")
            .field("fdsk", &"[REDACTED]")
            .finish()
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

// MAX_AUTH_LEVELS keys are captured; a family with more would
// silently truncate. Compile-time tripwire.
const _: () = assert!(MAX_AUTH_LEVELS >= 16);
