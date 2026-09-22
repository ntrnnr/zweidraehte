//! ETS keyring adaptation is optional; bus key storage has no file-format dependency.

use super::{DeviceSecurityMode, SecurityEntry, SecurityStore};
use zweidraehte_ets_files::keyring::Keyring;

impl SecurityStore {
    /// Insert a `Secure` entry for every keyring device that carries a
    /// key, replacing existing entries for the same IA, and take over
    /// every group key.
    ///
    /// For devices with a serial, the keyring's `SequenceNumber` (the
    /// device's last observed sending number at export) seeds the
    /// sequence store as `table_seq = SequenceNumber + 1` — forward-only,
    /// and the sync handshake on connect corrects it either way. The
    /// same value seeds the per-sender group replay floor, which has no
    /// sync to correct it. Devices with neither tool key nor FDSK are
    /// skipped: there is nothing to secure with.
    ///
    /// The keyring interfaces' per-tunnel-slot sender lists are not
    /// consumed.
    ///
    /// Returns how many device entries were added.
    pub fn import_keyring(&mut self, keyring: &Keyring) -> std::io::Result<usize> {
        // TODO: enforce keyring sender lists on incoming group traffic
        // if a use case appears — devices themselves accept any SIAT
        // sender, so this would be stricter than the installed base.
        for (ga, key) in keyring.group_keys() {
            self.set_group_key(ga, *key);
        }
        let mut added = 0;
        for device in &keyring.devices {
            if device.sequence_number > 0 {
                let floor = device.sequence_number + 1;
                if let Some(serial) = device.serial {
                    self.save_device_seq(&serial, floor)?;
                }
                self.save_sender_seq(device.individual_address, floor)?;
            }
            if device.tool_key().is_none() && device.fdsk().is_none() {
                continue;
            }
            self.set_device_security(
                device.individual_address,
                SecurityEntry::with_credentials(
                    DeviceSecurityMode::Secure,
                    device.tool_key().copied(),
                    device.fdsk().copied(),
                    device.serial,
                )
                .expect("key presence checked above"),
            );
            added += 1;
        }
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IndividualAddress;
    use zweidraehte_ets_files::keyring::KeyringDevice;

    const KEY: [u8; 16] = [0x11; 16];
    const FDSK: [u8; 16] = [0x22; 16];
    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01];

    #[test]
    fn import_keyring_fills_entries_and_seeds_seq() {
        let devices = vec![
            // Fully exported: tool key + FDSK + serial + seq.
            KeyringDevice::new(IndividualAddress::new(1, 0, 203))
                .with_tool_key(Some(KEY))
                .with_fdsk(Some(FDSK))
                .with_serial(Some(SERIAL))
                .with_sequence_number(1000),
            // No serial: entry still lands, counters unpersisted.
            KeyringDevice::new(IndividualAddress::new(1, 0, 201)).with_tool_key(Some(KEY)).with_sequence_number(500),
            // No key material at all: skipped.
            KeyringDevice::new(IndividualAddress::new(1, 0, 7)),
        ];
        let mut group_keys = std::collections::BTreeMap::new();
        group_keys.insert(0x0901u16, [0x42u8; 16]);
        group_keys.insert(0x1202u16, [0x43u8; 16]);
        let keyring = Keyring::new("test".into(), "6.4.1".into(), "2026-08-05T00:00:00".into())
            .with_group_keys(group_keys)
            .with_devices(devices);

        let mut store = SecurityStore::new();
        assert_eq!(store.import_keyring(&keyring).expect("keyring imports"), 2, "keyless device is skipped");

        assert_eq!(store.get_group_key(0x0901), Some(&[0x42u8; 16]));
        assert_eq!(store.get_group_key(0x1202), Some(&[0x43u8; 16]));
        assert_eq!(store.get_group_key(0x1B03), None);

        // Sender replay floors seeded from the exported sequence
        // numbers — keyed by IA, independent of key material.
        assert_eq!(store.sender_seq_floor(IndividualAddress::new(1, 0, 203)), 1001);
        assert_eq!(store.sender_seq_floor(IndividualAddress::new(1, 0, 201)), 501);
        assert_eq!(store.sender_seq_floor(IndividualAddress::new(1, 0, 7)), 1, "no seq exported");

        let full = store.get_entry(IndividualAddress::new(1, 0, 203)).expect("keyed device imported");
        assert_eq!(full.mode(), DeviceSecurityMode::Secure);
        assert_eq!(full.tool_key(), Some(&KEY));
        assert_eq!(full.fdsk(), Some(&FDSK));

        let ch = store.make_channel(IndividualAddress::new(1, 0, 203)).expect("keyed").expect("secure");
        assert_eq!(ch.key(), &KEY, "tool key preferred over FDSK");

        // The keyring seq number seeded the store: table_seq = seq + 1.
        assert_eq!(store.device_sequence_floor(&SERIAL), 1001);

        assert!(store.get_entry(IndividualAddress::new(1, 0, 201)).is_some());
        assert!(store.get_entry(IndividualAddress::new(1, 0, 7)).is_none());
    }
}
