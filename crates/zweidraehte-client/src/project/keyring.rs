//! Import decrypted ETS credentials into logical project identities.
//!
//! The plan retains writer exclusion through review and application. Key-file
//! replacement precedes forward-only sequence observations; separate files do
//! not form an atomic transaction.

use super::revision::FileRevision;
use super::session::LockedProjectStore;
use crate::configuration::ErrorDetail;
use crate::project::error::{Error, Result};
use crate::security::Keyring;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::num::NonZeroU8;
use std::sync::Arc;
use zweidraehte_ets_files::keyring::{
    KeyringDevice, KeyringInterface, derive_ip_device_authentication_code, derive_ip_user_password_hash,
};
use zweidraehte_project::{
    DomainAddress, IpServiceSecurity, KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMaterialStore,
    KeyMetadata, KeyOrigin, KeyRecord, KeyScope, KeyState, KeyStoreError, ProjectEvent, ProjectStore,
    ProjectStoreError, SenderIdentity, format_serial,
};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_util::secret::SecretBytes;

/// Counts safe to display before importing. External senders count as related
/// keyring entries, but not as matched managed devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyringImportSummary {
    pub matched_devices: usize,
    pub matched_groups: usize,
    pub ignored_devices: usize,
    pub ignored_groups: usize,
}

/// Validated import bound to its project inputs and retained writer.
///
/// Obtain this through [`super::ProjectCommissioningSession::plan_keyring_import`].
/// Dropping the plan discards its secrets; applying consumes it. Diagnostics
/// expose only counts, never key records or their fingerprints.
pub struct KeyringImportPlan {
    owner: Arc<LockedProjectStore>,
    files: FileRevision,
    records: Vec<KeyRecord>,
    active_epochs: Vec<(KeyId, KeyEpoch)>,
    events: Vec<ProjectEvent>,
    summary: KeyringImportSummary,
}

impl std::fmt::Debug for KeyringImportPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringImportPlan").field("summary", &self.summary).finish_non_exhaustive()
    }
}

impl KeyringImportPlan {
    pub fn summary(&self) -> KeyringImportSummary {
        self.summary
    }

    /// Revalidate inputs, persist keys, append observations, then compact.
    ///
    /// `KeyringImportInputsChanged` writes nothing. `KeyringImportPartial`
    /// means keys were committed; its count reports confirmed observations,
    /// not a rollback. A failing observation may itself have reached disk.
    /// Key-file I/O errors can also follow a rename; reopen before retrying.
    pub fn apply(self) -> Result<KeyringImportSummary> {
        let mut store = self.owner.lock().map_err(|_| Error::ProjectStorePoisoned)?;
        self.files.verify(|| Error::KeyringImportInputsChanged)?;
        store.keys_mut().ok_or(ProjectStoreError::NotInitialized)?.transaction(|transaction| {
            // A new group needs its active epoch before its first record:
            // later puts decode and validate the intermediate document.
            for (id, epoch) in self.active_epochs {
                transaction.set_active_epoch(&id, epoch)?;
            }
            for record in self.records {
                transaction.put(record)?;
            }
            Ok(())
        })?;
        let observation_count = self.events.len();
        for (observations_recorded, event) in self.events.into_iter().enumerate() {
            store.record(event).map_err(|source| Error::KeyringImportPartial { observations_recorded, source })?;
        }
        store
            .compact()
            .map_err(|source| Error::KeyringImportPartial { observations_recorded: observation_count, source })?;
        Ok(self.summary)
    }

    pub(super) fn prepare(
        store: &ProjectStore,
        keyring: &Keyring,
        owner: Arc<LockedProjectStore>,
        files: FileRevision,
    ) -> Result<KeyringImportPlan> {
        let keys = store.keys().ok_or(ProjectStoreError::NotInitialized)?;
        store.state().ok_or(ProjectStoreError::NotInitialized)?;

        let mut records = Vec::new();
        let mut events = Vec::new();
        let mut matched_devices = 0usize;
        let mut matched_keyring_devices = std::collections::BTreeSet::new();
        let mut imported_ip_backbone = false;
        for device in store.authored().devices.values().filter(|device| device.active) {
            let Some((keyring_index, imported)) =
                select_keyring_device(Some(keyring), device.serial, device.address, DeviceMatchPolicy::Import)?
            else {
                continue;
            };
            matched_keyring_devices.insert(keyring_index);
            matched_devices += 1;

            let mut serial = device.serial;
            merge_serial(&mut serial, imported.serial, "ETS keyring")?;
            if let Some(fdsk) = imported.fdsk() {
                records.push(imported_key_record(
                    KeyId { scope: KeyScope::Device(device.id.to_string()), kind: KeyKind::Fdsk },
                    None,
                    SecretBytes::new(fdsk),
                    serial,
                ));
            }
            if let Some(tool_key) = imported.tool_key() {
                records.push(imported_key_record(
                    KeyId { scope: KeyScope::Device(device.id.to_string()), kind: KeyKind::ToolKey },
                    None,
                    SecretBytes::new(tool_key),
                    None,
                ));
            }
            if let Some(ip) = &device.ip
                && let Some(security) = &ip.security
            {
                if security.routing == IpServiceSecurity::Secure {
                    let line = store.authored().line_topology(device.area, device.line).ok_or_else(|| {
                        Error::InvalidProject(ErrorDetail::new(format!(
                            "device `{}` has no unique KNX/IP topology line",
                            device.id
                        )))
                    })?;
                    let DomainAddress::Ip(authored_multicast) = line.domain.ok_or_else(|| {
                        Error::InvalidProject(ErrorDetail::new(format!(
                            "IP Secure device `{}` has no routing multicast address",
                            device.id
                        )))
                    })?
                    else {
                        return Err(Error::InvalidProject(ErrorDetail::new(format!(
                            "IP Secure device `{}` is not on a KNX/IP domain",
                            device.id
                        ))));
                    };
                    validate_imported_backbone(
                        Some(keyring),
                        authored_multicast,
                        security.multicast_latency_tolerance_ms,
                    )?;
                    if !imported_ip_backbone
                        && let Some(key) = keyring.backbone.as_ref().and_then(|backbone| backbone.key())
                    {
                        records.push(imported_key_record(
                            KeyId { scope: KeyScope::IpBackbone, kind: KeyKind::BackboneKey },
                            None,
                            SecretBytes::new(key),
                            None,
                        ));
                        imported_ip_backbone = true;
                    }
                }

                let user_security = security.device_management == IpServiceSecurity::Secure
                    || security.tunnelling == IpServiceSecurity::Secure;
                if user_security {
                    if let Some(code) = imported_authentication_code(Some(keyring), Some(imported), device.address)? {
                        records.push(imported_key_record(
                            KeyId {
                                scope: KeyScope::IpInterface(device.id.to_string()),
                                kind: KeyKind::DeviceAuthenticationCode,
                            },
                            None,
                            code,
                            None,
                        ));
                    }

                    for user_id in &ip.password_users {
                        if let Some(hash) =
                            imported_password_hash(Some(keyring), Some(imported), device.address, *user_id)?
                        {
                            records.push(imported_key_record(
                                KeyId {
                                    scope: KeyScope::IpUser { interface: device.id.to_string(), user_id: *user_id },
                                    kind: KeyKind::IpPasswordHash,
                                },
                                None,
                                hash,
                                None,
                            ));
                        }
                    }
                }
            }
            if imported.sequence_number > 0
                && let Some(serial) = serial
            {
                let next =
                    imported.sequence_number.checked_add(1).filter(|next| *next <= 0xFFFF_FFFF_FFFF).ok_or_else(
                        || {
                            Error::KeyringImport(ErrorDetail::new(
                                "ETS device sequence number has no representable 48-bit successor",
                            ))
                        },
                    )?;
                events.push(ProjectEvent::ObserveDeviceOutgoing { serial: format_serial(&serial), next });
            }
        }

        // An unmanaged sender has no device record in the project. Its keyring
        // sequence is still a useful forward-only SIAT observation when the IA is
        // declared explicitly in `external_sender`.
        for sender in store.authored().external_senders.values() {
            let Some((index, imported)) =
                select_keyring_device(Some(keyring), None, sender.address, DeviceMatchPolicy::Import)?
            else {
                continue;
            };
            matched_keyring_devices.insert(index);
            if imported.sequence_number > 0xFFFF_FFFF_FFFF {
                return Err(Error::KeyringImport(ErrorDetail::new("ETS sender sequence number exceeds 48 bits")));
            }
            if imported.sequence_number > 0 {
                events.push(ProjectEvent::ObserveSender {
                    sender: SenderIdentity::UnmanagedAddress(sender.address.to_string()),
                    last_valid: imported.sequence_number,
                });
            }
        }

        let mut nets_by_address = BTreeMap::new();
        for net in store.authored().nets.values() {
            let raw = u16::from_be_bytes(net.address.0);
            if let Some(previous) = nets_by_address.insert(raw, &net.id) {
                return Err(Error::KeyringImport(ErrorDetail::new(format!(
                    "nets `{previous}` and `{}` use the same group address {}",
                    net.id, net.address
                ))));
            }
        }
        let mut active_epochs = Vec::new();
        let mut matched_groups = 0usize;
        for (address, key) in keyring.group_keys() {
            let Some(net) = nets_by_address.get(&address) else { continue };
            matched_groups += 1;
            let id = KeyId { scope: KeyScope::Group(net.0.clone()), kind: KeyKind::GroupKey };
            let existing = keys.read(&id, None)?;
            let epoch = existing.as_ref().and_then(|record| record.metadata.epoch).unwrap_or(KeyEpoch(1));
            records.push(imported_key_record(id.clone(), Some(epoch), SecretBytes::new(key), None));
            if existing.is_none() {
                active_epochs.push((id, epoch));
            }
        }

        // Reject disagreements during preview; the transaction repeats the check
        // before committing, so no frontend has to interpret a key conflict itself.
        for record in &records {
            if let Some(existing) = keys.read(&record.metadata.id, record.metadata.epoch)?
                && existing.value != record.value
            {
                return Err(KeyStoreError::Conflict(record.metadata.id.clone()).into());
            }
        }
        files.verify(|| Error::KeyringImportInputsChanged)?;
        Ok(KeyringImportPlan {
            owner,
            files,
            records,
            active_epochs,
            events,
            summary: KeyringImportSummary {
                matched_devices,
                matched_groups,
                ignored_devices: keyring.devices.len().saturating_sub(matched_keyring_devices.len()),
                ignored_groups: keyring.group_key_count().saturating_sub(matched_groups),
            },
        })
    }
}

fn imported_key_record(
    id: KeyId,
    epoch: Option<KeyEpoch>,
    value: SecretBytes,
    embedded_serial: Option<[u8; 6]>,
) -> KeyRecord {
    KeyRecord {
        metadata: KeyMetadata {
            id,
            epoch,
            origin: KeyOrigin::Imported,
            encoding: KeyEncoding::Hex,
            state: KeyState::Active,
            fingerprint: value.fingerprint(),
        },
        value,
        embedded_serial,
    }
}

/// Import never falls back from a known serial. Runtime resolution also
/// checks address ownership and may use an address when the serial is absent
/// from the keyring. Keep this distinction explicit until policy changes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DeviceMatchPolicy {
    Import,
    Resolve,
}

pub(super) fn select_keyring_device(
    keyring: Option<&Keyring>,
    serial: Option<[u8; 6]>,
    desired_address: IndividualAddress,
    policy: DeviceMatchPolicy,
) -> Result<Option<(usize, &KeyringDevice)>> {
    let Some(keyring) = keyring else { return Ok(None) };
    if let Some(serial) = serial {
        let mut matches = keyring.devices.iter().enumerate().filter(|(_, device)| device.serial == Some(serial));
        let selected = matches.next();
        if matches.next().is_some() {
            return Err(Error::KeyringImport(ErrorDetail::new(format!(
                "ETS keyring contains multiple devices with serial {}",
                format_serial(&serial)
            ))));
        }
        if policy == DeviceMatchPolicy::Import {
            return Ok(selected);
        }
        let at_desired = unique_at_address(keyring, desired_address)?;
        if selected.is_some() {
            // A serial match must not bypass conflicting ownership of the
            // address being assigned, whichever order the entries have.
            if at_desired.is_some_and(|(_, device)| device.serial.is_some_and(|candidate| candidate != serial)) {
                return Err(Error::KeyringImport(ErrorDetail::new(
                    "ETS keyring assigns the desired individual address to a different serial number",
                )));
            }
            return Ok(selected);
        }
        return Ok(at_desired);
    }
    unique_at_address(keyring, desired_address)
}

/// The keyring entry at `address`, rejecting a keyring that gives the
/// address to more than one device.
fn unique_at_address(keyring: &Keyring, address: IndividualAddress) -> Result<Option<(usize, &KeyringDevice)>> {
    let mut matches = keyring.devices.iter().enumerate().filter(|(_, device)| device.individual_address == address);
    let selected = matches.next();
    if matches.next().is_some() {
        return Err(Error::KeyringImport(ErrorDetail::new(format!(
            "ETS keyring repeats individual address {address}"
        ))));
    }
    Ok(selected)
}

pub(super) fn validate_imported_backbone(
    keyring: Option<&Keyring>,
    multicast_address: [u8; 4],
    latency_tolerance_ms: u16,
) -> Result<()> {
    if let Some(backbone) = keyring.and_then(|keyring| keyring.backbone.as_ref()) {
        if let Some(address) = backbone.multicast_address.as_deref() {
            let address = address.parse::<Ipv4Addr>().map_err(|_| {
                Error::KeyringImport(ErrorDetail::new(format!(
                    "ETS keyring has malformed backbone multicast address `{address}`"
                )))
            })?;
            if address.octets() != multicast_address {
                return Err(Error::KeyringImport(ErrorDetail::new(format!(
                    "ETS keyring backbone multicast address {address} conflicts with the authored KNX/IP topology"
                ))));
            }
        }
        if let Some(latency) = backbone.latency_ms
            && latency != u32::from(latency_tolerance_ms)
        {
            return Err(Error::KeyringImport(ErrorDetail::new(format!(
                "ETS keyring backbone latency {latency} ms conflicts with authored {} ms",
                latency_tolerance_ms
            ))));
        }
    }

    Ok(())
}

// IP credentials may appear on both the device and its hosted interfaces.
// Both import and runtime resolution accept corroborating values and reject
// conflicting ones, ignoring credentials belonging to another host or user.
fn interfaces_for_device<'a>(
    keyring: Option<&'a Keyring>,
    device: Option<&KeyringDevice>,
    desired_address: IndividualAddress,
) -> impl Iterator<Item = &'a KeyringInterface> {
    let imported_address = device.map(|device| device.individual_address);
    keyring.into_iter().flat_map(|keys| &keys.interfaces).filter(move |interface| {
        interface.host.is_some_and(|host| host == desired_address || Some(host) == imported_address)
    })
}

pub(super) fn imported_authentication_code(
    keyring: Option<&Keyring>,
    device: Option<&KeyringDevice>,
    address: IndividualAddress,
) -> Result<Option<SecretBytes>> {
    unique_imported_secret(
        device
            .and_then(KeyringDevice::authentication)
            .into_iter()
            .chain(interfaces_for_device(keyring, device, address).filter_map(KeyringInterface::authentication))
            .map(derive_ip_device_authentication_code),
        "IP Secure Device Authentication Code",
    )
}

pub(super) fn imported_password_hash(
    keyring: Option<&Keyring>,
    device: Option<&KeyringDevice>,
    address: IndividualAddress,
    user_id: NonZeroU8,
) -> Result<Option<SecretBytes>> {
    unique_imported_secret(
        device
            .and_then(KeyringDevice::management_password)
            .filter(|_| user_id.get() == 1)
            .into_iter()
            .chain(
                interfaces_for_device(keyring, device, address)
                    .filter(|interface| interface.user_id == Some(user_id.get()))
                    .filter_map(KeyringInterface::password),
            )
            .map(derive_ip_user_password_hash),
        &format!("IP Secure password hash for user {user_id}"),
    )
}

/// Merge while retaining zeroization for both accepted and rejected candidates.
pub(super) fn merge_secret(
    current: &mut Option<SecretBytes>,
    incoming: SecretBytes,
    conflict: impl FnOnce() -> String,
) -> Result<()> {
    incoming.key16_ref().map_err(KeyStoreError::from)?;
    match current {
        Some(current) if current.as_slice() != incoming.as_slice() => {
            Err(Error::KeyringImport(ErrorDetail::new(conflict())))
        }
        Some(_) => Ok(()),
        None => {
            *current = Some(incoming);
            Ok(())
        }
    }
}

fn unique_imported_secret(values: impl IntoIterator<Item = [u8; 16]>, what: &str) -> Result<Option<SecretBytes>> {
    let mut selected = None;
    for value in values {
        merge_secret(&mut selected, value.into(), || format!("conflicting ETS keyring values for {what}"))?;
    }
    Ok(selected)
}

pub(super) fn merge_serial(target: &mut Option<[u8; 6]>, candidate: Option<[u8; 6]>, source: &str) -> Result<()> {
    let Some(candidate) = candidate else { return Ok(()) };
    match target {
        Some(existing) if *existing != candidate => Err(Error::KeyringImport(ErrorDetail::new(format!(
            "serial {} conflicts with {source} serial {}",
            format_serial(existing),
            format_serial(&candidate)
        )))),
        Some(_) => Ok(()),
        None => {
            *target = Some(candidate);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
