//! Merge installation security intent with inline and ETS key material.

use std::collections::{BTreeMap, BTreeSet};

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::download::{
    DeviceConfiguration, GroupObjectProtection, GroupObjectSecurity, NetSecurityPolicy, SecurityConfig,
};
use crate::error::{Error, Result};

use super::knxkeys::{Keyring, KeyringDevice};
use super::material::{
    KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMetadata, KeyOrigin, KeyRecord, KeyScope, KeyState,
    KeyStoreError, SecretBytes, format_serial,
};

/// Key material and device tables resolved before any bus mutation.
#[derive(Clone)]
pub struct ResolvedKeyMaterial {
    pub serial_number: Option<[u8; 6]>,
    pub fdsk: Option<[u8; 16]>,
    pub tool_key: Option<[u8; 16]>,
    pub application_security: Option<SecurityConfig>,
    pub secured_groups: BTreeMap<GroupAddress, GroupObjectProtection>,
    pub needs_tool_key_generation: bool,
    /// Non-secret audit trail for every value which participated in the
    /// merge. Equal values retain both origins instead of collapsing into an
    /// untraceable byte array.
    pub provenance: Vec<KeyMetadata>,
}

impl core::fmt::Debug for ResolvedKeyMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResolvedKeyMaterial")
            .field("serial_number", &self.serial_number)
            .field("fdsk", &self.fdsk.map(|_| "[REDACTED]"))
            .field("tool_key", &self.tool_key.map(|_| "[REDACTED]"))
            .field("application_security", &self.application_security.as_ref().map(|_| "[REDACTED]"))
            .field("secured_groups", &self.secured_groups)
            .field("needs_tool_key_generation", &self.needs_tool_key_generation)
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl ResolvedKeyMaterial {
    pub(crate) fn record_generated_tool_key(&mut self, key: [u8; 16]) {
        let scope = self
            .provenance
            .iter()
            .find(|metadata| metadata.id.kind == KeyKind::Fdsk)
            .map(|metadata| metadata.id.scope.clone())
            .unwrap_or_else(|| device_scope(self.serial_number, None));
        self.provenance.push(key_metadata(
            KeyId { scope, kind: KeyKind::ToolKey },
            key,
            KeyOrigin::Generated,
            KeyEncoding::Hex,
        ));
    }
}

/// Resolve credentials from the authoritative project key store. Logical
/// net identifiers select group-key records; group addresses remain the
/// protocol-facing keys in the compiled configuration.
pub fn resolve_project_key_material(
    configuration: &DeviceConfiguration,
    device_id: &str,
    net_ids: &BTreeMap<GroupAddress, String>,
    project_siat: &[(IndividualAddress, u64)],
    source: &dyn KeyMaterialSource,
    keyring: Option<&Keyring>,
    secure_product: bool,
) -> Result<ResolvedKeyMaterial> {
    let mut serial = configuration.identity.serial_number;
    let project_device_scope = KeyScope::Device(device_id.to_string());
    let fdsk_id = KeyId { scope: project_device_scope.clone(), kind: KeyKind::Fdsk };
    let tool_id = KeyId { scope: project_device_scope, kind: KeyKind::ToolKey };
    let fdsk_record = source.read(&fdsk_id, None)?;
    let tool_record = source.read(&tool_id, None)?;
    let mut provenance = Vec::new();
    if let Some(record) = &fdsk_record {
        merge_serial(&mut serial, record.embedded_serial, "FDSK label")?;
    }
    let keyring_device = select_keyring_device(keyring, serial, configuration.identity.desired_address)?;
    if let Some(device) = keyring_device {
        merge_serial(&mut serial, device.serial, "ETS keyring")?;
    }
    if secure_product && serial.is_none() {
        return Err(Error::DeviceConfiguration(format!(
            "secure project device `{device_id}` needs a serial from project.knx, its FDSK label, or the ETS keyring"
        )));
    }
    let mut fdsk = record_key(fdsk_record.as_ref())?;
    let mut tool_key = record_key(tool_record.as_ref())?;
    if let Some(record) = fdsk_record {
        provenance.push(record.metadata);
    }
    if let Some(record) = tool_record {
        provenance.push(record.metadata);
    }

    let imported_fdsk = keyring_device.and_then(|device| device.fdsk);
    let imported_tool = keyring_device.and_then(|device| device.tool_key);
    merge_key(&mut fdsk, imported_fdsk, "FDSK")?;
    merge_key(&mut tool_key, imported_tool, "tool key")?;
    let imported_scope = device_scope(serial, Some(configuration.identity.desired_address));
    if let Some(key) = imported_fdsk {
        provenance.push(key_metadata(
            KeyId { scope: imported_scope.clone(), kind: KeyKind::Fdsk },
            key,
            KeyOrigin::Imported,
            KeyEncoding::Binary,
        ));
    }
    if let Some(key) = imported_tool {
        provenance.push(key_metadata(
            KeyId { scope: imported_scope, kind: KeyKind::ToolKey },
            key,
            KeyOrigin::Imported,
            KeyEncoding::Binary,
        ));
    }

    let mut resolved_groups = BTreeMap::new();
    let mut group_keys = Vec::new();
    for (&address, &policy) in &configuration.net_security {
        let net_id = net_ids.get(&address).ok_or_else(|| {
            Error::DeviceConfiguration(format!("group address {address} has no logical project net identifier"))
        })?;
        let id = KeyId { scope: KeyScope::Group(net_id.clone()), kind: KeyKind::GroupKey };
        let project_record = source.read(&id, None)?;
        let mut key = record_key(project_record.as_ref())?;
        if let Some(record) = project_record {
            provenance.push(record.metadata);
        }
        let imported = keyring.and_then(|keys| keys.group_keys.get(&u16::from_be_bytes(address.0))).copied();
        merge_key(&mut key, imported, &format!("group key for net `{net_id}`"))?;
        if let Some(imported) = imported {
            provenance.push(key_metadata(id, imported, KeyOrigin::Imported, KeyEncoding::Binary));
        }

        let protection = match policy {
            NetSecurityPolicy::Plain => GroupObjectProtection::Plain,
            NetSecurityPolicy::Automatic => {
                key.map_or(GroupObjectProtection::Plain, |_| GroupObjectProtection::AuthenticationConfidentiality)
            }
            NetSecurityPolicy::Authentication if key.is_some() => GroupObjectProtection::Authentication,
            NetSecurityPolicy::AuthenticationConfidentiality if key.is_some() => {
                GroupObjectProtection::AuthenticationConfidentiality
            }
            NetSecurityPolicy::Authentication | NetSecurityPolicy::AuthenticationConfidentiality => {
                return Err(Error::DeviceConfiguration(format!(
                    "net `{net_id}` requires secure group traffic but has no active group key"
                )));
            }
        };
        if protection != GroupObjectProtection::Plain {
            group_keys.push((address, key.expect("secure protection checked the key")));
        }
        resolved_groups.insert(address, protection);
    }

    let group_objects = resolve_group_objects(configuration, &resolved_groups)?;
    if !secure_product && group_objects.iter().any(|entry| entry.protection != GroupObjectProtection::Plain) {
        return Err(Error::DeviceConfiguration(
            "a non-secure application cannot configure secured group objects".to_string(),
        ));
    }
    let siat = merge_project_siat(configuration, project_siat, keyring, keyring_device, &resolved_groups);
    let application_security = secure_product.then_some(SecurityConfig { group_keys, siat, group_objects });
    let needs_tool_key_generation = tool_key.is_none() && fdsk.is_some();
    if secure_product && tool_key.is_none() && fdsk.is_none() {
        return Err(Error::DeviceConfiguration("secure commissioning requires a tool key or FDSK".to_string()));
    }

    Ok(ResolvedKeyMaterial {
        serial_number: serial,
        fdsk,
        tool_key,
        application_security,
        secured_groups: resolved_groups,
        needs_tool_key_generation,
        provenance,
    })
}

fn record_key(record: Option<&KeyRecord>) -> Result<Option<[u8; 16]>> {
    record.map(|record| record.value.key16().map_err(Error::from)).transpose()
}

fn merge_project_siat(
    configuration: &DeviceConfiguration,
    project_siat: &[(IndividualAddress, u64)],
    keyring: Option<&Keyring>,
    keyring_device: Option<&KeyringDevice>,
    groups: &BTreeMap<GroupAddress, GroupObjectProtection>,
) -> Vec<(IndividualAddress, u64)> {
    let mut rows: BTreeMap<IndividualAddress, u64> = project_siat.iter().copied().collect();
    let secured_raw: BTreeSet<u16> = groups
        .iter()
        .filter(|(_, protection)| **protection != GroupObjectProtection::Plain)
        .map(|(address, _)| u16::from_be_bytes(address.0))
        .collect();
    if let Some(keyring) = keyring {
        for interface in &keyring.interfaces {
            for (group, senders) in &interface.group_addresses {
                if !secured_raw.contains(group) {
                    continue;
                }
                for &sender in senders {
                    let sequence = keyring
                        .devices
                        .iter()
                        .find(|device| device.individual_address == sender)
                        .map_or(0, |device| device.sequence_number);
                    rows.entry(sender).and_modify(|old| *old = (*old).max(sequence)).or_insert(sequence);
                }
            }
        }
    }
    rows.remove(&configuration.identity.desired_address);
    if let Some(device) = keyring_device {
        rows.remove(&device.individual_address);
    }
    rows.into_iter().collect()
}

fn device_scope(serial: Option<[u8; 6]>, address: Option<IndividualAddress>) -> KeyScope {
    serial.map_or_else(
        || {
            address.map_or_else(
                || KeyScope::Device("generated-device".to_string()),
                |address| KeyScope::Device(format!("ia:{}", u16::from_be_bytes(address.0))),
            )
        },
        |serial| KeyScope::Device(format!("serial:{}", format_serial(&serial))),
    )
}

fn key_metadata(id: KeyId, key: [u8; 16], origin: KeyOrigin, encoding: KeyEncoding) -> KeyMetadata {
    let value = SecretBytes::new(key);
    KeyMetadata { id, epoch: None, origin, encoding, state: KeyState::Active, fingerprint: value.fingerprint() }
}

fn merge_serial(target: &mut Option<[u8; 6]>, candidate: Option<[u8; 6]>, source: &str) -> Result<()> {
    let Some(candidate) = candidate else { return Ok(()) };
    match target {
        Some(existing) if *existing != candidate => Err(Error::DeviceConfiguration(format!(
            "serial {} conflicts with {source} serial {}",
            format_serial(existing),
            format_serial(&candidate)
        ))),
        Some(_) => Ok(()),
        None => {
            *target = Some(candidate);
            Ok(())
        }
    }
}

fn merge_key(target: &mut Option<[u8; 16]>, candidate: Option<[u8; 16]>, description: &str) -> Result<()> {
    let Some(candidate) = candidate else { return Ok(()) };
    match target {
        Some(existing) if *existing != candidate => {
            Err(Error::DeviceConfiguration(format!("conflicting values for {description}")))
        }
        Some(_) => Ok(()),
        None => {
            *target = Some(candidate);
            Ok(())
        }
    }
}

fn select_keyring_device(
    keyring: Option<&Keyring>,
    serial: Option<[u8; 6]>,
    desired_address: IndividualAddress,
) -> Result<Option<&KeyringDevice>> {
    let Some(keyring) = keyring else { return Ok(None) };
    if let Some(serial) = serial {
        let matches: Vec<_> = keyring.devices.iter().filter(|device| device.serial == Some(serial)).collect();
        if matches.len() > 1 {
            return Err(Error::DeviceConfiguration(format!(
                "ETS keyring contains {} devices with serial {}",
                matches.len(),
                format_serial(&serial)
            )));
        }
        if let Some(device) = matches.first() {
            if let Some(at_desired) =
                keyring.devices.iter().find(|candidate| candidate.individual_address == desired_address)
                && at_desired.serial.is_some_and(|candidate| candidate != serial)
            {
                return Err(Error::DeviceConfiguration(
                    "ETS keyring assigns the desired individual address to a different serial number".to_string(),
                ));
            }
            return Ok(Some(*device));
        }
    }

    let matches: Vec<_> =
        keyring.devices.iter().filter(|device| device.individual_address == desired_address).collect();
    if matches.len() > 1 {
        return Err(Error::DeviceConfiguration("ETS keyring repeats the desired individual address".to_string()));
    }
    Ok(matches.first().copied())
}

fn resolve_group_objects(
    configuration: &DeviceConfiguration,
    groups: &BTreeMap<GroupAddress, GroupObjectProtection>,
) -> Result<Vec<GroupObjectSecurity>> {
    let mut objects = BTreeMap::new();
    for membership in &configuration.object_memberships {
        let protection = *groups.get(&membership.group_address).unwrap_or(&GroupObjectProtection::Plain);
        match objects.insert(membership.com_object, protection) {
            Some(previous) if previous != protection => {
                return Err(Error::DeviceConfiguration(format!(
                    "communication object {} belongs to group addresses with incompatible security policies",
                    membership.com_object
                )));
            }
            _ => {}
        }
    }
    Ok(objects.into_iter().map(|(com_object, protection)| GroupObjectSecurity { com_object, protection }).collect())
}

/// Read-only adapter exposing an ETS keyring through the generic store
/// vocabulary. Commissioning uses the richer keyring topology directly
/// for SIAT sender lists, while future consumers can depend only on this
/// interface.
pub struct EtsKeyringSource<'a>(pub &'a Keyring);

impl KeyMaterialSource for EtsKeyringSource<'_> {
    fn list(&self) -> core::result::Result<Vec<KeyMetadata>, KeyStoreError> {
        Ok(self.records().into_iter().map(|record| record.metadata).collect())
    }

    fn read(&self, id: &KeyId, epoch: Option<KeyEpoch>) -> core::result::Result<Option<KeyRecord>, KeyStoreError> {
        Ok(self.records().into_iter().find(|record| record.metadata.id == *id && record.metadata.epoch == epoch))
    }
}

impl EtsKeyringSource<'_> {
    fn records(&self) -> Vec<KeyRecord> {
        let mut records = Vec::new();
        for device in &self.0.devices {
            let subject = device.serial.map_or_else(
                || format!("ia:{:?}", device.individual_address.0),
                |serial| format!("serial:{}", format_serial(&serial)),
            );
            if let Some(key) = device.fdsk {
                records.push(record(KeyId { scope: KeyScope::Device(subject.clone()), kind: KeyKind::Fdsk }, key));
            }
            if let Some(key) = device.tool_key {
                records.push(record(KeyId { scope: KeyScope::Device(subject), kind: KeyKind::ToolKey }, key));
            }
        }
        for (&group, &key) in &self.0.group_keys {
            let address = GroupAddress(group.to_be_bytes());
            records.push(record(KeyId { scope: KeyScope::Group(address.to_string()), kind: KeyKind::GroupKey }, key));
        }
        records
    }
}

fn record(id: KeyId, key: [u8; 16]) -> KeyRecord {
    let value = SecretBytes::new(key);
    KeyRecord {
        metadata: KeyMetadata {
            id,
            epoch: None,
            origin: KeyOrigin::Imported,
            encoding: KeyEncoding::Binary,
            state: KeyState::Active,
            fingerprint: value.fingerprint(),
        },
        value,
        embedded_serial: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::{DeviceIdentity, ObjectMembership, ParameterValue};

    const GROUP_KEY: [u8; 16] = [0xA5; 16];
    const TOOL_KEY: [u8; 16] = [0x5A; 16];
    const FDSK: [u8; 16] = [0x11; 16];

    #[derive(Default)]
    struct TestSource(Vec<KeyRecord>);

    impl TestSource {
        fn add(&mut self, scope: KeyScope, kind: KeyKind, value: [u8; 16], origin: KeyOrigin) {
            let value = SecretBytes::new(value);
            self.0.push(KeyRecord {
                metadata: KeyMetadata {
                    id: KeyId { scope, kind },
                    epoch: None,
                    origin,
                    encoding: KeyEncoding::Hex,
                    state: KeyState::Active,
                    fingerprint: value.fingerprint(),
                },
                value,
                embedded_serial: None,
            });
        }
    }

    impl KeyMaterialSource for TestSource {
        fn list(&self) -> core::result::Result<Vec<KeyMetadata>, KeyStoreError> {
            Ok(self.0.iter().map(|record| record.metadata.clone()).collect())
        }

        fn read(&self, id: &KeyId, epoch: Option<KeyEpoch>) -> core::result::Result<Option<KeyRecord>, KeyStoreError> {
            Ok(self.0.iter().find(|record| record.metadata.id == *id && record.metadata.epoch == epoch).cloned())
        }
    }

    fn configuration() -> DeviceConfiguration {
        let ga = GroupAddress::from_three_level(1, 2, 3);
        DeviceConfiguration {
            identity: DeviceIdentity {
                desired_address: IndividualAddress::new(1, 1, 42),
                serial_number: Some([0, 0xFA, 0, 0, 0, 1]),
            },
            parameters: Vec::<ParameterValue>::new(),
            object_memberships: vec![ObjectMembership {
                group_address: ga,
                com_object: 0,
                role: crate::download::MembershipRole::Primary,
            }],
            objects: Vec::new(),
            net_security: BTreeMap::from([(ga, NetSecurityPolicy::AuthenticationConfidentiality)]),
            max_apdu: None,
        }
    }

    fn project_source() -> TestSource {
        let mut source = TestSource::default();
        source.add(KeyScope::Device("button".into()), KeyKind::Fdsk, FDSK, KeyOrigin::DeviceLabel);
        source.add(KeyScope::Group("switch".into()), KeyKind::GroupKey, GROUP_KEY, KeyOrigin::Manual);
        source
    }

    fn net_ids() -> BTreeMap<GroupAddress, String> {
        BTreeMap::from([(GroupAddress::from_three_level(1, 2, 3), "switch".into())])
    }

    #[test]
    fn project_security_resolves_to_typed_tables() {
        let mut resolved = resolve_project_key_material(
            &configuration(),
            "button",
            &net_ids(),
            &[(IndividualAddress::new(1, 1, 10), 44)],
            &project_source(),
            None,
            true,
        )
        .expect("security resolves");
        assert!(resolved.needs_tool_key_generation);
        assert!(!format!("{resolved:?}").contains("11111111111111111111111111111111"));
        resolved.record_generated_tool_key([0xA6; 16]);
        assert!(resolved.provenance.iter().any(|metadata| metadata.origin == KeyOrigin::Generated));
        let security = resolved.application_security.expect("secure product has tables");
        assert_eq!(security.group_keys.len(), 1);
        assert_eq!(security.siat, [(IndividualAddress::new(1, 1, 10), 44)]);
        assert_eq!(security.group_objects[0].com_object, 0);
    }

    #[test]
    fn conflicting_object_policies_fail_before_lowering() {
        let mut configuration = configuration();
        let second = GroupAddress::from_three_level(1, 2, 4);
        configuration.object_memberships.push(ObjectMembership {
            group_address: second,
            com_object: 0,
            role: crate::download::MembershipRole::Additional,
        });
        configuration.net_security.insert(second, NetSecurityPolicy::Plain);
        assert!(
            resolve_project_key_material(
                &configuration,
                "button",
                &BTreeMap::from(
                    [(GroupAddress::from_three_level(1, 2, 3), "switch".into()), (second, "plain".into()),]
                ),
                &[],
                &project_source(),
                None,
                true,
            )
            .is_err()
        );
    }

    fn keyring(device: KeyringDevice, group_key: [u8; 16], senders: Vec<IndividualAddress>) -> Keyring {
        let group = u16::from_be_bytes(GroupAddress::from_three_level(1, 2, 3).0);
        Keyring {
            project: "test".to_string(),
            created_by: "test".to_string(),
            created: "2026-08-24T00:00:00Z".to_string(),
            backbone: None,
            interfaces: vec![super::super::knxkeys::KeyringInterface {
                interface_type: super::super::knxkeys::KeyringInterfaceType::Usb,
                individual_address: IndividualAddress::new(1, 1, 250),
                host: None,
                user_id: None,
                password: None,
                authentication: None,
                group_addresses: vec![(group, senders)],
            }],
            group_keys: BTreeMap::from([(group, group_key)]),
            devices: vec![device],
        }
    }

    fn keyring_device() -> KeyringDevice {
        KeyringDevice {
            individual_address: IndividualAddress::new(1, 1, 42),
            tool_key: Some(TOOL_KEY),
            fdsk: Some(FDSK),
            serial: Some([0, 0xFA, 0, 0, 0, 1]),
            sequence_number: 100,
            management_password: None,
            authentication: None,
        }
    }

    #[test]
    fn keyring_only_material_resolves_and_seeds_siat() {
        let sender = IndividualAddress::new(1, 1, 10);
        let mut sender_device = keyring_device();
        sender_device.individual_address = sender;
        sender_device.serial = Some([0, 0xFA, 0, 0, 0, 2]);
        sender_device.sequence_number = 1234;

        let mut keys = keyring(keyring_device(), GROUP_KEY, vec![sender, configuration().identity.desired_address]);
        keys.devices.push(sender_device);

        let resolved = resolve_project_key_material(
            &configuration(),
            "button",
            &net_ids(),
            &[],
            &TestSource::default(),
            Some(&keys),
            true,
        )
        .expect("keyring resolves");
        assert_eq!(resolved.tool_key, Some(TOOL_KEY));
        assert_eq!(resolved.fdsk, Some(FDSK));
        assert_eq!(resolved.application_security.expect("secure tables").siat, [(sender, 1234)]);
    }

    #[test]
    fn equal_mixed_sources_merge_but_conflicting_values_fail() {
        let mut source = project_source();
        source.add(KeyScope::Device("button".into()), KeyKind::ToolKey, TOOL_KEY, KeyOrigin::Manual);
        let matching = keyring(keyring_device(), GROUP_KEY, Vec::new());
        let resolved =
            resolve_project_key_material(&configuration(), "button", &net_ids(), &[], &source, Some(&matching), true)
                .expect("equal sources merge");
        let origins: BTreeSet<_> = resolved.provenance.iter().map(|metadata| metadata.origin).collect();
        assert_eq!(origins, BTreeSet::from([KeyOrigin::Manual, KeyOrigin::Imported, KeyOrigin::DeviceLabel]));

        let conflicting = keyring(keyring_device(), [0xCC; 16], Vec::new());
        assert!(matches!(
            resolve_project_key_material(
                &configuration(),
                "button",
                &net_ids(),
                &[],
                &source,
                Some(&conflicting),
                true,
            ),
            Err(Error::DeviceConfiguration(message)) if message.contains("conflicting values for group key")
        ));
    }

    #[test]
    fn siat_keeps_the_greatest_sequence_number() {
        let sender = IndividualAddress::new(1, 1, 10);
        let mut sender_device = keyring_device();
        sender_device.individual_address = sender;
        sender_device.serial = Some([0, 0xFA, 0, 0, 0, 2]);
        sender_device.sequence_number = 900;
        let mut keys = keyring(keyring_device(), GROUP_KEY, vec![sender]);
        keys.devices.push(sender_device);

        let mut source = project_source();
        source.add(KeyScope::Device("button".into()), KeyKind::ToolKey, TOOL_KEY, KeyOrigin::Manual);
        let security = resolve_project_key_material(
            &configuration(),
            "button",
            &net_ids(),
            &[(sender, 1234)],
            &source,
            Some(&keys),
            true,
        )
        .expect("sources merge")
        .application_security
        .expect("secure tables");
        assert_eq!(security.siat, [(sender, 1234)]);
    }

    #[test]
    fn explicit_secure_policy_requires_a_group_key() {
        let mut source = TestSource::default();
        source.add(KeyScope::Device("button".into()), KeyKind::ToolKey, TOOL_KEY, KeyOrigin::Manual);
        assert!(matches!(
            resolve_project_key_material(
                &configuration(),
                "button",
                &net_ids(),
                &[],
                &source,
                None,
                true,
            ),
            Err(Error::DeviceConfiguration(message)) if message.contains("no active group key")
        ));
    }
}
