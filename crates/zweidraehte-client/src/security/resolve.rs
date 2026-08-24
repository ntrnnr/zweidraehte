//! Merge installation security intent with inline and ETS key material.

use std::collections::{BTreeMap, BTreeSet};

use zweidraehte_knxprod::runtime::mods::{DeviceMods, GroupSecurityPolicy};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::download::{
    DeviceConfiguration, GroupObjectProtection, GroupObjectSecurity, NetSecurityPolicy, SecurityConfig,
};
use crate::error::{Error, Result};

use super::knxkeys::{Keyring, KeyringDevice};
use super::material::{
    KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMetadata, KeyOrigin, KeyRecord, KeyScope, KeyState,
    KeyStoreError, SecretBytes, format_serial, parse_fdsk, parse_key16,
};

/// Key material and device tables resolved before any bus mutation.
#[derive(Debug, Clone)]
pub struct ResolvedKeyMaterial {
    pub serial_number: Option<[u8; 6]>,
    pub fdsk: Option<[u8; 16]>,
    pub tool_key: Option<[u8; 16]>,
    pub application_security: Option<SecurityConfig>,
    pub secured_groups: BTreeMap<GroupAddress, GroupObjectProtection>,
    pub needs_tool_key_generation: bool,
}

/// Resolve the standalone mods workflow. A keyring supplements inline
/// fields, but never silently wins a conflict.
pub fn resolve_key_material(
    configuration: &DeviceConfiguration,
    mods: &DeviceMods,
    keyring: Option<&Keyring>,
    secure_product: bool,
) -> Result<ResolvedKeyMaterial> {
    let mut serial = configuration.identity.serial_number;
    let inline_fdsk = mods.security.fdsk.as_deref().map(parse_fdsk).transpose()?;
    if let Some(decoded) = inline_fdsk {
        merge_serial(&mut serial, decoded.serial, "FDSK label")?;
    }

    let keyring_device = select_keyring_device(keyring, serial, configuration.identity.desired_address)?;
    if let Some(device) = keyring_device {
        merge_serial(&mut serial, device.serial, "ETS keyring")?;
    }
    if secure_product && serial.is_none() {
        return Err(Error::DeviceConfiguration(
            "secure commissioning requires a serial number from mods, the FDSK label, or the ETS keyring".to_string(),
        ));
    }

    let mut fdsk = inline_fdsk.map(|decoded| decoded.key);
    merge_key(&mut fdsk, keyring_device.and_then(|device| device.fdsk), "FDSK")?;
    let mut tool_key = mods.security.tool_key.as_deref().map(parse_key16).transpose()?;
    merge_key(&mut tool_key, keyring_device.and_then(|device| device.tool_key), "tool key")?;

    let inline_groups = inline_group_keys(mods)?;
    let mut resolved_groups = BTreeMap::new();
    let mut group_keys = Vec::new();
    for (&address, &policy) in &configuration.net_security {
        let inline = inline_groups.get(&address).copied().flatten();
        let imported = keyring.and_then(|keys| keys.group_keys.get(&u16::from_be_bytes(address.0))).copied();
        let mut key = inline;
        merge_key(&mut key, imported, &format!("group key for {address:?}"))?;

        let protection = match policy {
            NetSecurityPolicy::Plain => {
                if inline.is_some() {
                    return Err(Error::DeviceConfiguration(format!(
                        "group {:?} is explicitly plain but carries an inline key",
                        address.0
                    )));
                }
                GroupObjectProtection::Plain
            }
            NetSecurityPolicy::Automatic => {
                if key.is_some() {
                    GroupObjectProtection::AuthenticationConfidentiality
                } else {
                    GroupObjectProtection::Plain
                }
            }
            NetSecurityPolicy::Authentication => {
                if key.is_none() {
                    return Err(Error::DeviceConfiguration(format!(
                        "group {:?} requires authentication but no key is available",
                        address.0
                    )));
                }
                GroupObjectProtection::Authentication
            }
            NetSecurityPolicy::AuthenticationConfidentiality => {
                if key.is_none() {
                    return Err(Error::DeviceConfiguration(format!(
                        "group {:?} requires authentication and confidentiality but no key is available",
                        address.0
                    )));
                }
                GroupObjectProtection::AuthenticationConfidentiality
            }
        };

        if protection != GroupObjectProtection::Plain {
            group_keys.push((address, key.expect("secure policy checked the key")));
        }
        resolved_groups.insert(address, protection);
    }

    let group_objects = resolve_group_objects(configuration, &resolved_groups)?;
    if !secure_product && group_objects.iter().any(|entry| entry.protection != GroupObjectProtection::Plain) {
        return Err(Error::DeviceConfiguration(
            "a non-secure application cannot configure secured group objects".to_string(),
        ));
    }

    let siat = resolve_siat(configuration, mods, keyring, keyring_device, &resolved_groups)?;
    let application_security = secure_product.then_some(SecurityConfig { group_keys, siat, group_objects });
    let needs_tool_key_generation = secure_product && tool_key.is_none() && fdsk.is_some();
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
    })
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

fn inline_group_keys(mods: &DeviceMods) -> Result<BTreeMap<GroupAddress, Option<[u8; 16]>>> {
    let mut result = BTreeMap::new();
    for group in &mods.security.groups {
        let address = parse_group_address(&group.group_address)?;
        let key = group.key.as_deref().map(parse_key16).transpose()?;
        if result.insert(address, key).is_some() {
            return Err(Error::DeviceConfiguration(format!(
                "security group {} is declared more than once",
                group.group_address
            )));
        }
        if group.policy == GroupSecurityPolicy::Plain && key.is_some() {
            return Err(Error::DeviceConfiguration(format!(
                "security group {} is plain but carries a key",
                group.group_address
            )));
        }
    }
    Ok(result)
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

fn resolve_siat(
    configuration: &DeviceConfiguration,
    mods: &DeviceMods,
    keyring: Option<&Keyring>,
    keyring_device: Option<&KeyringDevice>,
    groups: &BTreeMap<GroupAddress, GroupObjectProtection>,
) -> Result<Vec<(IndividualAddress, u64)>> {
    let mut rows: BTreeMap<IndividualAddress, u64> = BTreeMap::new();
    for sender in &mods.security.senders {
        let address = parse_individual_address(&sender.individual_address)?;
        rows.entry(address)
            .and_modify(|value| *value = (*value).max(sender.sequence_number))
            .or_insert(sender.sequence_number);
    }

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
                    rows.entry(sender).and_modify(|value| *value = (*value).max(sequence)).or_insert(sequence);
                }
            }
        }
    }

    rows.remove(&configuration.identity.desired_address);
    if let Some(device) = keyring_device {
        rows.remove(&device.individual_address);
    }
    Ok(rows.into_iter().collect())
}

pub(crate) fn parse_group_address(input: &str) -> Result<GroupAddress> {
    let parts: Vec<_> = input.split('/').collect();
    let [main, middle, sub] = parts.as_slice() else {
        return Err(Error::DeviceConfiguration(format!("group address {input:?} must use main/middle/sub notation")));
    };
    let main = main.parse::<u8>().ok().filter(|value| *value <= 31);
    let middle = middle.parse::<u8>().ok().filter(|value| *value <= 7);
    let sub = sub.parse::<u8>().ok();
    match (main, middle, sub) {
        (Some(main), Some(middle), Some(sub)) => Ok(GroupAddress::from_three_level(main, middle, sub)),
        _ => Err(Error::DeviceConfiguration(format!("group address {input:?} must use main/middle/sub notation"))),
    }
}

pub(crate) fn parse_individual_address(input: &str) -> Result<IndividualAddress> {
    let parts: Vec<_> = input.split('.').collect();
    let [area, line, device] = parts.as_slice() else {
        return Err(Error::DeviceConfiguration(format!(
            "individual address {input:?} must use area.line.device notation"
        )));
    };
    let area = area.parse::<u8>().ok().filter(|value| *value <= 15);
    let line = line.parse::<u8>().ok().filter(|value| *value <= 15);
    let device = device.parse::<u8>().ok();
    match (area, line, device) {
        (Some(area), Some(line), Some(device)) => Ok(IndividualAddress::new(area, line, device)),
        _ => {
            Err(Error::DeviceConfiguration(format!("individual address {input:?} must use area.line.device notation")))
        }
    }
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
            records
                .push(record(KeyId { scope: KeyScope::Group(format!("raw:{group}")), kind: KeyKind::GroupKey }, key));
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::{DeviceIdentity, ObjectMembership, ParameterValue};
    use zweidraehte_knxprod::runtime::mods::{GroupSecurity, SecuritySection, SecuritySender};

    fn configuration() -> DeviceConfiguration {
        let ga = GroupAddress::from_three_level(1, 2, 3);
        DeviceConfiguration {
            identity: DeviceIdentity {
                desired_address: IndividualAddress::new(1, 1, 42),
                serial_number: Some([0, 0xFA, 0, 0, 0, 1]),
            },
            parameters: Vec::<ParameterValue>::new(),
            object_memberships: vec![ObjectMembership { group_address: ga, com_object: 0 }],
            objects: Vec::new(),
            net_security: BTreeMap::from([(ga, NetSecurityPolicy::AuthenticationConfidentiality)]),
            max_apdu: None,
        }
    }

    #[test]
    fn inline_security_resolves_to_typed_tables() {
        let mods = DeviceMods {
            security: SecuritySection {
                fdsk: Some("00112233445566778899AABBCCDDEEFF".to_string()),
                groups: vec![GroupSecurity {
                    group_address: "1/2/3".to_string(),
                    policy: GroupSecurityPolicy::AuthenticationConfidentiality,
                    key: Some("FFEEDDCCBBAA99887766554433221100".to_string()),
                }],
                senders: vec![SecuritySender { individual_address: "1.1.10".to_string(), sequence_number: 44 }],
                ..Default::default()
            },
            ..Default::default()
        };

        let resolved = resolve_key_material(&configuration(), &mods, None, true).expect("security resolves");
        assert!(resolved.needs_tool_key_generation);
        let security = resolved.application_security.expect("secure product has tables");
        assert_eq!(security.group_keys.len(), 1);
        assert_eq!(security.siat, [(IndividualAddress::new(1, 1, 10), 44)]);
        assert_eq!(security.group_objects[0].com_object, 0);
    }

    #[test]
    fn conflicting_object_policies_fail_before_lowering() {
        let mut configuration = configuration();
        let second = GroupAddress::from_three_level(1, 2, 4);
        configuration.object_memberships.push(ObjectMembership { group_address: second, com_object: 0 });
        configuration.net_security.insert(second, NetSecurityPolicy::Plain);
        let mods = DeviceMods {
            security: SecuritySection {
                groups: vec![GroupSecurity {
                    group_address: "1/2/3".to_string(),
                    policy: GroupSecurityPolicy::AuthenticationConfidentiality,
                    key: Some("FFEEDDCCBBAA99887766554433221100".to_string()),
                }],
                tool_key: Some("00112233445566778899AABBCCDDEEFF".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(resolve_key_material(&configuration, &mods, None, true).is_err());
    }
}
