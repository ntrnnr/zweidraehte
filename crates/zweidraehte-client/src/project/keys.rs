//! Merge installation security intent with inline and ETS key material.

use super::ProjectSetupRequirement;
use super::keyring::{
    DeviceMatchPolicy, imported_authentication_code, imported_password_hash, merge_secret, merge_serial,
    select_keyring_device, validate_imported_backbone,
};
use std::collections::{BTreeMap, BTreeSet};

use zweidraehte_project::IpServiceSecurity;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::configuration::{
    GroupObjectProtection, GroupObjectSecurity, MaterializedDevice, NetSecurityPolicy, ResolvedIpSecureConfiguration,
    ResolvedKeyMaterial, SecurityConfig, Unkeyed,
};
use crate::project::error::{Error, Result};

use zweidraehte_ets_files::keyring::{Keyring, KeyringDevice};
use zweidraehte_project::{
    KeyEncoding, KeyId, KeyKind, KeyMaterialSource, KeyMetadata, KeyOrigin, KeyRecord, KeyScope, KeyState,
    KeyStoreError, NetId, ProjectDeviceId, format_serial,
};
use zweidraehte_util::secret::SecretBytes;

/// Application downloads require resolved security matching the project intent.
/// Offline previews and management-only operations may omit application tables.
pub(super) fn validate_application_security(
    device: &MaterializedDevice<Unkeyed>,
    security: Option<&SecurityConfig>,
) -> Result<()> {
    match (device.security_intent().data_secure_enabled, security.is_some()) {
        (true, false) => Err(Error::DeviceConfiguration(
            "Data Secure is enabled but no application-security configuration was supplied".to_string(),
        )),
        (false, true) => Err(Error::DeviceConfiguration(
            "application-security configuration was supplied while Data Secure is disabled".to_string(),
        )),
        _ => Ok(()),
    }
}

/// Resolve credentials from the authoritative project key store. Logical
/// net identifiers select group-key records; group addresses remain the
/// protocol-facing keys in the compiled configuration.
pub fn resolve_project_key_material(
    device: &MaterializedDevice<Unkeyed>,
    device_id: &str,
    net_ids: &BTreeMap<GroupAddress, String>,
    project_siat: &[(IndividualAddress, u64)],
    source: &dyn KeyMaterialSource,
    keyring: Option<&Keyring>,
    data_secure_enabled: bool,
) -> Result<ResolvedKeyMaterial> {
    let intent = device.security_intent();
    let (material, keyring_device) =
        resolve_management_keys(intent.serial_number, device.individual_address(), device_id, source, keyring)?;
    if data_secure_enabled && material.serial_number().is_none() {
        return Err(ProjectSetupRequirement::DeviceSerial { device: ProjectDeviceId(device_id.into()) }.into());
    }
    let mut provenance = material.provenance().to_vec();

    let mut resolved_groups = BTreeMap::new();
    let mut group_keys = Vec::new();
    for (&address, &policy) in &intent.net_security {
        let net_id = net_ids.get(&address).ok_or_else(|| {
            Error::DeviceConfiguration(format!("group address {address} has no logical project net identifier"))
        })?;
        let id = KeyId { scope: KeyScope::Group(net_id.clone()), kind: KeyKind::GroupKey };
        if !data_secure_enabled
            && matches!(policy, NetSecurityPolicy::Authentication | NetSecurityPolicy::AuthenticationConfidentiality)
        {
            return Err(Error::DeviceConfiguration(format!(
                "device `{device_id}` has Data Secure disabled but is linked to secured net `{net_id}`"
            )));
        }
        // A key retained from an earlier topology must be inert when the
        // effective policy is plain. Reading it here would also turn an
        // unused secret into a desired programming artifact.
        let mut key = None;
        if policy != NetSecurityPolicy::Plain {
            key = take_project_secret(source.read(&id, None)?, &mut provenance)?;
            let imported = keyring
                .and_then(|keys| keys.group_key(u16::from_be_bytes(address.0)))
                .map(|key| SecretBytes::new(key.as_slice()));
            merge_imported_secret(&mut key, imported, id, &mut provenance, &format!("group key for net `{net_id}`"))?;
        }

        let protection = match policy {
            NetSecurityPolicy::Plain => GroupObjectProtection::Plain,
            NetSecurityPolicy::Automatic => key
                .as_ref()
                .map_or(GroupObjectProtection::Plain, |_| GroupObjectProtection::AuthenticationConfidentiality),
            NetSecurityPolicy::Authentication if key.is_some() => GroupObjectProtection::Authentication,
            NetSecurityPolicy::AuthenticationConfidentiality if key.is_some() => {
                GroupObjectProtection::AuthenticationConfidentiality
            }
            NetSecurityPolicy::Authentication | NetSecurityPolicy::AuthenticationConfidentiality => {
                return Err(ProjectSetupRequirement::GroupKey { net: NetId(net_id.clone()) }.into());
            }
        };
        if protection != GroupObjectProtection::Plain {
            group_keys.push((
                address,
                *key.as_ref().expect("secure protection checked the key").key16_ref().expect("resolved key width"),
            ));
        }
        resolved_groups.insert(address, protection);
    }

    let group_objects = resolve_group_objects(device, &resolved_groups)?;
    if !data_secure_enabled && group_objects.iter().any(|entry| entry.protection != GroupObjectProtection::Plain) {
        let net_id = resolved_groups
            .iter()
            .find(|(_, protection)| **protection != GroupObjectProtection::Plain)
            .and_then(|(address, _)| net_ids.get(address))
            .map_or("unknown", String::as_str);
        return Err(Error::DeviceConfiguration(format!(
            "device `{device_id}` has Data Secure disabled but automatic policy secures net `{net_id}`"
        )));
    }
    let siat = merge_project_siat(device, project_siat, keyring, keyring_device, &resolved_groups);
    let application_security = data_secure_enabled.then_some(SecurityConfig::new(group_keys, siat, group_objects));
    let ip_secure =
        resolve_ip_secure_configuration(device, device_id, source, keyring, keyring_device, &mut provenance)?;
    let ip_secure_management =
        device.topology().ip.as_ref().is_some_and(|configuration| configuration.security.is_some());
    if (data_secure_enabled || ip_secure_management) && material.tool_key().is_none() && material.fdsk().is_none() {
        return Err(ProjectSetupRequirement::ManagementCredential { device: ProjectDeviceId(device_id.into()) }.into());
    }

    let mut material = material.with_secured_groups(resolved_groups).with_provenance(provenance);
    if let Some(security) = application_security {
        material = material.with_application_security(security);
    }
    if let Some(security) = ip_secure {
        material = material.with_ip_secure(security);
    }
    Ok(material)
}

/// Resolve only management identity and credentials. Desired tables and IP
/// security configuration cannot gate access needed to inspect or recover them.
pub(super) fn resolve_management_keys<'a>(
    serial: Option<[u8; 6]>,
    address: IndividualAddress,
    device_id: &str,
    source: &dyn KeyMaterialSource,
    keyring: Option<&'a Keyring>,
) -> Result<(ResolvedKeyMaterial, Option<&'a KeyringDevice>)> {
    let mut serial = serial;
    let project_device_scope = KeyScope::Device(device_id.to_string());
    let fdsk_id = KeyId { scope: project_device_scope.clone(), kind: KeyKind::Fdsk };
    let tool_id = KeyId { scope: project_device_scope, kind: KeyKind::ToolKey };
    let fdsk_record = source.read(&fdsk_id, None)?;
    let tool_record = source.read(&tool_id, None)?;
    let mut provenance = Vec::new();
    if let Some(record) = &fdsk_record {
        merge_serial(&mut serial, record.embedded_serial, "FDSK label")?;
    }
    let keyring_device =
        select_keyring_device(keyring, serial, address, DeviceMatchPolicy::Resolve)?.map(|(_, device)| device);
    if let Some(device) = keyring_device {
        merge_serial(&mut serial, device.serial, "ETS keyring")?;
    }
    let mut fdsk = take_project_secret(fdsk_record, &mut provenance)?;
    let mut tool_key = take_project_secret(tool_record, &mut provenance)?;
    let imported_scope = imported_device_scope(serial, address);
    merge_imported_secret(
        &mut fdsk,
        keyring_device.and_then(KeyringDevice::fdsk).map(|key| SecretBytes::new(key.as_slice())),
        KeyId { scope: imported_scope.clone(), kind: KeyKind::Fdsk },
        &mut provenance,
        "FDSK",
    )?;
    merge_imported_secret(
        &mut tool_key,
        keyring_device.and_then(KeyringDevice::tool_key).map(|key| SecretBytes::new(key.as_slice())),
        KeyId { scope: imported_scope, kind: KeyKind::ToolKey },
        &mut provenance,
        "tool key",
    )?;

    let generate = tool_key.is_none() && fdsk.is_some();
    let mut material =
        ResolvedKeyMaterial::default().with_management_secrets(fdsk, tool_key).with_provenance(provenance);
    if let Some(serial) = serial {
        material = material.with_serial_number(serial);
    }
    Ok((if generate { material.requiring_tool_key_generation() } else { material }, keyring_device))
}

fn resolve_ip_secure_configuration(
    device: &MaterializedDevice<Unkeyed>,
    device_id: &str,
    source: &dyn KeyMaterialSource,
    keyring: Option<&Keyring>,
    keyring_device: Option<&KeyringDevice>,
    provenance: &mut Vec<KeyMetadata>,
) -> Result<Option<ResolvedIpSecureConfiguration>> {
    let Some(ip) = device.topology().ip.as_ref() else { return Ok(None) };
    let Some(intent) = ip.security.as_ref() else { return Ok(None) };

    validate_imported_backbone(keyring, ip.routing_multicast_address, intent.multicast_latency_tolerance_ms)?;

    let routing_secure = intent.routing == IpServiceSecurity::Secure;
    let user_security =
        intent.device_management == IpServiceSecurity::Secure || intent.tunnelling == IpServiceSecurity::Secure;

    let backbone_id = KeyId { scope: KeyScope::IpBackbone, kind: KeyKind::BackboneKey };
    let mut backbone_key =
        if routing_secure { take_project_secret(source.read(&backbone_id, None)?, provenance)? } else { None };
    let imported_backbone = routing_secure
        .then(|| {
            keyring
                .and_then(|keys| keys.backbone.as_ref())
                .and_then(|backbone| backbone.key())
                .map(|key| SecretBytes::new(key.as_slice()))
        })
        .flatten();
    merge_imported_secret(&mut backbone_key, imported_backbone, backbone_id, provenance, "IP Secure backbone key")?;
    if routing_secure && backbone_key.is_none() {
        return Err(ProjectSetupRequirement::BackboneKey { device: ProjectDeviceId(device_id.into()) }.into());
    }

    let dac_id = KeyId { scope: KeyScope::IpInterface(device_id.to_string()), kind: KeyKind::DeviceAuthenticationCode };
    let mut device_authentication_code =
        if user_security { take_project_secret(source.read(&dac_id, None)?, provenance)? } else { None };
    let imported_dac = if user_security {
        imported_authentication_code(keyring, keyring_device, device.individual_address())?
    } else {
        None
    };
    merge_imported_secret(
        &mut device_authentication_code,
        imported_dac,
        dac_id,
        provenance,
        "IP Secure Device Authentication Code",
    )?;
    if user_security && device_authentication_code.is_none() {
        return Err(
            ProjectSetupRequirement::DeviceAuthenticationCode { device: ProjectDeviceId(device_id.into()) }.into()
        );
    }

    let mut password_hashes = Vec::new();
    if user_security {
        for &user_id in &ip.password_users {
            let id = KeyId {
                scope: KeyScope::IpUser { interface: device_id.to_string(), user_id },
                kind: KeyKind::IpPasswordHash,
            };
            let mut value = take_project_secret(source.read(&id, None)?, provenance)?;
            let description = format!("IP Secure password hash for user {user_id}");
            let imported = imported_password_hash(keyring, keyring_device, device.individual_address(), user_id)?;
            merge_imported_secret(&mut value, imported, id, provenance, &description)?;
            let value = value.ok_or_else(|| {
                Error::from(ProjectSetupRequirement::IpPasswordHash {
                    device: ProjectDeviceId(device_id.into()),
                    user: user_id,
                })
            })?;
            password_hashes.push((user_id, value));
        }
    }

    Ok(Some(ResolvedIpSecureConfiguration { backbone_key, device_authentication_code, password_hashes }))
}

fn take_project_secret(record: Option<KeyRecord>, provenance: &mut Vec<KeyMetadata>) -> Result<Option<SecretBytes>> {
    let Some(record) = record else { return Ok(None) };
    record.value.key16_ref().map_err(KeyStoreError::from)?;
    provenance.push(record.metadata);
    Ok(Some(record.value))
}

fn merge_imported_secret(
    current: &mut Option<SecretBytes>,
    incoming: Option<SecretBytes>,
    id: KeyId,
    provenance: &mut Vec<KeyMetadata>,
    what: &str,
) -> Result<()> {
    let Some(incoming) = incoming else { return Ok(()) };
    let metadata = secret_metadata(id, &incoming, KeyOrigin::Imported, KeyEncoding::Binary);
    merge_secret(current, incoming, || format!("conflicting values for {what}"))?;
    // Equality corroborates the original value and retains both origins.
    provenance.push(metadata);
    Ok(())
}

fn merge_project_siat(
    device: &MaterializedDevice<Unkeyed>,
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
    rows.remove(&device.individual_address());
    if let Some(device) = keyring_device {
        rows.remove(&device.individual_address);
    }
    rows.into_iter().collect()
}

fn imported_device_scope(serial: Option<[u8; 6]>, address: IndividualAddress) -> KeyScope {
    KeyScope::Device(serial.map_or_else(
        || format!("ia:{}", u16::from_be_bytes(address.0)),
        |serial| format!("serial:{}", format_serial(&serial)),
    ))
}

/// A generated key belongs to the logical device receiving the durable write,
/// even when its only FDSK provenance came from a serial-addressed ETS entry.
pub(super) fn install_generated_tool_key(material: &mut ResolvedKeyMaterial, device: &ProjectDeviceId, key: [u8; 16]) {
    let metadata = secret_metadata(
        KeyId { scope: KeyScope::Device(device.0.clone()), kind: KeyKind::ToolKey },
        &key.into(),
        KeyOrigin::Generated,
        KeyEncoding::Hex,
    );
    material.install_generated_tool_key(key, metadata);
}

fn secret_metadata(id: KeyId, value: &SecretBytes, origin: KeyOrigin, encoding: KeyEncoding) -> KeyMetadata {
    KeyMetadata { id, epoch: None, origin, encoding, state: KeyState::Active, fingerprint: value.fingerprint() }
}

fn resolve_group_objects(
    device: &MaterializedDevice<Unkeyed>,
    groups: &BTreeMap<GroupAddress, GroupObjectProtection>,
) -> Result<Vec<GroupObjectSecurity>> {
    let mut objects = BTreeMap::new();
    for membership in device.object_memberships() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{
        InstallationConfiguration, ObjectMembership, SecurityIntent, ToolManagedIpConfiguration,
    };
    use std::num::NonZeroU8;
    use zweidraehte_ets_files::keyring::{derive_ip_device_authentication_code, derive_ip_user_password_hash};
    use zweidraehte_project::{IpAssignment, IpSecurityIntent, IpTunnellingUserBinding, ProjectInstallationId};
    use zweidraehte_project::{KeyEpoch, KeyStoreError};

    const GROUP_KEY: [u8; 16] = [0xA5; 16];
    const TOOL_KEY: [u8; 16] = [0x5A; 16];
    const FDSK: [u8; 16] = [0x11; 16];

    #[test]
    fn data_secure_enablement_and_tables_must_agree() {
        let mut configuration = configuration();
        let security = SecurityConfig::default();
        assert!(validate_application_security(&device(&configuration), None).is_err());
        assert!(validate_application_security(&device(&configuration), Some(&security)).is_ok());

        configuration.security.data_secure_enabled = false;
        assert!(validate_application_security(&device(&configuration), Some(&security)).is_err());
        assert!(validate_application_security(&device(&configuration), None).is_ok());
    }

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

    fn configuration() -> InstallationConfiguration {
        let ga = GroupAddress::from_three_level(1, 2, 3);
        InstallationConfiguration {
            object_memberships: vec![ObjectMembership::primary(ga, 0)],
            security: SecurityIntent {
                serial_number: Some([0, 0xFA, 0, 0, 0, 1]),
                data_secure_enabled: true,
                net_security: BTreeMap::from([(ga, NetSecurityPolicy::AuthenticationConfidentiality)]),
            },
            ..InstallationConfiguration::new(IndividualAddress::new(1, 1, 42))
        }
    }

    /// Key resolution reads an evaluated device; these tests vary only its
    /// installation choices.
    fn device(installation: &InstallationConfiguration) -> MaterializedDevice<Unkeyed> {
        MaterializedDevice::from_parts(Default::default(), installation.clone(), Default::default())
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
        let resolved = resolve_project_key_material(
            &device(&configuration()),
            "button",
            &net_ids(),
            &[(IndividualAddress::new(1, 1, 10), 44)],
            &project_source(),
            None,
            true,
        )
        .expect("security resolves");
        assert!(resolved.needs_tool_key_generation());
        assert!(!format!("{resolved:?}").contains("11111111111111111111111111111111"));
        let security = resolved.application_security().expect("secure product has tables");
        assert_eq!(security.group_keys().len(), 1);
        assert_eq!(security.siat(), [(IndividualAddress::new(1, 1, 10), 44)]);
        assert_eq!(security.group_objects()[0].com_object, 0);
    }

    #[test]
    fn plain_policy_ignores_a_retained_group_key() {
        let mut configuration = configuration();
        configuration.security.net_security.values_mut().for_each(|policy| *policy = NetSecurityPolicy::Plain);

        let resolved = resolve_project_key_material(
            &device(&configuration),
            "button",
            &net_ids(),
            &[],
            &project_source(),
            None,
            true,
        )
        .expect("plain policy resolves without using the group key");

        assert_eq!(resolved.secured_groups()[&GroupAddress::from_three_level(1, 2, 3)], GroupObjectProtection::Plain,);
        assert_eq!(resolved.application_security().expect("Data Secure remains enabled").group_keys().len(), 0);
        assert!(resolved.provenance().iter().all(|metadata| metadata.id.kind != KeyKind::GroupKey));
    }

    #[test]
    fn ip_secure_secrets_resolve_without_entering_the_public_topology() {
        let user = NonZeroU8::new(1).expect("user one is nonzero");
        let mut configuration = configuration();
        configuration.topology.ip = Some(ToolManagedIpConfiguration {
            project_installation_id: ProjectInstallationId::new(42, 1).expect("valid project ID"),
            assignment: IpAssignment::AutomaticDhcp,
            routing_multicast_address: [224, 0, 23, 12],
            multicast_ttl: 16,
            friendly_name: "KNX IP Router".into(),
            additional_individual_addresses: vec![IndividualAddress::new(1, 1, 43)],
            security: Some(IpSecurityIntent {
                routing: IpServiceSecurity::Secure,
                device_management: IpServiceSecurity::Secure,
                tunnelling: IpServiceSecurity::Secure,
                multicast_latency_tolerance_ms: 50,
                sync_latency_fraction: 4,
                tunnelling_users: vec![IpTunnellingUserBinding { user_id: user, address_index: 1 }],
            }),
            password_users: vec![user],
        });
        let mut source = project_source();
        source.add(KeyScope::IpBackbone, KeyKind::BackboneKey, [0x31; 16], KeyOrigin::Manual);
        source.add(
            KeyScope::IpInterface("button".into()),
            KeyKind::DeviceAuthenticationCode,
            [0x32; 16],
            KeyOrigin::Manual,
        );
        source.add(
            KeyScope::IpUser { interface: "button".into(), user_id: user },
            KeyKind::IpPasswordHash,
            [0x33; 16],
            KeyOrigin::Manual,
        );

        let resolved =
            resolve_project_key_material(&device(&configuration), "button", &net_ids(), &[], &source, None, true)
                .expect("IP Secure material resolves");
        let ip = resolved.ip_secure().expect("private IP Secure material exists");

        assert_eq!(ip.backbone_key.as_ref().expect("backbone key").key16().expect("key width"), [0x31; 16]);
        assert_eq!(ip.device_authentication_code.as_ref().expect("DAC").key16().expect("key width"), [0x32; 16]);
        assert_eq!(ip.password_hashes[0].0, user);
        assert_eq!(ip.password_hashes[0].1.key16().expect("hash width"), [0x33; 16]);
        let diagnostic = format!("{resolved:?}");
        assert!(!diagnostic.contains("31313131"));
        assert!(diagnostic.contains("[REDACTED]"));

        // Device and hosted-interface imports corroborate project credentials.
        // Foreign hosts and unused users must not introduce conflicts.
        source.0.retain(|record| matches!(record.metadata.id.scope, KeyScope::Device(_) | KeyScope::Group(_)));
        source.add(KeyScope::IpBackbone, KeyKind::BackboneKey, [0x31; 16], KeyOrigin::Manual);
        source.add(
            KeyScope::IpInterface("button".into()),
            KeyKind::DeviceAuthenticationCode,
            derive_ip_device_authentication_code("router auth"),
            KeyOrigin::Manual,
        );
        source.add(
            KeyScope::IpUser { interface: "button".into(), user_id: user },
            KeyKind::IpPasswordHash,
            derive_ip_user_password_hash("router password"),
            KeyOrigin::Manual,
        );
        let interface = zweidraehte_ets_files::keyring::KeyringInterface::new(
            zweidraehte_ets_files::keyring::KeyringInterfaceType::Tunneling,
            IndividualAddress::new(1, 1, 43),
        )
        .with_host(Some(configuration.individual_address))
        .with_user_id(Some(1))
        .with_authentication(Some("router auth".into()))
        .with_password(Some("router password".into()));
        for conflict in 0..4 {
            let mut candidate = interface.clone();
            match conflict {
                1 => candidate = candidate.with_authentication(Some("different auth".into())),
                2 => candidate = candidate.with_password(Some("different password".into())),
                3 => candidate = candidate.with_user_id(Some(2)).with_password(Some("unused password".into())),
                _ => {}
            }
            let foreign = interface
                .clone()
                .with_host(Some(IndividualAddress::new(2, 1, 42)))
                .with_authentication(Some("foreign auth".into()))
                .with_password(Some("foreign password".into()));
            let keys = keyring(
                keyring_device()
                    .with_authentication(Some("router auth".into()))
                    .with_management_password(Some("router password".into())),
                GROUP_KEY,
                Vec::new(),
            )
            .with_backbone(Some(
                zweidraehte_ets_files::keyring::KeyringBackbone::new(None, None).with_key(Some([0x31; 16])),
            ))
            .with_interfaces(vec![candidate, foreign]);
            let merged = resolve_project_key_material(
                &device(&configuration),
                "button",
                &net_ids(),
                &[],
                &source,
                Some(&keys),
                true,
            );
            if conflict == 1 || conflict == 2 {
                let error = merged.expect_err("selected imported credentials disagree").to_string();
                assert!(error.contains("conflicting ETS keyring values"));
                assert!(!error.contains("router auth") && !error.contains("router password"));
            } else {
                let merged = merged.expect("equal and irrelevant imported candidates");
                for kind in [KeyKind::BackboneKey, KeyKind::DeviceAuthenticationCode, KeyKind::IpPasswordHash] {
                    let origins: BTreeSet<_> =
                        merged.provenance().iter().filter(|row| row.id.kind == kind).map(|row| row.origin).collect();
                    assert_eq!(origins, BTreeSet::from([KeyOrigin::Manual, KeyOrigin::Imported]));
                }
            }
        }
    }

    #[test]
    fn ip_secure_service_changes_require_secure_management_credentials() {
        let mut configuration = configuration();
        configuration.security.net_security.values_mut().for_each(|policy| *policy = NetSecurityPolicy::Plain);
        configuration.topology.ip = Some(ToolManagedIpConfiguration {
            project_installation_id: ProjectInstallationId::new(42, 1).expect("valid project ID"),
            assignment: IpAssignment::AutomaticDhcp,
            routing_multicast_address: [224, 0, 23, 12],
            multicast_ttl: 16,
            friendly_name: "KNX IP Router".into(),
            additional_individual_addresses: Vec::new(),
            security: Some(IpSecurityIntent {
                routing: IpServiceSecurity::Plain,
                device_management: IpServiceSecurity::Plain,
                tunnelling: IpServiceSecurity::Plain,
                multicast_latency_tolerance_ms: 50,
                sync_latency_fraction: 4,
                tunnelling_users: Vec::new(),
            }),
            password_users: Vec::new(),
        });

        let error = resolve_project_key_material(
            &device(&configuration),
            "router",
            &net_ids(),
            &[],
            &TestSource::default(),
            None,
            false,
        )
        .expect_err("IP Secure service configuration cannot use plaintext management");
        assert!(error.to_string().contains("tool key or FDSK"));
    }

    #[test]
    fn conflicting_object_policies_fail_before_lowering() {
        let mut configuration = configuration();
        let second = GroupAddress::from_three_level(1, 2, 4);
        configuration.object_memberships.push(ObjectMembership {
            group_address: second,
            com_object: 0,
            role: crate::configuration::MembershipRole::Additional,
        });
        configuration.security.net_security.insert(second, NetSecurityPolicy::Plain);
        assert!(
            resolve_project_key_material(
                &device(&configuration),
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

        configuration
            .security
            .net_security
            .insert(GroupAddress::from_three_level(1, 2, 3), NetSecurityPolicy::Automatic);
        let error = resolve_project_key_material(
            &device(&configuration),
            "button",
            &BTreeMap::from([(GroupAddress::from_three_level(1, 2, 3), "switch".into()), (second, "plain".into())]),
            &[],
            &project_source(),
            None,
            true,
        )
        .expect_err("automatic policy resolves before per-object comparison");
        assert!(error.to_string().contains("incompatible security policies"));
    }

    fn keyring(device: KeyringDevice, group_key: [u8; 16], senders: Vec<IndividualAddress>) -> Keyring {
        let group = u16::from_be_bytes(GroupAddress::from_three_level(1, 2, 3).0);
        Keyring::new("test".to_string(), "test".to_string(), "2026-08-24T00:00:00Z".to_string())
            .with_interfaces(vec![
                zweidraehte_ets_files::keyring::KeyringInterface::new(
                    zweidraehte_ets_files::keyring::KeyringInterfaceType::Usb,
                    IndividualAddress::new(1, 1, 250),
                )
                .with_group_addresses(vec![(group, senders)]),
            ])
            .with_group_keys(BTreeMap::from([(group, group_key)]))
            .with_devices(vec![device])
    }

    fn keyring_device() -> KeyringDevice {
        KeyringDevice::new(IndividualAddress::new(1, 1, 42))
            .with_tool_key(Some(TOOL_KEY))
            .with_fdsk(Some(FDSK))
            .with_serial(Some([0, 0xFA, 0, 0, 0, 1]))
            .with_sequence_number(100)
    }

    #[test]
    fn keyring_only_material_resolves_and_seeds_siat() {
        let sender = IndividualAddress::new(1, 1, 10);
        let mut sender_device = keyring_device();
        sender_device.individual_address = sender;
        sender_device.serial = Some([0, 0xFA, 0, 0, 0, 2]);
        sender_device.sequence_number = 1234;

        let mut keys = keyring(keyring_device(), GROUP_KEY, vec![sender, configuration().individual_address]);
        keys.devices.push(sender_device);

        let resolved = resolve_project_key_material(
            &device(&configuration()),
            "button",
            &net_ids(),
            &[],
            &TestSource::default(),
            Some(&keys),
            true,
        )
        .expect("keyring resolves");
        assert_eq!(resolved.tool_key(), Some(&TOOL_KEY));
        assert_eq!(resolved.fdsk(), Some(&FDSK));
        assert_eq!(resolved.application_security().expect("secure tables").siat(), [(sender, 1234)]);
    }

    #[test]
    fn equal_mixed_sources_merge_but_conflicting_values_fail() {
        let mut source = project_source();
        source.add(KeyScope::Device("button".into()), KeyKind::ToolKey, TOOL_KEY, KeyOrigin::Manual);
        let matching = keyring(keyring_device(), GROUP_KEY, Vec::new());
        let resolved = resolve_project_key_material(
            &device(&configuration()),
            "button",
            &net_ids(),
            &[],
            &source,
            Some(&matching),
            true,
        )
        .expect("equal sources merge");
        let origins: BTreeSet<_> = resolved.provenance().iter().map(|metadata| metadata.origin).collect();
        assert_eq!(origins, BTreeSet::from([KeyOrigin::Manual, KeyOrigin::Imported, KeyOrigin::DeviceLabel]));

        let conflicting = keyring(keyring_device(), [0xCC; 16], Vec::new());
        assert!(matches!(
            resolve_project_key_material(&device(&configuration()),
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
        let resolved = resolve_project_key_material(
            &device(&configuration()),
            "button",
            &net_ids(),
            &[(sender, 1234)],
            &source,
            Some(&keys),
            true,
        )
        .expect("sources merge");
        let security = resolved.application_security().expect("secure tables");
        assert_eq!(security.siat(), [(sender, 1234)]);
    }

    #[test]
    fn explicit_secure_policy_requires_a_group_key() {
        let mut source = TestSource::default();
        source.add(KeyScope::Device("button".into()), KeyKind::ToolKey, TOOL_KEY, KeyOrigin::Manual);
        assert!(matches!(
            resolve_project_key_material(&device(&configuration()),
                "button",
                &net_ids(),
                &[],
                &source,
                None,
                true,
            ),
            Err(Error::ProjectSetup(ProjectSetupRequirement::GroupKey { net })) if net == NetId("switch".into())
        ));
    }

    #[test]
    fn disabled_device_rejects_an_explicit_secure_net() {
        let mut configuration = configuration();
        configuration.security.data_secure_enabled = false;
        let error = resolve_project_key_material(
            &device(&configuration),
            "button",
            &net_ids(),
            &[],
            &project_source(),
            None,
            false,
        )
        .expect_err("disabled application rejects secure membership");
        assert!(error.to_string().contains("Data Secure disabled"));
        assert!(error.to_string().contains("net `switch`"));
    }

    #[test]
    fn disabled_device_rejects_automatic_net_when_a_key_makes_it_secure() {
        let mut configuration = configuration();
        configuration.security.data_secure_enabled = false;
        configuration
            .security
            .net_security
            .insert(GroupAddress::from_three_level(1, 2, 3), NetSecurityPolicy::Automatic);
        let error = resolve_project_key_material(
            &device(&configuration),
            "button",
            &net_ids(),
            &[],
            &project_source(),
            None,
            false,
        )
        .expect_err("automatic key protection rejects disabled application");
        assert!(error.to_string().contains("automatic policy secures net `switch`"));
    }

    #[test]
    fn disabled_device_accepts_automatic_net_without_a_key() {
        let mut configuration = configuration();
        configuration.security.data_secure_enabled = false;
        configuration
            .security
            .net_security
            .insert(GroupAddress::from_three_level(1, 2, 3), NetSecurityPolicy::Automatic);
        let resolved = resolve_project_key_material(
            &device(&configuration),
            "button",
            &net_ids(),
            &[],
            &TestSource::default(),
            None,
            false,
        )
        .expect("keyless automatic net remains plain");
        assert!(resolved.application_security().is_none());
        assert_eq!(resolved.secured_groups()[&GroupAddress::from_three_level(1, 2, 3)], GroupObjectProtection::Plain);
    }
}
