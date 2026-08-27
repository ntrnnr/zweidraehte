use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::model::{
    AuthoredProject, NetId, NetSecurityPolicy, ObjectFlagOverrides, ParamValue, ProjectDevice, ProjectDeviceId,
};
use crate::state::{DeploymentFingerprints, MutableProjectState};

#[derive(Debug, Clone, PartialEq)]
pub enum ProjectCommand {
    SetParameter { device: ProjectDeviceId, parameter: String, value: ParamValue },
    SetObjectFlags { device: ProjectDeviceId, com_object: u16, flags: ObjectFlagOverrides },
    SetMemberships { device: ProjectDeviceId, com_object: u16, primary: NetId, additional: Vec<NetId> },
    SetNetSecurity { net: NetId, policy: NetSecurityPolicy },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImpactReason {
    Selected,
    Identity,
    ProductOrParameters,
    ObjectFlags,
    Memberships,
    NetSecurity,
    SiatDependency,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectImpact {
    pub selected: BTreeSet<ProjectDeviceId>,
    pub affected: BTreeMap<ProjectDeviceId, BTreeSet<ImpactReason>>,
}

impl ProjectImpact {
    pub fn closure(&self) -> BTreeSet<ProjectDeviceId> {
        self.affected.keys().cloned().collect()
    }

    pub fn requires_other_devices(&self) -> bool {
        self.affected.keys().any(|device| !self.selected.contains(device))
    }
}

impl AuthoredProject {
    pub fn fingerprints(&self, device_id: &ProjectDeviceId) -> Option<DeploymentFingerprints> {
        let device = self.devices.get(device_id)?;
        Some(self.fingerprint_device(device))
    }

    pub fn impact(&self, state: Option<&MutableProjectState>, selected: &[ProjectDeviceId]) -> ProjectImpact {
        let selected: BTreeSet<_> = selected.iter().cloned().collect();
        let mut impact = ProjectImpact { selected: selected.clone(), affected: BTreeMap::new() };
        for device_id in &selected {
            impact.affected.entry(device_id.clone()).or_default().insert(ImpactReason::Selected);
            let Some(device) = self.devices.get(device_id) else { continue };
            let current = self.fingerprint_device(device);
            let deployed = state.and_then(|state| state.deployments.get(&device_id.0));
            let Some(deployed) = deployed else {
                // Adding a new secure sender changes existing receivers'
                // complete SIAT even though this device has no prior state.
                self.add_net_consumers(
                    &mut impact,
                    &current.sender_nets.iter().cloned().collect(),
                    ImpactReason::SiatDependency,
                );
                continue;
            };
            let mut dependency_nets: BTreeSet<String> = current.secured_nets.iter().cloned().collect();
            dependency_nets.extend(deployed.secured_nets.iter().cloned());

            if current.identity != deployed.identity
                || (!deployed.medium_configuration.is_empty()
                    && current.medium_configuration != deployed.medium_configuration)
            {
                add_reason(&mut impact, device_id, ImpactReason::Identity);
                self.add_net_consumers(&mut impact, &dependency_nets, ImpactReason::SiatDependency);
            }
            if current.product_parameters != deployed.product_parameters {
                add_reason(&mut impact, device_id, ImpactReason::ProductOrParameters);
            }
            if current.object_flags != deployed.object_flags {
                add_reason(&mut impact, device_id, ImpactReason::ObjectFlags);
                let mut sender_nets: BTreeSet<String> = current.sender_nets.iter().cloned().collect();
                sender_nets.extend(deployed.sender_nets.iter().cloned());
                self.add_net_consumers(&mut impact, &sender_nets, ImpactReason::SiatDependency);
            }
            if current.memberships != deployed.memberships {
                add_reason(&mut impact, device_id, ImpactReason::Memberships);
                self.add_net_consumers(&mut impact, &dependency_nets, ImpactReason::SiatDependency);
            }
            if current.net_security != deployed.net_security {
                add_reason(&mut impact, device_id, ImpactReason::NetSecurity);
                self.add_net_consumers(&mut impact, &dependency_nets, ImpactReason::NetSecurity);
            }
            if current.siat_dependencies != deployed.siat_dependencies {
                add_reason(&mut impact, device_id, ImpactReason::SiatDependency);
            }
        }
        impact
    }

    fn fingerprint_device(&self, device: &ProjectDevice) -> DeploymentFingerprints {
        let mut identity = format!("{}|", device.address);
        if let Some(serial) = device.serial {
            for byte in serial {
                identity.push_str(&format!("{byte:02X}"));
            }
        }
        let product_parameters = format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}",
            device.product, device.catalog_product, device.application_program, device.data_secure, device.parameters
        );
        let object_flags = device
            .objects
            .values()
            .map(|object| format!("{}:{:?}", object.com_object, object.flags))
            .collect::<Vec<_>>()
            .join("|");
        let memberships = device
            .objects
            .values()
            .flat_map(|object| {
                object
                    .memberships
                    .iter()
                    .map(move |membership| format!("{}:{:?}:{}", object.com_object, membership.role, membership.net))
            })
            .collect::<Vec<_>>()
            .join("|");
        let linked_nets: BTreeSet<_> = device
            .objects
            .values()
            .flat_map(|object| object.memberships.iter().map(|membership| membership.net.clone()))
            .collect();
        let net_security = linked_nets
            .iter()
            .filter_map(|id| {
                self.nets.get(id).map(|net| format!("{}:{}:{}:{:?}", id, net.address, net.dpt, net.security))
            })
            .collect::<Vec<_>>()
            .join("|");
        let secured_nets: Vec<String> = linked_nets
            .iter()
            .filter(|id| self.nets.get(*id).is_some_and(|net| net.security != NetSecurityPolicy::Plain))
            .map(|id| id.0.clone())
            .collect();
        let sender_nets: Vec<String> = linked_nets
            .iter()
            .filter(|net| self.explicit_sender_devices(net).contains(&device.id))
            .map(|net| net.0.clone())
            .collect();
        let siat_dependencies = format!("{}|{}", secured_nets.join(","), sender_nets.join(","));

        DeploymentFingerprints {
            identity: fingerprint(&identity),
            medium_configuration: fingerprint(&format!("{:?}", device.medium)),
            application: fingerprint(&format!(
                "{:?}|{:?}|{:?}",
                device.product, device.catalog_product, device.application_program
            )),
            parameters: fingerprint(&format!("{:?}", device.parameters)),
            product_parameters: fingerprint(&product_parameters),
            object_flags: fingerprint(&object_flags),
            memberships: fingerprint(&memberships),
            net_security: fingerprint(&net_security),
            siat_dependencies: fingerprint(&siat_dependencies),
            secured_nets,
            sender_nets,
            individual_address: device.address.to_string(),
        }
    }

    fn add_net_consumers(&self, impact: &mut ProjectImpact, nets: &BTreeSet<String>, reason: ImpactReason) {
        for device in self.devices.values() {
            let consumes = device
                .objects
                .values()
                .any(|object| object.memberships.iter().any(|membership| nets.contains(&membership.net.0)));
            if consumes {
                add_reason(impact, &device.id, reason);
            }
        }
    }
}

fn add_reason(impact: &mut ProjectImpact, device: &ProjectDeviceId, reason: ImpactReason) {
    impact.affected.entry(device.clone()).or_default().insert(reason);
}

fn fingerprint(value: &str) -> String {
    Sha256::digest(value.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthoredProject, ProjectEvent};

    const PROJECT: &str = r#"ga n = 1/0/1
net n : 1.001 { security authentication_confidentiality }
area 1 a { line 1 l { medium tp1
device a { product local:"a.mtxml" address 1.1.1 object 0 { on n flags { communication true transmit true } } }
device b { product local:"b.mtxml" address 1.1.2 object 0 { on n flags { communication true write true } } }
} }
"#;

    #[test]
    fn sender_flag_change_affects_other_secured_net_consumers() {
        let original = AuthoredProject::parse(PROJECT).expect("project parses");
        let mut state = MutableProjectState::new("state".into());
        for id in [ProjectDeviceId("a".into()), ProjectDeviceId("b".into())] {
            state.apply(&ProjectEvent::RecordDeployment {
                device: id.0.clone(),
                fingerprints: original.fingerprints(&id).expect("device exists"),
                mcb: Vec::new(),
            });
        }
        let changed =
            AuthoredProject::parse(PROJECT.replace("transmit true", "transmit false")).expect("project parses");
        let impact = changed.impact(Some(&state), &[ProjectDeviceId("a".into())]);
        assert!(impact.closure().contains(&ProjectDeviceId("b".into())));
    }

    #[test]
    fn parameter_only_change_stays_on_one_device() {
        let project = AuthoredProject::parse(PROJECT).expect("project parses");
        let mut state = MutableProjectState::new("state".into());
        let id = ProjectDeviceId("a".into());
        state.apply(&ProjectEvent::RecordDeployment {
            device: id.0.clone(),
            fingerprints: project.fingerprints(&id).expect("device exists"),
            mcb: Vec::new(),
        });
        let changed =
            AuthoredProject::parse(PROJECT.replace("address 1.1.1", "address 1.1.1 param \"M-00FA_A-1_P-1\" = 1"))
                .expect("changed project parses");
        let impact = changed.impact(Some(&state), std::slice::from_ref(&id));
        assert_eq!(impact.closure(), BTreeSet::from([id]));
    }

    #[test]
    fn editor_language_does_not_change_download_fingerprints() {
        let original = AuthoredProject::parse(PROJECT).expect("project parses");
        let changed = AuthoredProject::parse(
            PROJECT.replace("product local:\"a.mtxml\"", "product local:\"a.mtxml\" language \"de-DE\""),
        )
        .expect("project with language parses");
        let id = ProjectDeviceId("a".into());
        assert_eq!(original.fingerprints(&id), changed.fingerprints(&id));
    }

    #[test]
    fn changing_a_group_address_changes_every_linked_device_fingerprint() {
        let original = AuthoredProject::parse(PROJECT).expect("project parses");
        let changed = AuthoredProject::parse(PROJECT.replace("1/0/1", "1/0/2")).expect("changed project parses");
        for id in [ProjectDeviceId("a".into()), ProjectDeviceId("b".into())] {
            assert_ne!(
                original.fingerprints(&id).expect("device exists").net_security,
                changed.fingerprints(&id).expect("device exists").net_security
            );
        }
    }
}
