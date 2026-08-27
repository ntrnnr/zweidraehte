use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SenderIdentity {
    ManagedSerial(String),
    UnmanagedAddress(String),
}

// JSON requires object keys to be strings. Sender identities occur both as
// event values and as keys in the compact snapshot's SIAT maps, so one stable
// tagged string representation must serve both places.
impl Serialize for SenderIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::ManagedSerial(serial) => serializer.serialize_str(&format!("serial:{serial}")),
            Self::UnmanagedAddress(address) => serializer.serialize_str(&format!("ia:{address}")),
        }
    }
}

impl<'de> Deserialize<'de> for SenderIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Representation {
            TaggedString(String),
            LegacyObject { kind: String, value: String },
        }

        match Representation::deserialize(deserializer)? {
            Representation::TaggedString(encoded) => {
                if let Some(serial) = encoded.strip_prefix("serial:") {
                    return Ok(Self::ManagedSerial(serial.to_string()));
                }
                if let Some(address) = encoded.strip_prefix("ia:") {
                    return Ok(Self::UnmanagedAddress(address.to_string()));
                }
            }
            // Early project-store builds wrote this object form into journal
            // events. Keep accepting it so opening a project upgrades it on
            // the next compact rather than stranding sequence observations.
            Representation::LegacyObject { kind, value } => match kind.as_str() {
                "managed_serial" => return Ok(Self::ManagedSerial(value)),
                "unmanaged_address" => return Ok(Self::UnmanagedAddress(value)),
                _ => {}
            },
        }
        Err(de::Error::custom("sender identity needs a serial: or ia: prefix"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSequenceObservation {
    /// The device's next outgoing secure sequence number (PID 59).
    pub outgoing_next: u64,
    /// Last-valid values observed in the device's live SIAT, keyed by sender.
    pub siat_last_valid: BTreeMap<SenderIdentity, u64>,
}

/// Durable evidence for the five programming columns ETS exposes per device.
///
/// The flags say that the corresponding part was successfully programmed;
/// callers still compare its deployment fingerprint with the current desired
/// value before displaying it as complete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceProgrammingStatus {
    pub individual_address: bool,
    pub application_program: bool,
    pub parameters: bool,
    pub group_communication: bool,
    pub medium_configuration: bool,
}

impl DeviceProgrammingStatus {
    pub const ALL: Self = Self {
        individual_address: true,
        application_program: true,
        parameters: true,
        group_communication: true,
        medium_configuration: true,
    };

    pub const NONE: Self = Self {
        individual_address: false,
        application_program: false,
        parameters: false,
        group_communication: false,
        medium_configuration: false,
    };

    pub const fn is_complete(self) -> bool {
        self.individual_address
            && self.application_program
            && self.parameters
            && self.group_communication
            && self.medium_configuration
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentFingerprints {
    pub identity: String,
    /// Medium-specific configuration, corresponding to ETS's Cfg column.
    /// Older snapshots omit it and retain their previous completed status.
    #[serde(default)]
    pub medium_configuration: String,
    /// Product/application definition independent of configured values.
    ///
    /// Older snapshots omit this field. An empty value deliberately forces
    /// one full download before differential programming becomes eligible.
    #[serde(default)]
    pub application: String,
    /// Effective authored parameter values, separate from the application so
    /// a parameter-only change can select a mask's `Load/par` procedure.
    #[serde(default)]
    pub parameters: String,
    /// Legacy combined value retained for state compatibility and concise
    /// status reporting.
    pub product_parameters: String,
    pub object_flags: String,
    pub memberships: String,
    pub net_security: String,
    pub siat_dependencies: String,
    #[serde(default)]
    pub secured_nets: Vec<String>,
    #[serde(default)]
    pub sender_nets: Vec<String>,
    #[serde(default)]
    pub individual_address: String,
}

/// Device-generated Memory Control Block values retained after a successful
/// download. The CRC fields are live deployment evidence, not desired
/// configuration, so they deliberately stay outside [`DeploymentFingerprints`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McbSnapshot {
    pub object_index: u8,
    pub start_index: u16,
    /// Immutable segments retain their device-generated CRC; application-
    /// mutable segments are `None` and do not participate in comparison.
    pub segment_crc: Vec<Option<u16>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutableProjectState {
    pub version: u32,
    pub state_id: String,
    /// Set while sequence state is being reconstructed from receivers. A
    /// project in this state may inspect the bus but must not originate a
    /// secure telegram until recovery is completed explicitly.
    #[serde(default)]
    pub recovery_required: bool,
    /// One sending counter for every secure telegram emitted by this client.
    pub client_next: u64,
    #[serde(default)]
    pub sender_floors: BTreeMap<SenderIdentity, u64>,
    #[serde(default)]
    pub devices: BTreeMap<String, DeviceSequenceObservation>,
    #[serde(default)]
    pub deployments: BTreeMap<String, DeploymentFingerprints>,
    /// Which parts of each deployment are still known to be present.
    ///
    /// Snapshots written before this field existed implicitly treated every
    /// `deployments` entry as complete; [`programming_status`](Self::programming_status)
    /// retains that compatibility.
    #[serde(default)]
    pub programming_statuses: BTreeMap<String, DeviceProgrammingStatus>,
    #[serde(default)]
    pub deployment_mcb: BTreeMap<String, Vec<McbSnapshot>>,
    #[serde(default)]
    pub deployed_group_keys: BTreeMap<String, String>,
    #[serde(default)]
    pub inconsistent_devices: Vec<String>,
}

impl MutableProjectState {
    pub fn new(state_id: String) -> Self {
        Self {
            version: 1,
            state_id,
            recovery_required: false,
            client_next: 1,
            sender_floors: BTreeMap::new(),
            devices: BTreeMap::new(),
            deployments: BTreeMap::new(),
            programming_statuses: BTreeMap::new(),
            deployment_mcb: BTreeMap::new(),
            deployed_group_keys: BTreeMap::new(),
            inconsistent_devices: Vec::new(),
        }
    }

    /// Return the last known physical programming state for a device.
    ///
    /// A deployment from an older snapshot predates component flags, so it is
    /// interpreted as the complete state those snapshots represented.
    pub fn programming_status(&self, device: &str) -> DeviceProgrammingStatus {
        self.programming_statuses.get(device).copied().unwrap_or_else(|| {
            if self.deployments.contains_key(device) {
                DeviceProgrammingStatus::ALL
            } else {
                DeviceProgrammingStatus::NONE
            }
        })
    }

    pub(crate) fn apply(&mut self, event: &ProjectEvent) {
        match event {
            ProjectEvent::AdvanceClient { next } => self.client_next = self.client_next.max(*next),
            ProjectEvent::ObserveSender { sender, last_valid } => {
                self.sender_floors
                    .entry(sender.clone())
                    .and_modify(|old| *old = (*old).max(*last_valid))
                    .or_insert(*last_valid);
            }
            ProjectEvent::ObserveDeviceOutgoing { serial, next } => {
                self.devices.entry(serial.clone()).or_default().outgoing_next =
                    self.devices.get(serial).map_or(*next, |old| old.outgoing_next.max(*next));
            }
            ProjectEvent::ObserveDeviceSiat { serial, sender, last_valid } => {
                let table = &mut self.devices.entry(serial.clone()).or_default().siat_last_valid;
                table.entry(sender.clone()).and_modify(|old| *old = (*old).max(*last_valid)).or_insert(*last_valid);
            }
            ProjectEvent::RecordDeployment { device, fingerprints, mcb } => {
                self.deployments.insert(device.clone(), fingerprints.clone());
                self.programming_statuses.insert(device.clone(), DeviceProgrammingStatus::ALL);
                self.deployment_mcb.insert(device.clone(), mcb.clone());
                self.inconsistent_devices.retain(|candidate| candidate != device);
            }
            ProjectEvent::RecordIndividualAddress { device, identity, individual_address } => {
                let mut status = self.programming_status(device);
                let deployment = self.deployments.entry(device.clone()).or_default();
                deployment.identity.clone_from(identity);
                deployment.individual_address.clone_from(individual_address);

                status.individual_address = true;
                self.programming_statuses.insert(device.clone(), status);
            }
            ProjectEvent::RecordUnload { device, preserve_network_configuration } => {
                let mut status = self.programming_status(device);
                status.application_program = false;
                status.parameters = false;
                status.group_communication = false;

                if !preserve_network_configuration {
                    status.individual_address = false;
                    status.medium_configuration = false;
                    self.inconsistent_devices.retain(|candidate| candidate != device);
                }

                self.programming_statuses.insert(device.clone(), status);
                self.deployment_mcb.remove(device);
            }
            ProjectEvent::RecordGroupKey { net, fingerprint } => {
                self.deployed_group_keys.insert(net.clone(), fingerprint.clone());
            }
            ProjectEvent::MarkGroupCommunicationStale { devices } => {
                for device in devices {
                    let mut status = self.programming_status(device);
                    status.group_communication = false;
                    self.programming_statuses.insert(device.clone(), status);
                }
            }
            ProjectEvent::MarkInconsistent { devices } => {
                for device in devices {
                    if !self.inconsistent_devices.contains(device) {
                        self.inconsistent_devices.push(device.clone());
                    }
                }
                self.inconsistent_devices.sort();
            }
            ProjectEvent::BeginRecovery => self.recovery_required = true,
            ProjectEvent::CompleteRecovery => self.recovery_required = false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
// Journal events are short-lived serialization values. Boxing the deployment
// payload would complicate the public event API without reducing owned data.
#[allow(clippy::large_enum_variant)]
pub enum ProjectEvent {
    AdvanceClient {
        next: u64,
    },
    ObserveSender {
        sender: SenderIdentity,
        last_valid: u64,
    },
    ObserveDeviceOutgoing {
        serial: String,
        next: u64,
    },
    ObserveDeviceSiat {
        serial: String,
        sender: SenderIdentity,
        last_valid: u64,
    },
    RecordDeployment {
        device: String,
        fingerprints: DeploymentFingerprints,
        /// Absent in journals created before differential programming.
        #[serde(default)]
        mcb: Vec<McbSnapshot>,
    },
    /// Record a verified address-only commissioning without claiming that
    /// any application component was written.
    RecordIndividualAddress {
        device: String,
        identity: String,
        individual_address: String,
    },
    /// Record a successful physical unload. Application-only unload retains
    /// the individual address and medium/network configuration.
    RecordUnload {
        device: String,
        preserve_network_configuration: bool,
    },
    RecordGroupKey {
        net: String,
        fingerprint: String,
    },
    /// A changed sender IA makes this device's downloaded Security
    /// Individual Address Table obsolete without invalidating its program,
    /// parameters, or other network configuration.
    MarkGroupCommunicationStale {
        devices: Vec<String>,
    },
    MarkInconsistent {
        devices: Vec<String>,
    },
    BeginRecovery,
    CompleteRecovery,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_identities_are_valid_json_map_keys() {
        let state = MutableProjectState {
            sender_floors: BTreeMap::from([
                (SenderIdentity::ManagedSerial("00FA:00000001".into()), 12),
                (SenderIdentity::UnmanagedAddress("1.1.250".into()), 34),
            ]),
            ..MutableProjectState::new("test-state".into())
        };
        let encoded = serde_json::to_string(&state).expect("state serializes");
        let decoded: MutableProjectState = serde_json::from_str(&encoded).expect("state deserializes");
        assert_eq!(decoded, state);
    }

    #[test]
    fn legacy_sender_identity_events_remain_readable() {
        let event: ProjectEvent = serde_json::from_str(
            r#"{"event":"observe_sender","sender":{"kind":"unmanaged_address","value":"1.1.250"},"last_valid":34}"#,
        )
        .expect("legacy event deserializes");
        assert_eq!(event, ProjectEvent::ObserveSender {
            sender: SenderIdentity::UnmanagedAddress("1.1.250".into()),
            last_valid: 34,
        });
    }

    #[test]
    fn deployment_events_without_mcb_evidence_remain_readable() {
        let event: ProjectEvent = serde_json::from_str(
            r#"{"event":"record_deployment","device":"relay","fingerprints":{"identity":"","application":"","parameters":"","product_parameters":"","object_flags":"","memberships":"","net_security":"","siat_dependencies":""}}"#,
        )
        .expect("legacy deployment event deserializes");
        let ProjectEvent::RecordDeployment { mcb, .. } = event else {
            panic!("deployment event expected");
        };
        assert!(mcb.is_empty());
    }

    #[test]
    fn application_unload_preserves_network_programming_evidence() {
        let mut state = MutableProjectState::new("test-state".into());
        state.deployments.insert("relay".into(), DeploymentFingerprints::default());

        state.apply(&ProjectEvent::RecordUnload { device: "relay".into(), preserve_network_configuration: true });

        assert_eq!(state.programming_status("relay"), DeviceProgrammingStatus {
            individual_address: true,
            application_program: false,
            parameters: false,
            group_communication: false,
            medium_configuration: true,
        });
    }

    #[test]
    fn complete_unload_clears_all_programming_evidence() {
        let mut state = MutableProjectState::new("test-state".into());
        state.deployments.insert("relay".into(), DeploymentFingerprints::default());

        state.apply(&ProjectEvent::RecordUnload { device: "relay".into(), preserve_network_configuration: false });

        assert_eq!(state.programming_status("relay"), DeviceProgrammingStatus::NONE);
    }

    #[test]
    fn address_only_programming_does_not_claim_application_components() {
        let mut state = MutableProjectState::new("test-state".into());

        state.apply(&ProjectEvent::RecordIndividualAddress {
            device: "relay".into(),
            identity: "identity".into(),
            individual_address: "1.1.1".into(),
        });

        assert_eq!(state.programming_status("relay"), DeviceProgrammingStatus {
            individual_address: true,
            ..DeviceProgrammingStatus::NONE
        });
        assert_eq!(state.deployments["relay"].individual_address, "1.1.1");
    }

    #[test]
    fn stale_siat_clears_only_group_communication_status() {
        let mut state = MutableProjectState::new("test-state".into());
        state.programming_statuses.insert("consumer".into(), DeviceProgrammingStatus::ALL);

        state.apply(&ProjectEvent::MarkGroupCommunicationStale { devices: vec!["consumer".into()] });

        assert_eq!(state.programming_status("consumer"), DeviceProgrammingStatus {
            group_communication: false,
            ..DeviceProgrammingStatus::ALL
        });
    }
}
