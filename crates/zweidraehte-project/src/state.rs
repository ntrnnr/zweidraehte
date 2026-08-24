use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SenderIdentity {
    ManagedSerial(String),
    UnmanagedAddress(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSequenceObservation {
    /// The device's next outgoing secure sequence number (PID 59).
    pub outgoing_next: u64,
    /// Last-valid values observed in the device's live SIAT, keyed by sender.
    pub siat_last_valid: BTreeMap<SenderIdentity, u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentFingerprints {
    pub identity: String,
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
            deployed_group_keys: BTreeMap::new(),
            inconsistent_devices: Vec::new(),
        }
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
            ProjectEvent::RecordDeployment { device, fingerprints } => {
                self.deployments.insert(device.clone(), fingerprints.clone());
                self.inconsistent_devices.retain(|candidate| candidate != device);
            }
            ProjectEvent::RecordGroupKey { net, fingerprint } => {
                self.deployed_group_keys.insert(net.clone(), fingerprint.clone());
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
pub enum ProjectEvent {
    AdvanceClient { next: u64 },
    ObserveSender { sender: SenderIdentity, last_valid: u64 },
    ObserveDeviceOutgoing { serial: String, next: u64 },
    ObserveDeviceSiat { serial: String, sender: SenderIdentity, last_valid: u64 },
    RecordDeployment { device: String, fingerprints: DeploymentFingerprints },
    RecordGroupKey { net: String, fingerprint: String },
    MarkInconsistent { devices: Vec<String> },
    BeginRecovery,
    CompleteRecovery,
}
