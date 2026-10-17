//! Mutable project facts and the events that update them.
//!
//! The state records sequence observations, recovery facts, and exact evidence
//! from completed commissioning. Programming indicators are derived by comparing
//! that evidence with a freshly compiled desired manifest and are never stored.
//! Filesystem persistence and journal replay belong to the `storage` module.

use std::{collections::BTreeMap, fmt, num::NonZeroU16};

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
        let encoded = String::deserialize(deserializer)?;
        if let Some(serial) = encoded.strip_prefix("serial:") {
            return Ok(Self::ManagedSerial(serial.to_string()));
        }
        if let Some(address) = encoded.strip_prefix("ia:") {
            return Ok(Self::UnmanagedAddress(address.to_string()));
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

/// Derived view for the five programming columns ETS exposes per device.
///
/// This is deliberately not durable state. The client creates it by comparing
/// the compiler's current manifest with successfully established evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// Compiler-owned sections which ETS exposes as programming state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgrammingSection {
    Address,
    ApplicationProgram1,
    ApplicationProgram2,
    Parameters,
    GroupCommunication,
    Configuration,
}

mod manifest;
pub use manifest::{CredentialCommitment, DesiredProgrammingManifest, ProgrammingManifest, semantic_fingerprint};

/// Schema version for durable generic commissioning evidence.
///
/// This version is independent of the surrounding mutable-state snapshot so
/// the deployment format can evolve without invalidating unrelated project
/// state.
pub const COMMISSIONING_DEPLOYMENT_RECORD_VERSION: u32 = 3;

const fn default_commissioning_deployment_record_version() -> u32 {
    1 // Records without a version predate the current image model.
}

/// Exact Master Data identity. DD0 is not unique: some 0300 profiles also
/// require the Device Object's management descriptor (PID 72).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MaskIdentity {
    pub full_id: String,
    pub dd0: u16,
    pub management_descriptor_01: Option<[u8; 10]>,
}

impl fmt::Display for MaskIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} (DD0 {:04X})", self.full_id, self.dd0)?;
        if let Some(descriptor) = self.management_descriptor_01 {
            write!(formatter, ", PID 72 ")?;
            for octet in descriptor {
                write!(formatter, "{octet:02X}")?;
            }
        }
        Ok(())
    }
}

/// Exact programming-configuration identity within one mask entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommissioningProfileVariant {
    /// Stable source-document position. A fixed-width integer keeps the
    /// project format independent of the host architecture.
    pub source_index: u32,
    pub legacy_version: Option<i32>,
    pub ets3_system_plugin: Option<String>,
}

/// Lossless occurrence spelling used by interface-object selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Occurrence {
    Absent,
    Zero,
    Positive { value: NonZeroU16 },
}

impl Occurrence {
    pub const fn from_option(value: Option<u16>) -> Self {
        match value {
            None => Self::Absent,
            Some(0) => Self::Zero,
            Some(value) => Self::Positive { value: NonZeroU16::new(value).expect("zero is handled above") },
        }
    }

    pub const fn value(self) -> Option<u16> {
        match self {
            Self::Absent => None,
            Self::Zero => Some(0),
            Self::Positive { value } => Some(value.get()),
        }
    }

    /// Occurrence named by an MTXML `Occurrence` attribute.
    ///
    /// Every such attribute in the KNX project schema defaults to zero, so an
    /// omitted attribute selects the same first instance as an explicit zero.
    /// Engines use this canonical form whenever two spellings must address one
    /// interface object, such as image locations and resource matching.
    pub const fn from_schema(value: Option<u16>) -> Self {
        match value {
            None => Self::Zero,
            Some(value) => Self::from_option(Some(value)),
        }
    }

    /// Zero-based instance addressed on the device; omission is the first.
    pub const fn instance(self) -> u16 {
        match self.value() {
            Some(value) => value,
            None => 0,
        }
    }
}

/// Client-neutral interface-object selector retained by an image segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObjectSelector {
    Index { index: u16 },
    Type { object_type: u16, occurrence: Occurrence },
}

/// Logical resource name within the separately recorded exact profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceId(#[serde(deserialize_with = "resource_name")] pub String);

fn resource_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(de::Error::custom("resource identity must not be empty"));
    }
    Ok(value)
}

impl fmt::Display for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Client-neutral address space for one sparse image segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageSpace {
    StandardMemory,
    UserMemory,
    RelativeMemory {
        object: ObjectSelector,
    },
    Property {
        object: ObjectSelector,
        property_id: u16,
    },
    Pointer {
        resource_id: ResourceId,
    },
    LineCouplerFilter,
    LineCouplerSlave,
    /// Two big-endian bytes for the property's array element count, at byte offset zero.
    ///
    /// Count state is distinct from the property data beginning at wire element one.
    /// Its presence does not authorize a property service operation.
    PropertyCount {
        object: ObjectSelector,
        property_id: u16,
    },
}

/// One normalized, bit-masked range of a deployed sparse image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommissioningImageSegment {
    pub space: ImageSpace,
    pub offset: u32,
    pub data: Vec<u8>,
    pub mask: Vec<u8>,
}

/// Device-resident value which validates one logical Master Data resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStamp {
    #[serde(rename = "resource_id")]
    pub resource: ResourceId,
    pub value: Vec<u8>,
}

/// Observed System B association-table realization, independent of link count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommissioningAssociationEntrySize {
    TwoBytes,
    FourBytes,
}

/// PDT a target reported for a property which Master Data leaves untyped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObservedPropertyType {
    pub object: ObjectSelector,
    pub property_id: u16,
    pub pdt: u8,
}

/// Durable, non-secret evidence for a generic commissioning deployment.
///
/// These types intentionally duplicate no client implementation types. The
/// project crate sits below the client in the dependency graph and remains a
/// serialization boundary rather than depending on the commissioning engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommissioningDeploymentRecord {
    #[serde(default = "default_commissioning_deployment_record_version")]
    pub version: u32,
    pub mask: MaskIdentity,
    pub variant: CommissioningProfileVariant,
    pub master_data_fingerprint: [u8; 32],
    pub product_fingerprint: [u8; 32],
    pub image_fingerprint: [u8; 32],
    pub image_segments: Vec<CommissioningImageSegment>,
    pub device_stamps: Vec<DeviceStamp>,
    /// Valid only for this record's exact mask, variant and Master Data identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub association_table_entry_size: Option<CommissioningAssociationEntrySize>,
    /// Valid only for this record's exact mask, variant and Master Data identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_property_types: Vec<ObservedPropertyType>,
    /// Mode established by the successful programming operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_security_enabled: Option<bool>,
}

/// Successful physical evidence for one project device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDeploymentEvidence {
    pub manifest: ProgrammingManifest,
    /// Only a confirmed unload excludes this device from secure sender tables.
    /// Missing or obsolete image evidence does not establish an unloaded device.
    #[serde(default)]
    pub application_unloaded: bool,
    /// Exact image and live stamps used for verified differential downloads.
    #[serde(default, deserialize_with = "current_deployment")]
    pub commissioning: Option<CommissioningDeploymentRecord>,
}

// Both snapshot evidence and journal outcomes discard obsolete image baselines.
// Their separately decoded credential commitments remain available.
fn current_deployment<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<CommissioningDeploymentRecord>, D::Error> {
    let stored = serde_json::Value::deserialize(deserializer)?;
    if stored.get("version").and_then(serde_json::Value::as_u64)
        != Some(u64::from(COMMISSIONING_DEPLOYMENT_RECORD_VERSION))
    {
        return Ok(None);
    }
    serde_json::from_value(stored).map(Some).map_err(de::Error::custom)
}

fn current_boxed_deployment<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Box<CommissioningDeploymentRecord>>, D::Error> {
    current_deployment(deserializer).map(|record| record.map(Box::new))
}

/// One successful commissioning result recorded as a physical fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommissioningOutcome {
    Programmed {
        /// Complete replacement evidence for every listed section.
        established: ProgrammingManifest,
        /// Updated exact deployment base when application data was written.
        #[serde(default, deserialize_with = "current_boxed_deployment")]
        commissioning: Option<Box<CommissioningDeploymentRecord>>,
        /// True only when the report proves the complete desired manifest.
        fully_verified: bool,
    },
    Unloaded {
        preserve_network_configuration: bool,
        serial: Option<String>,
    },
    /// A failed physical run may have changed only these sections. Their
    /// previous evidence is no longer trustworthy; every unlisted section
    /// remains a valid factual programming result.
    Indeterminate {
        sections: Vec<ProgrammingSection>,
        /// Keys sent successfully or whose write outcome is unknown. Their
        /// rotation guards must become durable with the image invalidation.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exposed_group_keys: Vec<CredentialCommitment>,
    },
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
    pub deployments: BTreeMap<String, DeviceDeploymentEvidence>,
    #[serde(default)]
    pub inconsistent_devices: Vec<String>,
}

impl MutableProjectState {
    pub fn new(state_id: String) -> Self {
        Self {
            version: 2,
            state_id,
            recovery_required: false,
            client_next: 1,
            sender_floors: BTreeMap::new(),
            devices: BTreeMap::new(),
            deployments: BTreeMap::new(),
            inconsistent_devices: Vec::new(),
        }
    }

    pub fn deployment(&self, device: &str) -> Option<&DeviceDeploymentEvidence> {
        self.deployments.get(device)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
// Journal events are short-lived serialization values. Boxing the deployment
// payload would complicate the public event API without reducing owned data.
#[allow(clippy::large_enum_variant)]
pub enum ProjectEvent {
    AdvanceClient { next: u64 },
    ObserveSender { sender: SenderIdentity, last_valid: u64 },
    ObserveDeviceOutgoing { serial: String, next: u64 },
    ObserveDeviceSiat { serial: String, sender: SenderIdentity, last_valid: u64 },
    RecordCommissioningOutcome { device: String, outcome: CommissioningOutcome },
    MarkInconsistent { devices: Vec<String> },
    BeginRecovery,
    CompleteRecovery,
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    #[test]
    fn shared_image_vocabulary_preserves_persisted_json_shapes() {
        use serde_json::json;

        let cases = [
            (ImageSpace::StandardMemory, json!({"kind": "standard_memory"})),
            (ImageSpace::UserMemory, json!({"kind": "user_memory"})),
            (
                ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } },
                json!({"kind": "relative_memory", "object": {"kind": "index", "index": 3}}),
            ),
            (
                ImageSpace::Property {
                    object: ObjectSelector::Type { object_type: 17, occurrence: Occurrence::from_option(Some(2)) },
                    property_id: 54,
                },
                json!({"kind": "property", "object": {"kind": "type", "object_type": 17,
                    "occurrence": {"kind": "positive", "value": 2}}, "property_id": 54}),
            ),
            (
                ImageSpace::Pointer { resource_id: ResourceId("ApplicationDataPtr".into()) },
                json!({"kind": "pointer", "resource_id": "ApplicationDataPtr"}),
            ),
            (ImageSpace::LineCouplerFilter, json!({"kind": "line_coupler_filter"})),
            (ImageSpace::LineCouplerSlave, json!({"kind": "line_coupler_slave"})),
            (
                ImageSpace::PropertyCount { object: ObjectSelector::Index { index: 4 }, property_id: 71 },
                json!({"kind": "property_count", "object": {"kind": "index", "index": 4}, "property_id": 71}),
            ),
        ];
        for (space, expected) in cases {
            assert_eq!(serde_json::to_value(&space).expect("image space serializes"), expected);
            assert_eq!(serde_json::from_value::<ImageSpace>(expected).expect("legacy shape decodes"), space);
        }
        for (occurrence, expected) in [
            (Occurrence::Absent, json!({"kind": "absent"})),
            (Occurrence::Zero, json!({"kind": "zero"})),
            (Occurrence::from_option(Some(u16::MAX)), json!({"kind": "positive", "value": u16::MAX})),
        ] {
            assert_eq!(serde_json::to_value(occurrence).expect("occurrence serializes"), expected);
            assert_eq!(serde_json::from_value::<Occurrence>(expected).expect("occurrence decodes"), occurrence);
        }
        let stamp = DeviceStamp { resource: ResourceId("DownloadStamp".into()), value: vec![1, 2, 3] };
        let encoded = json!({"resource_id": "DownloadStamp", "value": [1, 2, 3]});
        assert_eq!(serde_json::to_value(&stamp).expect("stamp serializes"), encoded);
        assert_eq!(serde_json::from_value::<DeviceStamp>(encoded).expect("legacy stamp decodes"), stamp);
        let mask = MaskIdentity { full_id: "MV-0705".into(), dd0: 0x0705, management_descriptor_01: None };
        let encoded = json!({"full_id": "MV-0705", "dd0": 1797, "management_descriptor_01": null});
        assert_eq!(serde_json::to_value(&mask).expect("mask serializes"), encoded);
        assert_eq!(serde_json::from_value::<MaskIdentity>(encoded).expect("legacy mask decodes"), mask);
    }

    #[test]
    fn shared_image_vocabulary_rejects_invalid_occurrences_and_resource_names() {
        for value in [0, 65536] {
            assert!(
                serde_json::from_value::<Occurrence>(serde_json::json!({"kind": "positive", "value": value})).is_err()
            );
        }
        assert!(serde_json::from_str::<ImageSpace>(r#"{"kind":"pointer","resource_id":""}"#).is_err());
        assert!(serde_json::from_str::<DeviceStamp>(r#"{"resource_id":"","value":[]}"#).is_err());
    }

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
        assert_eq!(decoded.version, 2);
    }

    #[test]
    fn sender_identity_rejects_object_form() {
        let encoded = r#"{"kind":"managed_serial","value":"00FA:00000001"}"#;
        assert!(serde_json::from_str::<SenderIdentity>(encoded).is_err());
    }
}
