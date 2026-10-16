//! Live commissioning: preparation, execution, image knowledge and cleanup.
//!
//! This subsystem applies commissioning policy over the bus transport. An
//! `ExecutionSession` owns the observed image, authorization and mutation effects
//! for one live phase; `DeviceConnection` owns the underlying transport exchange.
//! Preparation and execution create separate sessions. A `PreparedProgram`
//! retains validated intent and evidence, never an open connection, and execution
//! revalidates that evidence before making changes.
use crate::bus::BusError as ClientError;
use crate::bus::{DeviceConnection, KnxBus};
use crate::commissioning::compiler::secrets::SecretCommissioningPayload;
use crate::commissioning::error::{Diagnostic, MutationStatus, mutating_request_may_have_reached_device};
use crate::commissioning::procedure::LoadControlCause;
use crate::commissioning::runtime::credentials::ManagementAccess;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_util::secret::SecretBytes;

mod access;
mod application;
mod binding;
mod comparison;
mod controls;
mod network;
pub(in crate::commissioning) use controls::ProcedureRunner;
pub(crate) mod commissioner;
pub(crate) mod credentials;
mod data;
mod execute;
pub(in crate::commissioning) mod identity;
mod image_state;
mod io;
mod lifecycle;
pub(crate) mod policy;
pub(crate) mod prepare;
pub(crate) mod prepared;

#[derive(Clone, PartialEq, Eq)]
pub(in crate::commissioning) enum AuthorizationPolicy {
    None,
    LegacyKey { key: SecretBytes, required_level: u8 },
}
impl fmt::Debug for AuthorizationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::LegacyKey { required_level, .. } => {
                f.debug_struct("LegacyKey").field("key", &"[REDACTED]").field("required_level", required_level).finish()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::commissioning) struct SessionConfig {
    pub scan_window: Duration,
    pub target_max_apdu: u16,
    pub verify_mode: bool,
    pub authorization: AuthorizationPolicy,
    pub load_state_poll_attempts: u16,
    pub load_state_poll_interval: Duration,
    pub minimum_restart_delay: Duration,
    pub minimum_equal_run: usize,
}

/// There is exactly one mirror of connection and tool state. Transport retries,
/// secure framing, and response matching remain in DeviceConnection.
pub(crate) struct ExecutionSession<'a> {
    bus: &'a KnxBus,
    target: IndividualAddress,
    config: SessionConfig,
    access: ManagementAccess,
    replacement_tool_key: Option<SecretBytes>,
    serial_number: Option<[u8; 6]>,
    connection: Option<DeviceConnection>,
    images: image_state::ImageState<'a>,
    original_device_control: Option<u8>,
    // None after an uncertain write forces re-observation before policy reuse.
    current_device_control: Option<u8>,
    effects: crate::commissioning::report::effects::ExecutionEffects,
    control_mutated: bool,
    property_descriptors: BTreeMap<DescriptorKey, PropertyDescriptor>,
    // Interface-object types in index order, read only as far as a lookup
    // needed. `None` marks the index after the last object.
    object_types: Vec<Option<u16>>,
    // Property data types the target described for indexed properties no
    // metadata types, keyed by object index and property ID. Like the
    // reference's per-object descriptor cache, this lasts until the session
    // closes or a control clears cached object types.
    described_property_types: BTreeMap<(u8, u8), u8>,
    // Property data types read by object type through extended property
    // services, keyed by object type and property ID like the reference's
    // per-type descriptor cache.
    described_property_types_by_type: BTreeMap<(u16, u16), u8>,
    secret_payload: SecretCommissioningPayload,
}

/// The properties one procedure declaration describes.
///
/// The reference keeps two descriptor caches: a declaration with an object
/// index describes that index, ignoring any occurrence, and one addressed by
/// object type describes the property on every object of that type. A
/// type-addressed key therefore drops the object instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DescriptorKey {
    Index { object_index: u8, property_id: u8 },
    ObjectType { object_type: zweidraehte_proto::dpt::InterfaceObjectType, property_id: u16 },
}

impl From<crate::commissioning::procedure::operands::PropertyAddress> for DescriptorKey {
    fn from(address: crate::commissioning::procedure::operands::PropertyAddress) -> Self {
        use crate::commissioning::procedure::operands::PropertyAddress;
        match address {
            PropertyAddress::Indexed { object_index, property_id } => Self::Index { object_index, property_id },
            PropertyAddress::Extended { object_type, property_id, .. } => Self::ObjectType { object_type, property_id },
        }
    }
}

#[derive(PartialEq, Eq)]
struct PropertyDescriptor {
    property_data_type: String,
    maximum_elements: u16,
    read_access: u8,
    write_access: u8,
    writable: bool,
}

/// Private payload ownership remains with the caller across awaited I/O. This
/// borrowed policy follows verification reads as well as the mutating chunks.
#[derive(Clone, Copy)]
pub(in crate::commissioning) enum TransferContext<'a> {
    Public,
    Private { group_keys: &'a [GroupAddress] },
}

impl<'a> TransferContext<'a> {
    fn group_keys(self) -> &'a [GroupAddress] {
        match self {
            Self::Public => &[],
            Self::Private { group_keys } => group_keys,
        }
    }
}

impl<'a> ExecutionSession<'a> {
    pub(in crate::commissioning) fn selected_credential(&self) -> crate::bus::access::ManagementCredential {
        self.access.credential()
    }

    pub(in crate::commissioning) fn identify(&mut self, serial_number: Option<[u8; 6]>) {
        self.serial_number = serial_number;
    }

    pub(in crate::commissioning) fn new(
        bus: &'a KnxBus,
        target: IndividualAddress,
        config: SessionConfig,
        access: ManagementAccess,
    ) -> Result<Self, Diagnostic> {
        if config.target_max_apdu == 0 || config.load_state_poll_attempts == 0 {
            return Err(Diagnostic::new("session requires nonzero APDU and polling limits"));
        }
        Ok(Self {
            bus,
            target,
            config,
            effects: Default::default(),
            access,
            replacement_tool_key: None,
            serial_number: None,
            connection: None,
            images: Default::default(),
            original_device_control: None,
            current_device_control: None,
            control_mutated: false,
            property_descriptors: BTreeMap::new(),
            object_types: Vec::new(),
            described_property_types: BTreeMap::new(),
            described_property_types_by_type: BTreeMap::new(),
            secret_payload: SecretCommissioningPayload::default(),
        })
    }

    fn secure_management(&self) -> bool {
        self.connection.as_ref().is_some_and(DeviceConnection::is_secure_management)
    }
    pub(in crate::commissioning::runtime) fn record_mutation(&mut self) {
        // A snapshot preceding a restart cannot describe a later mutation.
        self.images.discard_restart_snapshot();
        self.effects.record_mutation();
        self.control_mutated = true;
    }

    pub(crate) fn mutated(&self) -> bool {
        matches!(self.effects.mutation_status(), MutationStatus::PartiallyApplied | MutationStatus::Complete)
    }

    pub(in crate::commissioning::runtime) fn begin_execution(&mut self) {
        self.effects.begin();
    }

    fn payload_budget(&self, overhead: u16) -> Result<usize, Diagnostic> {
        crate::bus::reads::payload_budget(
            self.bus.max_apdu(),
            self.config.target_max_apdu,
            self.secure_management(),
            overhead,
        )
        .map_err(Diagnostic::from)
    }
}

impl ExecutionSession<'_> {
    #[cfg(test)]
    pub(crate) fn mutation_status(&self) -> MutationStatus {
        self.effects.mutation_status()
    }

    pub(crate) fn semantic_error(&self, message: impl Into<String>, cause: LoadControlCause) -> Diagnostic {
        let mut error = Diagnostic::new(message);
        error.load_control_cause = Some(cause);
        error
    }

    pub(crate) fn compare_error(&self, message: impl Into<String>) -> Diagnostic {
        self.semantic_error(message, LoadControlCause::CompareMismatch)
    }

    pub(crate) fn mutating_client_error(&mut self, error: ClientError) -> Diagnostic {
        // Once a mutating request has been handed to the connection, a lost
        // acknowledgement or response cannot prove that the device rejected
        // it. Preserve explicit negative confirmations/device return codes as
        // non-mutations, but classify uncertain delivery and post-write
        // verification failures conservatively for recovery and cleanup.
        let may_have_reached_device = mutating_request_may_have_reached_device(&error);
        let mapped = Diagnostic::from(error);
        if may_have_reached_device {
            self.record_mutation();
            self.images.forget_device();
        }
        mapped
    }
}
