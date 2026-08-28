//! KNX client library: bus access, group communication, and device
//! management from the management-client side (the role ETS or a
//! commissioning tool plays).
//!
//! # Architecture
//!
//! ```text
//!  KnxBus ── group_write / group_read / group_events()
//!    ├── connect_device(ia) → DeviceConnection   (RCo: connected mgmt)
//!    └── network_management() → NetworkManagement (NM_* + RCl mgmt)
//!         │
//!    BusCommand channel
//!         ▼
//!  BusTask (tokio task) ── TL client state machine (proto), procedure
//!         │                matching, group fan-out
//!         ▼
//!  KnxConnector (cEMI frames) ── IpTunnelConnector (UDP + sans-io
//!                                 TunnelSession), USB (planned)
//! ```
//!
//! Protocol logic is sans-io under [`mod@core`]; tokio I/O lives in the
//! connectors and the bus task. See `CLIENT.md` in the repository root for
//! the design document and roadmap.
//!
//! # Usage
//!
//! ```rust,ignore
//! use zweidraehte_client::{KnxBus, GroupValueEncoding};
//!
//! let bus = KnxBus::connect_ip("192.168.1.100:3671".parse()?).await?;
//!
//! // Group traffic — no device connection needed.
//! bus.group_write("2/0/3".parse()?, &[1], GroupValueEncoding::Short).await?;
//! let mut events = bus.group_events();
//!
//! // Connected (RCo) device management.
//! let mut device = bus.connect_device("1.1.42".parse()?).await?;
//! let serial = device.property_read(0, 11, 1, 1).await?;
//! device.close().await?;
//!
//! // Network management.
//! let found = bus.network_management()
//!     .read_individual_addresses(std::time::Duration::from_secs(3)).await?;
//!
//! bus.disconnect().await?;
//! ```

#![allow(async_fn_in_trait)]

mod api;
#[cfg(feature = "cli")]
pub mod cli;
pub mod connector;
pub mod core;
pub mod download;
mod driver;
mod error;
pub mod programming;
pub mod project;
pub mod security;
mod unload;

pub use api::{
    DeviceConnection, KnxBus, NetworkManagement, ProgrammingModeDevice, RestartAck, SerialAddressAssignment,
};
pub use connector::{ConnectorInfo, IpTunnelConnector, KnxConnector, UsbConnector, UsbSelector};
pub use core::group::{GroupService, GroupTelegram};
pub use core::management::{FunctionPropertyResult, PropertyDescription};
pub use error::{Error, MachineRef, Result};
pub use programming::{
    AddressAssignmentMethod, AddressAssignmentReport, AddressingMode, DeviceProgrammer, GeneratedToolKeySink,
    ManagementAccess, PreparedProgramming, ProgrammingEvent, ProgrammingOptions, ProgrammingReport, ProgrammingRequest,
    ProgrammingScope, ProgrammingStage, SecurityVerification, connect_management, connect_management_synchronized,
};
pub use project::{
    BatchSelection, LoweredProjectDevice, PlannedProjectDevice, PreparedProjectBatch, PreparedProjectDevice,
    ProgrammingBatchPlan, ProjectBatchReport, ProjectDeviceProgrammingReport, ProjectPlanRequest, ProjectProduct,
    ProjectProgrammer, ProjectProgrammingSession, build_project_keyring, load_project_products, lower_project_device,
};
pub use security::{DeviceSecurityMode, JsonSeqStore, SecurityEntry, SecurityStore, SeqNumberStore};
pub use unload::{
    UnloadEvent, UnloadFailure, UnloadOptions, UnloadReport, UnloadScope, UnloadStage, project_unload_state_events,
    unload_project_device,
};

/// Re-export commonly used proto types for convenience.
pub use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
pub use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
pub use zweidraehte_proto::device::{MaskFamily, MaskVersion};
pub use zweidraehte_proto::dpt::InterfaceObjectType;
pub use zweidraehte_proto::messages::apdu::group_value::GroupValueEncoding;
pub use zweidraehte_proto::messages::apdu::restart::{EraseCode, RestartError};
pub use zweidraehte_proto::pid;
