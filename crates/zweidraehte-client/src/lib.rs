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
//!                                 TunnelSession), UsbConnector
//! ```
//!
//! Transport protocol state comes from `zweidraehte-proto`; tokio I/O lives in the
//! connectors and the bus task. See `CLIENT.md` in the repository root for
//! the ownership and commissioning design.
//!
//! With no default features, bus access and Data Secure are available over
//! KNX/IP or custom connectors. Opt into `usb`, `commissioning` (including
//! configuration), `keyring`, or `project` as needed. `javascript` enables
//! product calculations; `master-data-download` enables catalog acquisition.
//! `cli` supplies the existing USB/keyring argument vocabulary without project
//! storage. Bus operations use [`BusError`]/[`BusResult`]; project errors and
//! results live under `project`, alongside its planning and execution APIs.
//! Each module's "Errors" section lists the error types that cross it.
//! [`BusTarget`] stores a built-in endpoint without depending on CLI parsing;
//! the `usb` feature adds its USB choice.
//!
//! The crate root provides bus access and common protocol values. Product
//! lowering lives in `configuration`, programming in `commissioning`, and
//! project orchestration in `project`. Expert procedure inspection lives in
//! `commissioning::inspection`; it does not grant permission to execute a program.
//!
//! # Usage
//!
//! ```no_run
//! use std::time::Duration;
//! use zweidraehte_client::{AddressTarget, GroupValueEncoding, KnxBus, PropertyAddress, pid};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let bus = KnxBus::connect_ip("192.168.1.100:3671".parse()?).await?;
//!
//! // Group traffic — no device connection needed.
//! bus.group_write("2/0/3".parse()?, &[1], GroupValueEncoding::Short).await?;
//! let mut events = bus.group_events();
//!
//! // Connected (RCo) device management.
//! let mut device = bus.connect_device("1.1.42".parse()?).await?;
//! let serial = device.property_read(PropertyAddress::indexed(0, pid::SERIAL_NUMBER)?, 1, 1).await?;
//! device.close().await?;
//!
//! // Network management.
//! let found = bus.network_management()
//!     .read_individual_addresses(AddressTarget::ProgrammingMode, Duration::from_secs(3))
//!     .await?;
//!
//! bus.disconnect().await?;
//! # Ok(())
//! # }
//! ```

pub mod bus;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "commissioning")]
pub mod commissioning;
#[cfg(feature = "commissioning")]
pub mod configuration;
pub mod connector;
#[cfg(feature = "project")]
pub mod project;
pub mod security;

pub use bus::access::{ManagementCredential, ManagementKeys};
pub use bus::group::{GroupService, GroupTelegram};

pub use bus::{
    AddressTarget, BusError, BusResult, DeviceConnection, FunctionPropertyResult, KnxBus, KnxBusBuilder, MemorySpace,
    NetworkManagement, ProgrammingModeDevice, PropertyAddress, PropertyDescription, Protection, RestartAck,
    SerialAddressAssignment, WriteCheck,
};
pub use connector::{BusTarget, ConnectorInfo, IpTunnelConnector, KnxConnector};
#[cfg(feature = "usb")]
pub use connector::{UsbConnector, UsbSelector};
pub use security::{DeviceSecurityMode, SecurityEntry, SecurityStore, SeqNumberStore};
/// Re-export commonly used proto types for convenience.
pub use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
pub use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
pub use zweidraehte_proto::device::{MaskFamily, MaskVersion};
pub use zweidraehte_proto::dpt::InterfaceObjectType;
pub use zweidraehte_proto::messages::apdu::group_value::GroupValueEncoding;
pub use zweidraehte_proto::messages::apdu::restart::{EraseCode, RestartError};
pub use zweidraehte_proto::pid;
