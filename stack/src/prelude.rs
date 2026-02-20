//! Convenience re-exports for common types and traits.
//!
//! ```rust,ignore
//! use zweidraehte::prelude::*;
//! ```

// Core stack
pub use crate::{
    Stack, Runner, StackResources, StackDefinition,
    StackState, IpStackState, IpDevice, IpPlatform, IpPlatformConfig,
    ReadObjectError, UpdateObjectError,
};

// Addressing
pub use crate::address::{IndividualAddress, GroupAddress};

// Device identity and ETS derive macros
pub use crate::ets::{DeviceDescriptor, MaskVersion, EtsComObjects, EtsEnum, EtsParams, EtsUnion};

// Communication objects
pub use crate::objects::comm::{
    ComObject, ComObjects, ComObjectIndex,
    ComObjectEvent, ComObjectStatus,
};

// Interface objects (traits + response/error types)
pub use crate::objects::interface::{
    InterfaceObject, PropertyServiceHandler, HasDeviceObject, HasRoutingCount,
    PropertyError, WriteResponse, PropertyDescriptionResponse,
};

// Table accessor traits
pub use crate::objects::tables::{
    HasAddressTable, HasAssociationTable,
    HasCommunicationObjectTable, HasApplication, HasPeiApplication,
    HasLoadStateMachine, HasRunStateMachine,
};

// Table events and memory types (used in StackDefinition impls and memory maps)
pub use crate::objects::tables::{LoadEvent, RunEvent, Table, TableMemory, ComObjectFlags};

// Storage and identity
pub use crate::storage::{DeviceIdentity, DeviceStorage, NoStorage, StaticIdentity};

// Memory
pub use crate::memory::{MemoryMap, MemoryError, NoMemoryMap};

// Transport layer
pub use crate::layers::transport::TlStyle;
