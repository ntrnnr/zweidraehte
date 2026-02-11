//! Convenience re-exports for common types and traits.
//!
//! ```rust,ignore
//! use zweidraehte::prelude::*;
//! ```

// Core stack
pub use crate::{
    Stack, Runner, StackResources, StackDefinition,
    StackState, IpStackState, IpDevice,
    ReadObjectError, UpdateObjectError,
};

// Addressing
pub use crate::address::{IndividualAddress, GroupAddress};

// Device identity
pub use crate::ets::{DeviceDescriptor, MaskVersion};

// Communication objects
pub use crate::objects::comm::{
    ComObject, ComObjects, ComObjectIndex,
    ComObjectEvent, ComObjectStatus,
};

// Interface objects (traits + response/error types)
pub use crate::objects::interface::{
    InterfaceObject, PropertyServiceHandler, HasDeviceObject,
    PropertyError, WriteResponse, PropertyDescriptionResponse,
};

// Table accessor traits
pub use crate::objects::tables::{
    HasAddressTable, HasAssociationTable,
    HasCommunicationObjectTable, HasApplication,
    HasLoadStateMachine, HasRunStateMachine,
};

// Storage
pub use crate::storage::{DeviceStorage, NoStorage};

// Memory
pub use crate::memory::{MemoryMap, NoMemoryMap};
