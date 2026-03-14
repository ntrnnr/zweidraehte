//! Convenience re-exports for common types and traits.
//!
//! ```rust,ignore
//! use zweidraehte_device::prelude::*;
//! ```

// Core stack
pub use crate::{
    Stack, Runner, StackResources, StackDefinition,
    LayerContext, InsecureDeviceLayers, StandardDeviceLayers,
    InsecureDeviceBuilder,
    StackState,
    ReadObjectError, UpdateObjectError,
    AccessContext,
};

// KNX/IP-specific types
#[cfg(feature = "knxip")]
pub use crate::{
    InsecureIpDeviceBuilder, IpDeviceLayers,
    IpStackState, IpDevice, IpPlatform, IpPlatformConfig,
};

// Channel types for KNX/IP stacks (used by InsecureIpDeviceBuilder and standalone tests)
#[cfg(feature = "knxip")]
pub use crate::context::{CemiTransportLayerChannelPair, CemiTransportLayerClientEndpoints, CemiTransportLayerEndpoints};

// Addressing
pub use crate::address::{IndividualAddress, GroupAddress};

// Device identity and ETS derive macros
pub use crate::ets::{DeviceDescriptor, MaskVersion, EtsComObjects, EtsEnum, EtsParams, EtsUnion};

// Communication objects
pub use crate::objects::comm::{
    ComObject, ComObjects, ComObjectIndex,
    ComObjectEvent, ComObjectStatus,
    LifecycleEvent,
};

// Interface objects (traits + response/error types)
pub use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, InterfaceObject,
    PropertyServiceHandler, HasDeviceObject, HasRoutingCount,
    PropertyError, PropertyReadRequest, PropertyWriteRequest, WriteResponse,
    PropertyDescriptionResponse,
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

// Mutex types for StackDefinition::Mutex
pub use embassy_sync::blocking_mutex::raw::{NoopRawMutex, CriticalSectionRawMutex};
