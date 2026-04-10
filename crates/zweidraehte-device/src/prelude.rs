//! Convenience re-exports for common types and traits.
//!
//! ```rust,ignore
//! use zweidraehte_device::prelude::*;
//! ```

// Core stack
pub use crate::{
    AccessContext, DeviceLayerStack, HasAuthorization, HasPersistence, HasSecureIdentity, InsecureDeviceBuilder,
    LayerBuildContext, ReadObjectError, Runner, SecureDeviceBuilder, Stack, StackDefinition, StackResources,
    StackState, StandardDeviceLayers, StandardSecureDeviceLayers, UpdateObjectError,
};

// KNX/IP-specific types
#[cfg(feature = "knxip")]
pub use crate::{InsecureIpDeviceBuilder, IpDeviceLayers, IpPlatform, IpPlatformConfig, IpPlatformState, IpStackState};

// Channel types for KNX/IP stacks (used by InsecureIpDeviceBuilder and standalone tests)
#[cfg(feature = "knxip")]
pub use crate::context::{
    CemiTransportLayerChannelPair, CemiTransportLayerClientEndpoints, CemiTransportLayerEndpoints,
};

// Addressing
pub use crate::address::{GroupAddress, IndividualAddress};

// Device identity and ETS derive macros
pub use crate::ets::{DeviceDescriptor, EtsComObjects, EtsEnum, EtsParams, EtsUnion, MaskVersion};

// Communication objects
pub use crate::objects::comm::{
    ComObject, ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects, LifecycleEvent,
};

// Interface objects (traits + response/error types)
pub use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, HasDeviceObject, HasMaxRetryCount, HasRoutingCount,
    InterfaceObject, PropertyDescriptionResponse, PropertyError, PropertyReadRequest, PropertyServiceHandler,
    PropertyWriteRequest, WriteResponse,
};

// Table accessor traits
pub use crate::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine,
    HasPeiApplication, HasRunStateMachine,
};

// Table events and memory types (used in StackDefinition impls and memory maps)
pub use crate::objects::tables::{ComObjectFlags, LoadEvent, RunEvent, Table, TableMemory};

// Storage and identity
pub use crate::storage::{DeviceIdentity, DeviceStorage, NoStorage, StaticIdentity};

// Memory
pub use crate::memory::{MemoryError, MemoryMap, NoMemoryMap};

// Transport layer
pub use crate::layers::transport::TlStyle;

// Mutex types for StackDefinition::Mutex
pub use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
