//! Context traits for KNX stack layers
//!
//! This module defines trait-based interfaces for accessing stack resources.
//! Layers depend only on the specific context traits they need, making them
//! easier to test and more modular.

#[cfg(feature = "knxip")]
use crate::address::IndividualAddress;
use crate::messages::buffers::DynBufferManager;
#[cfg(feature = "knxip")]
use crate::messages::knxip::substructs::{DeviceInformation, ExtendedDeviceInformation};
use crate::objects::interface::PropertyServiceHandler;

/// Provides access to the buffer manager for allocating and freeing message buffers
pub trait BufferManagerContext {
    /// Get a reference to the buffer manager
    fn buffer_manager(&self) -> &DynBufferManager<'static>;

    /// Get the maximum APDU length this device can handle.
    ///
    /// This is the runtime limit based on `StackState::max_apdu_length()`,
    /// which may be lower than the compile-time `StackDefinition::MAX_APDU_LENGTH`.
    /// Link layers should use this to filter/reject oversized incoming frames.
    fn max_apdu_length(&self) -> u16;

    /// Set the maximum APDU length this device can handle.
    ///
    /// This is called by link layers after detecting hardware capabilities.
    /// For example, a USB link layer may read the interface's MAX_APDU_LENGTH
    /// property and update the stack state accordingly.
    ///
    /// The value should not exceed the compile-time `StackDefinition::MAX_APDU_LENGTH`.
    fn set_max_apdu_length(&self, length: u16);
}

/// Provides access to the device's property service handler.
///
/// This allows link layers that implement connection-oriented management
/// protocols (e.g., KNX/IP Device Management) to read and write interface
/// object properties on behalf of remote clients like ETS.
pub trait PropertyServiceContext {
    /// Get a reference to the property service handler.
    fn property_handler(&self) -> &dyn PropertyServiceHandler;
}

#[cfg(feature = "knxip")]
/// Provides access to dynamic device information for KNX/IP discovery.
///
/// Implemented by the stack's runtime context so the KNX/IP link layer
/// can build fresh [`DeviceInformation`] on each discovery request,
/// reflecting current programming mode, individual address, etc.
///
/// Only implemented when the device state is [`IpStackState`](crate::IpStackState),
/// since discovery is a KNX/IP-only concept.
pub trait DeviceInfoContext {
    /// Build a [`DeviceInformation`] reflecting the current device state.
    fn device_information(&self) -> DeviceInformation;

    /// Build an [`ExtendedDeviceInformation`] reflecting the current device state.
    ///
    /// Used in `SearchResponseExtended` (spec §7.6.3.6). Contains medium status,
    /// max local APDU length, and device descriptor type 0.
    fn extended_device_information(&self) -> ExtendedDeviceInformation;

    /// The KNX manufacturer code (big-endian, 2 bytes).
    ///
    /// Used by tunneling feature responses (spec 03/08/04 §4.6).
    fn manufacturer_code(&self) -> u16;
}

#[cfg(feature = "knxip")]
/// Provides IP diagnostics data for remote configuration responses.
///
/// The remote diagnostic server (KNX 3/8/7) must include IP_CONFIG,
/// IP_CUR_CONFIG, and KNX_ADDRESSES DIBs in its responses. This trait
/// abstracts the data source so the server doesn't depend on
/// `IpStackState` directly.
///
/// Only relevant for KNX/IP devices. Implementations should query the
/// device state and platform for current network configuration.
pub trait IpDiagnosticsContext {
    /// Build an [`IpConfig`](crate::messages::knxip::substructs::IpConfig) DIB from configured (ETS-programmed) values.
    fn ip_config(&self) -> crate::messages::knxip::substructs::IpConfig;

    /// Build an [`IpCurrentConfig`](crate::messages::knxip::substructs::IpCurrentConfig) DIB from the platform's current state.
    fn ip_current_config(&self) -> crate::messages::knxip::substructs::IpCurrentConfig;
}

#[cfg(feature = "knxip")]
/// Provides additional KNX individual addresses for IP tunneling use-cases.
///
/// Uses a write-to-buffer pattern instead of returning a fixed-capacity Vec,
/// so the caller controls the buffer size (typically `N` from the tunnel
/// connection handler's const generic).
pub trait IpAdditionalIndividualAddressContext {
    /// Write additional individual addresses into `buf`.
    ///
    /// Returns the number of addresses written (`<= buf.len()`).
    fn write_additional_individual_addresses(&self, buf: &mut [IndividualAddress]) -> usize;
}

/// Provides the TP1 max retry count for DLL retry configuration.
///
/// Used by the TPUART link layer at init time to configure the chip's
/// retry behavior from PID_MAX_RETRY_COUNT (PID 52).
pub trait MaxRetryCountContext {
    /// Get the max retry count byte (busy_retry bits 6-4, nak_retry bits 2-0).
    fn max_retry_count(&self) -> u8;
}

/// Provides the KNX primary individual address.
pub trait KnxIndividualAddressContext {
    /// The device's primary individual address.
    fn individual_address(&self) -> crate::address::IndividualAddress;
}

// ============================================================================
// cEMI channel types
// ============================================================================

#[cfg(feature = "knxip")]
/// Owned channel pair for cEMI Transport Layer communication.
///
/// Allocated by [`Runner::run()`](crate::Runner::run) as a stack-local when
/// the [`LayerStack`](crate::router::LayerStack) requires it. Both the
/// router task (layer side) and the LL task (link-layer side) borrow from
/// this structure.
pub struct CemiTransportLayerChannelPair {
    /// DevMgmt handler → CemiTransportLayer (capacity 2: one Frame + one
    /// Activate/Deactivate can be pending simultaneously).
    pub event: embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, crate::layers::transport::cemi::CemiEvent, 2>,
    /// CemiTransportLayer → KNX/IP runtime (capacity 1: at most one
    /// response pending).
    pub response: embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, crate::messages::buffers::Buffer<'static>, 1>,
}

#[cfg(feature = "knxip")]
impl Default for CemiTransportLayerChannelPair {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "knxip")]
impl CemiTransportLayerChannelPair {
    /// Create a new channel pair.
    pub fn new() -> Self {
        Self {
            event: embassy_sync::channel::Channel::new(),
            response: embassy_sync::channel::Channel::new(),
        }
    }

    /// Extract layer-side endpoints (for the router/layer stack).
    pub fn layer_endpoints(&self) -> CemiTransportLayerClientEndpoints<'_> {
        CemiTransportLayerClientEndpoints {
            event_receiver: self.event.receiver().into(),
            response_sender: self.response.sender().into(),
        }
    }

    /// Extract link-layer-side endpoints (for the KNX/IP runtime).
    pub fn ll_endpoints(&self) -> CemiTransportLayerEndpoints<'_> {
        CemiTransportLayerEndpoints {
            event_sender: self.event.sender().into(),
            response_receiver: self.response.receiver().into(),
        }
    }
}

#[cfg(feature = "knxip")]
/// Layer-side endpoints borrowed from [`CemiTransportLayerChannelPair`].
///
/// Used by [`IpDeviceLayers`](crate::IpDeviceLayers) to
/// receive cEMI events and send responses.
pub struct CemiTransportLayerClientEndpoints<'a> {
    pub event_receiver: embassy_sync::channel::DynamicReceiver<'a, crate::layers::transport::cemi::CemiEvent>,
    pub response_sender: embassy_sync::channel::DynamicSender<'a, crate::messages::buffers::Buffer<'static>>,
}

#[cfg(feature = "knxip")]
/// Link-layer-side endpoints borrowed from [`CemiTransportLayerChannelPair`].
///
/// Used by the KNX/IP runtime to send cEMI events and receive responses.
pub struct CemiTransportLayerEndpoints<'a> {
    pub event_sender: embassy_sync::channel::DynamicSender<'a, crate::layers::transport::cemi::CemiEvent>,
    pub response_receiver: embassy_sync::channel::DynamicReceiver<'a, crate::messages::buffers::Buffer<'static>>,
}

/// Provides access to the device's address table for ACK decisions.
///
/// Used by the TPUART link layer's [`AutoAddressChecker`](crate::layers::linklayers::tpuart::AutoAddressChecker)
/// to construct a [`DeviceAddressChecker`](crate::layers::linklayers::tpuart::DeviceAddressChecker)
/// at link layer build time, when the address table is at a stable memory
/// location inside [`StackResources`](crate::StackResources).
pub trait AddressTableContext {
    /// The concrete address table type.
    type ADT: crate::objects::tables::AddressTable + crate::objects::tables::HasLoadStateMachine;

    /// Get a reference to the address table's RefCell.
    fn address_table(&self) -> &core::cell::RefCell<Self::ADT>;
}
