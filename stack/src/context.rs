//! Context traits for KNX stack layers
//!
//! This module defines trait-based interfaces for accessing stack resources.
//! Layers depend only on the specific context traits they need, making them
//! easier to test and more modular.

use crate::address::IndividualAddress;
use crate::messages::buffers::DynBufferManager;
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

/// Provides the KNX primary individual address.
pub trait KnxIndividualAddressContext {
    /// The device's primary individual address.
    fn individual_address(&self) -> crate::address::IndividualAddress;
}

/// Provides access to cEMI Transport Layer channels.
///
/// Implemented by [`StackContext`](crate::StackContext) when the device uses
/// KNX/IP with Device Management. The KNX/IP link layer uses these channels
/// to send cEMI events (activate/deactivate/frame) and receive AL responses.
pub trait CemiTransportContext {
    /// Send a cEMI event to the layer stack's `CemiTransportLayer`.
    ///
    /// Returns the sender's `DynamicSender`. The caller should use
    /// `try_send` or `send` as appropriate.
    fn cemi_event_sender(&self) -> Option<&embassy_sync::channel::DynamicSender<'_, crate::layers::transport::cemi::CemiEvent>>;

    /// Receive a cEMI response frame from the layer stack.
    ///
    /// Returns the receiver's `DynamicReceiver`. The KNX/IP runtime polls
    /// this to pick up AL responses that should be sent to the cEMI client.
    fn cemi_response_receiver(&self) -> Option<&embassy_sync::channel::DynamicReceiver<'_, crate::messages::buffers::Buffer<'static>>>;
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
