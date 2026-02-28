//! Context traits for KNX stack layers
//!
//! This module defines trait-based interfaces for accessing stack resources.
//! Layers depend only on the specific context traits they need, making them
//! easier to test and more modular.

use embassy_sync::channel::DynamicSender;

use crate::messages::buffers::{Buffer, DynBufferManager};
use crate::messages::builder::IndicationMessage;
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

/// Provides a sender to the application layer's incoming channel.
///
/// Used by cEMI Transport Layer mode (Device Management connections) to
/// inject synthetic indications directly into the application layer,
/// bypassing the bus transport/network layers.
pub trait ApplicationLayerContext {
    /// Get a sender to the application layer's indication channel.
    fn application_layer_sender(&self) -> DynamicSender<'_, IndicationMessage<Buffer<'static>>>;
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
pub trait IpAdditionalIndividualAddressContext {
    /// Additional individual addresses assigned to tunneling connections.
    fn additional_individual_addresses(&self) -> crate::AdditionalIndividualAddresses;
}

/// Provides the KNX primary individual address.
pub trait KnxIndividualAddressContext {
    /// The device's primary individual address.
    fn individual_address(&self) -> crate::address::IndividualAddress;
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
