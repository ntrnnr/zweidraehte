//! Traits for System B device specialization.
//!
//! These traits provide link-layer-specific configuration beyond what
//! [`StackDefinition`](crate::StackDefinition) covers. All common device
//! metadata (mask version, manufacturer ID, PEI type, table capacities)
//! lives in [`DeviceDescriptor`](crate::ets::DeviceDescriptor) via
//! `StackDefinition::DEVICE`.

use crate::{IpPlatform, IpPlatformConfig};

/// Trait for KNX/IP devices (mask version 57B0).
///
/// Provides KNX/IP-specific configuration: the network interface name
/// and the platform abstraction for querying runtime network state.
///
/// # Example
///
/// ```rust,ignore
/// impl KnxIpDevice for MyDevice {
///     const INTERFACE_NAME: &'static str = "eth0";
///     type Platform = LinuxPlatform;
/// }
/// ```
pub trait KnxIpDevice: Sized + Copy {
    /// Network interface name (e.g., "eth0", "wlan0", "enp0s3").
    const INTERFACE_NAME: &'static str;

    /// Platform for querying and applying network configuration.
    ///
    /// Must implement [`IpPlatform`] for reading current network state
    /// and [`IpPlatformConfig`] for applying IP configuration changes
    /// (e.g., switching between DHCP and static IP).
    type Platform: IpPlatform + IpPlatformConfig + Default;
}

/// Trait for TP1 devices (mask version 07B0).
///
/// TP1 link layer is not yet implemented. This trait is a placeholder
/// for future development.
pub trait TpDevice: Sized + Copy {
    // TODO: Add TP1-specific configuration when TPUART link layer is implemented
    // - UART peripheral configuration
    // - Baud rate (9600 for TP1)
    // - etc.
}

// ============================================================================
// System B KNX/IP Device Definition (simplified)
// ============================================================================

use const_default::ConstDefault;

use crate::ets::DeviceDescriptor;
use crate::layers::transport::TlStyle;
use crate::objects::comm::ComObjects;
use platform::IpTransport;

/// Simplified device definition for System B KNX/IP devices.
///
/// Implement this trait instead of [`StackDefinition`](crate::StackDefinition)
/// + [`KnxIpDevice`] to get both automatically via blanket implementations.
/// This eliminates the mechanical boilerplate of computing table sizes,
/// wiring up `IpSystemBDeviceState`, `MemoryLayout`, `SystemBMemoryMap`,
/// and the `InterfaceObjects` GAT.
///
/// # What you provide
///
/// - Device descriptor (hardware identity, table capacities)
/// - Network interface name
/// - Application parameter type and communication objects type
/// - Platform transport and network configuration types
///
/// # What you get for free
///
/// - `StackDefinition` impl with computed table sizes and memory layout
/// - `KnxIpDevice` impl
/// - `IpSystemBDeviceState` as the `State` type (via `StackDefinition::State`)
/// - `DefaultKnxIpInterfaceObjects` as the interface objects type
///
/// # Example
///
/// ```rust,ignore
/// // Precompute table sizes from descriptor (needed due to generic_const_exprs limitations).
/// type MyState = IpSystemBDeviceState<
///     { MY_DEVICE_DESCRIPTOR.address_table_size() },
///     { MY_DEVICE_DESCRIPTOR.association_table_size() },
///     { MY_DEVICE_DESCRIPTOR.comm_object_table_size() },
///     MyParams,
///     LinuxPlatform,
/// >;
///
/// #[derive(Debug, Clone, Copy)]
/// pub struct MyDevice;
///
/// impl SystemBIpDeviceDef for MyDevice {
///     const DEVICE: &'static DeviceDescriptor = &MY_DEVICE_DESCRIPTOR;
///     const INTERFACE_NAME: &'static str = "eth0";
///     type P = MyParams;
///     type CO = MyComObjects;
///     type Transport = LinuxIpTransport;
///     type Platform = LinuxPlatform;
///     type State = MyState;
/// }
/// ```
///
/// # Limitations
///
/// The `KnxNetIpBuilder` socket count is fixed at 2. Devices needing
/// more sockets should implement `StackDefinition` directly.
pub trait SystemBIpDeviceDef: Copy + 'static {
    /// Device descriptor — single source of truth for hardware identity
    /// and table capacities.
    const DEVICE: &'static DeviceDescriptor;

    /// Network interface name (e.g., "eth0", "wlan0").
    const INTERFACE_NAME: &'static str;

    /// Transport layer style (default: Style1).
    const TL_STYLE: TlStyle = TlStyle::Style1;

    /// Max APDU length for compile-time buffer allocation (default: 255).
    const MAX_APDU_LENGTH: u16 = crate::config::MAX_APDU_LENGTH_EXTENDED;

    /// Application parameter type.
    type P: ConstDefault + 'static;

    /// Communication objects type.
    type CO: ComObjects;

    /// IP transport implementation (e.g., `LinuxIpTransport`, `PicoWIpTransport`).
    type Transport: IpTransport + 'static;

    /// Platform for querying and applying network configuration.
    type Platform: IpPlatform + IpPlatformConfig + Default + 'static;

    /// Concrete device state type, pre-parameterized with table sizes.
    ///
    /// This is almost always `IpSystemBDeviceState<ADT, AST, COT, P, Platform>`
    /// with sizes from the device descriptor. A type alias keeps it short:
    ///
    /// ```rust,ignore
    /// type State = MyDeviceState; // where MyDeviceState is a type alias
    /// ```
    ///
    /// This is an associated type rather than being computed automatically
    /// because `generic_const_exprs` causes overflow errors in downstream
    /// static contexts when const generics are derived from trait-associated
    /// constants.
    type State: crate::StackState
        + crate::IpStackState
        + crate::objects::interface::HasRoutingCount
        + crate::objects::tables::HasAddressTable<
            ADT: crate::objects::tables::HasLoadStateMachine,
        >
        + crate::objects::tables::HasAssociationTable<
            AST: crate::objects::tables::HasLoadStateMachine,
        >
        + crate::objects::tables::HasCommunicationObjectTable<
            COT: crate::objects::tables::HasLoadStateMachine,
        >
        + crate::objects::tables::HasApplication<
            APP: crate::objects::tables::HasLoadStateMachine
                + crate::objects::tables::HasRunStateMachine,
        >
        + crate::objects::tables::HasPeiApplication<
            PEI: crate::objects::tables::HasLoadStateMachine
                + crate::objects::tables::HasRunStateMachine,
        >
        + 'static;
}

// Blanket impl: SystemBIpDeviceDef → KnxIpDevice
impl<T: SystemBIpDeviceDef> KnxIpDevice for T {
    const INTERFACE_NAME: &'static str = <T as SystemBIpDeviceDef>::INTERFACE_NAME;
    type Platform = T::Platform;
}

// Blanket impl: SystemBIpDeviceDef → StackDefinition
impl<T: SystemBIpDeviceDef> crate::StackDefinition for T {
    const DEVICE: &'static DeviceDescriptor = T::DEVICE;
    const TL_STYLE: TlStyle = T::TL_STYLE;
    const MAX_APDU_LENGTH: u16 = T::MAX_APDU_LENGTH;

    type P = T::P;
    type CO = T::CO;
    type LLB = crate::layers::linklayers::knxip::KnxNetIpBuilder<T::Transport, 2>;
    type State = T::State;
    type Mem = super::SystemBMemoryMap;

    type InterfaceObjects<'a> = super::DefaultKnxIpInterfaceObjects<'a, Self::State>;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        let layout = super::MemoryLayout::from_descriptor(
            super::SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
            T::DEVICE,
            core::mem::size_of::<T::P>(),
        );
        super::create_knxip_objects::<T, _>(state, &layout)
    }
}
