//! Traits for System B device specialization.
//!
//! These traits provide link-layer-specific configuration beyond what
//! [`StackDefinition`](crate::StackDefinition) covers. All common device
//! metadata (mask version, manufacturer ID, PEI type, table capacities)
//! lives in [`DeviceDescriptor`](crate::ets::DeviceDescriptor) via
//! `StackDefinition::DEVICE`.
//!
//! # Relationship to `StackDefinition`
//!
//! Both [`SystemBIpDeviceDef`] and [`SystemBTpDeviceDef`] are *organizational*
//! traits — they group the device-specific configuration needed for their
//! respective link layers. The user still writes `impl StackDefinition` manually,
//! but these traits provide:
//!
//! - Blanket [`KnxIpDevice`] / [`TpDevice`] impls
//! - Type-level documentation of what each link layer needs
//! - Associated type bounds that catch misconfigurations at compile time
//!
//! The `StackDefinition` impl is mechanical — it forwards everything from the
//! device def trait plus fills in the link layer builder, memory map, and
//! interface objects. See the examples on each trait.

#[cfg(feature = "knxip")]
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
#[cfg(feature = "knxip")]
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
/// Currently a marker trait. TP1-specific configuration (if any beyond what
/// [`SystemBTpDeviceDef`] provides) can be added here later.
pub trait TpDevice: Sized + Copy {}

// ============================================================================
// System B KNX/IP Device Definition
// ============================================================================

use const_default::ConstDefault;

use crate::ets::DeviceDescriptor;
use crate::layers::transport::TlStyle;
use crate::objects::comm::ComObjects;
#[cfg(feature = "knxip")]
use platform::IpTransport;

use super::memory_map::{MemoryLayout, SystemBMemoryMap};

/// Device definition for System B KNX/IP devices.
///
/// Implement this trait alongside [`StackDefinition`](crate::StackDefinition)
/// to define a KNX/IP device. This trait captures the IP-specific parts;
/// the `StackDefinition` impl wires them into the stack.
///
/// A blanket [`KnxIpDevice`] impl is provided automatically.
///
/// # Example
///
/// ```rust,ignore
/// type MyState = IpSystemBDeviceState<
///     { MY_DESCRIPTOR.address_table_size() },
///     { MY_DESCRIPTOR.association_table_size() },
///     { MY_DESCRIPTOR.comm_object_table_size() },
///     MyParams,
///     LinuxPlatform,
/// >;
///
/// #[derive(Debug, Clone, Copy)]
/// pub struct MyDevice;
///
/// impl SystemBIpDeviceDef for MyDevice {
///     const DEVICE: &'static DeviceDescriptor = &MY_DESCRIPTOR;
///     const INTERFACE_NAME: &'static str = "eth0";
///     type P = MyParams;
///     type CO = MyComObjects;
///     type Transport = LinuxIpTransport;
///     type Platform = LinuxPlatform;
///     type State = MyState;
/// }
///
/// impl StackDefinition for MyDevice {
///     const DEVICE: &'static DeviceDescriptor = &MY_DESCRIPTOR;
///     type P = MyParams;
///     type CO = MyComObjects;
///     type LLB = KnxNetIpBuilder<LinuxIpTransport, KnxIpDeviceUdp, 2>;
///     type State = MyState;
///     type Mem = SystemBMemoryMap;
///     type InterfaceObjects<'a> = DefaultKnxIpInterfaceObjects<'a, MyState>;
///
///     fn create_interface_objects<'a>(state: &'a MyState) -> Self::InterfaceObjects<'a> {
///         create_knxip_objects::<Self, _>(state, &Self::memory_layout())
///     }
/// }
/// ```
///
/// # Provided Methods
///
/// [`memory_layout()`](Self::memory_layout) and [`memory_map()`](Self::memory_map)
/// derive the memory layout from `DEVICE` and `P` so you don't need per-device
/// constants. Use `Self::memory_layout()` in `create_interface_objects` and
/// pass `MyDevice::memory_map()` to [`zweidraehte::new()`](crate::new).
///
/// # Limitations
///
/// The `KnxNetIpBuilder` socket count is fixed at 2 by convention. The
/// feature type parameter selects which optional servers to include at
/// compile time (e.g., `KnxIpDeviceUdp`, `KnxIpInterfaceUdp`).
#[cfg(feature = "knxip")]
pub trait SystemBIpDeviceDef: Copy + 'static {
    /// Device descriptor — single source of truth for hardware identity
    /// and table capacities.
    const DEVICE: &'static DeviceDescriptor;

    /// Network interface name (e.g., "eth0", "wlan0").
    const INTERFACE_NAME: &'static str;

    /// Transport layer style (default: Style1).
    const TL_STYLE: TlStyle = TlStyle::Style1;

    /// Max APDU length for compile-time buffer allocation (default: 254).
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
    /// with sizes from the device descriptor. A type alias keeps it short.
    ///
    /// This is an associated type rather than being computed automatically
    /// because `generic_const_exprs` causes overflow errors in downstream
    /// static contexts when const generics are derived from trait-associated
    /// constants.
    type State: crate::StackState
        + crate::IpStackState
        + crate::objects::interface::HasRoutingCount
        + crate::objects::tables::HasAddressTable<ADT: crate::objects::tables::HasLoadStateMachine>
        + crate::objects::tables::HasAssociationTable<AST: crate::objects::tables::HasLoadStateMachine>
        + crate::objects::tables::HasCommunicationObjectTable<COT: crate::objects::tables::HasLoadStateMachine>
        + crate::objects::tables::HasApplication<
            APP: crate::objects::tables::HasLoadStateMachine + crate::objects::tables::HasRunStateMachine,
        > + crate::objects::tables::HasPeiApplication<
            PEI: crate::objects::tables::HasLoadStateMachine + crate::objects::tables::HasRunStateMachine,
        > + 'static;

    /// Compute the memory layout for this device's tables.
    ///
    /// Derives all table offsets and sizes from [`Self::DEVICE`] and
    /// `size_of::<Self::P>()`. Override only if you need a non-standard
    /// base address or custom layout.
    fn memory_layout() -> MemoryLayout {
        MemoryLayout::from_descriptor(
            SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
            Self::DEVICE,
            core::mem::size_of::<Self::P>(),
        )
    }

    /// Compute the memory map for this device.
    ///
    /// Used as the `Mem` argument to [`zweidraehte::new()`](crate::new) and
    /// internally by [`create_interface_objects`](crate::StackDefinition::create_interface_objects).
    fn memory_map() -> SystemBMemoryMap {
        SystemBMemoryMap::new(Self::memory_layout())
    }
}

// Blanket impl: SystemBIpDeviceDef → KnxIpDevice
#[cfg(feature = "knxip")]
impl<T: SystemBIpDeviceDef> KnxIpDevice for T {
    const INTERFACE_NAME: &'static str = <T as SystemBIpDeviceDef>::INTERFACE_NAME;
    type Platform = T::Platform;
}

// ============================================================================
// System B TP1 Device Definition
// ============================================================================

/// Device definition for System B TP1 (TPUART) devices.
///
/// Implement this trait alongside [`StackDefinition`](crate::StackDefinition)
/// to define a TP1 device. This trait captures the TP1-specific parts;
/// the `StackDefinition` impl wires them into the stack.
///
/// A blanket [`TpDevice`] impl is provided automatically.
///
/// # Example
///
/// ```rust,ignore
/// type MyState = SystemBDeviceState<
///     { MY_DESCRIPTOR.address_table_size() },
///     { MY_DESCRIPTOR.association_table_size() },
///     { MY_DESCRIPTOR.comm_object_table_size() },
///     MyParams,
///     // LS defaults to () for TP1
/// >;
///
/// #[derive(Debug, Clone, Copy)]
/// pub struct MyTpDevice;
///
/// impl SystemBTpDeviceDef for MyTpDevice {
///     const DEVICE: &'static DeviceDescriptor = &MY_DESCRIPTOR;
///     type P = MyParams;
///     type CO = MyComObjects;
///     type UartTx = embassy_stm32::usart::UartTx<'static>;
///     type UartRx = embassy_stm32::usart::UartRx<'static>;
///     type State = MyState;
/// }
///
/// impl StackDefinition for MyTpDevice {
///     const DEVICE: &'static DeviceDescriptor = &MY_DESCRIPTOR;
///     type P = MyParams;
///     type CO = MyComObjects;
///     type LLB = TpUartLinkLayerBuilder<embassy_stm32::usart::UartTx<'static>, embassy_stm32::usart::UartRx<'static>>;
///     type State = MyState;
///     type Mem = SystemBMemoryMap;
///     type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<'a, MyState>;
///
///     fn create_interface_objects<'a>(state: &'a MyState) -> Self::InterfaceObjects<'a> {
///         create_system_b_objects::<Self, _>(state, &Self::memory_layout())
///     }
/// }
/// ```
pub trait SystemBTpDeviceDef: Copy + 'static {
    /// Device descriptor — single source of truth for hardware identity
    /// and table capacities.
    const DEVICE: &'static DeviceDescriptor;

    /// Transport layer style (default: Style1).
    const TL_STYLE: TlStyle = TlStyle::Style1;

    /// Max APDU length for compile-time buffer allocation.
    ///
    /// Defaults to 15 (TP1 standard frame). Devices on chips with larger
    /// buffers (NCN5120, E981) may increase this up to 248.
    const MAX_APDU_LENGTH: u16 = crate::config::MAX_APDU_LENGTH_TP1_STANDARD;

    /// Application parameter type.
    type P: ConstDefault + 'static;

    /// Communication objects type.
    type CO: ComObjects;

    /// UART TX half for TPUART communication.
    ///
    /// Split from the full UART so that TX and RX can proceed concurrently
    /// in the event loop (e.g., `BufferedUart::split()` on Embassy).
    type UartTx: embedded_io_async::Write + Send + 'static;

    /// UART RX half for TPUART communication.
    type UartRx: embedded_io_async::Read + Send + 'static;

    /// Concrete device state type, pre-parameterized with table sizes.
    ///
    /// This is almost always `SystemBDeviceState<ADT, AST, COT, P>` with
    /// sizes from the device descriptor. The `LS` parameter defaults to `()`
    /// for TP1 (no link-layer-specific state).
    ///
    /// This is an associated type rather than being computed automatically
    /// because `generic_const_exprs` causes overflow errors in downstream
    /// static contexts when const generics are derived from trait-associated
    /// constants.
    type State: crate::StackState
        + crate::objects::interface::HasRoutingCount
        + crate::objects::tables::HasAddressTable<ADT: crate::objects::tables::HasLoadStateMachine>
        + crate::objects::tables::HasAssociationTable<AST: crate::objects::tables::HasLoadStateMachine>
        + crate::objects::tables::HasCommunicationObjectTable<COT: crate::objects::tables::HasLoadStateMachine>
        + crate::objects::tables::HasApplication<
            APP: crate::objects::tables::HasLoadStateMachine + crate::objects::tables::HasRunStateMachine,
        > + crate::objects::tables::HasPeiApplication<
            PEI: crate::objects::tables::HasLoadStateMachine + crate::objects::tables::HasRunStateMachine,
        > + 'static;

    /// Compute the memory layout for this device's tables.
    ///
    /// Derives all table offsets and sizes from [`Self::DEVICE`] and
    /// `size_of::<Self::P>()`. Override only if you need a non-standard
    /// base address or custom layout.
    fn memory_layout() -> MemoryLayout {
        MemoryLayout::from_descriptor(
            SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
            Self::DEVICE,
            core::mem::size_of::<Self::P>(),
        )
    }

    /// Compute the memory map for this device.
    ///
    /// Used as the `Mem` argument to [`zweidraehte::new()`](crate::new) and
    /// internally by [`create_interface_objects`](crate::StackDefinition::create_interface_objects).
    fn memory_map() -> SystemBMemoryMap {
        SystemBMemoryMap::new(Self::memory_layout())
    }
}

// Blanket impl: SystemBTpDeviceDef → TpDevice
impl<T: SystemBTpDeviceDef> TpDevice for T {}
