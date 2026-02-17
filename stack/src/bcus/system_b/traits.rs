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
