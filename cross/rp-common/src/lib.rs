#![no_std]
#![feature(never_type)]

//! Shared platform code for RP2040/RP2350 KNX devices.
//!
//! Provides embassy-net based networking, flash storage, system control,
//! and a direct-register UART driver for latency-critical TPUART
//! communication.

pub mod button;
mod net;
mod network_info;
mod storage;
mod system;
pub mod uart;

pub use net::{EmbassyIpTransport, EmbassyUdpSocket, UdpError};
pub use network_info::{EmbassyNetworkInfo, IP_ASSIGN_DHCP, IP_ASSIGN_MANUAL, NetworkConfigError, mask_to_prefix};
#[cfg(feature = "rp2040")]
pub use storage::read_or_provision_identity;
pub use storage::{FlashError, FlashIdentityData, RpFlashStorage};
pub use system::{CortexMSystem, SystemError};
