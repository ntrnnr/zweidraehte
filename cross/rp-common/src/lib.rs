#![no_std]

//! Shared platform code for RP2040/RP2350 KNX devices.
//!
//! Provides embassy-net based networking, flash storage, and a
//! direct-register UART driver for latency-critical TPUART
//! communication. HAL-agnostic helpers (`DebouncedButton`,
//! `CortexMSystem`) live in `embedded-common` and are imported from
//! there directly at every call site.

mod net;
mod network_info;
mod storage;
pub mod uart;

pub use net::{EmbassyIpTransport, EmbassyUdpSocket, UdpError};
pub use network_info::{EmbassyNetworkInfo, IP_ASSIGN_DHCP, IP_ASSIGN_MANUAL, NetworkConfigError, mask_to_prefix};
#[cfg(feature = "rp2040")]
pub use storage::read_or_provision_identity;
pub use storage::{FlashError, FlashIdentityData, RpFlashStorage};
