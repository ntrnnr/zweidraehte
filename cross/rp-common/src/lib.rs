#![no_std]
#![feature(never_type)]

//! Shared platform code for RP2040/RP2350 KNX/IP devices.
//!
//! Provides embassy-net based networking, flash storage, and system control
//! implementations that are reusable across different network transports
//! (WiFi, Ethernet, etc.).

pub mod button;
mod net;
mod network_info;
mod storage;
mod system;

pub use net::{EmbassyIpTransport, EmbassyUdpSocket, UdpError};
pub use network_info::{EmbassyNetworkInfo, NetworkConfigError};
pub use storage::{FlashError, FlashIdentityData, RpFlashStorage};
#[cfg(feature = "rp2040")]
pub use storage::read_or_provision_identity;
pub use system::{CortexMSystem, SystemError};
