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
pub mod prov_storage;
pub mod storage;
pub mod uart;

pub use net::{
    EmbassyIpTransport, EmbassyIpTransportTcp, EmbassyTcpContext, EmbassyTcpListener, EmbassyTcpStream,
    EmbassyTcpStreamError, EmbassyUdpContext, EmbassyUdpSocket, EmbassyUdpSocketTcp, TcpError, TcpPool, UdpPool,
    UdpError,
};
pub use network_info::{EmbassyNetworkInfo, IP_ASSIGN_DHCP, IP_ASSIGN_MANUAL, NetworkConfigError, mask_to_prefix};
pub use prov_storage::identity_from_record;
#[cfg(all(feature = "rp2040", feature = "provision-on-boot"))]
pub use prov_storage::synthesize_and_write;
#[cfg(feature = "rp2040")]
pub use prov_storage::{read_provisioning, write_provisioning};
pub use storage::{FlashError, FlashIdentityData, RpFlashStorage};
