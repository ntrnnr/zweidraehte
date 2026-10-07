#![no_std]
#![feature(adt_const_params)]

//! Shared platform code for RP2040/RP2350 KNX devices.
//!
//! Provides embassy-net based networking, flash storage, and a
//! direct-register UART driver for latency-critical TPUART
//! communication. HAL-agnostic helpers (`DebouncedButton`,
//! `CortexMSystem`) live in `embedded-common` and are imported from
//! there directly at every call site.

pub mod flash_seq;
mod net;
mod network_info;
pub mod prov_storage;
pub mod rng;
pub mod storage;
pub mod uart;

pub use flash_seq::RpFlashIo;
pub use net::{
    EmbassyIpTransport, EmbassyIpTransportTcp, EmbassyTcpContext, EmbassyTcpListener, EmbassyTcpStream,
    EmbassyTcpStreamError, EmbassyUdpContext, EmbassyUdpSocket, EmbassyUdpSocketTcp, TcpError, TcpPool, UdpError,
    UdpPool,
};
pub use network_info::{
    EmbassyNetworkInfo, IP_ASSIGN_DHCP, IP_ASSIGN_MANUAL, NetworkConfigError, StoredIp, mask_to_prefix,
};
pub use prov_storage::{identity_from_record, secure_identity_from_record};
pub use rng::RpCommonRng;
pub use storage::{
    ConfigLog, FlashIdentityData, FlashSecureIdentityData, McTimerLog, PROVISIONING_SECTOR, QspiFlash, STORAGE_BASE,
    SiatLog, peek_config,
};
