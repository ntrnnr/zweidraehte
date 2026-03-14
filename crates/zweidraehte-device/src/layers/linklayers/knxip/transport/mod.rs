//! Transport managers for KNX/IP.
//!
//! Owns the UDP and TCP socket lifecycle. The main event loop
//! [`select`](embassy_futures::select)s on
//! [`UdpManager::next_event()`] and [`TcpManager::next_event()`] to
//! receive inbound frames.

mod tcp_framing;
pub(crate) mod tcp_manager;
pub(crate) mod udp_manager;

pub(super) use tcp_manager::{TcpEvent, TcpManager};
pub(super) use udp_manager::{SocketDescriptor, UdpEvent, UdpManager};
