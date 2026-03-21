//! KNX/IP tunneling connection management.
//!
//! The tunnel module handles the KNX/IP tunneling protocol:
//! - Connection establishment and teardown
//! - Heartbeat (ConnectionstateRequest/Response)
//! - Sequence number management
//! - cEMI frame encoding for outgoing and decoding for incoming traffic

pub(crate) mod codec;
pub mod worker;

pub use codec::CemiMode;
