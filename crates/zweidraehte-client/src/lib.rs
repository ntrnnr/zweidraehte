//! KNX/IP client library for device management.
//!
//! This crate provides a client-side KNX/IP tunneling connection with support
//! for both connected and unconnected device management services.
//!
//! # Architecture
//!
//! The client spawns a background worker task that owns the UDP socket and
//! manages the KNX/IP tunnel lifecycle (connection, heartbeat, sequence
//! numbers). The user-facing API communicates with the worker via channels.
//!
//! # Usage
//!
//! ```rust,ignore
//! use zweidraehte_client::KnxClient;
//! use zweidraehte_proto::address::IndividualAddress;
//!
//! let client = KnxClient::connect("192.168.1.100:3671".parse().unwrap()).await?;
//!
//! // Unconnected: read device descriptor
//! let desc = client.device_descriptor_read(IndividualAddress::new(1, 1, 1)).await?;
//!
//! // Connected: open transport connection for management
//! let device = client.open_connection(IndividualAddress::new(1, 1, 1)).await?;
//! let props = device.property_read(0, 56, 1, 1).await?;
//! device.close().await?;
//!
//! client.disconnect().await?;
//! ```

#![allow(async_fn_in_trait)]

mod client;
mod device;
mod error;
mod management;
mod transport;
pub mod tunnel;

pub use client::KnxClient;
pub use device::DeviceConnection;
pub use error::Error;
pub use management::{FunctionPropertyResult, PropertyDescription};
pub use tunnel::CemiMode;
pub use tunnel::worker::TunnelWorker;

/// Re-export commonly used proto types for convenience.
pub use zweidraehte_proto::address::IndividualAddress;
