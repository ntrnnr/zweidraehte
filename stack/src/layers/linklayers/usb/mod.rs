//! KNX USB Interface Support
//!
//! This module provides USB HID support for KNX interfaces as specified in
//! KNX System Specification Volume 9.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │           UsbLinkLayer                      │
//! │  - Implements LinkLayerBuilder              │
//! │  - Sets PID_COMM_MODE for DLL mode          │
//! │  - Converts internal format ↔ cEMI          │
//! └─────────────────────────────────────────────┘
//!                       │
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │         UsbCemiTransport                    │
//! │  - USB HID framing                          │
//! │  - EMI negotiation                          │
//! │  - Raw cEMI frame TX/RX                     │
//! │  - Device management (M_PropRead/Write)     │
//! └─────────────────────────────────────────────┘
//!                       │
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │           AsyncHidDevice                    │
//! │  - Raw USB HID reports                      │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ### As a Link Layer (recommended for most applications)
//!
//! ```ignore
//! use zweidraehte::layers::linklayers::usb::{UsbLinkLayerBuilder, UsbLinkLayerResources};
//!
//! // Auto-discover first KNX USB interface
//! let builder = UsbLinkLayerBuilder::new();
//! let mut resources = UsbLinkLayerResources::new();
//!
//! // Use with LinkLayerBuilder trait
//! builder.build_and_run(&mut resources, context, network_sender, inbox).await;
//! ```
//!
//! ### As a Raw Transport (for custom protocols or testing)
//!
//! ```ignore
//! use zweidraehte::layers::linklayers::usb::{
//!     UsbCemiTransport, UsbCemiTransportResources, DeviceSelector
//! };
//!
//! let mut resources = UsbCemiTransportResources::new();
//! let initialized = resources.init();
//!
//! let mut transport = UsbCemiTransport::open(&DeviceSelector::AutoDiscover, initialized).await?;
//! transport.initialize().await?;
//!
//! // Send raw cEMI frames
//! transport.send_cemi_raw(&cemi_data).await?;
//!
//! // Read/write interface properties
//! transport.prop_write(0x08, 0x08, &[0x00]).await?; // Set comm mode
//! ```

extern crate alloc;

// Submodules
pub mod bus_access;
pub mod device;
pub mod hid;
pub mod link_layer;
pub mod protocol;
pub mod transport;

// Re-exports for Link Layer usage
pub use link_layer::{UsbLinkLayerBuilder, UsbLinkLayerResources};

// Re-exports for Transport usage
pub use transport::{
    UsbCemiTransport, UsbCemiTransportResources, InitializedResources,
    comm_mode, properties,
};

// Re-exports for device handling
pub use device::{
    AsyncHidDevice, DeviceSelector, UsbHidDevice, UsbHidError,
    KNOWN_KNX_DEVICES, list_devices,
};

// Legacy alias for backward compatibility
pub use device::DeviceSelector as UsbDeviceSelector;
