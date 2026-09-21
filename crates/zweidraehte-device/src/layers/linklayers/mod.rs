pub mod mock;

// Each medium filters incoming frames using the same live destination policy.
#[cfg(any(feature = "tp1", feature = "rf", feature = "knxip"))]
pub mod address_check;

#[cfg(feature = "knxip")]
pub mod knxip;

#[cfg(feature = "tp1")]
pub mod tpuart;

#[cfg(feature = "rf")]
pub mod knxrf;

#[cfg(feature = "ip-interface")]
pub mod ip_interface;

#[cfg(feature = "usb")]
pub mod usb;
