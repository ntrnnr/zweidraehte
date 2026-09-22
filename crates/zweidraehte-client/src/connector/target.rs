//! Bus endpoint selection, independent of argument parsing and key acquisition.

use std::net::SocketAddrV4;

use crate::{BusResult, KnxBus, SecurityStore};

/// A built-in bus endpoint to open with caller-supplied security state.
///
/// KNX/IP is always available; the USB variant requires the `usb` feature.
/// Custom connectors can be passed directly to [`KnxBus::with_connector`].
///
/// ```no_run
/// use zweidraehte_client::{BusTarget, SecurityStore};
///
/// # async fn open_bus(security: SecurityStore) -> Result<(), Box<dyn std::error::Error>> {
/// let target = BusTarget::Ip("192.168.1.100:3671".parse()?);
/// let bus = target.connect_with_security(security).await?;
/// // Use group communication or device management through the bus.
/// bus.disconnect().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub enum BusTarget {
    /// A KNX/IP tunneling interface.
    Ip(SocketAddrV4),
    /// A KNX USB interface. Unavailable connectors cannot be selected.
    #[cfg(feature = "usb")]
    Usb(super::UsbSelector),
}

impl BusTarget {
    /// Connect with an empty security store and in-memory sequence state.
    pub async fn connect(&self) -> BusResult<KnxBus> {
        self.connect_with_security(SecurityStore::new()).await
    }

    /// Connect with prepared Data Secure keys and a caller-owned sequence store.
    /// Prepare durable sequence state before opening the connector, so secure
    /// traffic cannot accidentally start with an in-memory-only counter.
    pub async fn connect_with_security(&self, security: SecurityStore) -> BusResult<KnxBus> {
        // Logging keeps connector selection usable while a TUI owns the terminal.
        match self {
            Self::Ip(addr) => {
                log::info!("Connecting to KNX/IP interface at {addr}...");
                KnxBus::connect_ip_with_security(*addr, security).await
            }
            #[cfg(feature = "usb")]
            Self::Usb(selector) => {
                log::info!("Connecting to KNX USB interface ({selector:?})...");
                KnxBus::connect_usb_with_security(selector, security).await
            }
        }
    }
}
