//! Bus endpoint selection, independent of argument parsing and key acquisition.

use std::net::SocketAddrV4;

use crate::connector::IpTunnelConnector;
use crate::{BusResult, KnxBus, SecurityStore};

/// A built-in bus endpoint, opened with [`KnxBus::connect`] or
/// [`KnxBusBuilder::connect`](crate::KnxBusBuilder::connect).
///
/// KNX/IP is always available; the USB variant requires the `usb` feature.
/// Custom connectors go through [`KnxBusBuilder::attach`](crate::KnxBusBuilder::attach).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BusTarget {
    /// A KNX/IP tunneling interface.
    Ip(SocketAddrV4),
    /// A KNX USB interface. Unavailable connectors cannot be selected.
    #[cfg(feature = "usb")]
    Usb(super::UsbSelector),
}

impl BusTarget {
    /// Open this endpoint's connector and start the bus over it.
    pub(crate) async fn open(&self, security: SecurityStore) -> BusResult<KnxBus> {
        // Logging keeps connector selection usable while a TUI owns the terminal.
        match self {
            Self::Ip(addr) => {
                log::info!("Connecting to KNX/IP interface at {addr}...");
                let (connector, info) = IpTunnelConnector::connect(*addr).await?;
                Ok(KnxBus::start(connector, info, security))
            }
            #[cfg(feature = "usb")]
            Self::Usb(selector) => {
                log::info!("Connecting to KNX USB interface ({selector:?})...");
                let (connector, info) = super::UsbConnector::connect(selector).await?;
                Ok(KnxBus::start(connector, info, security))
            }
        }
    }
}
