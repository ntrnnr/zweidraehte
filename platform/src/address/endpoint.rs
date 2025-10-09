use crate::address::IpAddress;
use core::fmt;

/// An internet endpoint address.
///
/// An endpoint can be constructed from a port, in which case the address is unspecified.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Endpoint {
    pub addr: IpAddress,
    pub port: u16,
}

impl Endpoint {
    /// An endpoint with unspecified address and port.
    pub const UNSPECIFIED: Endpoint = Endpoint { addr: IpAddress::Unspecified, port: 0 };

    /// Create an endpoint address from given address and port.
    pub fn new(addr: IpAddress, port: u16) -> Endpoint {
        Endpoint { addr, port }
    }

    /// Query whether the endpoint has a specified address and port.
    pub fn is_specified(&self) -> bool {
        !self.addr.is_unspecified() && self.port != 0
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Endpoint {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{:?}:{=u16}", self.addr, self.port);
    }
}

#[cfg(feature = "std")]
impl From<::std::net::SocketAddr> for Endpoint {
    fn from(x: ::std::net::SocketAddr) -> Endpoint {
        Endpoint { addr: x.ip().into(), port: x.port() }
    }
}

#[cfg(feature = "std")]
impl From<::std::net::SocketAddrV4> for Endpoint {
    fn from(x: ::std::net::SocketAddrV4) -> Endpoint {
        Endpoint { addr: x.ip().clone().into(), port: x.port() }
    }
}

#[cfg(feature = "std")]
impl From<Endpoint> for ::std::net::SocketAddr {
    fn from(e: Endpoint) -> Self {
        ::std::net::SocketAddr::new(e.addr.into(), e.port)
    }
}

#[cfg(feature = "std")]
impl From<Endpoint> for ::std::net::SocketAddrV4 {
    fn from(e: Endpoint) -> Self {
        ::std::net::SocketAddrV4::new(e.addr.into(), e.port)
    }
}
