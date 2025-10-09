use core::fmt;

use crate::address::Ipv4Address;

/// An internetworking address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[non_exhaustive]
pub enum Address {
    /// An unspecified address.
    /// May be used as a placeholder for storage where the address is not assigned yet.
    Unspecified,
    /// An IPv4 address.
    Ipv4(Ipv4Address),
}

impl Address {
    /// Create an address wrapping an IPv4 address with the given octets.
    pub fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::Ipv4(Ipv4Address::new(a0, a1, a2, a3))
    }

    /// Return an address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            Address::Unspecified => &[],
            Address::Ipv4(ref addr) => addr.as_bytes(),
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        match *self {
            Address::Unspecified => true,
            Address::Ipv4(addr) => addr.is_unspecified(),
        }
    }

    /// Return an unspecified address that has the same IP version as `self`.
    pub fn to_unspecified(&self) -> Address {
        match *self {
            Address::Unspecified => Address::Unspecified,
            Address::Ipv4(_) => Address::Ipv4(Ipv4Address::UNSPECIFIED),
        }
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::Unspecified
    }
}

impl From<Ipv4Address> for Address {
    fn from(addr: Ipv4Address) -> Self {
        Address::Ipv4(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Address::Unspecified => write!(f, "*"),
            Address::Ipv4(addr) => write!(f, "{}", addr),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, f: defmt::Formatter) {
        match self {
            &Address::Unspecified => defmt::write!(f, "{:?}", "*"),
            &Address::Ipv4(addr) => defmt::write!(f, "{:?}", addr),
        }
    }
}

#[cfg(feature = "std")]
impl From<::std::net::IpAddr> for Address {
    fn from(x: ::std::net::IpAddr) -> Address {
        match x {
            ::std::net::IpAddr::V4(ipv4) => Address::Ipv4(ipv4.into()),
            ::std::net::IpAddr::V6(_) => unimplemented!(),
        }
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv4Addr> for Address {
    fn from(ipv4: ::std::net::Ipv4Addr) -> Address {
        Address::Ipv4(ipv4.into())
    }
}

#[cfg(feature = "std")]
impl From<Address> for ::std::net::IpAddr {
    fn from(e: Address) -> Self {
        match e {
            Address::Ipv4(ipv4) => ::std::net::IpAddr::V4(ipv4.into()),
            Address::Unspecified => unimplemented!(),
        }
    }
}

#[cfg(feature = "std")]
impl From<Address> for ::std::net::Ipv4Addr {
    fn from(e: Address) -> Self {
        match e {
            Address::Ipv4(ipv4) => ipv4.into(),
            Address::Unspecified => unimplemented!(),
        }
    }
}
