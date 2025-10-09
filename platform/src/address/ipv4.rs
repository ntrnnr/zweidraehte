use core::fmt;

/// A four-octet IPv4 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(C)]
pub struct Address(pub [u8; 4]);

impl Address {
    /// An unspecified address.
    pub const UNSPECIFIED: Address = Address([0x00; 4]);

    /// The broadcast address.
    pub const BROADCAST: Address = Address([0xff; 4]);

    /// All multicast-capable nodes
    pub const MULTICAST_ALL_SYSTEMS: Address = Address([224, 0, 0, 1]);

    /// All multicast-capable routers
    pub const MULTICAST_ALL_ROUTERS: Address = Address([224, 0, 0, 2]);

    /// Construct an IPv4 address from parts.
    pub const fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address([a0, a1, a2, a3])
    }

    /// Construct an IPv4 address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not four octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return an IPv4 address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        self.0[0..4] == [255; 4]
    }

    /// Query whether the address is a multicast address.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0xf0 == 224
    }

    /// Query whether the address falls into the "unspecified" range.
    pub const fn is_unspecified(&self) -> bool {
        self.0[0] == 0
    }

    /// Query whether the address falls into the "link-local" range.
    pub fn is_link_local(&self) -> bool {
        self.0[0..2] == [169, 254]
    }

    /// Query whether the address falls into the "loopback" range.
    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{=u8}.{=u8}.{=u8}.{=u8}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv4Addr> for Address {
    fn from(x: ::std::net::Ipv4Addr) -> Address {
        Address(x.octets())
    }
}

#[cfg(feature = "std")]
impl From<Address> for ::std::net::Ipv4Addr {
    fn from(Address(x): Address) -> ::std::net::Ipv4Addr {
        x.into()
    }
}
