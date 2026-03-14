use core::fmt;

use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// A KNX individual address.
#[derive(
    Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable,
    Serialize, Deserialize,
)]
//#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct IndividualAddress(pub [u8; 2]);

impl IndividualAddress {
    /// Construct a KNX individual address from parts.
    pub const fn new(area: u8, line: u8, device: u8) -> Self {
        Self([((area & 0xf) << 4) | (line & 0xf), device])
    }

    /// Construct an Individual address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not two octets long.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(data);
        Self(bytes)
    }

    /// Return an Individual address as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the area encoded in this address
    pub const fn area(&self) -> u8 {
        self.0[0] >> 4
    }

    /// Return the line encoded in this address
    pub const fn line(&self) -> u8 {
        self.0[0] & 0xf
    }

    /// Return the subnet (area and line) encoded in this address
    pub const fn subnet(&self) -> u8 {
        self.0[0]
    }

    /// Return the device encoded in this address
    pub const fn device(&self) -> u8 {
        self.0[1]
    }
}

impl From<[u8; 2]> for IndividualAddress {
    fn from(value: [u8; 2]) -> Self {
        Self::from_bytes(&value)
    }
}

impl fmt::Display for IndividualAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(f, "{}.{}.{}", bytes[0] >> 4, bytes[0] & 0xf, bytes[1])
    }
}

impl fmt::Debug for IndividualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        write!(f, "{}.{}.{}", bytes[0] >> 4, bytes[0] & 0xf, bytes[1])
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for IndividualAddress {
    fn format(&self, f: defmt::Formatter) {
        let bytes = self.0;
        defmt::write!(f, "{=u8}.{=u8}.{=u8}", bytes[0] >> 4, bytes[0] & 0xf, bytes[1]);
    }
}

/// A KNX group address.
#[repr(transparent)]
#[derive(
    Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable,
)]
//#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupAddress(pub [u8; 2]);

impl GroupAddress {
    /// Construct a KNX individual address from three parts.
    pub const fn from_three_level(main_group: u8, middle_group: u8, sub_group: u8) -> Self {
        Self([((main_group & 0x1f) << 3) | (middle_group & 0x7), sub_group])
    }

    /// Construct a KNX individual address from two parts.
    pub const fn from_two_level(main_group: u8, sub_group: u16) -> Self {
        Self([((main_group & 0x1f) << 3) | ((sub_group & 0x700) >> 8) as u8, (sub_group & 0xff) as u8])
    }

    /// Construct an Individual address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not two octets long.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(data);
        Self(bytes)
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the main group
    pub const fn main_group(&self) -> u8 {
        self.0[0] >> 3 & 0x1f
    }

    /// Return the middle group for the 3-level group notation
    pub const fn middle_group(&self) -> u8 {
        self.0[0] & 0x07
    }

    /// Return the sub group for the 3-level group notation
    pub const fn sub_group8(&self) -> u8 {
        self.0[1]
    }

    /// Return the sub group for the 2-level group notation
    pub const fn sub_group11(&self) -> u16 {
        (((self.0[0] as u16) & 0x7) << 8) | (self.0[1] as u16)
    }
}

impl fmt::Display for GroupAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}/{}", self.main_group(), self.middle_group(), self.sub_group8())
    }
}

impl fmt::Debug for GroupAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}/{}", self.main_group(), self.middle_group(), self.sub_group8())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for GroupAddress {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{=u8}/{=u8}/{=u8}", self.main_group(), self.middle_group(), self.sub_group8())
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KNXAddress {
    Individual(IndividualAddress),
    Group(GroupAddress),
    Unspecified([u8; 2]),
}

impl KNXAddress {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(data);
        Self::Unspecified(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Individual(i) => i.as_bytes(),
            Self::Group(g) => g.as_bytes(),
            Self::Unspecified(d) => d,
        }
    }

    pub fn as_individual_address(self) -> Self {
        match self {
            Self::Individual(_) => self,
            Self::Group(ga) => ga.into(),
            Self::Unspecified(d) => IndividualAddress::from_bytes(&d).into(),
        }
    }

    pub fn as_group_address(self) -> Self {
        match self {
            Self::Individual(ia) => ia.into(),
            Self::Group(_) => self,
            Self::Unspecified(d) => GroupAddress::from_bytes(&d).into(),
        }
    }

    pub fn is_group_address(&self) -> bool {
        match self {
            KNXAddress::Group(_) => true,
            _ => false,
        }
    }

    pub fn is_individual_address(&self) -> bool {
        match self {
            KNXAddress::Individual(_) => true,
            _ => false,
        }
    }
}

impl From<IndividualAddress> for KNXAddress {
    fn from(x: IndividualAddress) -> Self {
        KNXAddress::Individual(x)
    }
}

impl From<GroupAddress> for KNXAddress {
    fn from(x: GroupAddress) -> Self {
        KNXAddress::Group(x)
    }
}

impl From<[u8; 2]> for KNXAddress {
    fn from(value: [u8; 2]) -> Self {
        Self::from_bytes(&value)
    }
}

impl fmt::Display for KNXAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KNXAddress::Group(g) => write!(f, "Group Address: {}", g),
            KNXAddress::Individual(i) => write!(f, "Individual Address: {}", i),
            KNXAddress::Unspecified(u) => write!(f, "Unspecified Address: {:?}", u),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{GroupAddress, IndividualAddress};

    #[test]
    fn test_new() {
        let a = IndividualAddress::new(1, 1, 0);
        assert_eq!(a.area(), 1);
        assert_eq!(a.line(), 1);
        assert_eq!(a.device(), 0);
    }

    #[test]
    fn test_from_bytes() {
        let a = IndividualAddress::from_bytes(&[0x11, 0x00]);
        assert_eq!(a.area(), 1);
        assert_eq!(a.line(), 1);
        assert_eq!(a.device(), 0);
    }

    #[test]
    fn test_format() {
        let a = IndividualAddress::from_bytes(&[0x11, 0x00]);
        assert_eq!(format!("{}", a), "1.1.0");

        let a = IndividualAddress::from_bytes(&[0x11, 0xfe]);
        assert_eq!(format!("{}", a), "1.1.254");
    }

    #[test]
    fn test_ga_from_bytes_3l() {
        let a = GroupAddress::from_bytes(&[0x09, 0x01]);
        assert_eq!(a.main_group(), 1);
        assert_eq!(a.middle_group(), 1);
        assert_eq!(a.sub_group8(), 1);
        assert_eq!(format!("{}", a), "1/1/1");
    }
}
