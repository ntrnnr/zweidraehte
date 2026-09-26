use core::fmt;

use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// A KNX individual address.
#[derive(
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Default,
    FromBytes,
    IntoBytes,
    Unaligned,
    KnownLayout,
    Immutable,
    Serialize,
    Deserialize,
)]
//#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct IndividualAddress(pub [u8; 2]);

impl IndividualAddress {
    /// Construct a KNX individual address from parts.
    ///
    /// # Panics
    /// Panics if `area` or `line` exceeds 15. Invalid components must not be
    /// silently truncated into a different device's address.
    pub const fn new(area: u8, line: u8, device: u8) -> Self {
        core::assert!(area <= 15, "individual address area exceeds 15");
        core::assert!(line <= 15, "individual address line exceeds 15");
        Self([(area << 4) | line, device])
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
    /// Construct a KNX group address from three parts.
    ///
    /// # Panics
    /// Panics if `main_group` exceeds 31 or `middle_group` exceeds 7.
    /// Invalid components must not silently select a different group.
    pub const fn from_three_level(main_group: u8, middle_group: u8, sub_group: u8) -> Self {
        core::assert!(main_group <= 31, "group address main group exceeds 31");
        core::assert!(middle_group <= 7, "group address middle group exceeds 7");
        Self([(main_group << 3) | middle_group, sub_group])
    }

    /// Construct a KNX group address from two parts.
    ///
    /// # Panics
    /// Panics if `main_group` exceeds 31 or `sub_group` exceeds 2047.
    /// Invalid components must not silently select a different group.
    pub const fn from_two_level(main_group: u8, sub_group: u16) -> Self {
        core::assert!(main_group <= 31, "group address main group exceeds 31");
        core::assert!(sub_group <= 2047, "group address subgroup exceeds 2047");
        Self([(main_group << 3) | (sub_group >> 8) as u8, sub_group as u8])
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
        matches!(self, KNXAddress::Group(_))
    }

    pub fn is_individual_address(&self) -> bool {
        matches!(self, KNXAddress::Individual(_))
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
    fn individual_address_component_boundaries() {
        const ZERO: IndividualAddress = IndividualAddress::new(0, 0, 0);
        const MAX: IndividualAddress = IndividualAddress::new(15, 15, 255);
        assert_eq!(ZERO.as_bytes(), &[0, 0]);
        assert_eq!(MAX.as_bytes(), &[0xFF, 0xFF]);
    }

    #[test]
    #[should_panic(expected = "individual address area exceeds 15")]
    fn individual_address_rejects_area_overflow() {
        IndividualAddress::new(16, 1, 42);
    }

    #[test]
    #[should_panic(expected = "individual address line exceeds 15")]
    fn individual_address_rejects_line_overflow() {
        IndividualAddress::new(1, 16, 42);
    }

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
    fn group_address_component_boundaries() {
        const ZERO_THREE: GroupAddress = GroupAddress::from_three_level(0, 0, 0);
        const ZERO_TWO: GroupAddress = GroupAddress::from_two_level(0, 0);
        const MAX_THREE: GroupAddress = GroupAddress::from_three_level(31, 7, 255);
        const MAX_TWO: GroupAddress = GroupAddress::from_two_level(31, 2047);
        assert_eq!(ZERO_THREE.as_bytes(), &[0, 0]);
        assert_eq!(ZERO_TWO, ZERO_THREE);
        assert_eq!(MAX_THREE.as_bytes(), &[0xFF, 0xFF]);
        assert_eq!(MAX_TWO, MAX_THREE);

        assert_eq!(GroupAddress::from_three_level(3, 4, 5).as_bytes(), &[0x1C, 0x05]);
        assert_eq!(GroupAddress::from_two_level(3, 1029), GroupAddress::from_three_level(3, 4, 5));
    }

    #[test]
    #[should_panic(expected = "group address main group exceeds 31")]
    fn three_level_group_address_rejects_main_overflow() {
        GroupAddress::from_three_level(32, 1, 42);
    }

    #[test]
    #[should_panic(expected = "group address middle group exceeds 7")]
    fn three_level_group_address_rejects_middle_overflow() {
        GroupAddress::from_three_level(1, 8, 42);
    }

    #[test]
    #[should_panic(expected = "group address main group exceeds 31")]
    fn two_level_group_address_rejects_main_overflow() {
        GroupAddress::from_two_level(32, 42);
    }

    #[test]
    #[should_panic(expected = "group address subgroup exceeds 2047")]
    fn two_level_group_address_rejects_subgroup_overflow() {
        GroupAddress::from_two_level(1, 2048);
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
