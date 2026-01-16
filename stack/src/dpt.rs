#![allow(non_camel_case_types)]

use core::convert::TryInto;
use core::fmt;
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned, big_endian};

// Datapoint types: 3.7.2
// Identifiers: 3.7.3

pub const trait PropertyDataDefinition {
    const SIZE: usize;
    const ID: u8;
}

#[serde_as]
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    Unaligned,
    Serialize,
    Deserialize,
)]
#[repr(C)]
pub struct PropertyData<T, const ID: u8, const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
    #[serde(skip)]
    _p: PhantomData<T>,
}

// FIXME: remove this and implement specific Debug outputs for each PDT
impl<T, const ID: u8, const N: usize> core::fmt::Debug for PropertyData<T, ID, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.data)
    }
}

impl<T, const ID: u8, const N: usize> Default for PropertyData<T, ID, N> {
    fn default() -> Self {
        Self { data: [0; N], _p: PhantomData }
    }
}

// impl<T, const ID: u8, const N: usize> Serialize for PropertyData<T, ID, N> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         serializer.serialize_bytes(&self.data)
//     }
// }

// impl<'de, T, const ID: u8, const N: usize> Deserialize<'de> for PropertyData<T, ID, N> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         struct PropertyDataVisitor<T, const ID: u8, const N: usize>(PhantomData<T>);

//         impl<'de, T, const ID: u8, const N: usize> Visitor<'de> for PropertyDataVisitor<T, ID, N> {
//             type Value = PropertyData<T, ID, N>;

//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str("a byte array of the correct size")
//             }

//             fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
//             where
//                 E: serde::de::Error,
//             {
//                 if value.len() != N {
//                     return Err(E::invalid_length(value.len(), &self));
//                 }

//                 let mut data = [0; N];
//                 data.copy_from_slice(value);

//                 Ok(PropertyData {
//                     data,
//                     p: PhantomData,
//                 })
//             }
//         }

//         deserializer.deserialize_bytes(PropertyDataVisitor(PhantomData))
//     }
// }

impl<T, const ID: u8, const N: usize> const PropertyDataDefinition for PropertyData<T, ID, N> {
    const ID: u8 = ID;
    const SIZE: usize = N;
}

impl<T, const ID: u8, const N: usize> AsRef<[u8]> for PropertyData<T, ID, N> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T, const ID: u8, const N: usize> AsMut<[u8]> for PropertyData<T, ID, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

macro_rules! impl_primitive_pdt {
    ($typ:ty) => {
        impl<const ID: u8, const N: usize> PropertyData<$typ, ID, N> {
            pub const fn with_value(value: $typ) -> Self {
                Self { data: *(&value).to_be_bytes().as_array().unwrap(), _p: PhantomData }
            }

            pub const fn as_const_ref(&self) -> &[u8] {
                &self.data
            }

            pub fn value(&self) -> $typ {
                <$typ>::from_be_bytes(self.data[..N].try_into().unwrap())
            }

            pub fn set_value(&mut self, data: $typ) {
                self.data.copy_from_slice(&data.to_be_bytes()[..N]);
            }
        }

        impl<const ID: u8, const N: usize> Into<$typ> for PropertyData<$typ, ID, N> {
            fn into(self) -> $typ {
                self.value()
            }
        }

        impl<const ID: u8, const N: usize> From<$typ> for PropertyData<$typ, ID, N> {
            fn from(value: $typ) -> Self {
                Self::with_value(value)
            }
        }
    };
}

impl_primitive_pdt!(i8);
impl_primitive_pdt!(u8);
impl_primitive_pdt!(i16);
impl_primitive_pdt!(u16);
impl_primitive_pdt!(i32);
impl_primitive_pdt!(u32);
impl_primitive_pdt!(f32);
impl_primitive_pdt!(f64);

macro_rules! impl_array_pdt {
    ($typ:ty) => {
        impl<const ID: u8, const N: usize> PropertyData<$typ, ID, N> {
            pub const fn with_value(value: $typ) -> Self {
                Self { data: *(&value).as_array().unwrap(), _p: PhantomData }
            }

            pub const fn as_const_ref(&self) -> &[u8] {
                &self.data
            }

            pub fn value(&self) -> $typ {
                self.data[..N].try_into().unwrap()
            }

            pub fn set_value(&mut self, data: $typ) {
                self.data.copy_from_slice(&data[..N]);
            }
        }

        impl<const ID: u8, const N: usize> Into<$typ> for PropertyData<$typ, ID, N> {
            fn into(self) -> $typ {
                self.value()
            }
        }

        impl<const ID: u8, const N: usize> From<$typ> for PropertyData<$typ, ID, N> {
            fn from(value: $typ) -> Self {
                Self::with_value(value)
            }
        }
    };
}

impl_array_pdt!([u8; 01]);
impl_array_pdt!([u8; 02]);
impl_array_pdt!([u8; 03]);
impl_array_pdt!([u8; 04]);
impl_array_pdt!([u8; 05]);
impl_array_pdt!([u8; 06]);
impl_array_pdt!([u8; 07]);
impl_array_pdt!([u8; 08]);
impl_array_pdt!([u8; 09]);
impl_array_pdt!([u8; 10]);
impl_array_pdt!([u8; 11]);
impl_array_pdt!([u8; 12]);
impl_array_pdt!([u8; 13]);
impl_array_pdt!([u8; 14]);
impl_array_pdt!([u8; 15]);
impl_array_pdt!([u8; 16]);
impl_array_pdt!([u8; 17]);
impl_array_pdt!([u8; 18]);
impl_array_pdt!([u8; 19]);
impl_array_pdt!([u8; 20]);

// use const_bitfield::bitfield;

// bitfield! {
//     #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
//     pub struct KNXVersion(u16);

//     u8, revision, set_revision: 5, 0;
//     u8, version, set_version: 10, 6;
//     u8, magic, set_magic: 15, 11;
// }

// impl KNXVersion {
//     pub const fn from_triplet(magic: u8, version: u8, revision: u8) -> Self {
//         let mut v = KNXVersion(0);
//         v.set_magic(magic);
//         v.set_version(version);
//         v.set_revision(revision);
//         v
//     }
// }

// impl core::fmt::Debug for KNXVersion {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{:?}.{:?}.{:?}", self.magic(), self.version(), self.revision())
//     }
// }

// impl<const ID: u8, const N: usize> PropertyData<KNXVersion, ID, N> {
//     pub fn with_value(value: KNXVersion) -> Self {
//         let value: u16 = value.0;
//         Self { data: (&value.to_be_bytes()[0..N]).try_into().unwrap(), _p: PhantomData }
//     }

//     pub fn value(&self) -> KNXVersion {
//         let value = u16::from_be_bytes(self.data[..N].try_into().unwrap());
//         KNXVersion(value)
//     }

//     pub fn set_value(&mut self, data: KNXVersion) {
//         let data: u16 = data.0;
//         self.data.copy_from_slice(&data.to_be_bytes()[..N]);
//     }
// }

// impl<const ID: u8, const N: usize> Into<KNXVersion> for PropertyData<KNXVersion, ID, N> {
//     fn into(self) -> KNXVersion {
//         self.value()
//     }
// }

// impl<const ID: u8, const N: usize> From<KNXVersion> for PropertyData<KNXVersion, ID, N> {
//     fn from(value: KNXVersion) -> Self {
//         Self::with_value(value)
//     }
// }

pub type PDT_Control = PropertyData<[u8; 01], 0, 10>;
pub type PDT_Char = PropertyData<i8, 1, 1>;
pub type PDT_UnsignedChar = PropertyData<u8, 2, 1>;
pub type PDT_Int = PropertyData<i16, 3, 2>;
pub type PDT_UnsignedInt = PropertyData<u16, 4, 2>;
//pub type PDT_KNXFloat       = PropertyData<half, 5, 2>;
//pub type PDT_Date           = PropertyData<KNXDate, 6, 3>;
//pub type PDT_Time           = PropertyData<KNXTime, 7, 3>;
pub type PDT_Long = PropertyData<i32, 8, 4>;
pub type PDT_UnsignedLong = PropertyData<u32, 9, 4>;
pub type PDT_Float = PropertyData<f32, 0x0A, 4>;
pub type PDT_Double = PropertyData<f64, 0x0B, 8>;
pub type PDT_CharBlock = PropertyData<[u8; 10], 0x0C, 10>; //TODO: raw_data/set_raw_data
//pub type PDT_PollGroupSettings = PropertyData<PollGroupSettings, 0x0D, 3>;
pub type PDT_ShortCharBlock = PropertyData<[u8; 5], 0x0E, 5>; //TODO: raw_data/set_raw_data
//pub type PDT_DateTime       = PropertyData<KNXDateTime, 0x0F, 6>;
//pub type PDT_VariableLength = //TODO: Super special variable len WTF shit - need to investigate
pub type PDT_Generic01 = PropertyData<[u8; 01], 0x11, 01>;
pub type PDT_Generic02 = PropertyData<[u8; 02], 0x12, 02>;
pub type PDT_Generic03 = PropertyData<[u8; 03], 0x13, 03>;
pub type PDT_Generic04 = PropertyData<[u8; 04], 0x14, 04>;
pub type PDT_Generic05 = PropertyData<[u8; 05], 0x15, 05>;
pub type PDT_Generic06 = PropertyData<[u8; 06], 0x16, 06>;
pub type PDT_Generic07 = PropertyData<[u8; 07], 0x17, 07>;
pub type PDT_Generic08 = PropertyData<[u8; 08], 0x18, 08>;
pub type PDT_Generic09 = PropertyData<[u8; 09], 0x19, 09>;
pub type PDT_Generic10 = PropertyData<[u8; 10], 0x1A, 10>;
pub type PDT_Generic11 = PropertyData<[u8; 11], 0x1B, 11>;
pub type PDT_Generic12 = PropertyData<[u8; 12], 0x1C, 12>;
pub type PDT_Generic13 = PropertyData<[u8; 13], 0x1D, 13>;
pub type PDT_Generic14 = PropertyData<[u8; 14], 0x1E, 14>;
pub type PDT_Generic15 = PropertyData<[u8; 15], 0x1F, 15>;
pub type PDT_Generic16 = PropertyData<[u8; 16], 0x20, 16>;
pub type PDT_Generic17 = PropertyData<[u8; 17], 0x21, 17>;
pub type PDT_Generic18 = PropertyData<[u8; 18], 0x22, 18>;
pub type PDT_Generic19 = PropertyData<[u8; 19], 0x23, 19>;
pub type PDT_Generic20 = PropertyData<[u8; 20], 0x24, 20>;
//pub type PDT_UTF8           = //TODO: Super special variable len WTF shit - need to investigate
//pub type PDT_Version = PropertyData<KNXVersion, 0x30, 2>;
//pub type PDT_AlarmInfo      = PropertyData<KNXAlarmInfo, 0x31, 2>;
pub type PDT_BinaryInformation = PropertyData<bool, 0x32, 1>; //TODO: raw_data/set_raw_data
pub type PDT_Bitset8 = PropertyData<u8, 0x33, 1>;
pub type PDT_Bitset16 = PropertyData<u16, 0x34, 2>;
pub type PDT_Enum8 = PropertyData<u8, 0x35, 1>;
pub type PDT_Scaling = PropertyData<u8, 0x36, 1>; //TODO: Custom type?
//pub type PDT_NotEncodedVariableLength = //TODO: Super special variable len WTF shit - need to investigate
//pub type PDT_NotEncodedFixedLength = //TODO: Super special WTF shit - need to investigate
//pub type PDT_Function = //TODO: Super special WTF shit - need to investigate
//pub type PDT_Escape = //TODO: Super special WTF shit - need to investigate

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DatapointID<const MAIN: u16, const SUB: u16>;

impl<const MAIN: u16, const SUB: u16> DatapointID<MAIN, SUB> {
    pub fn main(&self) -> u16 {
        return MAIN;
    }

    pub fn sub(&self) -> u16 {
        return SUB;
    }
}

impl<const MAIN: u16, const SUB: u16> fmt::Display for DatapointID<MAIN, SUB> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{:03}", MAIN, SUB)
    }
}

impl<const MAIN: u16, const SUB: u16> fmt::Debug for DatapointID<MAIN, SUB> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DatapointID {}.{:03}", MAIN, SUB)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DatapointType<PDT, const MAIN: u16, const SUB: u16> {
    backing: PDT,
}

impl<PDT, const MAIN: u16, const SUB: u16> DatapointType<PDT, MAIN, SUB> {
    pub const fn id(&self) -> DatapointID<MAIN, SUB> {
        DatapointID
    }

    pub fn backing(&self) -> &PDT {
        &self.backing
    }

    pub fn backing_mut(&mut self) -> &mut PDT {
        &mut self.backing
    }
}

impl<PDT, const MAIN: u16, const SUB: u16> DatapointType<PDT, MAIN, SUB>
where
    PDT: Copy,
{
    pub const fn new(data: PDT) -> Self {
        Self { backing: data }
    }
}

impl<PDT, const MAIN: u16, const SUB: u16> Default for DatapointType<PDT, MAIN, SUB>
where
    PDT: Default,
{
    fn default() -> Self {
        Self { backing: PDT::default() }
    }
}

impl<PDT: PropertyDataDefinition, const MAIN: u16, const SUB: u16> PropertyDataDefinition
    for DatapointType<PDT, MAIN, SUB>
where
    PDT: Default,
{
    const ID: u8 = PDT::ID;
    const SIZE: usize = PDT::SIZE;
}

impl<PDT: PropertyDataDefinition, const MAIN: u16, const SUB: u16> crate::ets::HasDptInfo
    for DatapointType<PDT, MAIN, SUB>
where
    PDT: Default,
{
    const DPT_MAIN: u16 = MAIN;
    const DPT_SUB: u16 = SUB;
    /// Size in bits based on DPT main type.
    ///
    /// KNX DPT sizes:
    /// - DPT 1.x = 1 bit (boolean)
    /// - DPT 2.x = 2 bits (control)
    /// - DPT 3.x = 4 bits (dimming/blinds)
    /// - DPT 4.x and higher = bytes (use PDT::SIZE * 8)
    const SIZE_BITS: usize = match MAIN {
        1 => 1,       // DPT 1.x - 1 bit (Switch, Bool, etc.)
        2 => 2,       // DPT 2.x - 2 bits (Bool Control)
        3 => 4,       // DPT 3.x - 4 bits (Dimming, Blinds Control)
        _ => PDT::SIZE * 8, // All other DPTs use full byte size
    };
}

impl<PDT, const MAIN: u16, const SUB: u16> AsRef<[u8]> for DatapointType<PDT, MAIN, SUB>
where
    PDT: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.backing.as_ref()
    }
}

impl<PDT, const MAIN: u16, const SUB: u16> AsMut<[u8]> for DatapointType<PDT, MAIN, SUB>
where
    PDT: AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.backing.as_mut()
    }
}

/// Implement a conversion from a DPT (DatapointType) into the underlying
/// PDT (Property Datatype) and vice versa
macro_rules! datapoint_type_convs {
    ($pdt:ty) => {
        impl<const MAIN: u16, const SUB: u16> From<DatapointType<$pdt, MAIN, SUB>> for $pdt {
            fn from(value: DatapointType<$pdt, MAIN, SUB>) -> Self {
                value.backing
            }
        }

        impl<const MAIN: u16, const SUB: u16> From<$pdt> for DatapointType<$pdt, MAIN, SUB> {
            fn from(value: $pdt) -> Self {
                Self { backing: value }
            }
        }
    };
}

datapoint_type_convs!(PDT_Control);
datapoint_type_convs!(PDT_Char);
datapoint_type_convs!(PDT_UnsignedChar);
datapoint_type_convs!(PDT_Int);
datapoint_type_convs!(PDT_UnsignedInt);
//datapoint_type_convs!(PDT_KNXFloat);
//datapoint_type_convs!(PDT_Date);
//datapoint_type_convs!(PDT_Time);
datapoint_type_convs!(PDT_Long);
datapoint_type_convs!(PDT_UnsignedLong);
datapoint_type_convs!(PDT_Float);
datapoint_type_convs!(PDT_Double);
datapoint_type_convs!(PDT_CharBlock);
//datapoint_type_convs!(PDT_PollGroupSettings);
datapoint_type_convs!(PDT_ShortCharBlock);
//datapoint_type_convs!(PDT_DateTime);
//datapoint_type_convs!(PDT_VariableLength);
datapoint_type_convs!(PDT_Generic01);
datapoint_type_convs!(PDT_Generic02);
datapoint_type_convs!(PDT_Generic03);
datapoint_type_convs!(PDT_Generic04);
datapoint_type_convs!(PDT_Generic05);
datapoint_type_convs!(PDT_Generic06);
datapoint_type_convs!(PDT_Generic07);
datapoint_type_convs!(PDT_Generic08);
datapoint_type_convs!(PDT_Generic09);
datapoint_type_convs!(PDT_Generic10);
datapoint_type_convs!(PDT_Generic11);
datapoint_type_convs!(PDT_Generic12);
datapoint_type_convs!(PDT_Generic13);
datapoint_type_convs!(PDT_Generic14);
datapoint_type_convs!(PDT_Generic15);
datapoint_type_convs!(PDT_Generic16);
datapoint_type_convs!(PDT_Generic17);
datapoint_type_convs!(PDT_Generic18);
datapoint_type_convs!(PDT_Generic19);
datapoint_type_convs!(PDT_Generic20);
//datapoint_type_convs!(PDT_UTF8);
//datapoint_type_convs!(PDT_Version);
//datapoint_type_convs!(PDT_AlarmInfo);
datapoint_type_convs!(PDT_BinaryInformation);
datapoint_type_convs!(PDT_Bitset8);
datapoint_type_convs!(PDT_Bitset16);
datapoint_type_convs!(PDT_Enum8);
datapoint_type_convs!(PDT_Scaling);
//datapoint_type_convs!(PDT_NotEncodedVariableLength);
//datapoint_type_convs!(PDT_NotEncodedFixedLength);
//datapoint_type_convs!(PDT_Function);
//datapoint_type_convs!(PDT_Escape);

pub type DPT_SerNum = DatapointType<PDT_Generic06, 221, 001>;

impl core::fmt::Debug for DPT_SerNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i: KNXSerialNumber = self.clone().into();
        write!(f, "{:?}", i)
    }
}

#[derive(FromBytes, IntoBytes, Debug, Clone, Copy, PartialEq, Eq, Immutable, KnownLayout)]
#[repr(packed)]
pub struct KNXSerialNumber {
    pub manufacturer_code: big_endian::U16,
    pub incremented_number: big_endian::U32,
}

impl KNXSerialNumber {
    pub const fn new(manufacturer_code: u16, incremented_number: u32) -> Self {
        Self {
            manufacturer_code: big_endian::U16::new(manufacturer_code),
            incremented_number: big_endian::U32::new(incremented_number),
        }
    }
}

impl From<KNXSerialNumber> for DPT_SerNum {
    fn from(value: KNXSerialNumber) -> Self {
        let b = value.as_bytes();
        let a: [u8; 6] = b.try_into().unwrap();
        DPT_SerNum::new(a.into())
    }
}

impl From<DPT_SerNum> for KNXSerialNumber {
    fn from(value: DPT_SerNum) -> Self {
        let v: [u8; 6] = value.backing.into();
        let v: Ref<_, KNXSerialNumber> = Ref::from_bytes(&v[..]).unwrap();
        *v
    }
}

//impl core::fmt::Debug for DPT_SerNum {
//    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//        let s: KNXSerialNumber = self.clone().into();
//        write!(f, "{:?}", s)
//    }
//}

// ###########################################################################

pub type DPT_Switch = DatapointType<PDT_UnsignedChar, 1, 001>;

impl core::fmt::Debug for DPT_Switch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.backing)
    }
}

impl From<bool> for DPT_Switch {
    fn from(value: bool) -> Self {
        DPT_Switch::new((value as u8).into())
    }
}

impl From<DPT_Switch> for bool {
    fn from(value: DPT_Switch) -> Self {
        let value: u8 = value.backing.into();
        value & 1 == 1
    }
}

// ###########################################################################

/// DPT 5.010 - 1-byte unsigned counter (0..255)
/// Uses long format for GroupValue_Response (data > 6 bits)
pub type DPT_Value_1_Ucount = DatapointType<PDT_UnsignedChar, 5, 010>;

impl core::fmt::Debug for DPT_Value_1_Ucount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.backing)
    }
}

impl From<u8> for DPT_Value_1_Ucount {
    fn from(value: u8) -> Self {
        DPT_Value_1_Ucount::new(value.into())
    }
}

impl From<DPT_Value_1_Ucount> for u8 {
    fn from(value: DPT_Value_1_Ucount) -> Self {
        value.backing.into()
    }
}

// ###########################################################################

/// DPT for 3-byte value (used in conformance tests for invalid data length)
pub type DPT_Value_3_Ucount = DatapointType<PDT_Generic03, 232, 600>;

// ###########################################################################

pub type DPT_PropDataType = DatapointType<PDT_UnsignedInt, 7, 010>;

impl core::fmt::Debug for DPT_PropDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i: InterfaceObjectType = self.clone().into();
        write!(f, "{:?}", i)
    }
}

// InterfaceObjectType -> DPT_PropDataType -> PDT_UnsignedInt -> u16
// InterfaceObjectType ->                     PDT_UnsignedInt -> u16
// u16                 -> PDT_UnsignedInt -> DPT_PropDataType -> InterfaceObjectType
// u16                 -> PDT_UnsignedInt ->                     InterfaceObjectType

create_protocol_enum!(
    /// Interface object types
    #[derive(Eq, PartialEq, Copy, Clone, core::marker::ConstParamTy)]
    pub enum InterfaceObjectType: u16 {
        Device                  , 0x00, "Device";
        AddressTable            , 0x01, "AddressTable";
        AssociationTable        , 0x02, "AssociationTable";
        ApplicationProgram      , 0x03, "ApplicationProgram";
        InterfaceProgram        , 0x04, "InterfaceProgram";
        ObjectAssociationTable  , 0x05, "ObjectAssociationTable";
        Router                  , 0x06, "Router";
        LTEAddressRoutingTable  , 0x07, "LTEAddressRoutingTable";
        CEMIServer              , 0x08, "CEMIServer";
        GroupObjectTable        , 0x09, "GroupObjectTable";
        PollingMaster           , 0x0A, "PollingMaster";
        IPParameter             , 0x0B, "IPParameter";
        Reserved                , 0x0C, "Reserved";
        Fileserver              , 0x0D, "Fileserver";
        Security                , 0x11, "Security";
        RFMedium                , 0x13, "RFMedium";
        _,                              "Unknown Interface Object 0x{:x}";
    }
);

impl From<InterfaceObjectType> for DPT_PropDataType {
    fn from(value: InterfaceObjectType) -> Self {
        DPT_PropDataType::new(value.into())
    }
}

impl From<InterfaceObjectType> for PDT_UnsignedInt {
    fn from(value: InterfaceObjectType) -> Self {
        PDT_UnsignedInt::with_value(value.into())
    }
}

impl From<DPT_PropDataType> for InterfaceObjectType {
    fn from(value: DPT_PropDataType) -> Self {
        let value: u16 = value.backing.into();
        value.into()
    }
}

impl From<PDT_UnsignedInt> for InterfaceObjectType {
    fn from(value: PDT_UnsignedInt) -> Self {
        let v: u16 = value.into();
        v.into()
    }
}

//impl core::fmt::Debug for DPT_PropDataType {
//    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//        let i: InterfaceObjectType = self.clone().into();
//        write!(f, "{:?}", i)
//    }
//}

// ###########################################################################

pub type DPT_ErrorClass_System = DatapointType<PDT_Enum8, 20, 011>;

impl core::fmt::Debug for DPT_ErrorClass_System {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i: SystemError = self.clone().into();
        write!(f, "{:?}", i)
    }
}

create_protocol_enum!(
    /// System error types
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum SystemError: u8 {
        NoFault                         , 0x00, "NoFault";
        GeneralDeviceFault              , 0x01, "GeneralDeviceFault";
        CommunicationFault              , 0x02, "CommunicationFault";
        ConfigurationFault              , 0x03, "ConfigurationFault";
        HardwareFault                   , 0x04, "HardwareFault";
        SoftwareFault                   , 0x05, "SoftwareFault";
        InsufficientNonVolatileMemory   , 0x06, "InsufficientNonVolatileMemory";
        InsufficientVolatileMemory      , 0x07, "InsufficientVolatileMemory";
        MemAllocZeroReceived            , 0x08, "MemAllocZeroReceived";
        CRCError                        , 0x09, "CRCError";
        WatchdogReset                   , 0x0A, "WatchdogReset";
        InvalidOpcode                   , 0x0B, "InvalidOpcode";
        GeneralProtectionFault          , 0x0C, "GeneralProtectionFault";
        MaxTableLengthExceeded          , 0x0D, "MaxTableLengthExceeded";
        UndefinedLoadCommand            , 0x0E, "UndefinedLoadCommand";
        GroupAddressTableNotSorted      , 0x0F, "GroupAddressTableNotSorted";
        InvalidTSAP                     , 0x10, "InvalidTSAP";
        InvalidASAP                     , 0x11, "InvalidASAP";
        GroupObjectTypeTooBig           , 0x12, "GroupObjectTypeTooBig";
        _,                                      "Unknown System Error 0x{:x}";
    }
);

impl From<SystemError> for DPT_ErrorClass_System {
    fn from(value: SystemError) -> Self {
        DPT_ErrorClass_System::new(value.into())
    }
}

impl From<SystemError> for PDT_Enum8 {
    fn from(value: SystemError) -> Self {
        PDT_Enum8::with_value(value.into())
    }
}

impl From<DPT_ErrorClass_System> for SystemError {
    fn from(value: DPT_ErrorClass_System) -> Self {
        let value: u8 = value.backing.into();
        value.into()
    }
}

impl From<PDT_Enum8> for SystemError {
    fn from(value: PDT_Enum8) -> Self {
        let v: u8 = value.into();
        v.into()
    }
}

//impl core::fmt::Debug for DPT_ErrorClass_System {
//    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//        let i: SystemError = self.clone().into();
//        write!(f, "{:?}", i)
//    }
//}

// ###########################################################################

// pub type DPT_Version = DatapointType<PDT_Version, 217, 001>;

// impl core::fmt::Debug for DPT_Version {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let i: KNXVersion = self.clone().into();
//         write!(f, "{:?}.{:?}.{:?}", i.magic(), i.version(), i.revision())
//     }
// }

// impl From<KNXVersion> for DPT_Version {
//     fn from(value: KNXVersion) -> Self {
//         DPT_Version::new(value.into())
//     }
// }

// impl From<DPT_Version> for KNXVersion {
//     fn from(value: DPT_Version) -> Self {
//         value.backing.into()
//     }
// }

// ============================================================================
// Semantic Property Wrapper Types
// ============================================================================
//
// These types provide type-safe, ergonomic access to KNX property values.
// Instead of raw byte arrays, they expose named accessors for individual
// bits and fields according to the KNX specification.

/// Device Control flags (PID 14, DPT 21.002)
///
/// This property controls device behavior and is part of the Device Object (index 0).
///
/// # Bit Layout
/// - Bit 0: Safe State - Device is in safe/fail-safe state
/// - Bit 1: Reserved
/// - Bit 2: Verify Mode - Memory write verification enabled
/// - Bits 3-7: Reserved
///
/// # Example
/// ```ignore
/// let dc = DeviceControl::new();
/// if dc.verify_mode() {
///     // Send verification response after memory write
/// }
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct DeviceControl(u8);

impl DeviceControl {
    /// Create a new DeviceControl with all flags cleared
    #[inline]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create a DeviceControl from a raw byte value
    #[inline]
    pub const fn from_byte(value: u8) -> Self {
        Self(value)
    }

    /// Get the raw byte value
    #[inline]
    pub const fn as_byte(&self) -> u8 {
        self.0
    }

    /// Check if verify mode is enabled (bit 2)
    ///
    /// When enabled, the device sends a Memory_Response after Memory_Write
    /// to confirm the written data.
    #[inline]
    pub const fn verify_mode(&self) -> bool {
        self.0 & 0x04 != 0
    }

    /// Set verify mode (bit 2)
    #[inline]
    pub fn set_verify_mode(&mut self, enabled: bool) {
        if enabled {
            self.0 |= 0x04;
        } else {
            self.0 &= !0x04;
        }
    }

    /// Check if user application program is stopped (bit 0)
    ///
    /// When set, the user application program is not running.
    /// This bit is set by the run state machine when the application stops
    /// (via Stop command, Restart command, or Unload event).
    #[inline]
    pub const fn user_stopped(&self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Set user application stopped flag (bit 0)
    ///
    /// This should be called when the run state machine transitions away from RUNNING
    /// (i.e., when RunAction::LoadStart is returned).
    #[inline]
    pub fn set_user_stopped(&mut self, stopped: bool) {
        if stopped {
            self.0 |= 0x01;
        } else {
            self.0 &= !0x01;
        }
    }

    /// Check if individual address duplication was detected (bit 1)
    ///
    /// When set, the device has received a message from another device
    /// using the same individual address. This indicates an address
    /// configuration error on the bus.
    #[inline]
    pub const fn address_duplication(&self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Set individual address duplication flag (bit 1)
    ///
    /// This is set by the link layer when it receives a message where
    /// the source address matches our own individual address.
    #[inline]
    pub fn set_address_duplication(&mut self, detected: bool) {
        if detected {
            self.0 |= 0x02;
        } else {
            self.0 &= !0x02;
        }
    }
}

impl fmt::Debug for DeviceControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceControl")
            .field("user_stopped", &self.user_stopped())
            .field("address_duplication", &self.address_duplication())
            .field("verify_mode", &self.verify_mode())
            .field("raw", &format_args!("0x{:02X}", self.0))
            .finish()
    }
}

impl AsRef<[u8]> for DeviceControl {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        core::slice::from_ref(&self.0)
    }
}

impl AsMut<[u8]> for DeviceControl {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        core::slice::from_mut(&mut self.0)
    }
}

impl From<u8> for DeviceControl {
    #[inline]
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<DeviceControl> for u8 {
    #[inline]
    fn from(value: DeviceControl) -> Self {
        value.0
    }
}

impl From<[u8; 1]> for DeviceControl {
    #[inline]
    fn from(value: [u8; 1]) -> Self {
        Self(value[0])
    }
}

impl From<DeviceControl> for [u8; 1] {
    #[inline]
    fn from(value: DeviceControl) -> Self {
        [value.0]
    }
}

/// Programming Mode flag (PID 54)
///
/// When programming mode is active, the device responds to broadcast
/// address programming requests and can have its individual address changed.
///
/// # Bit Layout
/// - Bit 0: Programming mode enabled
/// - Bits 1-7: Reserved (should be 0)
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct ProgrammingMode(u8);

impl ProgrammingMode {
    /// Create with programming mode disabled
    #[inline]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create from a raw byte value
    #[inline]
    pub const fn from_byte(value: u8) -> Self {
        Self(value)
    }

    /// Get the raw byte value
    #[inline]
    pub const fn as_byte(&self) -> u8 {
        self.0
    }

    /// Check if programming mode is enabled
    #[inline]
    pub const fn enabled(&self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Set programming mode
    #[inline]
    pub fn set_enabled(&mut self, enabled: bool) {
        if enabled {
            self.0 = 0x01;
        } else {
            self.0 = 0x00;
        }
    }
}

impl fmt::Debug for ProgrammingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProgrammingMode")
            .field("enabled", &self.enabled())
            .finish()
    }
}

impl AsRef<[u8]> for ProgrammingMode {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        core::slice::from_ref(&self.0)
    }
}

impl AsMut<[u8]> for ProgrammingMode {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        core::slice::from_mut(&mut self.0)
    }
}

impl From<bool> for ProgrammingMode {
    #[inline]
    fn from(enabled: bool) -> Self {
        Self(if enabled { 0x01 } else { 0x00 })
    }
}

impl From<ProgrammingMode> for bool {
    #[inline]
    fn from(value: ProgrammingMode) -> Self {
        value.enabled()
    }
}

impl From<u8> for ProgrammingMode {
    #[inline]
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<[u8; 1]> for ProgrammingMode {
    #[inline]
    fn from(value: [u8; 1]) -> Self {
        Self(value[0])
    }
}

impl From<ProgrammingMode> for [u8; 1] {
    #[inline]
    fn from(value: ProgrammingMode) -> Self {
        [value.0]
    }
}

/// Routing Count (PID 51)
///
/// The hop count for outgoing messages. Valid range is 0-7.
/// Default value per KNX specification is 6.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct RoutingCount(u8);

impl RoutingCount {
    /// Default routing count per KNX specification
    pub const DEFAULT: u8 = 6;

    /// Create with default routing count (6)
    #[inline]
    pub const fn new() -> Self {
        Self(Self::DEFAULT)
    }

    /// Create from a raw value (clamped to 0-7)
    #[inline]
    pub const fn from_value(value: u8) -> Self {
        Self(value & 0x07)
    }

    /// Get the routing count value (0-7)
    #[inline]
    pub const fn value(&self) -> u8 {
        self.0
    }

    /// Set the routing count (clamped to 0-7)
    #[inline]
    pub fn set_value(&mut self, value: u8) {
        self.0 = value & 0x07;
    }
}

impl Default for RoutingCount {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RoutingCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoutingCount({})", self.0)
    }
}

impl AsRef<[u8]> for RoutingCount {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        core::slice::from_ref(&self.0)
    }
}

impl AsMut<[u8]> for RoutingCount {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        core::slice::from_mut(&mut self.0)
    }
}

impl From<u8> for RoutingCount {
    #[inline]
    fn from(value: u8) -> Self {
        Self::from_value(value)
    }
}

impl From<RoutingCount> for u8 {
    #[inline]
    fn from(value: RoutingCount) -> Self {
        value.0
    }
}

impl From<[u8; 1]> for RoutingCount {
    #[inline]
    fn from(value: [u8; 1]) -> Self {
        Self::from_value(value[0])
    }
}

impl From<RoutingCount> for [u8; 1] {
    #[inline]
    fn from(value: RoutingCount) -> Self {
        [value.0]
    }
}

// ============================================================================
// PropertyDataDefinition implementations for semantic types
// ============================================================================
//
// These allow the semantic types to be used in the define_interface_object! macro
// which needs the PDT type ID for property descriptors.

/// DeviceControl uses PDT_GENERIC_01 (ID 0x11) - 1 byte
impl const PropertyDataDefinition for DeviceControl {
    const SIZE: usize = 1;
    const ID: u8 = 0x11; // PDT_GENERIC_01
}

/// ProgrammingMode uses PDT_GENERIC_01 (ID 0x11) - 1 byte
impl const PropertyDataDefinition for ProgrammingMode {
    const SIZE: usize = 1;
    const ID: u8 = 0x11; // PDT_GENERIC_01
}

/// RoutingCount uses PDT_UNSIGNED_CHAR (ID 0x02) - 1 byte
impl const PropertyDataDefinition for RoutingCount {
    const SIZE: usize = 1;
    const ID: u8 = 0x02; // PDT_UNSIGNED_CHAR
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_interface_object() {
        //let mut i = DPT_PropDataType::default();
        let i: DPT_PropDataType = InterfaceObjectType::Device.into();

        let id = i.id();
        assert_eq!(id.main(), 7);
        assert_eq!(id.sub(), 010);

        // FIXME: we need a setter
        //i.set_value(InterfaceObjectType::Device);
        assert_eq!(InterfaceObjectType::from(i), InterfaceObjectType::Device);
    }

    #[test]
    fn test_dpt_switch() {
        let mut s: DPT_Switch = true.into();

        let id = s.id();
        assert_eq!(id.main(), 1);
        assert_eq!(id.sub(), 1);

        assert_eq!(bool::from(s), true);
        assert_eq!(s.backing.value(), 1);
        {
            let b = s.backing();
            assert_eq!(b.as_ref(), &[1]);
        }

        s = false.into();
        assert_eq!(bool::from(s), false);
        assert_eq!(s.backing.value(), 0);
        {
            let b = s.backing();
            assert_eq!(b.as_ref(), &[0]);
        }
    }

    #[test]
    fn test_dpt_propdatatype() {
        let s: DPT_PropDataType = InterfaceObjectType::AddressTable.into();

        let id = s.id();
        assert_eq!(id.main(), 7);
        assert_eq!(id.sub(), 010);

        assert_eq!(InterfaceObjectType::from(s), InterfaceObjectType::AddressTable);

        {
            let d = s.as_ref();

            assert_eq!(d.len(), 2);
            assert_eq!(d, &[0, 1]);
        }
    }

    #[test]
    fn test_dpt_sernum() {
        let s: DPT_SerNum =
            KNXSerialNumber { manufacturer_code: 0x1234.into(), incremented_number: 0x567890AA.into() }.into();

        let id = s.id();
        assert_eq!(id.main(), 221);
        assert_eq!(id.sub(), 1);

        assert_eq!(KNXSerialNumber::from(s), KNXSerialNumber {
            manufacturer_code: 0x1234.into(),
            incremented_number: 0x567890AA.into()
        });
        {
            let b = s.backing();
            assert_eq!(b.as_ref(), &[0x12, 0x34, 0x56, 0x78, 0x90, 0xAA]);
        }
    }

    // #[test]
    // fn test_dpt_version() {
    //     let s: DPT_Version = KNXVersion::from_triplet(3, 2, 1).into();

    //     let id = s.id();
    //     assert_eq!(id.main(), 217);
    //     assert_eq!(id.sub(), 1);

    //     assert_eq!(KNXVersion::from(s), KNXVersion::from_triplet(3, 2, 1));
    //     {
    //         let b = s.backing();
    //         // FIXME: endianness correct?
    //         assert_eq!(b.as_ref(), &[0b00011000, 0b10000001]);
    //     }
    // }
}
