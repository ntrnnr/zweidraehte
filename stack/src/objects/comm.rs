use crate::dpt::DatapointType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Status of a communication object
///
/// Defined in KNX 03/04/01 3.2 - Communication flags
pub enum ComObjectStatus {
    /// Update was updated remotely
    Updated,

    /// Read request was issued
    ReadRequest,

    /// Write request was issued
    WriteRequest,

    /// Read or Write request is currently handled
    Busy,

    /// Object is idle
    IdleOk,

    /// Object encountered an error during last requested bus transaction
    IdleError,

    /// Object is currently uninitialized
    Uninitialized,
}

impl Default for ComObjectStatus {
    fn default() -> Self {
        ComObjectStatus::Uninitialized
    }
}

/// A trait for communication object values to abstract over different DatapointTypes
pub trait ComObjectValueType: Clone + Default + AsRef<[u8]> + AsMut<[u8]> + Sized {}

// Implement the trait for all DatapointType instances
impl<T, const MAIN: u16, const SUB: u16> ComObjectValueType for DatapointType<T, MAIN, SUB>
where
    T: Clone + Default,
    DatapointType<T, MAIN, SUB>: Clone + Default + AsRef<[u8]> + AsMut<[u8]>,
{
}

/// Generic communication object with value of type T
pub struct ComObject<T: ComObjectValueType> {
    /// The actual value
    pub value: T,

    /// Status byte containing transmission state and flags
    pub status: ComObjectStatus,
}

impl<T: ComObjectValueType> ComObject<T> {
    pub fn new(value: T) -> Self {
        Self { value, status: ComObjectStatus::default() }
    }
}

pub struct ComObjectInfo<'a> {
    pub status: &'a ComObjectStatus,
    pub value: &'a [u8],
}

pub struct ComObjectInfoMut<'a> {
    pub status: &'a mut ComObjectStatus,
    pub value: &'a mut [u8],
}

pub trait ComObjects {
    fn new() -> Self;
    fn info<'a>(&'a self, idx: u16) -> ComObjectInfo<'a>;
    fn info_mut<'a>(&'a mut self, idx: u16) -> ComObjectInfoMut<'a>;

    fn status(&self, idx: u16) -> ComObjectStatus {
        let info = self.info(idx);
        *info.status
    }

    fn set_status(&mut self, idx: u16, status: ComObjectStatus) {
        let info = self.info_mut(idx);
        *info.status = status;
    }

    fn value(&self, idx: u16) -> &[u8] {
        let info = self.info(idx);
        info.value
    }

    fn value_mut(&mut self, idx: u16) -> &mut [u8] {
        let info = self.info_mut(idx);
        info.value
    }
}

#[macro_export]
macro_rules! define_com_objects {
    (
        $(#[$mod_meta:meta])*
        pub mod $mod_name:ident {
            $(#[$struct_meta:meta])*
            pub struct $struct_name:ident {
                $(
                    $(#[$field_meta:meta])*
                    $idx:expr => pub $obj_name:ident: $type:ty = $default:expr
                ),* $(,)?
            }
        }
    ) => {
        paste::paste! {
            $(#[$mod_meta])*
            pub mod $mod_name {
                use $crate::objects::comm::*;

                #[allow(unused_imports)]
                use $crate::dpt::*;

                /// Enum with all communication object names and their indices
                #[allow(dead_code)]
                #[derive(core::marker::ConstParamTy, Debug, Clone, Copy, PartialEq, Eq)]
                #[repr(u16)]
                pub enum ComObjectIndex {
                    $(
                        [<$obj_name:camel>] = $idx,
                    )*
                }

                #[allow(dead_code)]
                impl ComObjectIndex {
                    /// Convert from usize index to enum if valid
                    pub const fn from_index(idx: u16) -> Option<Self> {
                        match idx {
                            $(
                                $idx => Some(Self::[<$obj_name:camel>]),
                            )*
                            _ => None,
                        }
                    }

                    /// Get the index value
                    pub const fn index(self) -> u16 {
                        self as u16
                    }
                }

                /// The communication objects
                $(#[$struct_meta])*
                pub struct $struct_name {
                    $(
                        $(#[$field_meta])*
                        pub $obj_name: ComObject<$type>,
                    )*
                }

                impl ComObjects for $struct_name {
                    fn new() -> Self {
                        Self {
                            $(
                                $obj_name: ComObject::new($default),
                            )*
                        }
                    }

                    fn info<'a>(&'a self, idx: u16) -> ComObjectInfo<'a> {
                        match ComObjectIndex::from_index(idx).unwrap() {
                            $(
                                ComObjectIndex::[<$obj_name:camel>] => ComObjectInfo {
                                    status: &self.[<$obj_name>].status,
                                    value: self.[<$obj_name>].value.as_ref(),
                                },
                            )*
                        }
                    }

                    fn info_mut<'a>(&'a mut self, idx: u16) -> ComObjectInfoMut<'a> {
                        match ComObjectIndex::from_index(idx).unwrap() {
                            $(
                                ComObjectIndex::[<$obj_name:camel>] => ComObjectInfoMut {
                                    status: &mut self.[<$obj_name>].status,
                                    value: self.[<$obj_name>].value.as_mut(),
                                },
                            )*
                        }
                    }
                }
            }
        }
    };
}

// mod tests {
//     use super::*;

//     define_com_objects! {
//         pub mod CommObjs {
//         /// My application's communication objects
//             #[allow(dead_code)]
//             pub struct MyComObjects {
//                 0 => pub switch1: DPT_Switch = DPT_Switch::from(false),
//                 1 => pub version: DPT_Version = DPT_Version::from(KNXVersion::from_triplet(0, 1, 0)),
//                 2 => pub heater: DPT_Switch = DPT_Switch::from(false),
//             }
//         }
//     }

//     use CommObjs::*;

//     #[test]
//     fn test_comm_objs() {
//         let a = ComObjectIndex::from_index(0).unwrap();

//         let mut c = MyComObjects::new();
//         let v: bool = (*c.switch1.value()).into();

//         let info = c.info_mut(ComObjectIndex::Switch1);
//         //info.status
//         //    .set_transmission_state(TransmissionState::IdleOk);

//         //c.switch1.set_value().await
//         //c.switch1.subscribe().await

//         //let v2: bool = c.switch1.into();
//     }
// }
