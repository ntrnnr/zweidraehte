use bitflags::bitflags;

use crate::dpt::{DPT_Switch, DPT_Version, DatapointType, KNXVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransmissionState {
    IdleOk = 0,          // Object is idle
    IdleError = 1,       // Object is idle, last transmission failed
    Transmitting = 2,    // Object is currently transmitting
    TransmitRequest = 3, // Transmission is requested
}

bitflags! {
    /// RAM flags for a communication object
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ComObjectFlags: u8 {
        const READ_REQUEST   = 0b0000_0100;
        const UPDATE_FLAG    = 0b0000_1000;     /// Flag that indicated the value has been updated by a remote device via a KNX bus transaction
        const VALUE_CHANGED  = 0b0001_0000;     ///
        const VALUE_VALID    = 0b0010_0000;     /// Flag that indicates the value is valid, either by setting it explicitly or by receiving a valid value from the bus
        const FLAG_USER2     = 0b0100_0000;
        const FLAG_USER1     = 0b1000_0000;
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ComObjectStatus(u8);

impl ComObjectStatus {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn transmission_state(&self) -> TransmissionState {
        match self.0 & 0b0000_0011 {
            0 => TransmissionState::IdleOk,
            1 => TransmissionState::IdleError,
            2 => TransmissionState::Transmitting,
            3 => TransmissionState::TransmitRequest,
            _ => unreachable!(),
        }
    }

    pub fn set_transmission_state(&mut self, state: TransmissionState) {
        // Clear current state (first 2 bits)
        self.0 &= 0b1111_1100;
        // Set new state
        self.0 |= state as u8;
    }

    pub fn flags(&self) -> ComObjectFlags {
        // Mask out transmission state bits
        ComObjectFlags::from_bits_truncate(self.0 & 0b1111_1100)
    }

    pub fn set_flags(&mut self, flags: ComObjectFlags) {
        // Clear current flags but preserve transmission state
        self.0 &= 0b0000_0011;
        // Set new flags
        self.0 |= flags.bits();
    }

    pub fn update_flags(&mut self, flags: ComObjectFlags, value: bool) {
        if value {
            self.0 |= flags.bits();
        } else {
            self.0 &= !flags.bits();
        }
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn from_u8(value: u8) -> Self {
        Self(value)
    }
}

impl Default for ComObjectStatus {
    fn default() -> Self {
        Self::new()
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
        Self {
            value,
            status: ComObjectStatus::new(),
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    pub fn set_value(&mut self, value: T, request_tx: bool) {
        self.value = value;
        self.status
            .update_flags(ComObjectFlags::VALUE_CHANGED, true);

        if request_tx {
            self.status
                .set_transmission_state(TransmissionState::TransmitRequest);
        }
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
    type Index;

    fn new() -> Self;
    fn info<'a>(&'a self, idx: Self::Index) -> ComObjectInfo<'a>;
    fn info_mut<'a>(&'a mut self, idx: Self::Index) -> ComObjectInfoMut<'a>;
}

// pub struct MyComObjects {
//     pub switch1: ComObject<{ ComObjectIndex::switch1 }, DPT_Switch>,
//     pub version: ComObject<{ ComObjectIndex::version }, DPT_Version>,
//     pub heater: ComObject<{ ComObjectIndex::heater }, DPT_Switch>,
// }

// impl ComObjects for MyComObjects {
//     type Index = ComObjectIndex;

//     fn new() -> Self {
//         Self {
//             switch1: ComObject::new(DPT_Switch::from(false)),
//             version: ComObject::new(DPT_Version::from(KNXVersion::from_triplet(0, 1, 0))),
//             heater: ComObject::new(DPT_Switch::from(false)),
//         }
//     }

//     fn info<'a>(&'a self, idx: Self::Index) -> ComObjectInfo<'a> {
//         match idx {
//             ComObjectIndex::switch1 => ComObjectInfo {
//                 status: &self.switch1.status,
//                 value: self.switch1.value.as_ref(),
//             },
//             ComObjectIndex::version => ComObjectInfo {
//                 status: &self.version.status,
//                 value: self.version.value.as_ref(),
//             },
//             ComObjectIndex::heater => ComObjectInfo {
//                 status: &self.heater.status,
//                 value: self.heater.value.as_ref(),
//             },
//         }
//     }

//     fn info_mut<'a>(&'a mut self, idx: Self::Index) -> ComObjectInfoMut<'a> {
//         match idx {
//             ComObjectIndex::switch1 => ComObjectInfoMut {
//                 status: &mut self.switch1.status,
//                 value: self.switch1.value.as_mut(),
//             },
//             ComObjectIndex::version => ComObjectInfoMut {
//                 status: &mut self.version.status,
//                 value: self.version.value.as_mut(),
//             },
//             ComObjectIndex::heater => ComObjectInfoMut {
//                 status: &mut self.heater.status,
//                 value: self.heater.value.as_mut(),
//             },
//         }
//     }
// }

// #[allow(dead_code)]
// #[derive(core::marker::ConstParamTy, Debug, Clone, Copy, PartialEq, Eq)]
// pub enum ComObjectIndex {
//     switch1 = 0,
//     version = 1,
//     heater = 2,
// }

// #[allow(dead_code)]
// impl ComObjectIndex {
//     /// Convert from usize index to enum if valid
//     pub const fn from_index(idx: usize) -> Option<Self> {
//         match idx {
//             0 => Some(Self::switch1),
//             1 => Some(Self::version),
//             2 => Some(Self::heater),
//             _ => None,
//         }
//     }

//     /// Get the index value
//     pub const fn index(self) -> usize {
//         self as usize
//     }
// }

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
                pub enum ComObjectIndex {
                    $(
                        [<$obj_name:camel>] = $idx,
                    )*
                }

                #[allow(dead_code)]
                impl ComObjectIndex {
                    /// Convert from usize index to enum if valid
                    pub const fn from_index(idx: usize) -> Option<Self> {
                        match idx {
                            $(
                                $idx => Some(Self::[<$obj_name:camel>]),
                            )*
                            _ => None,
                        }
                    }

                    /// Get the index value
                    pub const fn index(self) -> usize {
                        self as usize
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
                    type Index = ComObjectIndex;

                    fn new() -> Self {
                        Self {
                            $(
                                $obj_name: ComObject::new($default),
                            )*
                        }
                    }

                    fn info<'a>(&'a self, idx: Self::Index) -> ComObjectInfo<'a> {
                        match idx {
                            $(
                                ComObjectIndex::[<$obj_name:camel>] => ComObjectInfo {
                                    status: &self.[<$obj_name>].status,
                                    value: self.[<$obj_name>].value.as_ref(),
                                },
                            )*
                        }
                    }

                    fn info_mut<'a>(&'a mut self, idx: Self::Index) -> ComObjectInfoMut<'a> {
                        match idx {
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

mod tests {
    use super::*;

    define_com_objects! {
        pub mod CommObjs {
        /// My application's communication objects
            #[allow(dead_code)]
            pub struct MyComObjects {
                0 => pub switch1: DPT_Switch = DPT_Switch::from(false),
                1 => pub version: DPT_Version = DPT_Version::from(KNXVersion::from_triplet(0, 1, 0)),
                2 => pub heater: DPT_Switch = DPT_Switch::from(false),
            }
        }
    }

    use CommObjs::*;

    #[test]
    fn test_comm_objs() {
        let a = ComObjectIndex::from_index(0).unwrap();

        let mut c = MyComObjects::new();
        let v: bool = (*c.switch1.value()).into();

        let info = c.info_mut(ComObjectIndex::Switch1);
        info.status
            .set_transmission_state(TransmissionState::IdleOk);

        //c.switch1.set_value().await
        //c.switch1.subscribe().await

        //let v2: bool = c.switch1.into();
    }
}
