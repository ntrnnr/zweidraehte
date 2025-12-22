use crate::dpt::DatapointType;

// FIXME: These need to follow the defined standard - rename a few?
//        Make sure the numeric values match the standard?
//        Conformance tests will access them to check for certain flags set in different circumstances
// FIXME: Do we clear Updated? When do we clear it? When do we set it?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Status of a communication object
///
/// Defined in KNX 03/04/01 3.2 - Communication flags
///
/// BCU1/BCU2 flag byte format:
/// - Bit 6: Idle indicator (1 = idle, 0 = transmitting)
/// - Bit 3: Update flag
/// - Bit 2: Read request pending
/// - Bit 1: Write/Transmit request pending
/// - Bit 0: Error flag (1 = error, 0 = ok)
pub enum ComObjectStatus {
    /// Object was updated remotely (0x48)
    Updated,

    /// Read request was issued, not yet sent (0x44)
    ReadRequest,

    /// Read request sent successfully, waiting for response (0x44)
    ReadRequestOk,

    /// Read request failed (transmission error or disabled) (0x45)
    ReadRequestError,

    /// Write request was issued (0x02)
    WriteRequest,

    /// Write request failed (transmission error or disabled) (0x41)
    WriteRequestError,

    /// Read or Write request is currently handled (0x02)
    Busy,

    /// Object is idle (0x40)
    IdleOk,

    /// Object encountered an error during last requested bus transaction (0x41)
    IdleError,

    /// Object is currently uninitialized
    Uninitialized,
}

impl Default for ComObjectStatus {
    fn default() -> Self {
        ComObjectStatus::Uninitialized
    }
}

impl ComObjectStatus {
    /// Convert status to a BCU1-style flags byte.
    ///
    /// Format (8 bits):
    /// - Bit 6: Idle indicator (1 = idle, 0 = transmitting)
    /// - Bit 3: Update flag
    /// - Bit 2: Read request pending
    /// - Bit 1: Write/Transmit request pending (BCU1 style)
    /// - Bit 0: Error flag (1 = error, 0 = ok)
    ///
    /// Common values:
    /// - 0x40: IdleOk
    /// - 0x41: IdleError
    /// - 0x42: Busy/Transmitting (WriteRequest pending)
    /// - 0x44: ReadRequest pending (idle)
    /// - 0x48: Updated
    pub fn to_flags_byte(&self) -> u8 {
        match self {
            ComObjectStatus::IdleOk => 0x40,             // Idle, OK
            ComObjectStatus::IdleError => 0x41,          // Idle, Error
            ComObjectStatus::Busy => 0x02,               // Transmitting (not idle)
            ComObjectStatus::WriteRequest => 0x02,       // Transmitting (not idle)
            ComObjectStatus::WriteRequestError => 0x41,  // Idle, Error (write failed)
            ComObjectStatus::ReadRequest => 0x44,        // Idle + Read request pending
            ComObjectStatus::ReadRequestOk => 0x44,      // Idle + Read request pending (sent OK)
            ComObjectStatus::ReadRequestError => 0x45,   // Idle + Read request pending + Error
            ComObjectStatus::Updated => 0x48,            // Idle + Updated
            ComObjectStatus::Uninitialized => 0x40,      // Treat as IdleOk
        }
    }

    /// Create status from a BCU1-style flags byte.
    ///
    /// Format (8 bits):
    /// - Bit 7: Set command (when writing, 1 = set flags, 0 = clear/read)
    /// - Bit 6: Idle indicator (ignored when parsing)
    /// - Bit 3: Update flag
    /// - Bit 2: Read request pending
    /// - Bit 1: Write/Transmit request pending
    /// - Bit 0: Error flag (1 = error, 0 = ok)
    ///
    /// This is the inverse of `to_flags_byte()`.
    pub fn from_flags_byte(flags: u8) -> Self {
        // Check special flags first (read request and update take priority)
        if flags & 0x04 != 0 {
            ComObjectStatus::ReadRequest
        } else if flags & 0x08 != 0 {
            ComObjectStatus::Updated
        } else if flags & 0x02 != 0 {
            // Write/Transmit request pending
            ComObjectStatus::WriteRequest
        } else if flags & 0x01 != 0 {
            ComObjectStatus::IdleError
        } else {
            ComObjectStatus::IdleOk
        }
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

pub const trait ComObjectIndex: Clone + Sized {
    fn from_index(idx: u16) -> Option<Self>;
    fn index(&self) -> u16;
}

/// Trait for managing communication objects in a KNX application.
pub trait ComObjects {
    type Index: ComObjectIndex;
    /// Context type for hooks. Use `()` if not needed.
    type HookContext;

    fn new() -> Self;
    fn info<'a>(&'a self, idx: u16) -> ComObjectInfo<'a>;
    fn info_mut<'a>(&'a mut self, idx: u16) -> ComObjectInfoMut<'a>;

    #[inline]
    fn status(&self, idx: u16) -> ComObjectStatus {
        let info = self.info(idx);
        *info.status
    }

    #[inline]
    fn set_status(&mut self, idx: u16, status: ComObjectStatus) {
        let info = self.info_mut(idx);
        *info.status = status;
    }

    #[inline]
    fn value(&self, idx: u16) -> &[u8] {
        let info = self.info(idx);
        info.value
    }

    #[inline]
    fn value_mut(&mut self, idx: u16) -> &mut [u8] {
        let info = self.info_mut(idx);
        info.value
    }

    /// Called before reading an object's value.
    #[inline]
    fn prepare_read(&mut self, _idx: u16, _ctx: &Self::HookContext) {
        // Default: no-op
    }

    /// Called after writing an object's value.
    #[inline]
    fn handle_write(&mut self, _idx: u16, _ctx: &Self::HookContext) {
        // Default: no-op
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComObjectEvent {
    /// A communication object was updated remotely by a GroupValueWrite
    Updated,

    /// A communication object was updated locally
    LocallyUpdated,

    /// A remote device requested to read this communication object's value
    Read,

    /// A response to a read request was received
    ReadResponse,
}

/// Defines communication objects for a KNX application.
///
/// # Syntax
///
/// ```rust,ignore
/// define_com_objects! {
///     pub mod my_objects {
///         pub struct MyComObjects {
///             1 => pub switch: DPT_Switch = DPT_Switch::from(false),
///             2 => pub dimmer: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),
///         }
///     }
/// }
/// ```
///
/// # Custom Implementation with Hooks
///
/// For objects that need custom behavior (e.g., computed values, validation,
/// or side effects on read/write), use the `#[manual_impl]` attribute to prevent
/// the macro from generating the `ComObjects` impl. Then provide your own
/// implementation with custom `prepare_read` and `handle_write` hooks:
///
/// ```rust,ignore
/// define_com_objects! {
///     pub mod my_objects {
///         #[manual_impl]  // Don't generate ComObjects impl
///         pub struct MyComObjects {
///             1 => pub temperature: DPT_Value_Temp = DPT_Value_Temp::default(),
///             2 => pub setpoint: DPT_Value_Temp = DPT_Value_Temp::default(),
///         }
///     }
/// }
///
/// use my_objects::*;
///
/// impl ComObjects for MyComObjects {
///     type Index = Index;
///     type HookContext = ();  // No external context needed
///
///     fn new() -> Self {
///         Self {
///             temperature: ComObject::new(DPT_Value_Temp::default()),
///             setpoint: ComObject::new(DPT_Value_Temp::default()),
///         }
///     }
///
///     fn info(&self, idx: u16) -> ComObjectInfo { /* ... */ }
///     fn info_mut(&mut self, idx: u16) -> ComObjectInfoMut { /* ... */ }
///
///     fn prepare_read(&mut self, idx: u16, _ctx: &()) {
///         if let Some(Index::Temperature) = Index::from_index(idx) {
///             // Update temperature from sensor before responding to read
///             // self.temperature.value = read_sensor();
///         }
///     }
///
///     fn handle_write(&mut self, idx: u16, _ctx: &()) {
///         if let Some(Index::Setpoint) = Index::from_index(idx) {
///             // Apply new setpoint to controller after write
///             // apply_setpoint(self.setpoint.value);
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_com_objects {
    // Variant with #[manual_impl] - generates struct and Index but NOT ComObjects impl
    (
        $(#[$mod_meta:meta])*
        pub mod $mod_name:ident {
            #[manual_impl]
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

                use embassy_sync::{
                    pubsub::{PubSubChannel, PubSubBehavior, DynSubscriber},
                    blocking_mutex::raw::NoopRawMutex
                };


                /// Enum with all communication object names and their indices
                #[allow(dead_code)]
                #[derive(core::marker::ConstParamTy, Debug, Clone, Copy, PartialEq, Eq)]
                #[repr(u16)]
                pub enum Index {
                    $(
                        [<$obj_name:camel>] = $idx,
                    )*
                }

                #[allow(dead_code)]
                impl ComObjectIndex for Index {
                    /// Convert from usize index to enum if valid
                    fn from_index(idx: u16) -> Option<Self> {
                        match idx {
                            $(
                                $idx => Some(Self::[<$obj_name:camel>]),
                            )*
                            _ => None,
                        }
                    }

                    /// Get the index value
                    fn index(&self) -> u16 {
                        *self as u16
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

                // Note: ComObjects impl is NOT generated - user must provide their own
            }
        }
    };

    // Standard variant - generates everything including ComObjects impl
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

                use embassy_sync::{
                    pubsub::{PubSubChannel, PubSubBehavior, DynSubscriber},
                    blocking_mutex::raw::NoopRawMutex
                };


                /// Enum with all communication object names and their indices
                #[allow(dead_code)]
                #[derive(core::marker::ConstParamTy, Debug, Clone, Copy, PartialEq, Eq)]
                #[repr(u16)]
                pub enum Index {
                    $(
                        [<$obj_name:camel>] = $idx,
                    )*
                }

                #[allow(dead_code)]
                impl ComObjectIndex for Index {
                    /// Convert from usize index to enum if valid
                    fn from_index(idx: u16) -> Option<Self> {
                        match idx {
                            $(
                                $idx => Some(Self::[<$obj_name:camel>]),
                            )*
                            _ => None,
                        }
                    }

                    /// Get the index value
                    fn index(&self) -> u16 {
                        *self as u16
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
                    type Index = Index;
                    type HookContext = ();

                    fn new() -> Self {
                        Self {
                            $(
                                $obj_name: ComObject::new($default),
                            )*
                        }
                    }

                    fn info<'a>(&'a self, idx: u16) -> ComObjectInfo<'a> {
                        match Index::from_index(idx).unwrap() {
                            $(
                                Index::[<$obj_name:camel>] => ComObjectInfo {
                                    status: &self.[<$obj_name>].status,
                                    value: self.[<$obj_name>].value.as_ref(),
                                },
                            )*
                        }
                    }

                    fn info_mut<'a>(&'a mut self, idx: u16) -> ComObjectInfoMut<'a> {
                        match Index::from_index(idx).unwrap() {
                            $(
                                Index::[<$obj_name:camel>] => ComObjectInfoMut {
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
