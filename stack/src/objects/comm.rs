use bitflags::bitflags;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;

use crate::dpt::DatapointType;

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

#[derive(Debug, Clone, Copy)]
pub struct ComObjectStatus {
    value: u8,
}

impl ComObjectStatus {
    pub fn new() -> Self {
        Self { value: 0 }
    }

    pub fn transmission_state(&self) -> TransmissionState {
        match self.value & 0b0000_0011 {
            0 => TransmissionState::IdleOk,
            1 => TransmissionState::IdleError,
            2 => TransmissionState::Transmitting,
            3 => TransmissionState::TransmitRequest,
            _ => unreachable!(),
        }
    }

    pub fn set_transmission_state(&mut self, state: TransmissionState) {
        // Clear current state (first 2 bits)
        self.value &= 0b1111_1100;
        // Set new state
        self.value |= state as u8;
    }

    pub fn flags(&self) -> ComObjectFlags {
        // Mask out transmission state bits
        ComObjectFlags::from_bits_truncate(self.value & 0b1111_1100)
    }

    pub fn set_flags(&mut self, flags: ComObjectFlags) {
        // Clear current flags but preserve transmission state
        self.value &= 0b0000_0011;
        // Set new flags
        self.value |= flags.bits();
    }

    pub fn update_flags(&mut self, flags: ComObjectFlags, value: bool) {
        if value {
            self.value |= flags.bits();
        } else {
            self.value &= !flags.bits();
        }
    }

    pub fn as_u8(&self) -> u8 {
        self.value
    }

    pub fn from_u8(value: u8) -> Self {
        Self { value }
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
    value: T,
    /// Status byte containing transmission state and flags
    status: ComObjectStatus,
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

    pub fn update_from_bytes(&mut self, data: &[u8]) -> bool {
        let dest = self.value.as_mut();
        if data.len() > dest.len() {
            return false;
        }

        dest[..data.len()].copy_from_slice(data);
        self.status
            .update_flags(ComObjectFlags::VALUE_CHANGED, true);
        self.status.update_flags(ComObjectFlags::VALUE_VALID, true);
        self.status.update_flags(ComObjectFlags::UPDATE_FLAG, true);
        true
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_ref()
    }

    pub fn transmission_state(&self) -> TransmissionState {
        self.status.transmission_state()
    }

    pub fn set_transmission_state(&mut self, state: TransmissionState) {
        self.status.set_transmission_state(state);
    }

    pub fn flags(&self) -> ComObjectFlags {
        self.status.flags()
    }

    pub fn set_flag(&mut self, flag: ComObjectFlags, value: bool) {
        self.status.update_flags(flag, value);
    }

    pub fn status_byte(&self) -> u8 {
        self.status.as_u8()
    }

    pub fn set_status_byte(&mut self, value: u8) {
        self.status = ComObjectStatus::from_u8(value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    ValueChanged,
    FlagsChanged,
    TransmissionCompleted(bool),
}

#[derive(Debug, Clone, Copy)]
pub struct ComObjectEvent<O> {
    pub object: O,
    pub event: EventType,
}

/// A channel for notifications about events on communication objects
pub struct ComObjectEventChannel<O> {
    channel: Channel<NoopRawMutex, ComObjectEvent<O>, 32>, // Buffer size of 32
}

impl<O: PartialEq> ComObjectEventChannel<O> {
    pub fn new() -> Self {
        Self {
            channel: Channel::new(),
        }
    }

    pub fn notify(&self, notification: ComObjectEvent<O>) {
        // Try to send, but don't block if full
        let _ = self.channel.try_send(notification);
    }

    // Get a future that resolves when a notification arrives
    pub async fn next_notification(&self) -> ComObjectEvent<O> {
        self.channel.receive().await
    }

    // Get a future that resolves when a notification for a specific object arrives
    pub async fn wait_for(&self, object: O) -> ComObjectEvent<O> {
        loop {
            let notification = self.channel.receive().await;
            if notification.object == object {
                return notification;
            }
        }
    }
}

pub trait ComObjects {
    fn new() -> Self;
}

#[macro_export]
macro_rules! define_com_objects {
    (
        $(#[$struct_meta:meta])*
        pub struct $struct_name:ident {
            $(
                $(#[$field_meta:meta])*
                $idx:expr => pub $obj_name:ident: $type:ty = $default:expr
            ),* $(,)?
        }
    ) => {
        paste::paste! {
            // FIXME: rename this and somehow get $struct_name in this
            /// Enum with all communication object names and their indices
            #[allow(dead_code)]
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum ComObjectIndex {
                $(
                    [<$obj_name:camel>] = $idx,
                )*
            }

            #[allow(dead_code)]
            impl ComObjectIndex {
                /// Convert from usize index to enum if valid
                pub fn from_index(idx: usize) -> Option<Self> {
                    match idx {
                        $(
                            $idx => Some(Self::[<$obj_name:camel>]),
                        )*
                        _ => None,
                    }
                }

                /// Get the index value
                pub fn index(self) -> usize {
                    self as usize
                }
            }

            // FIXME: make NoopRawMutex a generic?
            /// The communication objects
            $(#[$struct_meta])*
            pub struct $struct_name {
                $(
                    $(#[$field_meta])*
                    pub $obj_name: Mutex<NoopRawMutex, ComObject<$type>>,
                )*
                //pub notifier: ComObjectEventChannel<ComObjectIndex>,
            }

            impl ComObjects for $struct_name {
                fn new() -> Self {
                    Self {
                        $(
                            $obj_name: Mutex::new(ComObject::new($default)),
                        )*
                        //notifier: ComObjectEventChannel::new(),
                    }
                }
            }

            impl $struct_name {
                // /// Get the ComObjectIndex from a string name
                // pub fn get_name(&self, name: &str) -> Option<ComObjectIndex> {
                //     match name {
                //         $(
                //             stringify!($obj_name) => Some(ComObjectIndex::$obj_name),
                //         )*
                //         _ => None,
                //     }
                // }

                // /// Count the number of objects
                // pub const fn count() -> usize {
                //     let mut count = 0;
                //     $(
                //         // Count each object
                //         let _ = stringify!($obj_name);
                //         count += 1;
                //     )*
                //     count
                // }

                // /// Type-safe access methods for each object
                // $(
                //     /// Get the value of $obj_name
                //     pub async fn $obj_name(&self) -> $type {
                //         self.$obj_name.lock().await.value().clone()
                //     }

                //     /// Set the value of $obj_name
                //     pub async fn [<set_ $obj_name>](&self, value: $type, request_tx: bool) {
                //         let mut obj = self.$obj_name.lock().await;
                //         let changed = !obj.value().as_ref().eq(value.as_ref());
                //         obj.set_value(value, request_tx);

                //         if changed {
                //             // Send notification
                //             self.notifier.notify(ComObjectEvent {
                //                 object: ComObjectIndex::$obj_name,
                //                 event: EventType::ValueChanged,
                //             });
                //         }
                //     }
                // )*

                // // Generic methods that work with the ComObjectIndex enum

                // // /// Get an object value as bytes using ComObjectIndex
                // // pub async fn get_value_bytes(&self, name: ComObjectIndex) -> heapless::Vec<u8, 20> {
                // //     match name {
                // //         $(
                // //             ComObjectIndex::$obj_name => {
                // //                 let obj = self.$obj_name.lock().await;
                // //                 let bytes = obj.as_bytes();
                // //                 let mut vec = heapless::Vec::new();
                // //                 vec.extend_from_slice(bytes).ok();
                // //                 vec
                // //             },
                // //         )*
                // //     }
                // // }

                // /// Set an object value using ComObjectIndex
                // pub async fn set_value(&self, name: ComObjectIndex, data: &[u8], request_tx: bool) -> bool {
                //     match name {
                //         $(
                //             ComObjectIndex::$obj_name => {
                //                 let mut obj = self.$obj_name.lock().await;
                //                 let result = obj.update_from_bytes(data);
                //                 if result && request_tx {
                //                     obj.set_transmission_state(TransmissionState::TransmitRequest);
                //                 }

                //                 if result {
                //                     // Send notification
                //                     self.notifier.notify(ComObjectEvent {
                //                         object: name,
                //                         event: EventType::ValueChanged,
                //                     });
                //                 }

                //                 result
                //             },
                //         )*
                //     }
                // }

                // /// Update an object value by index
                // pub async fn update_value(&self, idx: usize, data: &[u8]) -> bool {
                //     match idx {
                //         $(
                //             $idx => {
                //                 let mut obj = self.$obj_name.lock().await;
                //                 let result = obj.update_from_bytes(data);

                //                 if result {
                //                     // Send notification
                //                     self.notifier.notify(ComObjectEvent {
                //                         object: ComObjectIndex::$obj_name,
                //                         event: EventType::ValueChanged,
                //                     });
                //                 }

                //                 result
                //             },
                //         )*
                //         _ => false,
                //     }
                // }

                // /// Get status byte by index
                // pub async fn get_status_byte(&self, idx: usize) -> Option<u8> {
                //     match idx {
                //         $(
                //             $idx => {
                //                 let obj = self.$obj_name.lock().await;
                //                 Some(obj.status_byte())
                //             },
                //         )*
                //         _ => None,
                //     }
                // }

                // /// Get status byte by name
                // pub async fn get_status_byte_by_name(&self, name: ComObjectIndex) -> u8 {
                //     match name {
                //         $(
                //             ComObjectIndex::$obj_name => {
                //                 self.$obj_name.lock().await.status_byte()
                //             },
                //         )*
                //     }
                // }

                // /// Set status byte by index
                // pub async fn set_status_byte(&self, idx: usize, status: u8) -> bool {
                //     match idx {
                //         $(
                //             $idx => {
                //                 let mut obj = self.$obj_name.lock().await;
                //                 obj.set_status_byte(status);
                //                 true
                //             },
                //         )*
                //         _ => false,
                //     }
                // }

                // /// Set status byte by name
                // pub async fn set_status_byte_by_name(&self, name: ComObjectIndex, status: u8) {
                //     match name {
                //         $(
                //             ComObjectIndex::$obj_name => {
                //                 self.$obj_name.lock().await.set_status_byte(status);
                //             },
                //         )*
                //     }
                // }

                // /// Set flag by index
                // pub async fn set_flag(&self, idx: usize, flag: ComObjectFlags, value: bool) -> bool {
                //     match idx {
                //         $(
                //             $idx => {
                //                 let mut obj = self.$obj_name.lock().await;
                //                 let changed = obj.flags().contains(flag) != value;
                //                 obj.set_flag(flag, value);

                //                 if changed {
                //                     // Send notification
                //                     self.notifier.notify(ComObjectEvent {
                //                         object: ComObjectIndex::$obj_name,
                //                         event: EventType::FlagsChanged,
                //                     });
                //                 }

                //                 true
                //             },
                //         )*
                //         _ => false,
                //     }
                // }

                // /// Set flag by name
                // pub async fn set_flag_by_name(&self, name: ComObjectIndex, flag: ComObjectFlags, value: bool) {
                //     match name {
                //         $(
                //             ComObjectIndex::$obj_name => {
                //                 let mut obj = self.$obj_name.lock().await;
                //                 let changed = obj.flags().contains(flag) != value;
                //                 obj.set_flag(flag, value);

                //                 if changed {
                //                     // Send notification
                //                     self.notifier.notify(ComObjectEvent {
                //                         object: name,
                //                         event: EventType::FlagsChanged,
                //                     });
                //                 }
                //             },
                //         )*
                //     }
                // }

                // /// Check flag by index
                // pub async fn check_flag(&self, idx: usize, flag: ComObjectFlags) -> Option<bool> {
                //     match idx {
                //         $(
                //             $idx => {
                //                 let obj = self.$obj_name.lock().await;
                //                 Some(obj.flags().contains(flag))
                //             },
                //         )*
                //         _ => None,
                //     }
                // }

                // /// Check flag by name
                // pub async fn check_flag_by_name(&self, name: ComObjectIndex, flag: ComObjectFlags) -> bool {
                //     match name {
                //         $(
                //             ComObjectIndex::$obj_name => {
                //                 self.$obj_name.lock().await.flags().contains(flag)
                //             },
                //         )*
                //     }
                // }

                // /// Get transmission state by index
                // pub async fn get_transmission_state(&self, idx: usize) -> Option<TransmissionState> {
                //     match idx {
                //         $(
                //             $idx => {
                //                 let obj = self.$obj_name.lock().await;
                //                 Some(obj.transmission_state())
                //             },
                //         )*
                //         _ => None,
                //     }
                // }

                // /// Get transmission state by name
                // pub async fn get_transmission_state_by_name(&self, name: ComObjectIndex) -> TransmissionState {
                //     match name {
                //         $(
                //             ComObjectIndex::$obj_name => {
                //                 self.$obj_name.lock().await.transmission_state()
                //             },
                //         )*
                //     }
                // }

                // /// Set transmission state by index
                // pub async fn set_transmission_state(&self, idx: usize, state: TransmissionState) -> bool {
                //     match idx {
                //         $(
                //             $idx => {
                //                 let mut obj = self.$obj_name.lock().await;
                //                 obj.set_transmission_state(state);
                //                 true
                //             },
                //         )*
                //         _ => false,
                //     }
                // }

                // /// Set transmission state by name
                // pub async fn set_transmission_state_by_name(&self, name: ComObjectIndex, state: TransmissionState) {
                //     match name {
                //         $(
                //             ComObjectIndex::$obj_name => {
                //                 self.$obj_name.lock().await.set_transmission_state(state);
                //             },
                //         )*
                //     }
                // }

                // // /// Get the next object that has a transmission request
                // // pub async fn get_next_transmission_request(&self) -> Option<(ComObjectIndex, heapless::Vec<u8, 20>)> {
                // //     $(
                // //         {
                // //             let mut obj = self.$obj_name.lock().await;
                // //             if obj.transmission_state() == TransmissionState::TransmitRequest {
                // //                 obj.set_transmission_state(TransmissionState::Transmitting);
                // //                 let bytes = obj.as_bytes();
                // //                 let mut vec = heapless::Vec::new();
                // //                 vec.extend_from_slice(bytes).ok();
                // //                 return Some((ComObjectIndex::$obj_name, vec));
                // //             }
                // //         }
                // //     )*

                // //     None
                // // }

                // /// Update transmission state
                // pub async fn update_transmission_state(&self, name: ComObjectIndex, success: bool) {
                //     let state = self.get_transmission_state_by_name(name).await;
                //     if state == TransmissionState::Transmitting {
                //         self.set_transmission_state_by_name(
                //             name,
                //             if success {
                //                 TransmissionState::IdleOk
                //             } else {
                //                 TransmissionState::IdleError
                //             }
                //         ).await;

                //         self.set_flag_by_name(name, ComObjectFlags::VALUE_VALID, success).await;

                //         // Send notification for transmission completion
                //         self.notifier.notify(ComObjectEvent {
                //             object: name,
                //             event: EventType::TransmissionCompleted(success),
                //         });
                //     }
                // }

                // /// Wait for any notification
                // pub async fn wait_for_any_change(&self) -> ComObjectEvent<ComObjectIndex> {
                //     self.notifier.next_notification().await
                // }

                // /// Wait for a specific object to change
                // pub async fn wait_for_change(&self, object: ComObjectIndex) -> ComObjectEvent<ComObjectIndex> {
                //     self.notifier.wait_for(object).await
                // }

                // /// Check if an object has the READ_REQUEST flag set
                // pub async fn has_read_request(&self, obj_idx: ComObjectIndex) -> bool {
                //     self.check_flag_by_name(obj_idx, ComObjectFlags::READ_REQUEST).await
                // }

                // /// Clear the READ_REQUEST flag for an object
                // pub async fn clear_read_request_flag(&self, obj_idx: ComObjectIndex) {
                //     self.set_flag_by_name(obj_idx, ComObjectFlags::READ_REQUEST, false).await;
                // }

                // /// Set the READ_REQUEST flag for an object
                // pub async fn set_read_request_flag(&self, obj_idx: ComObjectIndex) {
                //     self.set_flag_by_name(obj_idx, ComObjectFlags::READ_REQUEST, true).await;
                // }
            }
        }
    };
}

mod tests {
    use super::*;
    use crate::dpt::*;

    define_com_objects! {
        /// My application's communication objects
        #[allow(dead_code)]
        pub struct MyComObjects {
            0 => pub switch1: DPT_Switch = DPT_Switch::from(false),
            1 => pub version: DPT_Version = DPT_Version::from(KNXVersion::from_triplet(0, 1, 0)),
            2 => pub heater: DPT_Switch = DPT_Switch::from(false),
        }
    }

    #[test]
    fn test_comm_objs() {
        let _c = MyComObjects::new();
    }
}

// // Update your StackResources struct
// #[derive(Debug)]
// pub struct StackResources<P: ConstDefault> {
//     pub ind_addr: KNXIndividualAddress,
//     pub adt: AddrTab7<30>,
//     pub ast: AssoTab6<30>,
//     pub cot: CoTab7<30>,
//     // Our communication objects
//     pub com_objects: ComObjects,
//     pub app: Application<P>,
// }

// // Application task that reacts to changes
// #[embassy_executor::task]
// async fn app_task(stack: &'static StackResources<AppParams>) {
//     loop {
//         // Wait for any notification
//         let notification = stack.com_objects.wait_for_any_change().await;

//         match notification.object {
//             ComObjectIndex::switch1 => {
//                 // Only process value changes
//                 if let EventType::ValueChanged = notification.source {
//                     let switch = stack.com_objects.switch1().await;
//                     let is_on: bool = switch.into();
//                     println!("Switch changed to: {}", if is_on { "ON" } else { "OFF" });
//                 }
//             },
//             ComObjectIndex::temp_sensor => {
//                 if let EventType::ValueChanged = notification.source {
//                     let temp = stack.com_objects.temp_sensor().await;
//                     let temp_value: f32 = temp.backing().value();
//                     println!("Temperature update: {:.1}°C", temp_value);

//                     // Control heating
//                     if temp_value < 20.0 {
//                         stack.com_objects.set_heater(DPT_Switch::from(true), true).await;
//                     } else if temp_value > 22.0 {
//                         stack.com_objects.set_heater(DPT_Switch::from(false), true).await;
//                     }
//                 }
//             },
//             ComObjectIndex::heater => {
//                 if let EventType::TransmissionCompleted(success) = notification.source {
//                     println!("Heater command transmission: {}",
//                         if success { "successful" } else { "failed" });
//                 }
//             },
//             _ => {}
//         }
//     }
// }

// // Process outgoing transmissions
// #[embassy_executor::task]
// async fn network_tx_task(stack: &'static StackResources<AppParams>) {
//     loop {
//         // Check for objects that need to be transmitted
//         if let Some((name, value)) = stack.com_objects.get_next_transmission_request().await {
//             // Get group address from table
//             let idx = name.index();
//             let group_addr = stack.cot.get_group_addr(idx);

//             // Send the value
//             let success = send_group_value(group_addr, &value).await;

//             // Update status
//             stack.com_objects.update_transmission_state(name, success).await;
//         } else {
//             // No transmissions pending, wait a bit
//             Timer::after(Duration::from_millis(10)).await;
//         }
//     }
// }
