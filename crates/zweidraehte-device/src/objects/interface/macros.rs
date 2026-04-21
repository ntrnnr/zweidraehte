//! Macro for defining Interface Objects
//!
//! This module provides the `define_interface_object!` macro for creating
//! type-safe interface object definitions with minimal boilerplate.
//!
//! # Simple Interface Objects
//!
//! For objects with only static properties (stored in the struct):
//!
//! ```rust,ignore
//! define_interface_object! {
//!     pub struct MyObject: InterfaceObjectType::Device {
//!         pid::SERIAL_NUMBER => serial_number: PDT_Generic06, ReadWrite;
//!         pid::MANUFACTURER_ID => manufacturer_id: PDT_UnsignedInt, ReadOnly;
//!     }
//! }
//! ```
//!
//! # State-Backed Interface Objects
//!
//! For objects that need to access shared state (like `StackState`), use the
//! `with state` syntax. Properties can be either static (stored in struct) or
//! state-backed (read/written via the state reference).
//!
//! ## State Property Syntax Options
//!
//! There are four forms for state-backed properties, from simplest to most flexible:
//!
//! ### 1. Shorthand ReadWrite (auto-generated getter/setter)
//! ```rust,ignore
//! pid::TTL => state.ttl: PDT_UnsignedChar, ReadWrite
//! ```
//! This generates:
//! - Read: calls `s.ttl()` and converts to bytes
//! - Write: calls `s.set_ttl(value)` after converting from bytes
//!
//! ### 2. Shorthand ReadOnly (getter only)
//! ```rust,ignore
//! pid::CURRENT_IP_ADDRESS => state.current_ip_address(): PDT_UnsignedLong, ReadOnly
//! ```
//! This generates:
//! - Read: calls `s.current_ip_address()` and converts to bytes
//! - Write: returns WriteNotAllowed error
//!
//! ### 3. Shorthand ReadWrite Array (multi-element properties)
//! ```rust,ignore
//! state_rw_array {
//!     pid::FRIENDLY_NAME => friendly_name: PDT_UnsignedChar[30]
//! }
//! ```
//! This generates array property semantics with three derived methods
//! (naming convention based on the getter name, using `paste!`):
//! - Read: calls `s.friendly_name()` → `[u8; 30]` (full buffer, zero-padded)
//! - Length: calls `s.friendly_name_len()` → `usize` (actual element count)
//! - Write: calls `s.set_friendly_name(data: &[u8])`
//!
//! Array read behavior:
//! - `start_idx=0`: returns element count as 2 big-endian bytes
//! - `start_idx>=1`: returns requested element range with bounds checking
//!
//! ### 4. Full closure syntax (for complex logic)
//! ```rust,ignore
//! pid::PROGMODE => {
//!     read: |s| [if s.programming_mode() { 0x01 } else { 0x00 }],
//!     write: |s, data| { s.set_programming_mode(data[0] != 0); Ok(()) }
//! }: PDT_Generic01, ReadWrite
//! ```
//!
//! ## Complete Example
//!
//! ```rust,ignore
//! define_interface_object! {
//!     pub struct DeviceObject<'a, S: StackState>: InterfaceObjectType::Device
//!         with state: &'a S
//!     {
//!         // Static properties
//!         pid::SERIAL_NUMBER => serial_number: PDT_Generic06, ReadWrite;
//!     }
//!     state {
//!         // Shorthand: auto getter/setter for simple types
//!         pid::TTL => state.ttl: PDT_UnsignedChar, ReadWrite,
//!
//!         // Shorthand: getter only for read-only properties
//!         pid::MAC_ADDRESS => state.mac_address(): PDT_Generic06, ReadOnly,
//!
//!         // Full closures for complex logic
//!         pid::PROGMODE => {
//!             read: |s| [if s.programming_mode() { 0x01 } else { 0x00 }],
//!             write: |s, data| { s.set_programming_mode(data[0] != 0); Ok(()) }
//!         }: PDT_Generic01, ReadWrite
//!     }
//! }
//! ```

/// Define an Interface Object with its properties
///
/// This macro generates a struct with the specified properties and implements
/// the `InterfaceObject` trait automatically. It provides:
///
/// - A struct with typed fields for each property
/// - Const array of property descriptors for efficient lookup
/// - `InterfaceObject` trait implementation with read/write methods
/// - Automatic OBJECT_TYPE property (PID 1) as the first property
///
/// # Syntax
///
/// ## Simple (no state)
/// ```rust,ignore
/// define_interface_object! {
///     /// Documentation for the object
///     pub struct ObjectName: InterfaceObjectType::TypeName {
///         // PID => field_name: PropertyDataType, Access [= default_value];
///         pid::SERIAL_NUMBER => serial_number: PDT_Generic06, ReadWrite;
///         pid::MANUFACTURER_ID => manufacturer_id: PDT_UnsignedInt, ReadOnly = PDT_UnsignedInt::with_value(0x1234);
///     }
/// }
/// ```
///
/// ## With state access
/// ```rust,ignore
/// define_interface_object! {
///     pub struct DeviceObject<'a, S: StackState>: InterfaceObjectType::Device
///         with state: &'a S
///     {
///         // Static property
///         pid::SERIAL_NUMBER => serial_number: PDT_Generic06, ReadWrite;
///
///         // State-backed property
///         pid::PROGMODE => state {
///             read: |s| [if s.programming_mode() { 0x01 } else { 0x00 }],
///             write: |s, data| { s.set_programming_mode(data[0] != 0); Ok(()) }
///         }: PDT_Generic01, ReadWrite;
///     }
/// }
/// ```
///
/// # Access Modes
///
/// - `ReadOnly` - Property can only be read, writes return an error
/// - `ReadWrite` - Property can be read and written
/// - `WriteOnly` - Property can only be written (rare, e.g., security keys)
///
/// # Generated Code
///
/// The macro generates:
///
/// 1. A struct with the specified fields
/// 2. A `PROPERTY_DESCRIPTORS` const array
/// 3. Implementation of `InterfaceObject` trait
/// 4. Implementation of `Default` trait (using provided defaults or `Default::default()`)
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte_device::objects::interface::*;
/// use zweidraehte_proto::dpt::*;
///
/// define_interface_object! {
///     /// Device Object containing basic device information
///     pub struct DeviceObject: InterfaceObjectType::Device {
///         pid::SERIAL_NUMBER => serial_number: PDT_Generic06, ReadWrite;
///         pid::MANUFACTURER_ID => manufacturer_id: PDT_UnsignedInt, ReadOnly;
///         pid::DEVICE_CONTROL => device_control: PDT_Generic01, ReadWrite;
///     }
/// }
///
/// // Usage
/// let mut device = DeviceObject::default();
/// device.serial_number.set_value([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
///
/// // Access via InterfaceObject trait
/// let mut buf = [0u8; 6];
/// device.read_property(pid::SERIAL_NUMBER, 1, 1, &mut buf).unwrap();
/// ```
#[macro_export]
macro_rules! define_interface_object {
    (
        $(#[$obj_meta:meta])*
        $vis:vis struct $name:ident : $obj_type:tt :: $obj_variant:tt {
            $(
                $pid_path:path => $field_name:ident : $pdt:ty , $access:ident
                $([$($access_spec:tt)*])?
                $(= $default:expr)?
            );* $(;)?
        }
    ) => {
        $(#[$obj_meta])*
        $vis struct $name {
            $(
                pub $field_name: $pdt,
            )*
        }

        impl $name {
            /// Property descriptors for this interface object (const array)
            ///
            /// Index 0 is always OBJECT_TYPE (PID 1).
            /// Subsequent indices correspond to the properties in definition order.
            pub const PROPERTY_DESCRIPTORS: &'static [$crate::objects::interface::PropertyDescriptor] = &[
                // PID_OBJECT_TYPE is always the first property (index 0)
                $crate::define_interface_object!(@make_descriptor
                    $crate::objects::interface::pid::OBJECT_TYPE,
                    ::zweidraehte_proto::dpt::PDT_UnsignedInt, 1, ReadOnly,
                ),
                // User-defined properties follow
                $(
                    $crate::define_interface_object!(@make_descriptor
                        $pid_path, $pdt, 1, $access,
                        $([$($access_spec)*])?
                    ),
                )*
            ];

            /// Create a new instance with default values
            pub fn new() -> Self {
                Self {
                    $(
                        $field_name: $crate::define_interface_object!(@default $pdt $(, $default)?),
                    )*
                }
            }

            /// Get direct typed access to a property field
            ///
            /// This provides application-side type-safe access to properties.
            #[inline]
            pub fn get<T>(&self) -> &T
            where
                Self: $crate::objects::interface::HasProperty<T>,
            {
                <Self as $crate::objects::interface::HasProperty<T>>::get(self)
            }

            /// Get mutable typed access to a property field
            #[inline]
            pub fn get_mut<T>(&mut self) -> &mut T
            where
                Self: $crate::objects::interface::HasProperty<T>,
            {
                <Self as $crate::objects::interface::HasProperty<T>>::get_mut(self)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::objects::interface::InterfaceObject for $name {
            fn object_type(&self) -> ::zweidraehte_proto::dpt::InterfaceObjectType {
                ::zweidraehte_proto::dpt::$obj_type::$obj_variant
            }

            fn property_count(&self) -> u16 {
                Self::PROPERTY_DESCRIPTORS.len() as u16
            }

            fn property_descriptor_by_index(
                &self,
                prop_idx: u16,
            ) -> Option<$crate::objects::interface::PropertyDescriptor> {
                Self::PROPERTY_DESCRIPTORS.get(prop_idx as usize).copied()
            }

            fn property_descriptor_by_id(
                &self,
                pid: u16,
            ) -> Option<(u16, $crate::objects::interface::PropertyDescriptor)> {
                Self::PROPERTY_DESCRIPTORS
                    .iter()
                    .enumerate()
                    .find(|(_, d)| d.pid == pid)
                    .map(|(i, d)| (i as u16, *d))
            }

            fn read_property(
                &self,
                req: $crate::objects::interface::PropertyReadRequest,
                buf: &mut [u8],
            ) -> Result<usize, $crate::objects::interface::PropertyError> {
                // Validate start_idx and count for single-element properties
                // Special case: start_idx=0 means query element count (regardless of count value)
                // Per KNX spec, when start_idx=0, return the current number of elements
                if req.start_idx == 0 {
                    // Return 1 for single-element properties (2 bytes, big-endian)
                    if buf.len() >= 2 {
                        buf[0] = 0;
                        buf[1] = 1;
                        return Ok(2);
                    }
                    return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                }

                // For single-element properties, only start_idx=1, count=1 is valid
                if req.start_idx != 1 || req.count != 1 {
                    return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
                }

                match req.pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => {
                        let obj_type: u16 = <::zweidraehte_proto::dpt::InterfaceObjectType as Into<u16>>::into(::zweidraehte_proto::dpt::$obj_type::$obj_variant);
                        if buf.len() < 2 {
                            return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                        }
                        buf[0..2].copy_from_slice(&obj_type.to_be_bytes());
                        Ok(2)
                    }
                    $(
                        $pid_path => {
                            let data: &[u8] = self.$field_name.as_ref();
                            if buf.len() < data.len() {
                                return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                            }
                            buf[..data.len()].copy_from_slice(data);
                            Ok(data.len())
                        }
                    )*
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn write_property(
                &mut self,
                req: $crate::objects::interface::PropertyWriteRequest<'_>,
            ) -> Result<$crate::objects::interface::WriteResponse, $crate::objects::interface::PropertyError> {
                match req.pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => {
                        Err($crate::objects::interface::PropertyError::WriteNotAllowed)
                    }
                    $(
                        $pid_path => {
                            $crate::define_interface_object!(@write_static $access, self.$field_name, req.start_idx, req.data)?;
                            Ok($crate::objects::interface::WriteResponse::Echo)
                        }
                    )*
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn property_element_count(
                &self,
                pid: u16,
            ) -> Result<u16, $crate::objects::interface::PropertyError> {
                match pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => Ok(1),
                    $($pid_path => Ok(1),)*
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }
        }
    };

    // ========================================================================
    // Variant: Interface object with state reference
    // ========================================================================
    // This variant supports both static properties (stored in struct) and
    // state-backed properties (read/written via the state reference).
    //
    // Syntax:
    //   - Static: `pid::FOO => field_name: Type, Access;`
    //   - Closure-based: `state { pid::FOO => { read: |s| expr, write: |s, data| expr }: Type, Access }`
    //   - Shorthand RW: `state_rw { pid::FOO => getter: Type }`  (auto getter/setter)
    //   - Shorthand RO: `state_ro { pid::FOO => getter: Type }`  (getter only)
    (
        $(#[$obj_meta:meta])*
        $vis:vis struct $name:ident <$lt:lifetime, $state_ty:ident : $state_bound:path>
            : $obj_type:tt :: $obj_variant:tt
            with state : & $state_lt:lifetime $state_ty2:ident
        {
            $(
                // Static property: pid => field_name: Type, Access [rl, wl, policy] [= default]
                $pid_path:path => $field_name:ident : $pdt:ty , $access:ident
                $([$($access_spec:tt)*])?
                $(= $default:expr)?
            ),*
        }
        // State-backed properties with closures (for complex logic)
        // Optional [rl, wl] or [rl, wl, policy] after the access mode
        $(state {
            $(
                $state_pid_path:path => {
                    read : | $read_state:ident | $read_expr:expr ,
                    write : | $write_state:ident , $write_data:ident | $write_expr:expr
                } : $state_pdt:ty , $state_access:ident
                $([$($state_access_spec:tt)*])?
            ),*
        })?
        // Shorthand ReadWrite properties: auto getter/setter
        $(state_rw {
            $(
                $rw_pid_path:path => $rw_getter:ident : $rw_pdt:ty
                $([$($rw_access_spec:tt)*])?
            ),*
        })?
        // Shorthand ReadOnly properties: getter only
        $(state_ro {
            $(
                $ro_pid_path:path => $ro_getter:ident : $ro_pdt:ty
                $([$($ro_access_spec:tt)*])?
            ),*
        })?
        // Shorthand ReadWrite array properties
        $(state_rw_array {
            $(
                $rwa_pid_path:path => $rwa_getter:ident : $rwa_pdt:ty [$rwa_max:expr]
                $([$($rwa_access_spec:tt)*])?
            ),*
        })?
    ) => {
        $(#[$obj_meta])*
        $vis struct $name<$lt, $state_ty: $state_bound> {
            $(
                pub $field_name: $pdt,
            )*
            state: &$lt $state_ty,
        }

        impl<$lt, $state_ty: $state_bound> $name<$lt, $state_ty> {
            /// Property descriptors for this interface object (const array)
            pub const PROPERTY_DESCRIPTORS: &'static [$crate::objects::interface::PropertyDescriptor] = &[
                // PID_OBJECT_TYPE is always the first property (index 0)
                $crate::define_interface_object!(@make_descriptor
                    $crate::objects::interface::pid::OBJECT_TYPE,
                    ::zweidraehte_proto::dpt::PDT_UnsignedInt, 1, ReadOnly,
                ),
                // Static properties
                $(
                    $crate::define_interface_object!(@make_descriptor
                        $pid_path, $pdt, 1, $access,
                        $([$($access_spec)*])?
                    ),
                )*
                // State-backed properties (closure-based)
                $($(
                    $crate::define_interface_object!(@make_descriptor
                        $state_pid_path, $state_pdt, 1, $state_access,
                        $([$($state_access_spec)*])?
                    ),
                )*)?
                // Shorthand ReadWrite properties
                $($(
                    $crate::define_interface_object!(@make_descriptor
                        $rw_pid_path, $rw_pdt, 1, ReadWrite,
                        $([$($rw_access_spec)*])?
                    ),
                )*)?
                // Shorthand ReadOnly properties
                $($(
                    $crate::define_interface_object!(@make_descriptor
                        $ro_pid_path, $ro_pdt, 1, ReadOnly,
                        $([$($ro_access_spec)*])?
                    ),
                )*)?
                // Shorthand ReadWrite array properties
                $($(
                    $crate::define_interface_object!(@make_array_descriptor
                        $rwa_pid_path, $rwa_pdt, $rwa_max,
                        $([$($rwa_access_spec)*])?
                    ),
                )*)?
            ];

            /// Create a new instance with a state reference
            pub fn new(state: &$lt $state_ty) -> Self {
                Self {
                    $(
                        $field_name: $crate::define_interface_object!(@default $pdt $(, $default)?),
                    )*
                    state,
                }
            }
        }

        impl<$lt, $state_ty: $state_bound> $crate::objects::interface::InterfaceObject for $name<$lt, $state_ty> {
            fn object_type(&self) -> ::zweidraehte_proto::dpt::InterfaceObjectType {
                ::zweidraehte_proto::dpt::$obj_type::$obj_variant
            }

            fn property_count(&self) -> u16 {
                Self::PROPERTY_DESCRIPTORS.len() as u16
            }

            fn property_descriptor_by_index(
                &self,
                prop_idx: u16,
            ) -> Option<$crate::objects::interface::PropertyDescriptor> {
                Self::PROPERTY_DESCRIPTORS.get(prop_idx as usize).copied()
            }

            fn property_descriptor_by_id(
                &self,
                pid: u16,
            ) -> Option<(u16, $crate::objects::interface::PropertyDescriptor)> {
                Self::PROPERTY_DESCRIPTORS
                    .iter()
                    .enumerate()
                    .find(|(_, d)| d.pid == pid)
                    .map(|(i, d)| (i as u16, *d))
            }

            fn read_property(
                &self,
                req: $crate::objects::interface::PropertyReadRequest,
                buf: &mut [u8],
            ) -> Result<usize, $crate::objects::interface::PropertyError> {
                match req.pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => {
                        let obj_type: u16 = <::zweidraehte_proto::dpt::InterfaceObjectType as Into<u16>>::into(::zweidraehte_proto::dpt::$obj_type::$obj_variant);
                        $crate::objects::interface::PropertyRead::read_property(
                            &obj_type.to_be_bytes(), req.start_idx, req.count, buf,
                        )
                    }
                    // Static properties
                    $(
                        $pid_path => {
                            $crate::objects::interface::PropertyRead::read_property(
                                &self.$field_name, req.start_idx, req.count, buf,
                            )
                        }
                    )*
                    // State-backed properties (closure-based)
                    $($(
                        $state_pid_path => {
                            let $read_state = self.state;
                            let data = $read_expr;
                            $crate::objects::interface::PropertyRead::read_property(
                                &data, req.start_idx, req.count, buf,
                            )
                        }
                    )*)?
                    // Shorthand ReadWrite properties
                    $($(
                        $rw_pid_path => {
                            $crate::define_interface_object!(@read_shorthand self.state, $rw_getter, $rw_pdt, req.start_idx, req.count, buf)
                        }
                    )*)?
                    // Shorthand ReadOnly properties
                    $($(
                        $ro_pid_path => {
                            $crate::define_interface_object!(@read_shorthand self.state, $ro_getter, $ro_pdt, req.start_idx, req.count, buf)
                        }
                    )*)?
                    // Shorthand ReadWrite array properties
                    $($(
                        $rwa_pid_path => {
                            $crate::define_interface_object!(@read_array_shorthand self.state, $rwa_getter, req.start_idx, req.count, buf)
                        }
                    )*)?
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn write_property(
                &mut self,
                req: $crate::objects::interface::PropertyWriteRequest<'_>,
            ) -> Result<$crate::objects::interface::WriteResponse, $crate::objects::interface::PropertyError> {
                match req.pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => {
                        Err($crate::objects::interface::PropertyError::WriteNotAllowed)
                    }
                    // Static properties
                    $(
                        $pid_path => {
                            $crate::define_interface_object!(@write_static $access, self.$field_name, req.start_idx, req.data)?;
                            Ok($crate::objects::interface::WriteResponse::Echo)
                        }
                    )*
                    // State-backed properties (closure-based)
                    $($(
                        $state_pid_path => {
                            $crate::define_interface_object!(@write_state_property $state_access, self.state, req.start_idx, req.data, $write_state, $write_data, $write_expr)?;
                            Ok($crate::objects::interface::WriteResponse::Echo)
                        }
                    )*)?
                    // Shorthand ReadWrite properties
                    $($(
                        $rw_pid_path => {
                            $crate::define_interface_object!(@write_shorthand self.state, $rw_getter, $rw_pdt, req.start_idx, req.data)?;
                            Ok($crate::objects::interface::WriteResponse::Echo)
                        }
                    )*)?
                    // Shorthand ReadOnly properties
                    $($(
                        $ro_pid_path => {
                            Err($crate::objects::interface::PropertyError::WriteNotAllowed)
                        }
                    )*)?
                    // Shorthand ReadWrite array properties
                    $($(
                        $rwa_pid_path => {
                            $crate::define_interface_object!(@write_array_shorthand self.state, $rwa_getter, $rwa_max, req.start_idx, req.data)?;
                            Ok($crate::objects::interface::WriteResponse::Echo)
                        }
                    )*)?
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn property_element_count(
                &self,
                pid: u16,
            ) -> Result<u16, $crate::objects::interface::PropertyError> {
                match pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => Ok(1),
                    $($pid_path => Ok(1),)*
                    $($($state_pid_path => Ok(1),)*)?
                    $($($rw_pid_path => Ok(1),)*)?
                    $($($ro_pid_path => Ok(1),)*)?
                    $($(
                        $rwa_pid_path => {
                            Ok($crate::paste::paste! {
                                self.state.[<$rwa_getter _len>]()
                            } as u16)
                        }
                    )*)?
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }
        }
    };

    // Helper: provide default value or call Default::default()
    (@default $pdt:ty) => {
        <$pdt as Default>::default()
    };
    (@default $pdt:ty, $default:expr) => {
        $default
    };

    // Helper: write static property (handles ReadOnly without generating unreachable code)
    (@write_static ReadOnly, $target:expr, $start_idx:expr, $data:expr) => {
        Err($crate::objects::interface::PropertyError::WriteNotAllowed)
    };
    (@write_static ReadWrite, $target:expr, $start_idx:expr, $data:expr) => {{
        $crate::objects::interface::PropertyWrite::write_property(
            &mut $target, $start_idx, $data,
        )?;
        Ok(())
    }};
    (@write_static WriteOnly, $target:expr, $start_idx:expr, $data:expr) => {{
        $crate::objects::interface::PropertyWrite::write_property(
            &mut $target, $start_idx, $data,
        )?;
        Ok(())
    }};

    // Helper: write state-backed property (handles ReadOnly without generating unreachable code)
    (@write_state_property ReadOnly, $state:expr, $start_idx:expr, $data_in:expr, $write_state:ident, $write_data:ident, $write_expr:expr) => {
        Err($crate::objects::interface::PropertyError::WriteNotAllowed)
    };
    (@write_state_property ReadWrite, $state:expr, $start_idx:expr, $data_in:expr, $write_state:ident, $write_data:ident, $write_expr:expr) => {{
        if $start_idx != 1 {
            return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
        }
        let $write_state = $state;
        let $write_data = $data_in;
        $write_expr
    }};
    (@write_state_property WriteOnly, $state:expr, $start_idx:expr, $data_in:expr, $write_state:ident, $write_data:ident, $write_expr:expr) => {{
        if $start_idx != 1 {
            return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
        }
        let $write_state = $state;
        let $write_data = $data_in;
        $write_expr
    }};

    // ========================================================================
    // Shorthand helpers for auto-generated read/write
    // ========================================================================
    // These helpers use the StatePropertyValue trait to convert between
    // property values and their byte representations.

    // Read shorthand: calls state.getter() and converts to bytes via StatePropertyValue,
    // then delegates to PropertyRead for KNX semantics (element count, bounds check).
    (@read_shorthand $state:expr, $getter:ident, $pdt:ty, $start_idx:expr, $count:expr, $buf:expr) => {{
        let value = $state.$getter();
        let data = <$pdt as $crate::objects::interface::StatePropertyValue>::to_bytes(&value);
        $crate::objects::interface::PropertyRead::read_property(&data, $start_idx, $count, $buf)
    }};

    // Write shorthand: validates start_idx, converts bytes to value via StatePropertyValue,
    // and calls state.set_getter().
    (@write_shorthand $state:expr, $getter:ident, $pdt:ty, $start_idx:expr, $data:expr) => {{
        if $start_idx != 1 {
            return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
        }
        match <$pdt as $crate::objects::interface::StatePropertyValue>::from_bytes($data) {
            Ok(value) => {
                $crate::paste::paste! {
                    $state.[<set_ $getter>](value);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }};

    // ========================================================================
    // Array property helpers
    // ========================================================================
    // These helpers implement KNX array property semantics for state-backed
    // properties where the getter returns a fixed-size array and a separate
    // _len method gives the actual element count.

    // Read array shorthand:
    //   - start_idx=0 → element count as 2 big-endian bytes
    //   - start_idx>=1 → slice of elements with bounds checking
    (@read_array_shorthand $state:expr, $getter:ident, $start_idx:expr, $count:expr, $buf:expr) => {{
        $crate::paste::paste! {
            let data = $state.$getter();
            let len = $state.[<$getter _len>]();
            if $start_idx == 0 {
                if $buf.len() < 2 {
                    return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                }
                $buf[..2].copy_from_slice(&(len as u16).to_be_bytes());
                Ok(2)
            } else {
                let start = ($start_idx - 1) as usize;
                if start >= len {
                    return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
                }
                let end = (start + $count as usize).min(len);
                let n = end - start;
                if $buf.len() < n {
                    return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                }
                $buf[..n].copy_from_slice(&data[start..end]);
                Ok(n)
            }
        }
    }};

    // Write array shorthand: supports partial writes at arbitrary start indices.
    // Performs a read-modify-write: reads the current buffer, patches the written
    // range, and calls set_getter() with the full updated buffer.
    (@write_array_shorthand $state:expr, $getter:ident, $max:expr, $start_idx:expr, $data:expr) => {{
        $crate::paste::paste! {
            if $start_idx == 0 {
                return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
            }
            let start = ($start_idx - 1) as usize;
            let mut buf = $state.$getter();
            let end = (start + $data.len()).min($max);
            let copy_len = end - start;
            if copy_len == 0 || start >= $max {
                return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
            }
            buf[start..end].copy_from_slice(&$data[..copy_len]);
            // Update the length if the write extends beyond the current content.
            let current_len = $state.[<$getter _len>]();
            let new_len = end.max(current_len);
            // We can't set the length separately through the shorthand, so we
            // pass the full buffer and let set_getter determine the length from
            // the content (it receives the entire max-sized buffer, zero-padded
            // beyond the written region).
            //
            // However, the setter takes a slice and uses its length as the new
            // length. So we pass exactly new_len bytes.
            $state.[<set_ $getter>](&buf[..new_len]);
            Ok(())
        }
    }};

    // ========================================================================
    // Internal descriptor builder helpers
    // ========================================================================
    // These normalize the optional [read_level, write_level, policy] access
    // specification into a PropertyDescriptor::with_policy() call.

    // With levels and policy: [rl, wl, policy]
    (@make_descriptor $pid:expr, $pdt:ty, $max:expr, $access:ident, [$rl:expr, $wl:expr, $policy:expr]) => {
        $crate::objects::interface::PropertyDescriptor::with_policy(
            $pid,
            <$pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
            $max,
            $crate::objects::interface::PropertyAccess::$access,
            $rl,
            $wl,
            $policy,
        )
    };

    // With levels only: [rl, wl] — default policy
    (@make_descriptor $pid:expr, $pdt:ty, $max:expr, $access:ident, [$rl:expr, $wl:expr]) => {
        $crate::objects::interface::PropertyDescriptor::with_policy(
            $pid,
            <$pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
            $max,
            $crate::objects::interface::PropertyAccess::$access,
            $rl,
            $wl,
            ::zweidraehte_proto::access::AccessPolicy::READ_OPEN_WRITE_TOOL,
        )
    };

    // No access spec — defaults to 3/3, READ_OPEN_WRITE_TOOL
    (@make_descriptor $pid:expr, $pdt:ty, $max:expr, $access:ident,) => {
        $crate::objects::interface::PropertyDescriptor::with_policy(
            $pid,
            <$pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
            $max,
            $crate::objects::interface::PropertyAccess::$access,
            3,
            3,
            ::zweidraehte_proto::access::AccessPolicy::READ_OPEN_WRITE_TOOL,
        )
    };

    // ========================================================================
    // Array descriptor builder helpers (for state_rw_array)
    // ========================================================================
    // Same as @make_descriptor but takes max_elements from the property spec.

    // With levels and policy
    (@make_array_descriptor $pid:expr, $pdt:ty, $max:expr, [$rl:expr, $wl:expr, $policy:expr]) => {
        $crate::objects::interface::PropertyDescriptor::with_policy(
            $pid,
            <$pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
            $max,
            $crate::objects::interface::PropertyAccess::ReadWrite,
            $rl,
            $wl,
            $policy,
        )
    };

    // With levels only
    (@make_array_descriptor $pid:expr, $pdt:ty, $max:expr, [$rl:expr, $wl:expr]) => {
        $crate::objects::interface::PropertyDescriptor::with_policy(
            $pid,
            <$pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
            $max,
            $crate::objects::interface::PropertyAccess::ReadWrite,
            $rl,
            $wl,
            ::zweidraehte_proto::access::AccessPolicy::READ_OPEN_WRITE_TOOL,
        )
    };

    // No access spec
    (@make_array_descriptor $pid:expr, $pdt:ty, $max:expr,) => {
        $crate::objects::interface::PropertyDescriptor::with_policy(
            $pid,
            <$pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
            $max,
            $crate::objects::interface::PropertyAccess::ReadWrite,
            3,
            3,
            ::zweidraehte_proto::access::AccessPolicy::READ_OPEN_WRITE_TOOL,
        )
    };
}

/// Marker trait for typed property access
///
/// This trait enables the `get::<PropertyType>()` pattern for type-safe
/// property access on the application side.
pub trait HasProperty<T> {
    fn get(&self) -> &T;
    fn get_mut(&mut self) -> &mut T;
}

#[cfg(test)]
mod tests {
    use crate::objects::interface::{
        InterfaceObject, PropertyAccess, PropertyError, PropertyReadRequest, PropertyWriteRequest, pid,
    };
    use zweidraehte_proto::dpt::*;

    define_interface_object! {
        /// Test device object
        pub struct TestDeviceObject: InterfaceObjectType::Device {
            pid::SERIAL_NUMBER => serial_number: PDT_Generic06, ReadWrite;
            pid::MANUFACTURER_ID => manufacturer_id: PDT_UnsignedInt, ReadOnly
                = PDT_UnsignedInt::with_value(0xBEEF)
        }
    }

    #[test]
    fn test_object_creation() {
        let obj = TestDeviceObject::new();
        assert_eq!(obj.object_type(), InterfaceObjectType::Device);
        assert_eq!(obj.property_count(), 3); // OBJECT_TYPE + 2 properties
    }

    #[test]
    fn test_property_descriptors() {
        let obj = TestDeviceObject::new();

        // Index 0 should be OBJECT_TYPE
        let desc = obj.property_descriptor_by_index(0).unwrap();
        assert_eq!(desc.pid, pid::OBJECT_TYPE);
        assert!(matches!(desc.access, PropertyAccess::ReadOnly));

        // Index 1 should be SERIAL_NUMBER
        let desc = obj.property_descriptor_by_index(1).unwrap();
        assert_eq!(desc.pid, pid::SERIAL_NUMBER);
        assert!(matches!(desc.access, PropertyAccess::ReadWrite));

        // Index 2 should be MANUFACTURER_ID
        let desc = obj.property_descriptor_by_index(2).unwrap();
        assert_eq!(desc.pid, pid::MANUFACTURER_ID);
        assert!(matches!(desc.access, PropertyAccess::ReadOnly));

        // Out of range
        assert!(obj.property_descriptor_by_index(3).is_none());
    }

    #[test]
    fn test_read_object_type() {
        let obj = TestDeviceObject::new();
        let mut buf = [0u8; 4];

        let req = PropertyReadRequest { pid: pid::OBJECT_TYPE, start_idx: 1, count: 1 };
        let len = obj.read_property(req, &mut buf).unwrap();
        assert_eq!(len, 2);
        // Device = 0x0000
        assert_eq!(&buf[0..2], &[0x00, 0x00]);
    }

    #[test]
    fn test_read_write_property() {
        let mut obj = TestDeviceObject::new();

        // Write serial number
        let req =
            PropertyWriteRequest { pid: pid::SERIAL_NUMBER, start_idx: 1, data: &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06] };
        obj.write_property(req).unwrap();

        // Read it back
        let mut buf = [0u8; 8];
        let req = PropertyReadRequest { pid: pid::SERIAL_NUMBER, start_idx: 1, count: 1 };
        let len = obj.read_property(req, &mut buf).unwrap();
        assert_eq!(len, 6);
        assert_eq!(&buf[0..6], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn test_read_only_write_fails() {
        let mut obj = TestDeviceObject::new();

        // Try to write read-only property
        let req = PropertyWriteRequest { pid: pid::MANUFACTURER_ID, start_idx: 1, data: &[0x12, 0x34] };
        assert_eq!(obj.write_property(req), Err(PropertyError::WriteNotAllowed));

        // Object type should also be read-only
        let req = PropertyWriteRequest { pid: pid::OBJECT_TYPE, start_idx: 1, data: &[0x00, 0x01] };
        assert_eq!(obj.write_property(req), Err(PropertyError::WriteNotAllowed));
    }

    #[test]
    fn test_default_value() {
        let obj = TestDeviceObject::new();
        let mut buf = [0u8; 4];

        let req = PropertyReadRequest { pid: pid::MANUFACTURER_ID, start_idx: 1, count: 1 };
        let len = obj.read_property(req, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0xBE, 0xEF]);
    }

    #[test]
    fn test_direct_field_access() {
        let mut obj = TestDeviceObject::new();

        // Direct field access for application code
        obj.serial_number.set_value([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let value = obj.serial_number.value();
        assert_eq!(value, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    // ====================================================================
    // Array property tests
    // ====================================================================

    use core::cell::Cell;

    /// Mock state for testing state_rw_array properties.
    struct MockArrayState {
        name: Cell<[u8; 8]>,
        name_len: Cell<usize>,
    }

    impl MockArrayState {
        fn new() -> Self {
            Self { name: Cell::new([0; 8]), name_len: Cell::new(0) }
        }

        fn name(&self) -> [u8; 8] {
            self.name.get()
        }

        fn name_len(&self) -> usize {
            self.name_len.get()
        }

        fn set_name(&self, data: &[u8]) {
            let mut buf = [0u8; 8];
            let len = data.len().min(8);
            buf[..len].copy_from_slice(&data[..len]);
            self.name.set(buf);
            self.name_len.set(len);
        }
    }

    /// Dummy trait to satisfy the macro's state bound.
    trait HasName {
        fn name(&self) -> [u8; 8];
        fn name_len(&self) -> usize;
        fn set_name(&self, data: &[u8]);
    }

    impl HasName for MockArrayState {
        fn name(&self) -> [u8; 8] {
            self.name()
        }
        fn name_len(&self) -> usize {
            self.name_len()
        }
        fn set_name(&self, data: &[u8]) {
            self.set_name(data)
        }
    }

    // PID 200 is unused — suitable for testing.
    const TEST_ARRAY_PID: u8 = 200;

    define_interface_object! {
        /// Test object with an array property.
        pub struct TestArrayObject<'a, S: HasName>: InterfaceObjectType::Device
            with state: &'a S
        {
        }
        state_rw_array {
            TEST_ARRAY_PID => name: PDT_UnsignedChar[8]
        }
    }

    #[test]
    fn test_array_element_count_query() {
        let state = MockArrayState::new();
        state.set_name(b"Hello");
        let obj = TestArrayObject::new(&state);

        let mut buf = [0u8; 4];
        let req = PropertyReadRequest { pid: TEST_ARRAY_PID, start_idx: 0, count: 1 };
        let len = obj.read_property(req, &mut buf).unwrap();
        assert_eq!(len, 2);
        // Element count = 5 ("Hello")
        assert_eq!(&buf[..2], &[0x00, 0x05]);
    }

    #[test]
    fn test_array_read_elements() {
        let state = MockArrayState::new();
        state.set_name(b"Hello");
        let obj = TestArrayObject::new(&state);

        // Read all 5 elements starting at index 1
        let mut buf = [0u8; 8];
        let req = PropertyReadRequest { pid: TEST_ARRAY_PID, start_idx: 1, count: 5 };
        let len = obj.read_property(req, &mut buf).unwrap();
        assert_eq!(len, 5);
        assert_eq!(&buf[..5], b"Hello");
    }

    #[test]
    fn test_array_read_partial() {
        let state = MockArrayState::new();
        state.set_name(b"Hello");
        let obj = TestArrayObject::new(&state);

        // Read 2 elements starting at index 3 (0-based offset 2 → "ll")
        let mut buf = [0u8; 4];
        let req = PropertyReadRequest { pid: TEST_ARRAY_PID, start_idx: 3, count: 2 };
        let len = obj.read_property(req, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[..2], b"ll");
    }

    #[test]
    fn test_array_read_out_of_bounds() {
        let state = MockArrayState::new();
        state.set_name(b"Hi");
        let obj = TestArrayObject::new(&state);

        // start_idx=3 is past the 2-element content
        let mut buf = [0u8; 4];
        let req = PropertyReadRequest { pid: TEST_ARRAY_PID, start_idx: 3, count: 1 };
        assert_eq!(obj.read_property(req, &mut buf), Err(PropertyError::InvalidStartIndex));
    }

    #[test]
    fn test_array_write() {
        let state = MockArrayState::new();
        let mut obj = TestArrayObject::new(&state);

        let req = PropertyWriteRequest { pid: TEST_ARRAY_PID, start_idx: 1, data: b"World" };
        obj.write_property(req).unwrap();

        assert_eq!(state.name_len(), 5);
        assert_eq!(&state.name()[..5], b"World");
    }

    #[test]
    fn test_array_property_descriptor() {
        let state = MockArrayState::new();
        let obj = TestArrayObject::new(&state);

        // OBJECT_TYPE at index 0, array property at index 1
        assert_eq!(obj.property_count(), 2);

        let desc = obj.property_descriptor_by_id(TEST_ARRAY_PID).unwrap();
        assert_eq!(desc.0, 1); // index
        assert_eq!(desc.1.pid, TEST_ARRAY_PID);
        assert_eq!(desc.1.max_elements, 8);
        assert!(matches!(desc.1.access, PropertyAccess::ReadWrite));
    }

    #[test]
    fn test_array_property_element_count() {
        let state = MockArrayState::new();
        state.set_name(b"Test");
        let obj = TestArrayObject::new(&state);

        assert_eq!(obj.property_element_count(TEST_ARRAY_PID).unwrap(), 4);
    }

    #[test]
    fn test_array_write_partial() {
        let state = MockArrayState::new();
        state.set_name(b"Hello");
        let mut obj = TestArrayObject::new(&state);

        // Overwrite bytes at positions 2-3 (start_idx=3, 1-based)
        let req = PropertyWriteRequest { pid: TEST_ARRAY_PID, start_idx: 3, data: b"LL" };
        obj.write_property(req).unwrap();

        assert_eq!(state.name_len(), 5);
        assert_eq!(&state.name()[..5], b"HeLLo");
    }

    #[test]
    fn test_array_write_extends_length() {
        let state = MockArrayState::new();
        state.set_name(b"Hi");
        let mut obj = TestArrayObject::new(&state);

        // Write at start_idx=3 (1-based), extending beyond current length
        let req = PropertyWriteRequest { pid: TEST_ARRAY_PID, start_idx: 3, data: b"!" };
        obj.write_property(req).unwrap();

        // Length should extend to 3 (positions 0,1,2 now occupied)
        assert_eq!(state.name_len(), 3);
        assert_eq!(&state.name()[..3], b"Hi!");
    }

    #[test]
    fn test_array_write_start_idx_zero_rejected() {
        let state = MockArrayState::new();
        let mut obj = TestArrayObject::new(&state);

        let req = PropertyWriteRequest { pid: TEST_ARRAY_PID, start_idx: 0, data: b"X" };
        assert_eq!(obj.write_property(req), Err(PropertyError::InvalidStartIndex));
    }
}
