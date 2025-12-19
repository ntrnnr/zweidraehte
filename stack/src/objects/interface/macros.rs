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
//! There are three forms for state-backed properties, from simplest to most flexible:
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
//! ### 3. Full closure syntax (for complex logic)
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
/// use zweidraehte::objects::interface::*;
/// use zweidraehte::dpt::*;
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
                $crate::objects::interface::PropertyDescriptor::new(
                    $crate::objects::interface::pid::OBJECT_TYPE,
                    <$crate::dpt::PDT_UnsignedInt as $crate::dpt::PropertyDataDefinition>::ID,
                    1,
                    $crate::objects::interface::PropertyAccess::ReadOnly,
                ),
                // User-defined properties follow
                $(
                    $crate::objects::interface::PropertyDescriptor::new(
                        $pid_path,
                        <$pdt as $crate::dpt::PropertyDataDefinition>::ID,
                        1,
                        $crate::objects::interface::PropertyAccess::$access,
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
            fn object_type(&self) -> $crate::dpt::InterfaceObjectType {
                $crate::dpt::$obj_type::$obj_variant
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
                pid: u8,
            ) -> Option<(u16, $crate::objects::interface::PropertyDescriptor)> {
                Self::PROPERTY_DESCRIPTORS
                    .iter()
                    .enumerate()
                    .find(|(_, d)| d.pid == pid)
                    .map(|(i, d)| (i as u16, *d))
            }

            fn read_property(
                &self,
                pid: u8,
                start_idx: u16,
                count: u16,
                buf: &mut [u8],
            ) -> Result<usize, $crate::objects::interface::PropertyError> {
                // Validate start_idx and count for single-element properties
                if start_idx != 1 || count != 1 {
                    // For single-element properties, only start_idx=1, count=1 is valid
                    // Array properties would need different handling
                    if start_idx == 0 && count == 0 {
                        // Special case: query current element count
                        // Return 1 for single-element properties
                        if buf.len() >= 2 {
                            buf[0] = 0;
                            buf[1] = 1;
                            return Ok(2);
                        }
                        return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                    }
                    return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
                }

                match pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => {
                        let obj_type: u16 = <$crate::dpt::InterfaceObjectType as Into<u16>>::into($crate::dpt::$obj_type::$obj_variant);
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
                pid: u8,
                start_idx: u16,
                data: &[u8],
            ) -> Result<(), $crate::objects::interface::PropertyError> {
                if start_idx != 1 {
                    return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
                }

                match pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => {
                        Err($crate::objects::interface::PropertyError::WriteNotAllowed)
                    }
                    $(
                        $pid_path => {
                            $crate::define_interface_object!(@write_static $access, self.$field_name, data)
                        }
                    )*
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn property_element_count(
                &self,
                pid: u8,
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
                // Static property: pid => field_name: Type, Access [= default]
                $pid_path:path => $field_name:ident : $pdt:ty , $access:ident
                $(= $default:expr)?
            ),*
        }
        // State-backed properties with closures (for complex logic)
        $(state {
            $(
                $state_pid_path:path => {
                    read : | $read_state:ident | $read_expr:expr ,
                    write : | $write_state:ident , $write_data:ident | $write_expr:expr
                } : $state_pdt:ty , $state_access:ident
            ),*
        })?
        // Shorthand ReadWrite properties: auto getter/setter
        // Syntax: pid::FOO => getter_name: Type
        // Generates: read calls s.getter_name(), write calls s.set_getter_name(value)
        $(state_rw {
            $(
                $rw_pid_path:path => $rw_getter:ident : $rw_pdt:ty
            ),*
        })?
        // Shorthand ReadOnly properties: getter only
        // Syntax: pid::FOO => getter_name: Type
        // Generates: read calls s.getter_name(), write returns WriteNotAllowed
        $(state_ro {
            $(
                $ro_pid_path:path => $ro_getter:ident : $ro_pdt:ty
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
                $crate::objects::interface::PropertyDescriptor::new(
                    $crate::objects::interface::pid::OBJECT_TYPE,
                    <$crate::dpt::PDT_UnsignedInt as $crate::dpt::PropertyDataDefinition>::ID,
                    1,
                    $crate::objects::interface::PropertyAccess::ReadOnly,
                ),
                // Static properties
                $(
                    $crate::objects::interface::PropertyDescriptor::new(
                        $pid_path,
                        <$pdt as $crate::dpt::PropertyDataDefinition>::ID,
                        1,
                        $crate::objects::interface::PropertyAccess::$access,
                    ),
                )*
                // State-backed properties (closure-based)
                $($(
                    $crate::objects::interface::PropertyDescriptor::new(
                        $state_pid_path,
                        <$state_pdt as $crate::dpt::PropertyDataDefinition>::ID,
                        1,
                        $crate::objects::interface::PropertyAccess::$state_access,
                    ),
                )*)?
                // Shorthand ReadWrite properties
                $($(
                    $crate::objects::interface::PropertyDescriptor::new(
                        $rw_pid_path,
                        <$rw_pdt as $crate::dpt::PropertyDataDefinition>::ID,
                        1,
                        $crate::objects::interface::PropertyAccess::ReadWrite,
                    ),
                )*)?
                // Shorthand ReadOnly properties
                $($(
                    $crate::objects::interface::PropertyDescriptor::new(
                        $ro_pid_path,
                        <$ro_pdt as $crate::dpt::PropertyDataDefinition>::ID,
                        1,
                        $crate::objects::interface::PropertyAccess::ReadOnly,
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
            fn object_type(&self) -> $crate::dpt::InterfaceObjectType {
                $crate::dpt::$obj_type::$obj_variant
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
                pid: u8,
            ) -> Option<(u16, $crate::objects::interface::PropertyDescriptor)> {
                Self::PROPERTY_DESCRIPTORS
                    .iter()
                    .enumerate()
                    .find(|(_, d)| d.pid == pid)
                    .map(|(i, d)| (i as u16, *d))
            }

            fn read_property(
                &self,
                pid: u8,
                start_idx: u16,
                count: u16,
                buf: &mut [u8],
            ) -> Result<usize, $crate::objects::interface::PropertyError> {
                // Validate start_idx and count for single-element properties
                if start_idx != 1 || count != 1 {
                    if start_idx == 0 && count == 0 {
                        if buf.len() >= 2 {
                            buf[0] = 0;
                            buf[1] = 1;
                            return Ok(2);
                        }
                        return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                    }
                    return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
                }

                match pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => {
                        let obj_type: u16 = <$crate::dpt::InterfaceObjectType as Into<u16>>::into($crate::dpt::$obj_type::$obj_variant);
                        if buf.len() < 2 {
                            return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                        }
                        buf[0..2].copy_from_slice(&obj_type.to_be_bytes());
                        Ok(2)
                    }
                    // Static properties
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
                    // State-backed properties (closure-based)
                    $($(
                        $state_pid_path => {
                            let $read_state = self.state;
                            let data: &[u8] = &$read_expr;
                            if buf.len() < data.len() {
                                return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                            }
                            buf[..data.len()].copy_from_slice(data);
                            Ok(data.len())
                        }
                    )*)?
                    // Shorthand ReadWrite properties
                    $($(
                        $rw_pid_path => {
                            $crate::define_interface_object!(@read_shorthand self.state, $rw_getter, $rw_pdt, buf)
                        }
                    )*)?
                    // Shorthand ReadOnly properties
                    $($(
                        $ro_pid_path => {
                            $crate::define_interface_object!(@read_shorthand self.state, $ro_getter, $ro_pdt, buf)
                        }
                    )*)?
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn write_property(
                &mut self,
                pid: u8,
                start_idx: u16,
                data: &[u8],
            ) -> Result<(), $crate::objects::interface::PropertyError> {
                if start_idx != 1 {
                    return Err($crate::objects::interface::PropertyError::InvalidStartIndex);
                }

                match pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => {
                        Err($crate::objects::interface::PropertyError::WriteNotAllowed)
                    }
                    // Static properties
                    $(
                        $pid_path => {
                            $crate::define_interface_object!(@write_static $access, self.$field_name, data)
                        }
                    )*
                    // State-backed properties (closure-based)
                    $($(
                        $state_pid_path => {
                            $crate::define_interface_object!(@write_state_property $state_access, self.state, data, $write_state, $write_data, $write_expr)
                        }
                    )*)?
                    // Shorthand ReadWrite properties
                    $($(
                        $rw_pid_path => {
                            $crate::define_interface_object!(@write_shorthand self.state, $rw_getter, $rw_pdt, data)
                        }
                    )*)?
                    // Shorthand ReadOnly properties
                    $($(
                        $ro_pid_path => {
                            Err($crate::objects::interface::PropertyError::WriteNotAllowed)
                        }
                    )*)?
                    _ => Err($crate::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn property_element_count(
                &self,
                pid: u8,
            ) -> Result<u16, $crate::objects::interface::PropertyError> {
                match pid {
                    $crate::objects::interface::pid::OBJECT_TYPE => Ok(1),
                    $($pid_path => Ok(1),)*
                    $($($state_pid_path => Ok(1),)*)?
                    $($($rw_pid_path => Ok(1),)*)?
                    $($($ro_pid_path => Ok(1),)*)?
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
    (@write_static ReadOnly, $target:expr, $data:expr) => {
        Err($crate::objects::interface::PropertyError::WriteNotAllowed)
    };
    (@write_static ReadWrite, $target:expr, $data:expr) => {{
        let target: &mut [u8] = $target.as_mut();
        if $data.len() > target.len() {
            return Err($crate::objects::interface::PropertyError::BufferTooSmall);
        }
        target[..$data.len()].copy_from_slice($data);
        Ok(())
    }};
    (@write_static WriteOnly, $target:expr, $data:expr) => {{
        let target: &mut [u8] = $target.as_mut();
        if $data.len() > target.len() {
            return Err($crate::objects::interface::PropertyError::BufferTooSmall);
        }
        target[..$data.len()].copy_from_slice($data);
        Ok(())
    }};

    // Helper: write state-backed property (handles ReadOnly without generating unreachable code)
    (@write_state_property ReadOnly, $state:expr, $data_in:expr, $write_state:ident, $write_data:ident, $write_expr:expr) => {
        Err($crate::objects::interface::PropertyError::WriteNotAllowed)
    };
    (@write_state_property ReadWrite, $state:expr, $data_in:expr, $write_state:ident, $write_data:ident, $write_expr:expr) => {{
        let $write_state = $state;
        let $write_data = $data_in;
        $write_expr
    }};
    (@write_state_property WriteOnly, $state:expr, $data_in:expr, $write_state:ident, $write_data:ident, $write_expr:expr) => {{
        let $write_state = $state;
        let $write_data = $data_in;
        $write_expr
    }};

    // ========================================================================
    // Shorthand helpers for auto-generated read/write
    // ========================================================================
    // These helpers use the StatePropertyValue trait to convert between
    // property values and their byte representations.

    // Read shorthand: calls state.getter() and converts to bytes via StatePropertyValue
    (@read_shorthand $state:expr, $getter:ident, $pdt:ty, $buf:expr) => {{
        let value = $state.$getter();
        let data = <$pdt as $crate::objects::interface::StatePropertyValue>::to_bytes(&value);
        let data_ref: &[u8] = data.as_ref();
        if $buf.len() < data_ref.len() {
            return Err($crate::objects::interface::PropertyError::BufferTooSmall);
        }
        $buf[..data_ref.len()].copy_from_slice(data_ref);
        Ok(data_ref.len())
    }};

    // Write shorthand: converts bytes to value via StatePropertyValue and calls state.set_getter()
    (@write_shorthand $state:expr, $getter:ident, $pdt:ty, $data:expr) => {{
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
    use super::*;
    use crate::dpt::*;
    use crate::objects::interface::{pid, InterfaceObject, PropertyAccess, PropertyError};

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

        let len = obj
            .read_property(pid::OBJECT_TYPE, 1, 1, &mut buf)
            .unwrap();
        assert_eq!(len, 2);
        // Device = 0x0000
        assert_eq!(&buf[0..2], &[0x00, 0x00]);
    }

    #[test]
    fn test_read_write_property() {
        let mut obj = TestDeviceObject::new();

        // Write serial number
        obj.write_property(pid::SERIAL_NUMBER, 1, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .unwrap();

        // Read it back
        let mut buf = [0u8; 8];
        let len = obj
            .read_property(pid::SERIAL_NUMBER, 1, 1, &mut buf)
            .unwrap();
        assert_eq!(len, 6);
        assert_eq!(&buf[0..6], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn test_read_only_write_fails() {
        let mut obj = TestDeviceObject::new();

        // Try to write read-only property
        let result = obj.write_property(pid::MANUFACTURER_ID, 1, &[0x12, 0x34]);
        assert_eq!(result, Err(PropertyError::WriteNotAllowed));

        // Object type should also be read-only
        let result = obj.write_property(pid::OBJECT_TYPE, 1, &[0x00, 0x01]);
        assert_eq!(result, Err(PropertyError::WriteNotAllowed));
    }

    #[test]
    fn test_default_value() {
        let obj = TestDeviceObject::new();
        let mut buf = [0u8; 4];

        let len = obj
            .read_property(pid::MANUFACTURER_ID, 1, 1, &mut buf)
            .unwrap();
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
}
