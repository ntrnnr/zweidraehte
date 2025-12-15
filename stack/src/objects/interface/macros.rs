//! Macro for defining Interface Objects
//!
//! This module provides the `define_interface_object!` macro for creating
//! type-safe interface object definitions with minimal boilerplate.

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
                            $crate::define_interface_object!(@write_check $access);
                            let target: &mut [u8] = self.$field_name.as_mut();
                            if data.len() > target.len() {
                                return Err($crate::objects::interface::PropertyError::BufferTooSmall);
                            }
                            target[..data.len()].copy_from_slice(data);
                            Ok(())
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

    // Helper: provide default value or call Default::default()
    (@default $pdt:ty) => {
        <$pdt as Default>::default()
    };
    (@default $pdt:ty, $default:expr) => {
        $default
    };

    // Helper: write access check for ReadOnly properties
    (@write_check ReadOnly) => {
        return Err($crate::objects::interface::PropertyError::WriteNotAllowed);
    };
    (@write_check ReadWrite) => {
        // Write allowed
    };
    (@write_check WriteOnly) => {
        // Write allowed
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
