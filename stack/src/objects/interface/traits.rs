//! Interface Object traits
//!
//! These traits define the interface between concrete object implementations
//! and the stack's management layer.

use core::net::Ipv4Addr;

use super::{PropertyDescriptionResponse, PropertyDescriptor, PropertyError};
use crate::AccessContext;
use crate::dpt::{
    InterfaceObjectType, PDT_Bitset8, PDT_Bitset16, PDT_Generic06, PDT_UnsignedChar, PDT_UnsignedInt, PDT_UnsignedLong,
};

// ============================================================================
// Write Response
// ============================================================================

/// Maximum size for transformed write response data.
///
/// This is sized for the largest transformed response (LOAD_STATE_CONTROL returns 1 byte).
/// If larger responses are needed in the future, increase this value.
pub const MAX_WRITE_RESPONSE_DATA: usize = 4;

/// Response from a property write operation.
///
/// Most property writes simply echo the written data back. However, some special
/// properties (like `LOAD_STATE_CONTROL` and `RUN_STATE_CONTROL`) transform the
/// input and return different data (e.g., the resulting state machine state).
///
/// This enum avoids the need for a separate response buffer by allowing the
/// response to either echo the input or provide inline transformed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteResponse {
    /// Echo the input data back (the common case for most properties).
    /// The caller should use the original write data as the response.
    Echo,

    /// Return transformed data inline.
    /// Used by properties like `LOAD_STATE_CONTROL` that transform the input
    /// and return the resulting state.
    Data(heapless::Vec<u8, MAX_WRITE_RESPONSE_DATA>),
}

impl WriteResponse {
    /// Create a new `WriteResponse::Data` from a slice.
    ///
    /// # Panics
    /// Panics if the slice is longer than `MAX_WRITE_RESPONSE_DATA`.
    #[inline]
    pub fn data(slice: &[u8]) -> Self {
        WriteResponse::Data(heapless::Vec::from_slice(slice).expect("Write response data too large"))
    }

    /// Create a `WriteResponse::Data` containing a single byte.
    #[inline]
    pub fn byte(b: u8) -> Self {
        let mut v = heapless::Vec::new();
        v.push(b).unwrap();
        WriteResponse::Data(v)
    }

    /// Get the response data as a slice.
    ///
    /// For `Echo`, this returns `None` - the caller should use the original input data.
    /// For `Data`, this returns `Some(&[u8])` with the transformed data.
    #[inline]
    pub fn as_slice(&self) -> Option<&[u8]> {
        match self {
            WriteResponse::Echo => None,
            WriteResponse::Data(v) => Some(v.as_slice()),
        }
    }
}

// ============================================================================
// State Property Value Conversion
// ============================================================================

/// Trait for converting between state getter return values and byte representations.
///
/// This trait is used by the shorthand macro syntax to automatically convert
/// between the native type returned by a state getter (e.g., `u8`, `Ipv4Addr`)
/// and the byte representation stored in the property.
///
/// The trait is parameterized by the PDT type (e.g., `PDT_UnsignedChar`),
/// which determines the wire format.
///
/// # Example
///
/// For `PDT_UnsignedChar`, the value type is `u8`:
/// - `to_bytes(&value)` returns `[u8; 1]`
/// - `from_bytes(data)` parses a single byte into `u8`
///
/// For `PDT_UnsignedLong`, the value type can be `u32` or `Ipv4Addr`:
/// - `to_bytes(&value)` returns `[u8; 4]` in big-endian
/// - `from_bytes(data)` parses 4 bytes into the value type
pub trait StatePropertyValue {
    /// The native value type (e.g., `u8`, `u16`, `u32`, `Ipv4Addr`, `[u8; 6]`)
    type Value;

    /// The byte array type for this property (e.g., `[u8; 1]`, `[u8; 4]`)
    type Bytes: AsRef<[u8]>;

    /// Convert a native value to bytes
    fn to_bytes(value: &Self::Value) -> Self::Bytes;

    /// Convert bytes to a native value
    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError>;
}

// PDT_UnsignedChar: u8 <-> 1 byte
impl StatePropertyValue for PDT_UnsignedChar {
    type Value = u8;
    type Bytes = [u8; 1];

    fn to_bytes(value: &Self::Value) -> Self::Bytes {
        [*value]
    }

    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
        if data.is_empty() {
            return Err(PropertyError::BufferTooSmall);
        }
        Ok(data[0])
    }
}

// PDT_UnsignedInt: u16 <-> 2 bytes (big-endian)
impl StatePropertyValue for PDT_UnsignedInt {
    type Value = u16;
    type Bytes = [u8; 2];

    fn to_bytes(value: &Self::Value) -> Self::Bytes {
        value.to_be_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
        if data.len() < 2 {
            return Err(PropertyError::BufferTooSmall);
        }
        Ok(u16::from_be_bytes([data[0], data[1]]))
    }
}

// PDT_UnsignedLong: u32 <-> 4 bytes (big-endian)
impl StatePropertyValue for PDT_UnsignedLong {
    type Value = u32;
    type Bytes = [u8; 4];

    fn to_bytes(value: &Self::Value) -> Self::Bytes {
        value.to_be_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
        if data.len() < 4 {
            return Err(PropertyError::BufferTooSmall);
        }
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }
}

// PDT_Bitset8: u8 <-> 1 byte
impl StatePropertyValue for PDT_Bitset8 {
    type Value = u8;
    type Bytes = [u8; 1];

    fn to_bytes(value: &Self::Value) -> Self::Bytes {
        [*value]
    }

    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
        if data.is_empty() {
            return Err(PropertyError::BufferTooSmall);
        }
        Ok(data[0])
    }
}

// PDT_Bitset16: u16 <-> 2 bytes (big-endian)
impl StatePropertyValue for PDT_Bitset16 {
    type Value = u16;
    type Bytes = [u8; 2];

    fn to_bytes(value: &Self::Value) -> Self::Bytes {
        value.to_be_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
        if data.len() < 2 {
            return Err(PropertyError::BufferTooSmall);
        }
        Ok(u16::from_be_bytes([data[0], data[1]]))
    }
}

// PDT_Generic06: [u8; 6] <-> 6 bytes (e.g., MAC address)
impl StatePropertyValue for PDT_Generic06 {
    type Value = [u8; 6];
    type Bytes = [u8; 6];

    fn to_bytes(value: &Self::Value) -> Self::Bytes {
        *value
    }

    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
        if data.len() < 6 {
            return Err(PropertyError::BufferTooSmall);
        }
        let mut arr = [0u8; 6];
        arr.copy_from_slice(&data[..6]);
        Ok(arr)
    }
}

// ============================================================================
// Ipv4 Wrapper for PDT_UnsignedLong
// ============================================================================

/// Wrapper type to use Ipv4Addr with PDT_UnsignedLong in the shorthand syntax.
///
/// Since a single PDT type can only have one `StatePropertyValue` implementation,
/// and `PDT_UnsignedLong` uses `u32` by default, we provide this wrapper for
/// properties that return `Ipv4Addr`.
///
/// # Usage in macro
///
/// ```rust,ignore
/// state_ro {
///     pid::CURRENT_IP_ADDRESS => current_ip_address: Ipv4Property
/// }
/// ```
///
/// The state getter should return `Ipv4Addr`, and this wrapper handles the
/// conversion to/from `u32` wire format.
pub struct Ipv4Property;

// Ipv4Property uses the same wire format as PDT_UnsignedLong (4 bytes, ID 9)
impl const crate::dpt::PropertyDataDefinition for Ipv4Property {
    const SIZE: usize = 4;
    const ID: u8 = 9; // PDT_UnsignedLong
}

impl StatePropertyValue for Ipv4Property {
    type Value = Ipv4Addr;
    type Bytes = [u8; 4];

    fn to_bytes(value: &Self::Value) -> Self::Bytes {
        u32::from(*value).to_be_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
        if data.len() < 4 {
            return Err(PropertyError::BufferTooSmall);
        }
        let raw = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        Ok(Ipv4Addr::from(raw))
    }
}

// ============================================================================
// Property Service Handler
// ============================================================================

/// Trait for handling property service requests
///
/// This trait provides the interface needed by ApplicationLayer to handle
/// management protocol requests. Interface object containers implement this
/// trait directly, dispatching requests to the appropriate object based on
/// the object index.
///
/// # Example
///
/// ```rust,ignore
/// impl PropertyServiceHandler for MyInterfaceObjects {
///     fn object_count(&self) -> u16 {
///         3 // Device, AddressTable, ApplicationProgram
///     }
///
///     fn property_value_read(
///         &self,
///         object_idx: u16,
///         prop_id: u8,
///         start_idx: u16,
///         count: u16,
///         buf: &mut [u8],
///     ) -> Result<usize, PropertyError> {
///         match object_idx {
///             0 => self.device.borrow().read_property(prop_id, start_idx, count, buf),
///             1 => self.addr_table.borrow().read_property(prop_id, start_idx, count, buf),
///             2 => self.app_program.borrow().read_property(prop_id, start_idx, count, buf),
///             _ => Err(PropertyError::InvalidObjectIndex),
///         }
///     }
///     // ... other methods
/// }
/// ```
pub trait PropertyServiceHandler {
    /// Get the number of interface objects
    fn object_count(&self) -> u16;

    /// Handle A_PropertyDescription_Read request
    ///
    /// Returns property metadata including type, max elements, and access rights.
    ///
    /// # Arguments
    /// * `object_idx` - Object index (0-based)
    /// * `prop_id` - Property ID to search for (0 = search by prop_idx instead)
    /// * `prop_idx` - Property index to search for (only used if prop_id == 0)
    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError>;

    /// Handle A_PropertyValue_Read request
    ///
    /// Reads property data into the provided buffer.
    ///
    /// # Arguments
    /// * `object_idx` - Object index (0-based)
    /// * `prop_id` - Property ID to read
    /// * `start_idx` - 1-based start index for array properties
    /// * `count` - Number of elements to read
    /// * `buf` - Buffer to write data into
    /// * `ctx` - Caller's access context
    ///
    /// # Returns
    /// Number of bytes written or error (including `AccessDenied` if insufficient access)
    fn property_value_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
        ctx: AccessContext,
    ) -> Result<usize, PropertyError>;

    /// Handle A_PropertyValue_Write request
    ///
    /// Writes data to a property.
    ///
    /// # Arguments
    /// * `object_idx` - Object index (0-based)
    /// * `prop_id` - Property ID to write
    /// * `start_idx` - 1-based start index for array properties
    /// * `data` - Data to write
    /// * `ctx` - Caller's access context
    ///
    /// # Returns
    /// * `Ok(WriteResponse::Echo)` - The write succeeded; response should echo the input data
    /// * `Ok(WriteResponse::Data(&[u8]))` - The write succeeded; response is transformed data
    /// Returns `AccessDenied` if insufficient access level.
    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        data: &[u8],
        ctx: AccessContext,
    ) -> Result<WriteResponse, PropertyError>;
}

// ============================================================================
// Interface Object
// ============================================================================

/// Core trait for Interface Objects
///
/// This trait is implemented by all interface objects and provides the
/// dynamic interface used by the stack's management layer. The stack
/// works with `&dyn InterfaceObject` to handle any object type uniformly.
///
/// # Implementation
///
/// Objects can implement this trait manually or use the `define_interface_object!`
/// macro for common cases. Table-based objects (Address Table, Association Table, etc.)
/// typically wrap existing table implementations.
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte::objects::interface::*;
/// use zweidraehte::dpt::InterfaceObjectType;
///
/// struct MyDeviceObject {
///     serial_number: PDT_Generic06,
///     manufacturer_id: PDT_UnsignedInt,
/// }
///
/// impl InterfaceObject for MyDeviceObject {
///     fn object_type(&self) -> InterfaceObjectType {
///         InterfaceObjectType::Device
///     }
///
///     fn property_count(&self) -> u16 {
///         3 // OBJECT_TYPE + serial_number + manufacturer_id
///     }
///
///     // ... other methods
/// }
/// ```
pub trait InterfaceObject {
    /// Get the object type identifier
    fn object_type(&self) -> InterfaceObjectType;

    /// Get the total number of properties in this object
    ///
    /// This includes the implicit OBJECT_TYPE property (PID 1).
    fn property_count(&self) -> u16;

    /// Get property descriptor by 0-based property index
    ///
    /// Property index 0 should always return the OBJECT_TYPE property.
    /// Returns `None` if the index is out of range.
    fn property_descriptor_by_index(&self, prop_idx: u16) -> Option<PropertyDescriptor>;

    /// Get property descriptor and index by Property ID (PID)
    ///
    /// Returns `Some((prop_idx, descriptor))` if found, `None` otherwise.
    fn property_descriptor_by_id(&self, pid: u8) -> Option<(u16, PropertyDescriptor)>;

    /// Read property value
    ///
    /// # Arguments
    /// * `pid` - Property ID to read
    /// * `start_idx` - 1-based start index for array properties (use 1 for single values)
    /// * `count` - Number of elements to read (use 1 for single values)
    /// * `buf` - Buffer to write the property data into
    ///
    /// # Returns
    /// * `Ok(bytes_written)` - Number of bytes written to buffer
    /// * `Err(PropertyError)` - If the read fails
    fn read_property(&self, pid: u8, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError>;

    /// Write property value
    ///
    /// # Arguments
    /// * `pid` - Property ID to write
    /// * `start_idx` - 1-based start index for array properties (use 1 for single values)
    /// * `data` - Data to write
    ///
    /// # Returns
    /// * `Ok(WriteResponse::Echo)` - The write succeeded; response should echo the input data
    /// * `Ok(WriteResponse::Data(&[u8]))` - The write succeeded; response is transformed data
    ///   (e.g., LOAD_STATE_CONTROL returns the resulting state, not the command)
    /// * `Err(PropertyError)` - If the write fails
    fn write_property(&mut self, pid: u8, start_idx: u16, data: &[u8]) -> Result<WriteResponse, PropertyError>;

    /// Get current element count for an array property
    ///
    /// For single-value properties, this returns 1.
    /// For array properties, returns the current number of elements.
    fn property_element_count(&self, pid: u8) -> Result<u16, PropertyError>;

    /// Handle property description request
    ///
    /// This is a convenience method that handles the A_PropertyDescription_Read logic.
    /// If `prop_id` is non-zero, searches by PID. Otherwise, searches by `prop_idx`.
    fn property_description(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        let (idx, desc) = if prop_id != 0 {
            // Search by property ID
            self.property_descriptor_by_id(prop_id).ok_or(PropertyError::InvalidPropertyId)?
        } else {
            // Search by property index
            let desc = self.property_descriptor_by_index(prop_idx as u16).ok_or(PropertyError::InvalidPropertyIndex)?;
            (prop_idx as u16, desc)
        };

        Ok(PropertyDescriptionResponse::from_descriptor(object_idx, idx as u8, &desc))
    }
}

/// Marker trait for objects that can be loaded/unloaded
///
/// This applies to table objects (Address Table, Association Table, etc.)
/// that have a Load State Machine controlled via PID_LOAD_STATE_CONTROL.
pub trait LoadableInterfaceObject: InterfaceObject {
    /// Get the current load state
    fn load_state(&self) -> super::super::tables::LoadState;

    /// Process a load state control command
    fn process_load_control(&mut self, data: &[u8]) -> Result<(), PropertyError>;
}

/// Context trait for accessing interface objects from within the stack.
///
/// This trait is implemented by types that have access to the interface
/// objects container. It's used by management layer handlers to read/write
/// properties.
pub trait InterfaceObjectsContext {
    /// The type of interface objects container
    type Objects;

    /// Get a reference to the interface objects container
    fn interface_objects(&self) -> &Self::Objects;
}
/// Implement PropertyServiceHandler for () (empty container)
///
/// This allows using `()` as interface objects when no interface objects are needed.
/// All property requests return "no objects".
impl PropertyServiceHandler for () {
    fn object_count(&self) -> u16 {
        0
    }

    fn property_description_read(
        &self,
        _object_idx: u16,
        _prop_id: u8,
        _prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }

    fn property_value_read(
        &self,
        _object_idx: u16,
        _prop_id: u8,
        _start_idx: u16,
        _count: u16,
        _buf: &mut [u8],
        _ctx: AccessContext,
    ) -> Result<usize, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }

    fn property_value_write(
        &self,
        _object_idx: u16,
        _prop_id: u8,
        _start_idx: u16,
        _data: &[u8],
        _ctx: AccessContext,
    ) -> Result<WriteResponse, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }
}

/// Implement HasDeviceObject for () (empty container) for testing purposes
impl HasDeviceObject for () {
    fn device_control(&self) -> DeviceControl {
        DeviceControl::new()
    }

    fn set_device_control(&self, _value: DeviceControl) {}

    fn programming_mode(&self) -> ProgrammingMode {
        ProgrammingMode::new()
    }

    fn set_programming_mode(&self, _value: ProgrammingMode) {}

    fn routing_count(&self) -> RoutingCount {
        RoutingCount::new()
    }

    fn set_routing_count(&self, _value: RoutingCount) {}
}

// ============================================================================
// Tuple-Based Interface Object Composition
// ============================================================================
//
// These implementations enable composing interface objects from multiple
// parts using tuples. For example, a KNX/IP device can be:
//   (SystemBObjects, IpObjects)
// And a router could be:
//   (SystemBObjects, IpObjects, RouterObjects)
//
// Each part handles its own object indices, and the tuple impl routes
// requests to the appropriate part based on the cumulative object count.

/// Implement PropertyServiceHandler for 2-tuples (Base, Extension).
///
/// This enables composing interface objects from parts. The base handles
/// objects 0..base.object_count(), and the extension handles the rest
/// with indices offset by the base count.
impl<A, B> PropertyServiceHandler for (A, B)
where
    A: PropertyServiceHandler,
    B: PropertyServiceHandler,
{
    fn object_count(&self) -> u16 {
        self.0.object_count() + self.1.object_count()
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        let base_count = self.0.object_count();
        if object_idx < base_count {
            self.0.property_description_read(object_idx, prop_id, prop_idx)
        } else {
            // Delegate to extension with local index, then restore global index in response
            let mut response = self.1.property_description_read(object_idx - base_count, prop_id, prop_idx)?;
            response.object_idx = object_idx;
            Ok(response)
        }
    }

    fn property_value_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
        ctx: AccessContext,
    ) -> Result<usize, PropertyError> {
        let base_count = self.0.object_count();
        if object_idx < base_count {
            self.0.property_value_read(object_idx, prop_id, start_idx, count, buf, ctx)
        } else {
            self.1.property_value_read(object_idx - base_count, prop_id, start_idx, count, buf, ctx)
        }
    }

    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        data: &[u8],
        ctx: AccessContext,
    ) -> Result<WriteResponse, PropertyError> {
        let base_count = self.0.object_count();
        if object_idx < base_count {
            self.0.property_value_write(object_idx, prop_id, start_idx, data, ctx)
        } else {
            self.1.property_value_write(object_idx - base_count, prop_id, start_idx, data, ctx)
        }
    }
}

/// Implement HasDeviceObject for 2-tuples by delegating to the first element.
///
/// The DeviceObject is always in the base (first element) of the tuple,
/// so we delegate all device property access to it.
impl<A, B> HasDeviceObject for (A, B)
where
    A: HasDeviceObject,
{
    fn device_control(&self) -> DeviceControl {
        self.0.device_control()
    }

    fn set_device_control(&self, value: DeviceControl) {
        self.0.set_device_control(value);
    }

    fn programming_mode(&self) -> ProgrammingMode {
        self.0.programming_mode()
    }

    fn set_programming_mode(&self, value: ProgrammingMode) {
        self.0.set_programming_mode(value);
    }

    fn routing_count(&self) -> RoutingCount {
        self.0.routing_count()
    }

    fn set_routing_count(&self, value: RoutingCount) {
        self.0.set_routing_count(value);
    }
}

// ============================================================================
// Typed Property Access Traits
// ============================================================================
//
// These traits provide type-safe access to interface object properties
// without going through the PropertyServiceHandler byte-buffer protocol.
// They are used by stack layers that need direct access to specific properties.

use crate::dpt::{DeviceControl, ProgrammingMode, RoutingCount};

/// Trait for types that provide a routing count.
///
/// The routing count (hop count) determines how many routers a message
/// can pass through. Value 0-7, default is 6 per KNX specification.
pub trait HasRoutingCount {
    /// Get the routing count.
    fn routing_count(&self) -> u8;
}

/// Trait for containers that provide access to DeviceObject properties.
///
/// This trait enables type-safe access to the DeviceObject's semantic properties
/// (like `DeviceControl`, `ProgrammingMode`, `RoutingCount`) without going through
/// the `PropertyServiceHandler` byte-buffer protocol.
///
/// # Usage
///
/// Stack layers that need access to device properties can require this trait:
///
/// ```rust,ignore
/// impl<D: StackDefinition> ApplicationLayer<D>
/// where
///     D::InterfaceObjects<'static>: HasDeviceObject,
/// {
///     fn handle_memory_write(&mut self, ...) {
///         // Type-safe, ergonomic access to verify mode
///         if self.interface_objects.device_control().verify_mode() {
///             // Send verification response
///         }
///     }
/// }
/// ```
pub trait HasDeviceObject {
    /// Get the DeviceControl property (PID 14).
    ///
    /// Returns the device control flags including verify mode and safe state.
    fn device_control(&self) -> DeviceControl;

    /// Set the DeviceControl property (PID 14).
    fn set_device_control(&self, value: DeviceControl);

    /// Get the ProgrammingMode property (PID 54).
    ///
    /// Returns whether the device is in programming mode.
    fn programming_mode(&self) -> ProgrammingMode;

    /// Set the ProgrammingMode property (PID 54).
    fn set_programming_mode(&self, value: ProgrammingMode);

    /// Get the RoutingCount property (PID 51).
    ///
    /// Returns the hop count for outgoing messages.
    fn routing_count(&self) -> RoutingCount;

    /// Set the RoutingCount property (PID 51).
    fn set_routing_count(&self, value: RoutingCount);

    // ========================================================================
    // Convenience methods with direct types
    // ========================================================================

    /// Check if verify mode is enabled.
    ///
    /// When verify mode is enabled, the device sends Memory_Response
    /// after Memory_Write to confirm the written data.
    #[inline]
    fn verify_mode(&self) -> bool {
        self.device_control().verify_mode()
    }

    /// Check if programming mode is enabled.
    ///
    /// When programming mode is active, the device responds to broadcast
    /// address programming requests.
    #[inline]
    fn is_programming_mode(&self) -> bool {
        self.programming_mode().enabled()
    }

    /// Set the user application stopped flag in DeviceControl.
    ///
    /// This should be called when the run state machine transitions:
    /// - Set to `true` when application stops (RUNNING → any other state)
    /// - Set to `false` when application starts (any state → RUNNING)
    ///
    /// This corresponds to bit 0 of PID_DEVICE_CONTROL.
    #[inline]
    fn set_user_stopped(&self, stopped: bool) {
        let mut dc = self.device_control();
        dc.set_user_stopped(stopped);
        self.set_device_control(dc);
    }

    /// Set the individual address duplication flag in DeviceControl.
    ///
    /// This should be called by the link layer when it receives a message
    /// where the source address matches our own individual address.
    /// This indicates another device on the bus has the same address.
    ///
    /// This corresponds to bit 1 of PID_DEVICE_CONTROL.
    #[inline]
    fn set_address_duplication(&self, detected: bool) {
        let mut dc = self.device_control();
        dc.set_address_duplication(detected);
        self.set_device_control(dc);
    }

    /// Set programming mode enabled/disabled.
    #[inline]
    fn set_programming_mode_enabled(&self, enabled: bool) {
        self.set_programming_mode(ProgrammingMode::from(enabled));
    }

    /// Get the routing count value (0-7).
    #[inline]
    fn routing_count_value(&self) -> u8 {
        self.routing_count().value()
    }

    /// Set the routing count value (clamped to 0-7).
    #[inline]
    fn set_routing_count_value(&self, value: u8) {
        self.set_routing_count(RoutingCount::from_value(value));
    }
}
