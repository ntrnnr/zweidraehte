//! Interface Object traits
//!
//! These traits define the interface between concrete object implementations
//! and the stack's management layer.

use core::net::Ipv4Addr;

use super::{PropertyDescriptionResponse, PropertyDescriptor, PropertyError};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::messages::apdu::go_diagnostics::GoDiagReturnCode;
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_Bitset8, PDT_Bitset16, PDT_Generic06, PDT_UnsignedChar, PDT_UnsignedInt, PDT_UnsignedLong,
};

// ============================================================================
// Inline Property Buffer
// ============================================================================

/// Maximum size for transformed write response data.
///
/// Sized for the largest transformed response (LOAD_STATE_CONTROL returns 1 byte,
/// but we leave room for future use).
pub const MAX_WRITE_RESPONSE_DATA: usize = 4;

/// Fixed-capacity inline buffer for small property data.
///
/// Used in [`WriteResponse`] for transformed write results (e.g.,
/// `LOAD_STATE_CONTROL` returns the resulting state byte). Unlike
/// `heapless::Vec`, this is `Copy` and has no external dependency.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PropertyBuf<const N: usize> {
    buf: [u8; N],
    len: u8,
}

impl<const N: usize> PropertyBuf<N> {
    /// Create from a byte slice.
    ///
    /// # Panics
    /// Panics if `src.len() > N`.
    #[inline]
    pub fn new(src: &[u8]) -> Self {
        assert!(src.len() <= N, "PropertyBuf overflow: {} > {}", src.len(), N);
        let mut buf = [0u8; N];
        buf[..src.len()].copy_from_slice(src);
        Self { buf, len: src.len() as u8 }
    }

    /// Create from a single byte.
    #[inline]
    pub fn from_byte(b: u8) -> Self {
        let mut buf = [0u8; N];
        buf[0] = b;
        Self { buf, len: 1 }
    }

    /// View the stored data as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// Number of bytes stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> AsRef<[u8]> for PropertyBuf<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> core::fmt::Debug for PropertyBuf<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PropertyBuf").field(&self.as_slice()).finish()
    }
}

// ============================================================================
// Write Response
// ============================================================================

/// Response from a property write operation.
///
/// Most property writes simply echo the written data back. However, some special
/// properties (like `LOAD_STATE_CONTROL` and `RUN_STATE_CONTROL`) transform the
/// input and return different data (e.g., the resulting state machine state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteResponse {
    /// Echo the input data back (the common case for most properties).
    /// The caller should use the original write data as the response.
    Echo,

    /// Return transformed data inline.
    /// Used by properties like `LOAD_STATE_CONTROL` that transform the input
    /// and return the resulting state.
    Data(PropertyBuf<MAX_WRITE_RESPONSE_DATA>),
}

impl WriteResponse {
    /// Create a new `WriteResponse::Data` from a slice.
    ///
    /// # Panics
    /// Panics if the slice is longer than `MAX_WRITE_RESPONSE_DATA`.
    #[inline]
    pub fn data(slice: &[u8]) -> Self {
        WriteResponse::Data(PropertyBuf::new(slice))
    }

    /// Create a `WriteResponse::Data` containing a single byte.
    #[inline]
    pub fn byte(b: u8) -> Self {
        WriteResponse::Data(PropertyBuf::from_byte(b))
    }

    /// Get the response data as a slice.
    ///
    /// For `Echo`, this returns `None` — the caller should use the original input data.
    /// For `Data`, this returns `Some(&[u8])` with the transformed data.
    #[inline]
    pub fn as_slice(&self) -> Option<&[u8]> {
        match self {
            WriteResponse::Echo => None,
            WriteResponse::Data(buf) => Some(buf.as_slice()),
        }
    }
}

// ============================================================================
// Property Request Types
// ============================================================================

/// Parameters for a property read at the [`InterfaceObject`] level.
///
/// Bundles `pid`, `start_idx`, and `count` — the parameters that every
/// `read_property` call needs.
#[derive(Debug, Clone, Copy)]
pub struct PropertyReadRequest {
    /// Property ID to read.
    pub pid: u16,
    /// 1-based start index for array properties (0 = query element count).
    pub start_idx: u16,
    /// Number of elements to read.
    pub count: u16,
}

/// Parameters for a property write at the [`InterfaceObject`] level.
///
/// Bundles `pid`, `start_idx`, and the write payload.
#[derive(Debug, Clone, Copy)]
pub struct PropertyWriteRequest<'a> {
    /// Property ID to write.
    pub pid: u16,
    /// 1-based start index for array properties.
    pub start_idx: u16,
    /// Data to write.
    pub data: &'a [u8],
}

/// Full property read request including object routing and access control.
///
/// Used at the [`PropertyServiceHandler`] and `Augment<D>` level
/// where the caller specifies which object to address and under what access
/// context.
#[derive(Debug, Clone, Copy)]
pub struct FullPropertyReadRequest {
    /// Object index (0-based).
    pub object_idx: u16,
    /// Property ID to read.
    pub pid: u16,
    /// 1-based start index for array properties (0 = query element count).
    pub start_idx: u16,
    /// Number of elements to read.
    pub count: u16,
    /// Caller's access context.
    pub ctx: AccessContext,
}

impl FullPropertyReadRequest {
    /// Extract the [`PropertyReadRequest`] portion (without object routing / access).
    #[inline]
    pub fn property_request(&self) -> PropertyReadRequest {
        PropertyReadRequest { pid: self.pid, start_idx: self.start_idx, count: self.count }
    }

    /// Create a copy with a different `object_idx` (used by tuple dispatch
    /// to offset the index before forwarding to a sub-handler).
    #[inline]
    pub fn with_object_idx(&self, object_idx: u16) -> Self {
        Self { object_idx, ..*self }
    }
}

/// Full property write request including object routing and access control.
///
/// Used at the [`PropertyServiceHandler`] and `Augment<D>` level.
#[derive(Debug, Clone, Copy)]
pub struct FullPropertyWriteRequest<'a> {
    /// Object index (0-based).
    pub object_idx: u16,
    /// Property ID to write.
    pub pid: u16,
    /// Number of elements to write (from the wire header).
    pub count: u16,
    /// 1-based start index for array properties.
    pub start_idx: u16,
    /// Data to write.
    pub data: &'a [u8],
    /// Caller's access context.
    pub ctx: AccessContext,
}

impl<'a> FullPropertyWriteRequest<'a> {
    /// Extract the [`PropertyWriteRequest`] portion (without object routing / access).
    #[inline]
    pub fn property_request(&self) -> PropertyWriteRequest<'a> {
        PropertyWriteRequest { pid: self.pid, start_idx: self.start_idx, data: self.data }
    }

    /// Create a copy with a different `object_idx`.
    #[inline]
    pub fn with_object_idx(&self, object_idx: u16) -> Self {
        Self { object_idx, ..*self }
    }
}

// ============================================================================
// Function Property Request / Result Types
// ============================================================================

/// Maximum size for function property response data.
///
/// Sized to fit within a standard APDU. The response data starts at
/// APDU byte 5, so for a 255-byte APDU this leaves ~250 bytes. We use
/// a practical limit matching the property value read handler.
pub const MAX_FUNCTION_PROPERTY_RESPONSE: usize = 64;

/// Request for `A_FunctionPropertyCommand` or `A_FunctionPropertyState_Read`.
///
/// Used at the [`PropertyServiceHandler`] and `Augment<D>` level.
/// The `service_data` is opaque and function-specific — the handler decides
/// what it means.
#[derive(Debug, Clone, Copy)]
pub struct FunctionPropertyRequest<'a> {
    /// Object index (0-based).
    pub object_idx: u16,
    /// Property ID of the function property.
    pub prop_id: u16,
    /// Opaque service data from the request.
    pub service_data: &'a [u8],
    /// Caller's access context.
    pub ctx: AccessContext,
}

impl<'a> FunctionPropertyRequest<'a> {
    /// Create a copy with a different `object_idx` (used by tuple dispatch
    /// to offset the index before forwarding to a sub-handler).
    #[inline]
    pub fn with_object_idx(&self, object_idx: u16) -> Self {
        Self { object_idx, ..*self }
    }
}

/// Result from a function property operation.
///
/// Named `Result` (not `Response`) to avoid collision with the wire-format
/// [`FunctionPropertyResponse`](zweidraehte_proto::messages::apdu::function_property::FunctionPropertyResponse)
/// in the proto crate.
#[derive(Debug, Clone, Copy)]
pub struct FunctionPropertyResult {
    /// Raw return code (0x00 = success).
    ///
    /// Deliberately a `u8` and not one of the return-code enums: a function
    /// property answers from whichever code space its property defines.
    /// Most use the generic
    /// [`PropertyReturnCode`] table, but `PID_OPERATION_MODE` and
    /// `PID_GO_DIAGNOSTICS` answer from the disjoint, numerically
    /// overlapping [`GoDiagReturnCode`] table. Build results through
    /// [`with_code`](Self::with_code) / [`go_diag`](Self::go_diag) rather
    /// than writing the byte directly, so the intended code space is
    /// visible at the call site.
    pub return_code: u8,
    /// Response data (variable length, may be empty).
    pub data: PropertyBuf<MAX_FUNCTION_PROPERTY_RESPONSE>,
}

impl FunctionPropertyResult {
    /// Result carrying a generic property-service return code
    /// (spec 03/03/07 §3.4.5.5).
    pub fn with_code(return_code: PropertyReturnCode, data: &[u8]) -> Self {
        Self { return_code: return_code.into(), data: PropertyBuf::new(data) }
    }

    /// Result carrying a `PID_OPERATION_MODE` / `PID_GO_DIAGNOSTICS`
    /// return code (spec 03/05/01 §4.3.8, §4.8.1).
    pub fn go_diag(return_code: GoDiagReturnCode, data: &[u8]) -> Self {
        Self { return_code: return_code.into(), data: PropertyBuf::new(data) }
    }

    /// Success with no response data.
    pub fn success() -> Self {
        Self::with_code(PropertyReturnCode::Success, &[])
    }

    /// Success with response data.
    pub fn success_with_data(data: &[u8]) -> Self {
        Self::with_code(PropertyReturnCode::Success, data)
    }

    /// Error: function property not supported by this object/property.
    ///
    /// 0x02 is outside both named code spaces; it is the value the stack
    /// has always returned here and conformance expectations pin it.
    pub fn not_supported() -> Self {
        Self { return_code: 0x02, data: PropertyBuf::new(&[]) }
    }

    /// Error: access denied (security policy or access level).
    pub fn access_denied() -> Self {
        Self::with_code(PropertyReturnCode::AccessDenied, &[])
    }

    /// Error: invalid object index.
    ///
    /// 0x05 is outside both named code spaces; see
    /// [`not_supported`](Self::not_supported).
    pub fn invalid_object_index() -> Self {
        Self { return_code: 0x05, data: PropertyBuf::new(&[]) }
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

/// Implement `StatePropertyValue` for integer-backed PDT types that use
/// big-endian byte order. Handles both single-byte (`u8`) and multi-byte
/// (`u16`, `u32`) native types.
macro_rules! impl_state_property_int {
    ($pdt:ty, $native:ty, $size:literal) => {
        impl StatePropertyValue for $pdt {
            type Value = $native;
            type Bytes = [u8; $size];

            fn to_bytes(value: &Self::Value) -> Self::Bytes {
                <$native>::to_be_bytes(*value)
            }

            fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
                let bytes: [u8; $size] =
                    data.get(..$size).and_then(|s| s.try_into().ok()).ok_or(PropertyError::BufferTooSmall)?;
                Ok(<$native>::from_be_bytes(bytes))
            }
        }
    };
}

impl_state_property_int!(PDT_UnsignedChar, u8, 1);
impl_state_property_int!(PDT_UnsignedInt, u16, 2);
impl_state_property_int!(PDT_UnsignedLong, u32, 4);
impl_state_property_int!(PDT_Bitset8, u8, 1);
impl_state_property_int!(PDT_Bitset16, u16, 2);

// PDT_Generic06: [u8; 6] <-> 6 raw bytes (e.g., MAC address, serial number).
// Not integer-backed, so handled separately from the macro above.
impl StatePropertyValue for PDT_Generic06 {
    type Value = [u8; 6];
    type Bytes = [u8; 6];

    fn to_bytes(value: &Self::Value) -> Self::Bytes {
        *value
    }

    fn from_bytes(data: &[u8]) -> Result<Self::Value, PropertyError> {
        data.get(..6).and_then(|s| s.try_into().ok()).ok_or(PropertyError::BufferTooSmall)
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
///     pid::ip::CURRENT_IP_ADDRESS => current_ip_address: Ipv4Property
/// }
/// ```
///
/// The state getter should return `Ipv4Addr`, and this wrapper handles the
/// conversion to/from `u32` wire format.
pub struct Ipv4Property;

// Ipv4Property uses the same wire format as PDT_UnsignedLong (4 bytes, ID 9)
const impl zweidraehte_proto::dpt::PropertyDataDefinition for Ipv4Property {
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

/// Trait for handling property service requests.
///
/// This is the top-level interface used by the application layer and KNX/IP
/// device management to read and write interface object properties. Containers
/// of interface objects implement this trait, dispatching requests to the
/// appropriate object based on `object_idx`.
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
///         req: &FullPropertyReadRequest,
///         buf: &mut [u8],
///     ) -> Result<usize, PropertyError> {
///         match req.object_idx {
///             0 => self.device.borrow().read_property(req.property_request(), buf),
///             1 => self.addr_table.borrow().read_property(req.property_request(), buf),
///             _ => Err(PropertyError::InvalidObjectIndex),
///         }
///     }
///     // ... other methods
/// }
/// ```
pub trait PropertyServiceHandler {
    /// Get the number of interface objects.
    fn object_count(&self) -> u16;

    /// Get the object type for a given index.
    ///
    /// Returns `None` if `object_idx` is out of range.
    fn object_type_at(&self, object_idx: u16) -> Option<InterfaceObjectType>;

    /// Resolve a (object_type, object_instance) pair to a flat object index.
    ///
    /// `object_instance` is 1-based per spec 03_05_01 §4.18.5.2.5:
    /// instance 1 is the first object of that type, instance 2 the
    /// second, etc. The field is 12-bit on the extended services wire
    /// (range `1..=0xFFF`) and 8-bit on the cEMI Local Management
    /// wire; callers from the narrower path widen to `u16` before
    /// calling.
    ///
    /// Returns `None` if no object with that type and instance exists,
    /// or if `object_instance` is 0.
    fn resolve_object_index(&self, object_type: u16, object_instance: u16) -> Option<u16> {
        if object_instance == 0 {
            return None;
        }
        let target_type = InterfaceObjectType::from(object_type);
        let mut instance_count: u16 = 0;

        for idx in 0..self.object_count() {
            if self.object_type_at(idx) == Some(target_type) {
                instance_count += 1;

                if instance_count == object_instance {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Resolve an extended `(object_type, object_instance)` pair to a
    /// flat object index for AN163 extended property services.
    ///
    /// The extended-services wire carries `object_instance` as 12 bits
    /// (spec 03_03_07 §3.4.3.2), so the default delegates straight to
    /// [`resolve_object_index`](Self::resolve_object_index) without narrowing.
    fn resolve_ext_object_index(&self, object_type: u16, object_instance: u16) -> Option<u16> {
        self.resolve_object_index(object_type, object_instance)
    }

    /// Handle A_PropertyDescription_Read request.
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
        prop_id: u16,
        prop_idx: u16,
    ) -> Result<PropertyDescriptionResponse, PropertyError>;

    /// Handle A_PropertyValue_Read request.
    ///
    /// Reads property data into the provided buffer.
    fn property_value_read(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError>;

    /// Handle A_PropertyValue_Write request.
    ///
    /// Writes data to a property. Returns [`WriteResponse::Echo`] on success
    /// (caller echoes the input data) or [`WriteResponse::Data`] when the
    /// property transforms the input (e.g., `LOAD_STATE_CONTROL`).
    fn property_value_write(&self, req: &FullPropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError>;

    /// Handle `A_FunctionPropertyCommand` request.
    ///
    /// Executes a function on a property. The default returns "not supported"
    /// since most interface objects don't implement function properties.
    fn function_property_command(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        let _ = req;
        FunctionPropertyResult::not_supported()
    }

    /// Handle `A_FunctionPropertyState_Read` request.
    ///
    /// Reads the state of a function property. The default returns
    /// "not supported".
    fn function_property_state_read(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        let _ = req;
        FunctionPropertyResult::not_supported()
    }
}

// ============================================================================
// Interface Object Augmentation
// ============================================================================

/// How to look up a property in an augment's `property_description_read`.
///
/// The container translates the raw `(prop_id, prop_idx)` wire fields into
/// this enum before calling the augment, so augments don't need to handle
/// the `prop_id == 0` convention themselves.
#[derive(Debug, Clone, Copy)]
pub enum PropertyLookup {
    /// Look up by Property ID (direct access). `u16` holds the 12-bit
    /// PID from the extended services wire format (spec 03_03_07
    /// §3.4.3.2) as well as 8-bit PIDs from the regular services.
    ByPid(u16),
    /// Look up by augment-local 0-based index (during property scanning).
    ByIndex(u16),
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
/// Objects can implement this trait manually or use the `#[interface_object]`
/// attribute macro for common cases. Table-based objects (Address Table, Association Table, etc.)
/// typically wrap existing table implementations.
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte_device::objects::interface::*;
/// use zweidraehte_proto::dpt::InterfaceObjectType;
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
    /// Get the object type identifier.
    fn object_type(&self) -> InterfaceObjectType;

    /// Get the total number of properties in this object.
    ///
    /// This includes the implicit OBJECT_TYPE property (PID 1).
    fn property_count(&self) -> u16;

    /// Get property descriptor by 0-based property index.
    ///
    /// Property index 0 should always return the OBJECT_TYPE property.
    /// Returns `None` if the index is out of range.
    fn property_descriptor_by_index(&self, prop_idx: u16) -> Option<PropertyDescriptor>;

    /// Get property descriptor and index by Property ID (PID).
    ///
    /// Returns `Some((prop_idx, descriptor))` if found, `None` otherwise.
    fn property_descriptor_by_id(&self, pid: u16) -> Option<(u16, PropertyDescriptor)>;

    /// Read property value into a buffer.
    fn read_property(&self, req: PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError>;

    /// Write property value.
    fn write_property(&mut self, req: PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError>;

    /// Get current element count for an array property.
    ///
    /// For single-value properties, this returns 1.
    /// For array properties, returns the current number of elements.
    fn property_element_count(&self, pid: u16) -> Result<u16, PropertyError>;

    /// Handle property description request.
    ///
    /// This is a convenience method that handles the A_PropertyDescription_Read logic.
    /// If `prop_id` is non-zero, searches by PID. Otherwise, searches by `prop_idx`.
    fn property_description(
        &self,
        object_idx: u16,
        prop_id: u16,
        prop_idx: u16,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        let (idx, desc) = if prop_id != 0 {
            // Search by property ID
            self.property_descriptor_by_id(prop_id).ok_or(PropertyError::InvalidPropertyId)?
        } else {
            // Search by property index
            let desc = self.property_descriptor_by_index(prop_idx).ok_or(PropertyError::InvalidPropertyIndex)?;
            (prop_idx, desc)
        };

        Ok(PropertyDescriptionResponse::from_descriptor(object_idx, idx, &desc))
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

    fn object_type_at(&self, _object_idx: u16) -> Option<InterfaceObjectType> {
        None
    }

    fn property_description_read(
        &self,
        _object_idx: u16,
        _prop_id: u16,
        _prop_idx: u16,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }

    fn property_value_read(&self, _req: &FullPropertyReadRequest, _buf: &mut [u8]) -> Result<usize, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }

    fn property_value_write(&self, _req: &FullPropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }

    fn function_property_command(&self, _req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        FunctionPropertyResult::invalid_object_index()
    }

    fn function_property_state_read(&self, _req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        FunctionPropertyResult::invalid_object_index()
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

    fn object_type_at(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        let base_count = self.0.object_count();
        if object_idx < base_count {
            self.0.object_type_at(object_idx)
        } else {
            self.1.object_type_at(object_idx - base_count)
        }
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u16,
        prop_idx: u16,
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

    fn property_value_read(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let base_count = self.0.object_count();
        if req.object_idx < base_count {
            self.0.property_value_read(req, buf)
        } else {
            self.1.property_value_read(&req.with_object_idx(req.object_idx - base_count), buf)
        }
    }

    fn property_value_write(&self, req: &FullPropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        let base_count = self.0.object_count();
        if req.object_idx < base_count {
            self.0.property_value_write(req)
        } else {
            self.1.property_value_write(&req.with_object_idx(req.object_idx - base_count))
        }
    }

    fn function_property_command(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        let base_count = self.0.object_count();
        if req.object_idx < base_count {
            self.0.function_property_command(req)
        } else {
            self.1.function_property_command(&req.with_object_idx(req.object_idx - base_count))
        }
    }

    fn function_property_state_read(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        let base_count = self.0.object_count();
        if req.object_idx < base_count {
            self.0.function_property_state_read(req)
        } else {
            self.1.function_property_state_read(&req.with_object_idx(req.object_idx - base_count))
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

use zweidraehte_proto::dpt::{DeviceControl, ProgrammingMode, RoutingCount};

/// Trait for types that provide a routing count.
///
/// The routing count (hop count) determines how many routers a message
/// can pass through. Value 0-7, default is 6 per KNX specification.
pub trait HasRoutingCount {
    /// Get the routing count.
    fn routing_count(&self) -> u8;

    /// Set the routing count (clamped to 0-7 by convention).
    fn set_routing_count(&self, value: u8);
}

/// Trait for types that provide a max retry count.
///
/// The max retry count (PID 52) encodes DLL retry parameters for TP1 devices:
/// busy_retry (bits 6-4) and nak_retry (bits 2-0). Default 0x33 (3 busy, 3 NAK).
/// Not applicable for KNX/IP devices.
pub trait HasMaxRetryCount {
    /// Get the max retry count byte.
    fn max_retry_count(&self) -> u8;

    /// Set the max retry count byte.
    fn set_max_retry_count(&self, value: u8);
}

/// Trait for device state that stores a 6-octet RF Domain Address.
///
/// Backs the RF Medium Object's `PID_RF_DOMAIN_ADDRESS` (PID 56, mandatory per
/// KNX 03/05/01 §4.15.8) and feeds the KNX-RF link layer's Domain-Address
/// filtering and frame construction via
/// [`RfDomainAddressContext`](crate::context::RfDomainAddressContext). Distinct
/// from [`HasDomainAddress`], which is medium-generic (4 octets for KNX/IP); the
/// RF Domain Address is always 6 octets.
pub trait HasRfDomainAddress {
    /// Copy the stored 6-octet RF Domain Address into `out`.
    fn rf_domain_address(&self, out: &mut [u8; 6]);

    /// Replace the stored 6-octet RF Domain Address.
    fn set_rf_domain_address(&self, addr: &[u8; 6]);
}

/// Trait for device state that carries the KNX-RF retransmitter role.
///
/// Implemented only by the optional retransmitter wrapper extension
/// (`RfRetransmitterExtension`); its presence on `D::State` is what makes
/// [`RfRetransmitterContext`](crate::context::RfRetransmitterContext)
/// available, which in turn is the compile-time gate for the
/// `RetransmitEnabled` KNX-RF link-layer policy. Backs the RF Medium Object's
/// `PID_RF_RETRANSMITTER` (PID 57, 03/05/01 §4.15.9) and the Device Object's
/// `PID_RF_REPEAT_COUNTER` (PID 74, the optional cascade-depth limit from
/// 03/02/05 §6.1.7.4).
pub trait HasRfRetransmitter {
    /// Whether the device should currently repeat qualifying RF frames.
    ///
    /// Reflects `PID_RF_RETRANSMITTER`; ETS may toggle it at runtime even on a
    /// device built with the retransmitter compiled in.
    fn rf_retransmit_enabled(&self) -> bool;

    /// Replace the runtime retransmitter-enabled flag.
    fn set_rf_retransmit_enabled(&self, value: bool);

    /// The RF Repetition Counter limit (`PID_RF_REPEAT_COUNTER`). A received
    /// frame is repeated only while its RC is `> 0` and `> limit`; the RC is
    /// decremented on each hop (03/02/05 §6.1.7.4). Default 0.
    fn rf_repeat_counter_limit(&self) -> u8;

    /// Replace the RF Repetition Counter limit.
    fn set_rf_repeat_counter_limit(&self, value: u8);
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

// ============================================================================
// Domain Address
// ============================================================================

/// Trait for devices that store a domain address.
///
/// The domain address is a medium-specific identifier:
/// - **KNX/IP**: 4-byte IPv4 multicast address (e.g., `224.0.23.12`)
/// - **RF**: 6-byte RF domain address
/// - **TP1**: Not applicable (domain address length is 0)
///
/// Used by `A_DomainAddressSerialNumber_Read/Write` services. The AL
/// extension for domain address handling requires this trait on the
/// device state.
pub trait HasDomainAddress {
    /// Domain address length in bytes.
    ///
    /// This determines how many bytes are included in
    /// `A_DomainAddressSerialNumber_Response` and expected in
    /// `A_DomainAddressSerialNumber_Write`.
    const DOMAIN_ADDRESS_LENGTH: usize;

    /// Get the current domain address.
    ///
    /// The returned slice must be exactly [`DOMAIN_ADDRESS_LENGTH`](Self::DOMAIN_ADDRESS_LENGTH) bytes.
    /// For IP devices this is the routing multicast address in network byte order.
    fn domain_address(&self, buf: &mut [u8]);

    /// Set the domain address.
    ///
    /// `addr` is exactly [`DOMAIN_ADDRESS_LENGTH`](Self::DOMAIN_ADDRESS_LENGTH) bytes.
    fn set_domain_address(&self, addr: &[u8]);
}
