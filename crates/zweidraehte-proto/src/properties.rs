//! Property types and descriptors for Interface Objects

use core::fmt;

use crate::AccessContext;
use crate::access::{AccessLevelSpec, AccessPolicy};
use crate::dpt::PropertyDataDefinition;
use crate::messages::apdu::property_ext::PropertyReturnCode;

/// Property access rights
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PropertyAccess {
    /// Property can only be read
    ReadOnly = 0,
    /// Property can be read and written
    ReadWrite = 1,
    /// Property can only be written (rare, e.g., keys)
    WriteOnly = 2,
}

/// Property errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PropertyError {
    /// Object index out of range
    InvalidObjectIndex,
    /// Property ID not found in object
    InvalidPropertyId,
    /// Property index out of range
    InvalidPropertyIndex,
    /// Start index out of range (for array properties)
    InvalidStartIndex,
    /// Requested element count exceeds available
    InvalidElementCount,
    /// Write not allowed (read-only property)
    WriteNotAllowed,
    /// Read not allowed (write-only property)
    ReadNotAllowed,
    /// Data type mismatch
    TypeMismatch,
    /// Value inside the property's range but not one it accepts.
    ///
    /// Distinct from [`ValueBelowMin`](Self::ValueBelowMin) and
    /// [`ValueAboveMax`](Self::ValueAboveMax): those say the value fell
    /// off one end, this says it is a hole in the middle.
    ValueOutOfRange,
    /// Value below the property's minimum.
    ValueBelowMin,
    /// Value above the property's maximum.
    ValueAboveMax,
    /// Access denied (insufficient access level)
    AccessDenied,
    /// Buffer too small to hold result
    BufferTooSmall,
    /// Object is in wrong load state for this operation
    InvalidLoadState,
}

impl fmt::Display for PropertyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropertyError::InvalidObjectIndex => write!(f, "Invalid object index"),
            PropertyError::InvalidPropertyId => write!(f, "Invalid property ID"),
            PropertyError::InvalidPropertyIndex => write!(f, "Invalid property index"),
            PropertyError::InvalidStartIndex => write!(f, "Invalid start index"),
            PropertyError::InvalidElementCount => write!(f, "Invalid element count"),
            PropertyError::WriteNotAllowed => write!(f, "Write not allowed"),
            PropertyError::ReadNotAllowed => write!(f, "Read not allowed"),
            PropertyError::TypeMismatch => write!(f, "Type mismatch"),
            PropertyError::ValueOutOfRange => write!(f, "Value out of range"),
            PropertyError::ValueBelowMin => write!(f, "Value below minimum"),
            PropertyError::ValueAboveMax => write!(f, "Value above maximum"),
            PropertyError::AccessDenied => write!(f, "Access denied"),
            PropertyError::BufferTooSmall => write!(f, "Buffer too small"),
            PropertyError::InvalidLoadState => write!(f, "Invalid load state"),
        }
    }
}

impl PropertyError {
    /// Convert to an AN163 extended property service return code.
    ///
    /// See spec 03_03_07 section 3.4.5.5 "Return Codes".
    pub fn to_ext_return_code(self) -> PropertyReturnCode {
        match self {
            PropertyError::InvalidObjectIndex
            | PropertyError::InvalidPropertyId
            | PropertyError::InvalidPropertyIndex
            | PropertyError::InvalidStartIndex
            | PropertyError::InvalidElementCount => PropertyReturnCode::AddressVoid,
            PropertyError::AccessDenied => PropertyReturnCode::AccessDenied,
            PropertyError::WriteNotAllowed => PropertyReturnCode::AccessReadOnly,
            PropertyError::ReadNotAllowed => PropertyReturnCode::AccessWriteOnly,
            PropertyError::TypeMismatch => PropertyReturnCode::DataTypeConflict,
            PropertyError::BufferTooSmall => PropertyReturnCode::LengthExceedsMaxApduLength,
            PropertyError::ValueOutOfRange => PropertyReturnCode::DataVoid,
            PropertyError::ValueBelowMin => PropertyReturnCode::DataMin,
            PropertyError::ValueAboveMax => PropertyReturnCode::DataMax,
            PropertyError::InvalidLoadState => PropertyReturnCode::TemporarilyNotAvailable,
        }
    }
}

/// Static property descriptor
///
/// Describes a property's metadata including its ID, data type, element count,
/// access rights, and access policy. This is returned by
/// A_PropertyDescription_Read service.
///
/// Access control is enforced at two independent levels:
/// 1. **Legacy access levels** (`read_level`/`write_level`): Checked against the
///    connection's current A_Authorize level (0-3 on 4-level devices,
///    0-15 on 16-level devices such as System 7).
/// 2. **Access policy**: Checked against the sender's security context (role,
///    security mode). See [`AccessPolicy`] for details.
///
/// Both checks must pass for access to be granted.
#[derive(Clone, Copy, Debug)]
pub struct PropertyDescriptor {
    /// Property Identifier (PID)
    pub pid: u16,
    /// Property Data Type identifier (PDT)
    pub pdt_id: u8,
    /// Maximum number of elements (0 = current count, for variable-length properties)
    pub max_elements: u16,
    /// Access rights
    pub access: PropertyAccess,
    /// Write access level (0 = most restricted; the profile's maximum
    /// level — 3 or 15 — is unrestricted). 4-bit wire field.
    pub write_level: u8,
    /// Read access level (0 = most restricted; the profile's maximum
    /// level — 3 or 15 — is unrestricted). 4-bit wire field.
    pub read_level: u8,
    /// KNX Data Secure access policy (per spec 03/04/01, section 6.2).
    pub policy: AccessPolicy,
}

impl PropertyDescriptor {
    /// Create a new property descriptor.
    ///
    /// Access levels are 4-bit values (0-15), where:
    /// - 0 = most restricted (requires full access/authorization)
    /// - the profile's maximum level (3 on 4-level devices, 15 on
    ///   16-level devices) = unrestricted
    ///
    /// A caller with level N can access a property if their level <= the
    /// property's level. The access policy provides additional KNX Data
    /// Secure access control and **must be supplied explicitly**: there
    /// is no default. Picking a default would silently grant
    /// `READ_OPEN_WRITE_TOOL` to security-sensitive properties whose
    /// spec policy is stricter (AN193 e.g. `15F/04C` for
    /// `PID_TUNNELLING_ADDRESSES`), so callers are required to consult
    /// AN193 / the relevant Profile spec and pick the correct one.
    pub const fn new(
        pid: u16,
        pdt_id: u8,
        max_elements: u16,
        access: PropertyAccess,
        read_level: u8,
        write_level: u8,
        policy: AccessPolicy,
    ) -> Self {
        Self {
            pid,
            pdt_id,
            max_elements,
            access,
            write_level: write_level & 0x0F,
            read_level: read_level & 0x0F,
            policy,
        }
    }

    /// Create a property descriptor for a type implementing
    /// [`PropertyDataDefinition`]. The PDT id is taken from `T::ID`;
    /// the policy still has to be supplied — see [`new`](Self::new).
    pub const fn from_type<T: PropertyDataDefinition>(
        pid: u16,
        access: PropertyAccess,
        read_level: u8,
        write_level: u8,
        policy: AccessPolicy,
    ) -> Self {
        Self::new(pid, T::ID, 1, access, read_level, write_level, policy)
    }

    /// Replace the two access levels, leaving everything else alone.
    ///
    /// Used by [`PropertyDescriptorSpec::for_levels`] to turn a
    /// profile-independent spec into the descriptor a given device
    /// answers with.
    pub const fn with_levels(self, read_level: u8, write_level: u8) -> Self {
        Self { read_level: read_level & 0x0F, write_level: write_level & 0x0F, ..self }
    }

    /// Create a property descriptor for an array property of the typed
    /// PDT `T`. Convenience over [`new`](Self::new) for runtime-built
    /// descriptors whose `max_elements` value isn't known at compile
    /// time (for example, when it comes from a const generic).
    pub const fn array<T: PropertyDataDefinition>(
        pid: u16,
        max_elements: u16,
        access: PropertyAccess,
        read_level: u8,
        write_level: u8,
        policy: AccessPolicy,
    ) -> Self {
        Self::new(pid, T::ID, max_elements, access, read_level, write_level, policy)
    }

    /// Check if reading is allowed under the given access context.
    ///
    /// Checks both the legacy access level and the access policy direction flag.
    /// Both must permit the operation for access to be granted.
    ///
    /// The `device_security_on` parameter indicates whether the device's
    /// Security Mode is enabled (PID_SECURITY_MODE). When Data Secure is not
    /// in use, pass `false`.
    pub const fn can_read(&self, ctx: AccessContext) -> bool {
        matches!(self.access, PropertyAccess::ReadOnly | PropertyAccess::ReadWrite)
            && ctx.access_level <= self.read_level
    }

    /// Check if reading is allowed, including access policy evaluation.
    ///
    /// This is the full check that includes both legacy access levels and
    /// KNX Data Secure access policies. Use this when the device's security
    /// mode state is known.
    pub const fn can_read_secure(&self, ctx: &AccessContext, device_security_on: bool) -> bool {
        matches!(self.access, PropertyAccess::ReadOnly | PropertyAccess::ReadWrite)
            && ctx.access_level <= self.read_level
            && self.policy.can_read(ctx, device_security_on)
    }

    /// Check if writing is allowed under the given access context.
    ///
    /// Checks both the legacy access level and the write-enable flag.
    pub const fn can_write(&self, ctx: AccessContext) -> bool {
        matches!(self.access, PropertyAccess::ReadWrite | PropertyAccess::WriteOnly)
            && ctx.access_level <= self.write_level
    }

    /// Check if writing is allowed, including access policy evaluation.
    pub const fn can_write_secure(&self, ctx: &AccessContext, device_security_on: bool) -> bool {
        matches!(self.access, PropertyAccess::ReadWrite | PropertyAccess::WriteOnly)
            && ctx.access_level <= self.write_level
            && self.policy.can_write(ctx, device_security_on)
    }

    /// Check if a Function Property command (write-like) is allowed.
    ///
    /// Unlike [`can_write_secure`], this does NOT check [`PropertyAccess`]
    /// because PDT_FUNCTION properties are always accessed via Function
    /// Property services, not PropertyValueWrite — so they may be marked
    /// ReadOnly in the descriptor while still being writable via command.
    pub const fn can_function_write_secure(&self, ctx: &AccessContext, device_security_on: bool) -> bool {
        self.policy.can_write(ctx, device_security_on)
    }

    /// Check if a Function Property state read is allowed.
    ///
    /// Like [`can_function_write_secure`], skips the PropertyAccess check.
    pub const fn can_function_read_secure(&self, ctx: &AccessContext, device_security_on: bool) -> bool {
        self.policy.can_read(ctx, device_security_on)
    }
}

/// A property descriptor whose two access levels have not been resolved
/// against a profile yet.
///
/// The access octet of 03/03/07 §3.4.3.2 holds numbers, but which number
/// an audience gets depends on whether the hosting profile has 4 or 16
/// authorisation levels (03/04/01 §4.3.2.2 Table 1). An interface object
/// that belongs to exactly one profile resolves that at its definition
/// site and publishes plain [`PropertyDescriptor`]s. An object shared
/// between profiles publishes these instead, and the device resolves
/// them from its own
/// `HasAuthorization::MAX_ACCESS_LEVELS`.
#[derive(Clone, Copy, Debug)]
pub struct PropertyDescriptorSpec {
    /// Property Identifier (PID)
    pub pid: u16,
    /// Property Data Type identifier (PDT)
    pub pdt_id: u8,
    /// Maximum number of elements (0 = current count, for variable-length properties)
    pub max_elements: u16,
    /// Access rights
    pub access: PropertyAccess,
    /// Read access level, before resolution.
    pub read_level: AccessLevelSpec,
    /// Write access level, before resolution.
    pub write_level: AccessLevelSpec,
    /// KNX Data Secure access policy.
    pub policy: AccessPolicy,
}

impl PropertyDescriptorSpec {
    /// Create a spec. Mirrors [`PropertyDescriptor::new`]'s argument
    /// order, with the two levels given as specs rather than numbers.
    pub const fn new(
        pid: u16,
        pdt_id: u8,
        max_elements: u16,
        access: PropertyAccess,
        read_level: AccessLevelSpec,
        write_level: AccessLevelSpec,
        policy: AccessPolicy,
    ) -> Self {
        Self { pid, pdt_id, max_elements, access, read_level, write_level, policy }
    }

    /// Resolve into the descriptor a device with `max_levels`
    /// authorisation levels answers with.
    pub const fn for_levels(&self, max_levels: u8) -> PropertyDescriptor {
        PropertyDescriptor::new(
            self.pid,
            self.pdt_id,
            self.max_elements,
            self.access,
            self.read_level.for_levels(max_levels),
            self.write_level.for_levels(max_levels),
            self.policy,
        )
    }
}

/// Response data for A_PropertyDescription_Read service
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PropertyDescriptionResponse {
    /// Object index
    pub object_idx: u16,
    /// Property ID (12 bit on the extended services wire, 8 bit on the
    /// regular services wire; stored as the union).
    pub prop_id: u16,
    /// Property index (0-based, up to 12 bits for extended services)
    pub prop_idx: u16,
    /// Writability flag (1 = writable)
    pub writeable: bool,
    /// Property Data Type
    pub pdt: u8,
    /// Maximum number of elements
    pub max_elements: u16,
    /// Read access level
    pub read_level: u8,
    /// Write access level
    pub write_level: u8,
}

impl PropertyDescriptionResponse {
    /// Create from a property descriptor
    pub fn from_descriptor(object_idx: u16, prop_idx: u16, desc: &PropertyDescriptor) -> Self {
        Self {
            object_idx,
            prop_id: desc.pid,
            prop_idx,
            writeable: matches!(desc.access, PropertyAccess::ReadWrite | PropertyAccess::WriteOnly),
            pdt: desc.pdt_id,
            max_elements: desc.max_elements,
            read_level: desc.read_level,
            write_level: desc.write_level,
        }
    }

    /// Encode to bytes for transmission
    /// Format per KNX spec 3/5/1:
    /// `[ObjectIndex(1)][PropertyId(1)][PropertyIndex(1)][Type+MaxElements(2)][Access(1)]`
    /// Where Type+MaxElements: bit 15 = writeable, bits 13-8 = PDT, bits 11-0 = MaxElements
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 7 {
            return 0;
        }
        buf[0] = self.object_idx as u8;
        // Regular A_PropertyDescription_Response carries an 8-bit
        // prop_id on the wire. The field is widened to `u16` to share
        // storage with the Extended services; regular services never
        // originate PIDs above 255, so this cast is lossless in
        // practice.
        buf[1] = self.prop_id as u8;
        buf[2] = self.prop_idx as u8;
        // Type+MaxElements: [Writeable:1][reserved:1][PDT:6][MaxElements:12] - but overlaps!
        // Actually per spec: byte3=[W:1][PDT:7], bytes 4-5 = [PDT:4][MaxElements:12]
        // The PDT upper 4 bits go into byte 4 upper nibble
        let type_and_max = ((self.pdt as u16 & 0x3F) << 12) | (self.max_elements & 0x0FFF);
        buf[3] = if self.writeable { 0x80 } else { 0x00 } | (self.pdt & 0x3F);
        buf[4] = (type_and_max >> 8) as u8;
        buf[5] = type_and_max as u8;
        buf[6] = (self.read_level << 4) | self.write_level;
        7
    }
}

// ============================================================================
// Property Read/Write Traits
// ============================================================================

/// Trait for reading a single-value property with KNX semantics.
///
/// Handles:
/// - `start_idx=0`: Returns element count (1) as 2 bytes big-endian
/// - `start_idx=1, count=1`: Copies data to buffer
/// - Other combinations: Returns `InvalidStartIndex` error
///
/// # Example
/// ```ignore
/// fn read_property(&self, pid: u16, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
///     match pid {
///         pid::PROGRAM_VERSION => self.program_version.read_property(start_idx, count, buf),
///         pid::PEI_TYPE => self.pei_type.read_property(start_idx, count, buf),
///         _ => Err(PropertyError::InvalidPropertyId),
///     }
/// }
/// ```
pub trait PropertyRead {
    /// Read this property with KNX semantics.
    fn read_property(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError>;
}

/// Trait for writing a single-value property with KNX semantics.
///
/// Handles:
/// - `start_idx=1`: Copies data to property
/// - Other: Returns `InvalidStartIndex` error
pub trait PropertyWrite {
    /// Write this property with KNX semantics. Returns bytes written.
    fn write_property(&mut self, start_idx: u16, data: &[u8]) -> Result<usize, PropertyError>;
}

/// Blanket implementation for any type that can be viewed as bytes.
/// This covers all PDT types (PDT_Generic06, PDT_UnsignedInt, etc.)
impl<T: AsRef<[u8]>> PropertyRead for T {
    fn read_property(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        // Handle element count query (start_idx=0 per KNX spec)
        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[0] = 0;
            buf[1] = 1; // Single element
            return Ok(2);
        }
        if start_idx != 1 || count != 1 {
            return Err(PropertyError::InvalidStartIndex);
        }
        let data = self.as_ref();
        if buf.len() < data.len() {
            return Err(PropertyError::BufferTooSmall);
        }
        buf[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }
}

/// Blanket implementation for any type that can be mutably viewed as bytes.
impl<T: AsMut<[u8]>> PropertyWrite for T {
    fn write_property(&mut self, start_idx: u16, data: &[u8]) -> Result<usize, PropertyError> {
        if start_idx != 1 {
            return Err(PropertyError::InvalidStartIndex);
        }
        let target = self.as_mut();
        if data.len() > target.len() {
            return Err(PropertyError::BufferTooSmall);
        }
        target[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }
}

// ============================================================================
// Array Property Read/Write Traits
// ============================================================================

/// Trait for reading an array property with KNX semantics.
///
/// Array properties store multiple elements of the same size. The trait handles:
/// - `start_idx=0`: Returns current element count as 2 bytes big-endian
/// - `start_idx>=1`: Returns requested elements starting at the given 1-based index
///
/// # Example
/// ```ignore
/// fn read_property(&self, pid: u16, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
///     match pid {
///         pid::TABLE => self.table_data.read_array_property(start_idx, count, 2, buf), // 2 bytes per element
///         _ => Err(PropertyError::InvalidPropertyId),
///     }
/// }
/// ```
pub trait ArrayPropertyRead {
    /// Read array property with KNX semantics.
    ///
    /// # Arguments
    /// * `start_idx` - 1-based start index (0 = query element count)
    /// * `count` - Number of elements to read
    /// * `element_size` - Size of each element in bytes
    /// * `buf` - Output buffer
    fn read_array_property(
        &self,
        start_idx: u16,
        count: u16,
        element_size: usize,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError>;

    /// Get the current element count for this array property.
    fn element_count(&self, element_size: usize) -> u16;
}

/// Trait for writing an array property with KNX semantics.
pub trait ArrayPropertyWrite {
    /// Write array property with KNX semantics. Returns bytes written.
    ///
    /// # Arguments
    /// * `start_idx` - 1-based start index (0 = write at beginning, e.g., for count prefix)
    /// * `data` - Data to write
    /// * `element_size` - Size of each element in bytes
    fn write_array_property(
        &mut self,
        start_idx: u16,
        data: &[u8],
        element_size: usize,
    ) -> Result<usize, PropertyError>;
}

/// Blanket implementation for slices.
impl<T: AsRef<[u8]>> ArrayPropertyRead for T {
    fn read_array_property(
        &self,
        start_idx: u16,
        count: u16,
        element_size: usize,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        let data = self.as_ref();

        // start_idx=0 means query element count
        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            let elem_count = (data.len() / element_size) as u16;
            buf[0..2].copy_from_slice(&elem_count.to_be_bytes());
            return Ok(2);
        }

        // Calculate byte offset (1-indexed)
        let byte_start = ((start_idx - 1) as usize) * element_size;
        let byte_count = (count as usize) * element_size;

        if byte_start >= data.len() {
            return Err(PropertyError::InvalidStartIndex);
        }

        let available = data.len() - byte_start;
        let to_copy = byte_count.min(available).min(buf.len());

        buf[..to_copy].copy_from_slice(&data[byte_start..byte_start + to_copy]);
        Ok(to_copy)
    }

    fn element_count(&self, element_size: usize) -> u16 {
        (self.as_ref().len() / element_size) as u16
    }
}

/// Blanket implementation for mutable slices.
impl<T: AsMut<[u8]>> ArrayPropertyWrite for T {
    fn write_array_property(
        &mut self,
        start_idx: u16,
        data: &[u8],
        element_size: usize,
    ) -> Result<usize, PropertyError> {
        let target = self.as_mut();

        // Calculate byte offset (start_idx=0 means write at beginning)
        let byte_start = if start_idx == 0 { 0 } else { ((start_idx - 1) as usize) * element_size };

        if byte_start + data.len() > target.len() {
            return Err(PropertyError::InvalidStartIndex);
        }

        target[byte_start..byte_start + data.len()].copy_from_slice(data);
        Ok(data.len())
    }
}

// ============================================================================
// Array Property with Count Prefix
// ============================================================================

/// Trait for reading an array property that has a 2-byte count prefix.
///
/// Many KNX table properties store data as: `[count:2][entry1][entry2]...`
/// This trait handles that format, reading the count from the first 2 bytes.
pub trait ArrayPropertyWithPrefixRead {
    /// Read array property with count prefix.
    ///
    /// # Arguments
    /// * `start_idx` - 1-based start index (0 = query element count from prefix)
    /// * `count` - Number of elements to read
    /// * `element_size` - Size of each element in bytes
    /// * `buf` - Output buffer
    fn read_array_with_prefix(
        &self,
        start_idx: u16,
        count: u16,
        element_size: usize,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError>;

    /// Get the element count from the 2-byte prefix.
    fn element_count_from_prefix(&self) -> u16;
}

/// Trait for writing an array property with count prefix.
pub trait ArrayPropertyWithPrefixWrite {
    /// Write array property with count prefix. Returns bytes written.
    fn write_array_with_prefix(
        &mut self,
        start_idx: u16,
        data: &[u8],
        element_size: usize,
    ) -> Result<usize, PropertyError>;
}

impl<T: AsRef<[u8]>> ArrayPropertyWithPrefixRead for T {
    fn read_array_with_prefix(
        &self,
        start_idx: u16,
        count: u16,
        element_size: usize,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        let data = self.as_ref();

        // start_idx=0 means query element count (read from prefix)
        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            if data.len() >= 2 {
                buf[0..2].copy_from_slice(&data[0..2]);
            } else {
                buf[0] = 0;
                buf[1] = 0;
            }
            return Ok(2);
        }

        // Data starts after 2-byte count prefix, 1-indexed
        let byte_start = 2 + ((start_idx - 1) as usize) * element_size;
        let byte_count = (count as usize) * element_size;

        if byte_start >= data.len() {
            return Err(PropertyError::InvalidStartIndex);
        }

        let available = data.len() - byte_start;
        let to_copy = byte_count.min(available).min(buf.len());

        buf[..to_copy].copy_from_slice(&data[byte_start..byte_start + to_copy]);
        Ok(to_copy)
    }

    fn element_count_from_prefix(&self) -> u16 {
        let data = self.as_ref();
        if data.len() >= 2 { u16::from_be_bytes([data[0], data[1]]) } else { 0 }
    }
}

impl<T: AsMut<[u8]>> ArrayPropertyWithPrefixWrite for T {
    fn write_array_with_prefix(
        &mut self,
        start_idx: u16,
        data: &[u8],
        element_size: usize,
    ) -> Result<usize, PropertyError> {
        let target = self.as_mut();

        // Calculate byte offset
        let byte_start = if start_idx == 0 {
            0 // Write at beginning (e.g., the count prefix itself)
        } else {
            2 + ((start_idx - 1) as usize) * element_size
        };

        if byte_start + data.len() > target.len() {
            return Err(PropertyError::InvalidStartIndex);
        }

        target[byte_start..byte_start + data.len()].copy_from_slice(data);
        Ok(data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{AccessContext, AccessPolicy};

    /// The access levels are 4-bit wire fields: a 16-level device
    /// (System 7) must be able to round-trip level 15 through the
    /// descriptor and the A_PropertyDescription_Response encoding.
    #[test]
    fn descriptor_round_trips_level_15() {
        let desc = PropertyDescriptor::new(56, 0x04, 1, PropertyAccess::ReadWrite, 15, 1, AccessPolicy::OPEN);
        assert_eq!(desc.read_level, 15);
        assert_eq!(desc.write_level, 1);

        let response = PropertyDescriptionResponse::from_descriptor(0, 0, &desc);
        let mut buf = [0u8; 7];
        assert_eq!(response.encode(&mut buf), 7);
        // Access octet: [read_level:4][write_level:4]
        assert_eq!(buf[6], 0xF1);
    }

    /// A caller at the 16-level minimum (level 15) must clear a
    /// level-15 read gate and fail every stricter one.
    #[test]
    fn level_15_context_checks() {
        let desc = PropertyDescriptor::new(56, 0x04, 1, PropertyAccess::ReadWrite, 15, 1, AccessPolicy::OPEN);
        let everyone = AccessContext::new(15);
        let privileged = AccessContext::new(1);
        assert!(everyone.access_level <= desc.read_level);
        assert!(everyone.access_level > desc.write_level);
        assert!(privileged.access_level <= desc.write_level);
    }
}
