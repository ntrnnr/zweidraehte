//! Property types and descriptors for Interface Objects

use core::fmt;

use crate::dpt::PropertyDataDefinition;

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
    /// Value out of range
    ValueOutOfRange,
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
            PropertyError::AccessDenied => write!(f, "Access denied"),
            PropertyError::BufferTooSmall => write!(f, "Buffer too small"),
            PropertyError::InvalidLoadState => write!(f, "Invalid load state"),
        }
    }
}

/// Static property descriptor
///
/// Describes a property's metadata including its ID, data type, element count,
/// and access rights. This is returned by A_PropertyDescription_Read service.
#[derive(Clone, Copy, Debug)]
pub struct PropertyDescriptor {
    /// Property Identifier (PID)
    pub pid: u8,
    /// Property Data Type identifier (PDT)
    pub pdt_id: u8,
    /// Maximum number of elements (0 = current count, for variable-length properties)
    pub max_elements: u16,
    /// Access rights
    pub access: PropertyAccess,
    /// Write access level (0-3, 0 = most restricted, 3 = no restriction)
    pub write_level: u8,
    /// Read access level (0-3, 0 = most restricted, 3 = no restriction)
    pub read_level: u8,
}

impl PropertyDescriptor {
    /// Create a new property descriptor with default access levels (unrestricted)
    /// Default read/write levels are 3, meaning anyone can access (levels 0-3 all pass the check).
    pub const fn new(pid: u8, pdt_id: u8, max_elements: u16, access: PropertyAccess) -> Self {
        Self { pid, pdt_id, max_elements, access, write_level: 3, read_level: 3 }
    }

    /// Create a property descriptor for a type implementing PropertyDataDefinition
    pub const fn from_type<T: PropertyDataDefinition>(pid: u8, access: PropertyAccess) -> Self {
        Self::new(pid, T::ID, 1, access)
    }

    /// Create a property descriptor for an array property
    pub const fn array<T: PropertyDataDefinition>(pid: u8, max_elements: u16, access: PropertyAccess) -> Self {
        Self::new(pid, T::ID, max_elements, access)
    }

    /// Set access levels (builder pattern)
    pub const fn with_levels(mut self, read_level: u8, write_level: u8) -> Self {
        self.read_level = read_level & 0x0F;
        self.write_level = write_level & 0x0F;
        self
    }

    /// Check if reading is allowed at the given access level
    ///
    /// In KNX, lower access level = more permissions (0 = full access, 3 = minimal).
    /// A property with `read_level=0` requires the caller to have access level 0.
    /// A property with `read_level=3` can be read by anyone (levels 0-3).
    pub const fn can_read(&self, caller_level: u8) -> bool {
        matches!(self.access, PropertyAccess::ReadOnly | PropertyAccess::ReadWrite) && caller_level <= self.read_level
    }

    /// Check if writing is allowed at the given access level
    ///
    /// In KNX, lower access level = more permissions (0 = full access, 3 = minimal).
    /// A property with `write_level=0` requires the caller to have access level 0.
    /// A property with `write_level=3` can be written by anyone (levels 0-3).
    pub const fn can_write(&self, caller_level: u8) -> bool {
        matches!(self.access, PropertyAccess::ReadWrite | PropertyAccess::WriteOnly) && caller_level <= self.write_level
    }
}

/// Response data for A_PropertyDescription_Read service
#[derive(Clone, Copy, Debug)]
pub struct PropertyDescriptionResponse {
    /// Object index
    pub object_idx: u16,
    /// Property ID
    pub prop_id: u8,
    /// Property index (0-based)
    pub prop_idx: u8,
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
    pub fn from_descriptor(object_idx: u16, prop_idx: u8, desc: &PropertyDescriptor) -> Self {
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
    /// [ObjectIndex(1)][PropertyId(1)][PropertyIndex(1)][Type+MaxElements(2)][Access(1)]
    /// Where Type+MaxElements: bit 15 = writeable, bits 13-8 = PDT, bits 11-0 = MaxElements
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 7 {
            return 0;
        }
        buf[0] = self.object_idx as u8;
        buf[1] = self.prop_id;
        buf[2] = self.prop_idx;
        // Type+MaxElements: [Writeable:1][reserved:1][PDT:6][MaxElements:12] - but overlaps!
        // Actually per spec: byte3=[W:1][PDT:7], bytes 4-5 = [PDT:4][MaxElements:12]
        // The PDT upper 4 bits go into byte 4 upper nibble
        let type_and_max = ((self.pdt as u16 & 0x3F) << 12) | (self.max_elements & 0x0FFF);
        buf[3] = if self.writeable { 0x80 } else { 0x00 } | (self.pdt & 0x3F);
        buf[4] = (type_and_max >> 8) as u8;
        buf[5] = type_and_max as u8;
        buf[6] = (self.write_level << 4) | self.read_level;
        7
    }
}

/// Helper trait for property value storage
///
/// This trait abstracts over different ways a property value can be stored:
/// - Direct field in a struct
/// - Part of a table's data
/// - Computed value
pub trait PropertyStorage {
    /// Read property data into buffer
    ///
    /// # Arguments
    /// * `start_idx` - 1-based start index (1 = first element)
    /// * `count` - Number of elements to read
    /// * `buf` - Buffer to write data into
    ///
    /// # Returns
    /// Number of bytes written, or error
    fn read(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError>;

    /// Write property data from buffer
    ///
    /// # Arguments
    /// * `start_idx` - 1-based start index (1 = first element)
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Ok(()) on success, or error
    fn write(&mut self, start_idx: u16, data: &[u8]) -> Result<(), PropertyError>;

    /// Get current element count
    fn element_count(&self) -> u16;
}

/// Simple single-value property storage wrapper
pub struct SingleValueProperty<T> {
    value: T,
}

impl<T> SingleValueProperty<T> {
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    pub fn get(&self) -> &T {
        &self.value
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }

    pub fn set(&mut self, value: T) {
        self.value = value;
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> PropertyStorage for SingleValueProperty<T> {
    fn read(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        if start_idx != 1 || count != 1 {
            return Err(PropertyError::InvalidStartIndex);
        }
        let data = self.value.as_ref();
        if buf.len() < data.len() {
            return Err(PropertyError::BufferTooSmall);
        }
        buf[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    fn write(&mut self, start_idx: u16, data: &[u8]) -> Result<(), PropertyError> {
        if start_idx != 1 {
            return Err(PropertyError::InvalidStartIndex);
        }
        let target = self.value.as_mut();
        if data.len() > target.len() {
            return Err(PropertyError::BufferTooSmall);
        }
        target[..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn element_count(&self) -> u16 {
        1
    }
}
