//! Interface Object traits
//!
//! These traits define the interface between concrete object implementations
//! and the stack's management layer.

use core::cell::RefCell;

use crate::dpt::InterfaceObjectType;
use crate::objects::tables::LoadableTable;

use super::{PropertyDescriptionResponse, PropertyDescriptor, PropertyError};

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
    ///
    /// # Returns
    /// Number of bytes written or error
    fn property_value_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
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
    ///
    /// # Returns
    /// `Ok(())` on success or error
    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        data: &[u8],
    ) -> Result<(), PropertyError>;
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
    /// * `Ok(())` - Write successful
    /// * `Err(PropertyError)` - If the write fails
    fn write_property(&mut self, pid: u8, start_idx: u16, data: &[u8]) -> Result<(), PropertyError>;

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

// FIXME: The interface objects builder could also load and deserialize stored data from storage (flash, JSON etc.)

// ============================================================================
// Interface Objects Builder
// ============================================================================

/// Builder trait for creating interface objects.
///
/// This trait follows the same pattern as `LinkLayerBuilder` - the application
/// defines an implementation that specifies which interface objects to create
/// for a particular device type. Different `StackDefinition`s can have
/// completely different sets of interface objects.
///
/// The builder is consumed during stack initialization to create the
/// `InterfaceObjects` container, which is then stored in the stack's
/// internal state and accessible via a context trait.
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte::objects::interface::*;
/// use core::cell::RefCell;
///
/// // A simple KNXnet/IP device with standard objects
/// pub struct KnxIpInterfaceObjectsBuilder {
///     pub serial_number: [u8; 6],
///     pub manufacturer_id: u16,
/// }
///
/// // The container that will hold all the interface objects
/// pub struct KnxIpInterfaceObjects<'a, ADT, AST, COT> {
///     pub device: RefCell<DeviceObject>,
///     pub addr_table: RefCell<AddressTableObject<'a, ADT>>,
///     pub asso_table: RefCell<AssociationTableObject<'a, AST>>,
///     pub app_program: RefCell<ApplicationProgramObject>,
///     pub group_object_table: RefCell<GroupObjectTableObject<'a, COT>>,
///     pub ip_parameter: RefCell<IpParameterObject>,
/// }
///
/// impl InterfaceObjectsBuilder for KnxIpInterfaceObjectsBuilder {
///     type Objects<'a, ADT, AST, COT> = KnxIpInterfaceObjects<'a, ADT, AST, COT>
///     where
///         ADT: LoadableTable + 'a,
///         AST: LoadableTable + 'a,
///         COT: LoadableTable + 'a;
///
///     fn build<'a, ADT, AST, COT>(
///         self,
///         addr_table: &'a RefCell<ADT>,
///         asso_table: &'a RefCell<AST>,
///         co_table: &'a RefCell<COT>,
///     ) -> Self::Objects<'a, ADT, AST, COT>
///     where
///         ADT: LoadableTable,
///         AST: LoadableTable,
///         COT: LoadableTable,
///     {
///         // Create and configure all interface objects
///         let mut device = DeviceObject::new();
///         device.serial_number = self.serial_number.into();
///         device.manufacturer_id = self.manufacturer_id.into();
///         // ... etc
///
///         KnxIpInterfaceObjects {
///             device: RefCell::new(device),
///             addr_table: RefCell::new(AddressTableObject::new(addr_table)),
///             // ... etc
///         }
///     }
/// }
/// ```
pub trait InterfaceObjectsBuilder: Sized {
    /// The container type that holds all interface objects.
    ///
    /// This is a GAT (Generic Associated Type) that allows the container
    /// to hold references to the tables with the appropriate lifetimes.
    /// The container must implement `PropertyServiceHandler` so the
    /// ApplicationLayer can dispatch property read/write requests to it.
    type Objects<'a, ADT, AST, COT>: PropertyServiceHandler
    where
        ADT: LoadableTable + 'a,
        AST: LoadableTable + 'a,
        COT: LoadableTable + 'a;

    /// Build the interface objects container.
    ///
    /// This method consumes the builder and creates all interface objects,
    /// wrapping the provided table references as needed.
    ///
    /// # Arguments
    /// * `addr_table` - Reference to the address table (stored in stack Inner)
    /// * `asso_table` - Reference to the association table (stored in stack Inner)
    /// * `co_table` - Reference to the communication object table (stored in stack Inner)
    /// * `state` - Reference to the shared stack state (programming mode, etc.)
    ///
    /// # Returns
    /// The container holding all interface objects for this device.
    fn build<'a, ADT, AST, COT, S>(
        self,
        addr_table: &'a RefCell<ADT>,
        asso_table: &'a RefCell<AST>,
        co_table: &'a RefCell<COT>,
        state: &'a S,
    ) -> Self::Objects<'a, ADT, AST, COT>
    where
        ADT: LoadableTable,
        AST: LoadableTable,
        COT: LoadableTable,
        S: crate::StackState;
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
// ============================================================================
// Empty Interface Objects Builder
// ============================================================================

/// An empty interface objects builder that creates no interface objects.
///
/// This is useful for testing or when interface objects are not needed.
/// The resulting container is an empty unit type `()`.
///
/// # Example
///
/// ```rust,ignore
/// impl StackDefinition for MyTestStack {
///     type IOB = EmptyInterfaceObjectsBuilder;
///     // ...
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyInterfaceObjectsBuilder;

impl InterfaceObjectsBuilder for EmptyInterfaceObjectsBuilder {
    type Objects<'a, ADT, AST, COT>
        = ()
    where
        ADT: LoadableTable + 'a,
        AST: LoadableTable + 'a,
        COT: LoadableTable + 'a;

    fn build<'a, ADT, AST, COT, S>(
        self,
        _addr_table: &'a RefCell<ADT>,
        _asso_table: &'a RefCell<AST>,
        _co_table: &'a RefCell<COT>,
        _state: &'a S,
    ) -> Self::Objects<'a, ADT, AST, COT>
    where
        ADT: LoadableTable,
        AST: LoadableTable,
        COT: LoadableTable,
        S: crate::StackState,
    {
        // No interface objects created
    }
}

/// Implement PropertyServiceHandler for () (empty container)
///
/// This allows `EmptyInterfaceObjectsBuilder` to work - it returns `()` which
/// handles all property requests by returning "no objects".
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
    ) -> Result<usize, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }

    fn property_value_write(
        &self,
        _object_idx: u16,
        _prop_id: u8,
        _start_idx: u16,
        _data: &[u8],
    ) -> Result<(), PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }
}
