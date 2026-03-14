//! KNX/IP interface objects for System B devices.
//!
//! Contains the IP Parameter Object container (`IpObjects`), the tunneling
//! augment (`TunnelingAugment`), composed type aliases, and helper functions
//! for creating KNX/IP device object sets.

use core::cell::RefCell;

use zerocopy::FromBytes;

use crate::{
    IpStackState, StackDefinition, StackState,
    dpt::{InterfaceObjectType, PDT_UnsignedChar, PDT_UnsignedInt},
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, InterfaceObject,
        InterfaceObjectAugment, IpParameterObject, PropertyAccess, PropertyDescriptionResponse,
        PropertyDescriptor, PropertyError, PropertyServiceHandler, WriteResponse, pid,
    },
    objects::tables::{
        HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable,
        HasLoadStateMachine, HasPeiApplication, HasRunStateMachine,
    },
};
use crate::objects::interface::HasRoutingCount;

use super::SystemBObjects;

// ============================================================================
// TunnelingAugment
// ============================================================================

/// Augment that adds tunneling-related IP properties.
///
/// - PID 53: Additional Individual Addresses
/// - PID 79: Tunnelling Addresses (device-part view of PID 53 entries)
#[derive(Debug, Clone, Copy, Default)]
pub struct TunnelingAugment;

impl TunnelingAugment {
    const KNXNETIP_CAP_TUNNELING_BIT: u16 = 1 << 1;

    fn enabled(state: &impl IpStackState) -> bool {
        (state.knxnetip_device_capabilities() & Self::KNXNETIP_CAP_TUNNELING_BIT) != 0
    }

    fn descriptor(state: &impl IpStackState, prop_id: u8) -> Option<PropertyDescriptor> {
        let max_addrs = state.additional_individual_address_capacity() as u16;
        match prop_id {
            pid::ADDITIONAL_INDIVIDUAL_ADDRESSES => Some(PropertyDescriptor::array::<PDT_UnsignedInt>(
                prop_id,
                max_addrs,
                PropertyAccess::ReadWrite,
                3,
                3,
            )),
            pid::TUNNELLING_ADDRESSES => Some(PropertyDescriptor::array::<PDT_UnsignedChar>(
                prop_id,
                max_addrs,
                PropertyAccess::ReadOnly,
                3,
                3,
            )),
            _ => None,
        }
    }

    fn encode_addrs(
        state: &impl IpStackState,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        // Reinterpret the byte buffer as an address buffer (round to even length)
        // and write addresses directly into it — no intermediate stack buffer.
        // IndividualAddress is repr(transparent) over [u8; 2] with Unaligned,
        // so this reinterpretation is always valid.
        let addr_cap = buf.len() / 2;
        let addr_buf = <[crate::address::IndividualAddress]>::mut_from_bytes(&mut buf[..addr_cap * 2])
            .expect("IndividualAddress is Unaligned; length rounded to even");
        let addr_count = state.write_additional_individual_addresses(addr_buf);

        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&(addr_count as u16).to_be_bytes());
            return Ok(2);
        }

        if count == 0 {
            return Err(PropertyError::InvalidElementCount);
        }

        let start = (start_idx - 1) as usize;
        if start >= addr_count {
            return Err(PropertyError::InvalidStartIndex);
        }

        let end = (start + count as usize).min(addr_count);
        let needed = (end - start) * 2;
        if buf.len() < needed {
            return Err(PropertyError::BufferTooSmall);
        }

        // Shift the requested range to the front of the buffer. The addresses
        // were written starting at offset 0, so range [start..end] lives at
        // byte offsets [start*2 .. end*2].
        buf.copy_within(start * 2..end * 2, 0);
        Ok(needed)
    }

    fn decode_addrs(state: &impl IpStackState, start_idx: u16, data: &[u8]) -> Result<WriteResponse, PropertyError> {
        if start_idx != 1 {
            return Err(PropertyError::InvalidStartIndex);
        }

        // Reinterpret the raw bytes as a slice of IndividualAddress directly —
        // no intermediate heapless::Vec needed. IndividualAddress is
        // repr(transparent) over [u8; 2] with FromBytes + Unaligned.
        // ref_from_bytes fails if data.len() is not a multiple of 2.
        let addrs =
            <[crate::address::IndividualAddress]>::ref_from_bytes(data).map_err(|_| PropertyError::TypeMismatch)?;

        // The actual device capacity (N) is enforced by set_additional_individual_addresses().
        state.set_additional_individual_addresses(addrs).map_err(|_| PropertyError::WriteNotAllowed)?;
        Ok(WriteResponse::Echo)
    }

    fn encode_tunnelling_devices(
        state: &impl IpStackState,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        // Write all addresses into buf as raw [IndividualAddress] (2 bytes each),
        // then compact in-place to extract only the device byte from each.
        let addr_cap = buf.len() / 2;
        let addr_buf = <[crate::address::IndividualAddress]>::mut_from_bytes(&mut buf[..addr_cap * 2])
            .expect("IndividualAddress is Unaligned; length rounded to even");
        let addr_count = state.write_additional_individual_addresses(addr_buf);

        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&(addr_count as u16).to_be_bytes());
            return Ok(2);
        }

        if count == 0 {
            return Err(PropertyError::InvalidElementCount);
        }

        let start = (start_idx - 1) as usize;
        if start >= addr_count {
            return Err(PropertyError::InvalidStartIndex);
        }

        let end = (start + count as usize).min(addr_count);
        let needed = end - start;
        if buf.len() < needed {
            return Err(PropertyError::BufferTooSmall);
        }

        // Compact in-place: extract the device byte (offset 1 of each 2-byte
        // IndividualAddress). Source index ((start+i)*2 + 1) is always ahead of
        // dest index (i), so reads never alias with prior writes.
        for i in 0..needed {
            buf[i] = buf[(start + i) * 2 + 1];
        }

        Ok(needed)
    }
}

impl<S: StackState + IpStackState> InterfaceObjectAugment<S> for TunnelingAugment {
    fn property_description_read(
        &self,
        state: &S,
        object_type: InterfaceObjectType,
        object_idx: u16,
        prop_id: u8,
        _prop_idx: u8,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        if object_type != InterfaceObjectType::IPParameter {
            return None;
        }

        if !Self::enabled(state) {
            return None;
        }

        if prop_id == 0 {
            return None;
        }

        let desc = Self::descriptor(state, prop_id)?;
        Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &desc)))
    }

    fn property_value_read(
        &self,
        state: &S,
        object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        if object_type != InterfaceObjectType::IPParameter {
            return None;
        }

        if !Self::enabled(state) {
            return None;
        }

        let desc = Self::descriptor(state, req.pid)?;

        if !desc.can_read(req.ctx) {
            return Some(Err(PropertyError::AccessDenied));
        }

        Some(match req.pid {
            pid::ADDITIONAL_INDIVIDUAL_ADDRESSES => Self::encode_addrs(state, req.start_idx, req.count, buf),
            pid::TUNNELLING_ADDRESSES => Self::encode_tunnelling_devices(state, req.start_idx, req.count, buf),
            _ => Err(PropertyError::InvalidPropertyId),
        })
    }

    fn property_value_write(
        &self,
        state: &S,
        object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        if object_type != InterfaceObjectType::IPParameter {
            return None;
        }

        if !Self::enabled(state) {
            return None;
        }

        let desc = Self::descriptor(state, req.pid)?;

        if !desc.can_write(req.ctx) {
            return Some(Err(PropertyError::AccessDenied));
        }

        Some(match req.pid {
            pid::ADDITIONAL_INDIVIDUAL_ADDRESSES => Self::decode_addrs(state, req.start_idx, req.data),
            pid::TUNNELLING_ADDRESSES => Err(PropertyError::WriteNotAllowed),
            _ => Err(PropertyError::InvalidPropertyId),
        })
    }
}

// ============================================================================
// IpObjects
// ============================================================================

/// IP interface objects for KNX/IP devices (index 6).
///
/// Contains only the IP Parameter Object. Compose with [`SystemBObjects`]
/// using a tuple to create a complete KNX/IP device:
///
/// ```rust,ignore
/// let objects: (SystemBObjects<...>, IpObjects<...>) = (base, ip);
/// // objects.object_count() == 7
/// ```
///
/// The tuple's `PropertyServiceHandler` implementation automatically handles
/// index offsetting - IpObjects receives index 0 for what is logically index 6.
pub struct IpObjects<'a, S: StackState + IpStackState, A: InterfaceObjectAugment<S> = ()> {
    state: &'a S,
    ip_parameter: RefCell<IpParameterObject<'a, S>>,
    augment: A,
}

impl<'a, S: StackState + IpStackState> IpObjects<'a, S, ()> {
    /// Create new IP objects with no augmentation.
    pub fn new(state: &'a S) -> Self {
        Self::with_augment(state, ())
    }
}

impl<'a, S: StackState + IpStackState, A: InterfaceObjectAugment<S>> IpObjects<'a, S, A> {
    /// Number of interface objects in this container.
    pub const OBJECT_COUNT: u16 = 1;

    /// Create new IP objects with an augment chain.
    pub fn with_augment(state: &'a S, augment: A) -> Self {
        Self { state, ip_parameter: RefCell::new(IpParameterObject::with_state(state)), augment }
    }

    /// Get a reference to the IP Parameter Object.
    pub fn ip_parameter(&self) -> &RefCell<IpParameterObject<'a, S>> {
        &self.ip_parameter
    }

    /// Get the configured augment chain.
    pub fn augment(&self) -> &A {
        &self.augment
    }
}

impl<'a, S: StackState + IpStackState, A: InterfaceObjectAugment<S>> PropertyServiceHandler for IpObjects<'a, S, A> {
    fn object_count(&self) -> u16 {
        Self::OBJECT_COUNT
    }

    fn object_type_at(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        match object_idx {
            0 => Some(InterfaceObjectType::IPParameter),
            _ => None,
        }
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        if object_idx == 0 {
            if let Some(result) = self.augment.property_description_read(
                self.state,
                InterfaceObjectType::IPParameter,
                object_idx,
                prop_id,
                prop_idx,
            ) {
                return result;
            }
            // Note: We need to report the actual object index (5) in the response,
            // but the tuple impl calls us with 0. The caller handles this.
            self.ip_parameter.borrow().property_description(object_idx, prop_id, prop_idx)
        } else {
            Err(PropertyError::InvalidObjectIndex)
        }
    }

    fn property_value_read(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        if req.object_idx == 0 {
            if let Some(result) =
                self.augment.property_value_read(self.state, InterfaceObjectType::IPParameter, req, buf)
            {
                return result;
            }
            // Check access level
            if let Some((_, desc)) = self.ip_parameter.borrow().property_descriptor_by_id(req.pid) {
                if !desc.can_read(req.ctx) {
                    return Err(PropertyError::AccessDenied);
                }
            } else {
                return Err(PropertyError::InvalidPropertyId);
            }
            self.ip_parameter.borrow().read_property(req.property_request(), buf)
        } else {
            Err(PropertyError::InvalidObjectIndex)
        }
    }

    fn property_value_write(&self, req: &FullPropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        if req.object_idx == 0 {
            if let Some(result) = self.augment.property_value_write(self.state, InterfaceObjectType::IPParameter, req) {
                if result.is_ok() {
                    self.state.mark_dirty();
                }
                return result;
            }
            // Check access level
            if let Some((_, desc)) = self.ip_parameter.borrow().property_descriptor_by_id(req.pid) {
                if !desc.can_write(req.ctx) {
                    return Err(PropertyError::AccessDenied);
                }
            } else {
                return Err(PropertyError::InvalidPropertyId);
            }
            let result = self.ip_parameter.borrow_mut().write_property(req.property_request());
            if result.is_ok() {
                self.state.mark_dirty();
            }
            result
        } else {
            Err(PropertyError::InvalidObjectIndex)
        }
    }
}

// ============================================================================
// KNX/IP Interface Objects - Composed Type Aliases
// ============================================================================

/// Interface objects for KNX/IP devices (57B0).
///
/// This is a type alias for the tuple `(SystemBObjects, IpObjects)`.
/// The tuple's `PropertyServiceHandler` and `HasDeviceObject` implementations
/// automatically handle dispatch to the appropriate component.
///
/// Contains 7 interface objects:
/// - Device Object (index 0)
/// - Address Table Object (index 1)
/// - Association Table Object (index 2)
/// - Group Object Table Object (index 3)
/// - Application Program Object (index 4)
/// - PEI Program Object (index 5)
/// - IP Parameter Object (index 6)
pub type KnxIpInterfaceObjects<'a, S, ADT, AST, COT, APP, PEI, A = ()> =
    (SystemBObjects<'a, S, ADT, AST, COT, APP, PEI>, IpObjects<'a, S, A>);

/// Convenience alias that fills in the GAT projections automatically.
///
/// Equivalent to `KnxIpInterfaceObjects` with all table types inferred
/// from `S`'s `Has*Table` implementations. Use this in
/// [`StackDefinition::InterfaceObjects`](crate::StackDefinition) to avoid
/// spelling out 5 associated type projections manually.
pub type DefaultKnxIpInterfaceObjects<'a, S, A = ()> = KnxIpInterfaceObjects<
    'a,
    S,
    <S as HasAddressTable>::ADT,
    <S as HasAssociationTable>::AST,
    <S as HasCommunicationObjectTable>::COT,
    <S as HasApplication>::APP,
    <S as HasPeiApplication>::PEI,
    A,
>;

// ============================================================================
// KNX/IP Helper Functions
// ============================================================================

/// Create KNX/IP interface objects (7 objects: indices 0-6).
///
/// Use this function in your `StackDefinition::create_interface_objects` implementation
/// for KNX/IP System B devices (57B0).
pub fn create_knxip_objects<'a, D, S>(
    state: &'a S,
    layout: &crate::bcus::system_b::memory_map::MemoryLayout,
) -> KnxIpInterfaceObjects<'a, S, S::ADT, S::AST, S::COT, S::APP, S::PEI>
where
    D: StackDefinition,
    S: StackState
        + IpStackState
        + HasAddressTable
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasApplication
        + HasPeiApplication
        + HasRoutingCount,
    S::ADT: HasLoadStateMachine,
    S::AST: HasLoadStateMachine,
    S::COT: HasLoadStateMachine,
    S::APP: HasLoadStateMachine + HasRunStateMachine,
    S::PEI: HasLoadStateMachine + HasRunStateMachine,
{
    let base = super::create_system_b_objects::<D, S>(state, layout);
    let ip = IpObjects::new(state);
    (base, ip)
}

/// Create KNX/IP interface objects with an explicit augment chain.
pub fn create_knxip_objects_with_augment<'a, D, S, A>(
    state: &'a S,
    layout: &crate::bcus::system_b::memory_map::MemoryLayout,
    augment: A,
) -> KnxIpInterfaceObjects<'a, S, S::ADT, S::AST, S::COT, S::APP, S::PEI, A>
where
    D: StackDefinition,
    S: StackState
        + IpStackState
        + HasAddressTable
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasApplication
        + HasPeiApplication
        + HasRoutingCount,
    S::ADT: HasLoadStateMachine,
    S::AST: HasLoadStateMachine,
    S::COT: HasLoadStateMachine,
    S::APP: HasLoadStateMachine + HasRunStateMachine,
    S::PEI: HasLoadStateMachine + HasRunStateMachine,
    A: InterfaceObjectAugment<S>,
{
    let base = super::create_system_b_objects::<D, S>(state, layout);
    let ip = IpObjects::with_augment(state, augment);
    (base, ip)
}

/// Create KNX/IP interface objects with built-in tunneling property augmentation.
pub fn create_knxip_tunneling_objects<'a, D, S>(
    state: &'a S,
    layout: &crate::bcus::system_b::memory_map::MemoryLayout,
) -> KnxIpInterfaceObjects<'a, S, S::ADT, S::AST, S::COT, S::APP, S::PEI, (TunnelingAugment, ())>
where
    D: StackDefinition,
    S: StackState
        + IpStackState
        + HasAddressTable
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasApplication
        + HasPeiApplication
        + HasRoutingCount,
    S::ADT: HasLoadStateMachine,
    S::AST: HasLoadStateMachine,
    S::COT: HasLoadStateMachine,
    S::APP: HasLoadStateMachine + HasRunStateMachine,
    S::PEI: HasLoadStateMachine + HasRunStateMachine,
{
    create_knxip_objects_with_augment::<D, S, _>(state, layout, (TunnelingAugment, ()))
}
