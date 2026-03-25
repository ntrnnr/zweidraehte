//! TP1-specific interface object augment.
//!
//! Adds PID_MAX_RETRY_COUNT (PID 52) to the Device Object for TP1 devices.
//! This is a data property (not a function property) containing the DLL
//! retry parameters: busy_retry (bits 6-4) and nak_retry (bits 2-0).

use crate::dpt::{InterfaceObjectType, PDT_Generic01};
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, HasMaxRetryCount, InterfaceObjectAugment,
    PropertyAccess, PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup,
    WriteResponse, pid,
};
use crate::StackState;

/// Augment that adds PID_MAX_RETRY_COUNT to the Device Object on TP1 devices.
///
/// Wire this into your `StackDefinition` by passing it as the augment parameter
/// to [`create_system_b_objects`](super::create_system_b_objects):
///
/// ```rust,ignore
/// type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<'a, MyState, Tp1Augment>;
///
/// fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a> {
///     create_system_b_objects::<Self, _, _>(state, &Self::memory_layout(), Tp1Augment)
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Tp1Augment;

impl<S: StackState + HasMaxRetryCount> InterfaceObjectAugment<S> for Tp1Augment {
    fn property_description_read(
        &self,
        _state: &S,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        if object_type != InterfaceObjectType::Device {
            return None;
        }

        if !matches!(
            lookup,
            PropertyLookup::ByPid(pid::MAX_RETRY_COUNT) | PropertyLookup::ByIndex(0)
        ) {
            return None;
        }

        let desc = PropertyDescriptor::from_type::<PDT_Generic01>(
            pid::MAX_RETRY_COUNT,
            PropertyAccess::ReadWrite,
            3, // read level: unrestricted
            3, // write level: unrestricted
        );
        Some(Ok(PropertyDescriptionResponse::from_descriptor(
            object_idx,
            0,
            &desc,
        )))
    }

    fn property_value_read(
        &self,
        state: &S,
        object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        if object_type != InterfaceObjectType::Device || req.pid != pid::MAX_RETRY_COUNT {
            return None;
        }

        // Element count query (start_idx=0 per KNX spec).
        if req.start_idx == 0 {
            if buf.len() < 2 {
                return Some(Err(PropertyError::BufferTooSmall));
            }
            buf[0] = 0;
            buf[1] = 1; // Single element
            return Some(Ok(2));
        }

        // Non-array data property: start_idx must be 1, count must be 1.
        if req.start_idx != 1 || req.count != 1 {
            return Some(Err(PropertyError::InvalidStartIndex));
        }

        if buf.is_empty() {
            return Some(Err(PropertyError::BufferTooSmall));
        }

        buf[0] = state.max_retry_count();
        Some(Ok(1))
    }

    fn property_value_write(
        &self,
        state: &S,
        object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        if object_type != InterfaceObjectType::Device || req.pid != pid::MAX_RETRY_COUNT {
            return None;
        }

        if req.data.is_empty() {
            return Some(Err(PropertyError::TypeMismatch));
        }

        state.set_max_retry_count(req.data[0]);
        Some(Ok(WriteResponse::Echo))
    }
}
