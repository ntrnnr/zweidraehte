//! Tunnelling extension: persistent storage for additional individual
//! addresses + augment for the two tunnelling-conditional PIDs on the
//! IP Parameter Object (Type 11).
//!
//! Devices that need KNXnet/IP tunnelling include both
//! [`IpExtensionState`](super::ip::IpExtensionState) and
//! [`TunnellingExtension`] in their state. The IP extension owns the
//! always-present IP PIDs; this extension owns the const-generic-`N`
//! sized address list and dispatches:
//!
//! - **`PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`** (PID 53) — read/write
//!   array of [`IndividualAddress`] (2 bytes per element).
//! - **`PID_TUNNELLING_ADDRESSES`** (PID 79) — read-only;
//!   `RESTRICTED` access policy.
//!
//! Both PIDs follow the KNX array-property convention where
//! `start_idx == 0` returns the current element count and
//! `start_idx >= 1` reads/writes elements at the given offset. The
//! reads also reinterpret the buffer as `[IndividualAddress]` via
//! zerocopy — neither pattern fits the macro's standard
//! `PropertyRead` / `PropertyWrite` framing, so both PIDs are
//! declared `manual` and routed through
//! [`handle_extra_pid_read`](TunnellingAugment::handle_extra_pid_read)
//! / [`handle_extra_pid_write`](TunnellingAugment::handle_extra_pid_write).
//! The macro still emits their descriptors into the static
//! `DESCRIPTORS` table — no parallel `handle_extra_pid_descriptor` —
//! because [`array(max = N as u16)`](crate::objects::interface::interface_object_augment)
//! now accepts the const generic.

use core::cell::RefCell;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zerocopy::FromBytes;

use crate::HasSecurityMode;
use crate::StackDefinition;
use crate::bcus::system_b::{Extension, ExtensionConfig, ExtensionState};
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, PropertyDescriptor, PropertyError, WritablePropertyValueArray,
    WriteResponse, interface_object_augment, pid,
};
use crate::restart::EraseCode;
use crate::service::ServiceCtx;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_UnsignedChar, PDT_UnsignedInt};

// ============================================================================
// Persisted Config
// ============================================================================

/// Persisted list of additional individual addresses.
///
/// `N` is the maximum number of slots; the actual populated count is
/// `additional_individual_addresses_len`. Trailing slots beyond that
/// length carry zeroes and are ignored on load.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnellingExtensionConfig<const N: usize> {
    #[serde_as(as = "[[_; 2]; N]")]
    pub additional_individual_addresses: [[u8; 2]; N],
    pub additional_individual_addresses_len: u8,
}

impl<const N: usize> Default for TunnellingExtensionConfig<N> {
    fn default() -> Self {
        Self { additional_individual_addresses: [[0; 2]; N], additional_individual_addresses_len: 0 }
    }
}

impl<const N: usize> ExtensionConfig for TunnellingExtensionConfig<N> {}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime tunnelling state with interior mutability.
///
/// Holds the additional individual address table, sized at compile time
/// by the const generic `N` (the link layer's tunnelling capacity —
/// e.g. `<KnxIpInterfaceUdp<4>>::Tunneling::CAPACITY` is `4`).
///
/// The dispatch for PIDs 53 and 79 is provided by [`TunnellingAugment`],
/// which borrows this state.
pub struct TunnellingExtension<const N: usize> {
    additional_individual_addresses: RefCell<heapless::Vec<IndividualAddress, N>>,
}

impl<const N: usize> TunnellingExtension<N> {
    /// Maximum number of additional individual address slots (the const
    /// generic `N`).
    pub const CAPACITY: usize = N;

    /// Number of currently populated address slots.
    pub fn count(&self) -> usize {
        self.additional_individual_addresses.borrow().len()
    }

    /// Copy the populated addresses into `buf`. Returns the number of
    /// addresses actually written (`<= buf.len()` and `<= count()`).
    pub fn write_into(&self, buf: &mut [IndividualAddress]) -> usize {
        let stored = self.additional_individual_addresses.borrow();
        let n = stored.len().min(buf.len());
        buf[..n].copy_from_slice(&stored[..n]);
        n
    }

    /// Whether `addr` is currently in the additional-IA list.
    pub fn contains(&self, addr: IndividualAddress) -> bool {
        self.additional_individual_addresses.borrow().contains(&addr)
    }

    /// Replace the entire address list. Returns `Err(())` if `addrs`
    /// exceeds the compile-time capacity.
    // Capacity is the only failure mode, and callers only need success or
    // failure. A dedicated public error type would carry no extra information.
    #[allow(clippy::result_unit_err)]
    pub fn set(&self, addrs: &[IndividualAddress]) -> Result<(), ()> {
        if addrs.len() > N {
            return Err(());
        }
        let mut vec = heapless::Vec::<IndividualAddress, N>::new();
        for &addr in addrs {
            vec.push(addr).map_err(|_| ())?;
        }
        *self.additional_individual_addresses.borrow_mut() = vec;
        Ok(())
    }
}

// ============================================================================
// ExtensionState
// ============================================================================

impl<const N: usize> HasGoSecurityView for TunnellingExtension<N> {}

impl<const N: usize> HasSecurityMode for TunnellingExtension<N> {}

impl<const N: usize> ExtensionState for TunnellingExtension<N> {
    type Config = TunnellingExtensionConfig<N>;
    type Resources = ();

    fn from_config(config: TunnellingExtensionConfig<N>, _resources: ()) -> Self {
        let mut additional = heapless::Vec::<IndividualAddress, N>::new();
        for raw in config
            .additional_individual_addresses
            .iter()
            .take((config.additional_individual_addresses_len as usize).min(N))
        {
            let _ = additional.push(IndividualAddress::from_bytes(raw));
        }
        Self { additional_individual_addresses: RefCell::new(additional) }
    }

    fn to_config(&self) -> TunnellingExtensionConfig<N> {
        let stored = self.additional_individual_addresses.borrow();
        let mut raw = [[0u8; 2]; N];
        for (idx, addr) in stored.iter().enumerate() {
            raw[idx].copy_from_slice(addr.as_bytes());
        }
        TunnellingExtensionConfig {
            additional_individual_addresses: raw,
            additional_individual_addresses_len: stored.len() as u8,
        }
    }

    fn on_erase(&self, code: EraseCode) {
        if matches!(code, EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA) {
            self.additional_individual_addresses.borrow_mut().clear();
        }
    }
}

// ============================================================================
// Augment
// ============================================================================

/// Augment for the IP Parameter Object's tunnelling-conditional PIDs.
///
/// Owns PIDs 53 (`ADDITIONAL_INDIVIDUAL_ADDRESSES`) and 79
/// (`TUNNELLING_ADDRESSES`). Both are array properties whose
/// `max_elements` is the const generic `N` carried from the
/// [`TunnellingExtension`] this augment borrows.
///
/// The descriptors are emitted into the static `DESCRIPTORS` table by
/// the macro (the `array(max = N as u16)` form propagates the const
/// generic). Value reads and writes are declared `manual` because both
/// PIDs use bespoke buffer manipulation: the KNX array protocol's
/// `start_idx == 0 → return-count` branch, zerocopy reinterpretation
/// of `[IndividualAddress]`, and read-modify-write across arbitrary
/// indices for PID 53. The dispatch lives in
/// [`handle_extra_pid_read`](Self::handle_extra_pid_read) and
/// [`handle_extra_pid_write`](Self::handle_extra_pid_write).
//
// `target_objects = [IPParameter]` — this augment is a peer of
// `IpAugment` on Object Type 11. The `ServiceRegistry` chain on the
// outer device-side `Augments` struct walks both peers; first match
// wins. Since the two augments own disjoint PIDs, ordering is
// irrelevant for correctness.
#[interface_object_augment(target_objects = [InterfaceObjectType::IPParameter])]
pub struct TunnellingAugment<'a, const N: usize> {
    /// Borrowed reference to the persisted state. The augment is
    /// constructed once per dispatch via
    /// [`Extension::create_augment`](crate::bcus::system_b::Extension::create_augment).
    pub state: &'a TunnellingExtension<N>,

    // PID 53 — PID_ADDITIONAL_INDIVIDUAL_ADDRESSES. AN193
    // §"Object Type 11" lists `3FF/0CC` (READ_OPEN_WRITE_TOOL).
    //
    // The descriptor's `max_elements` comes from the const generic
    // `N`; `manual` skips arm generation for the value read/write
    // path, which is implemented in `handle_extra_pid_read` /
    // `handle_extra_pid_write` below.
    #[io(pid = pid::ip::ADDITIONAL_INDIVIDUAL_ADDRESSES, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime,
         array(max = N as u16), manual)]
    _additional_individual_addresses_io: (),

    // PID 79 — PID_TUNNELLING_ADDRESSES. AN193 §"Object Type 11"
    // lists `15F/04C` (RESTRICTED): the tunnelling-client list is
    // security-sensitive, so plain unlisted reads are forbidden once
    // Security Mode is on.
    //
    // The write level is decorative — `PropertyAccess::ReadOnly` is
    // checked before it in `PropertyDescriptor::can_write` — and stays
    // at the `Runtime` that Annex A's `3` denotes so the reported
    // descriptor keeps its current value.
    #[io(pid = pid::ip::TUNNELLING_ADDRESSES, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::RESTRICTED, rl = Runtime, wl = Runtime,
         array(max = N as u16), manual)]
    _tunnelling_addresses_io: (),
}

impl<'a, const N: usize> TunnellingAugment<'a, N> {
    /// Create a new augment borrowing the given state.
    pub fn new(state: &'a TunnellingExtension<N>) -> Self {
        Self { state }
    }
}

// ----------------------------------------------------------------------------
// Manual dispatch — array-property reads and writes for PIDs 53 & 79.
// ----------------------------------------------------------------------------
//
// Both PIDs follow the KNX array-property convention: `start_idx == 0`
// returns the current element count as a 16-bit big-endian value;
// `start_idx >= 1` reads or writes elements at that 1-based offset.
// Reads of PID 53 hand back the addresses verbatim (zerocopy
// reinterpretation of `[IndividualAddress]`); reads of PID 79 return
// only the second byte of each address per the KNX spec.

struct AdditionalAddressesPropertyArray<'a, const N: usize> {
    state: &'a TunnellingExtension<N>,
}

impl<const N: usize> WritablePropertyValueArray for AdditionalAddressesPropertyArray<'_, N> {
    fn element_size(&self) -> usize {
        2
    }

    fn current_element_count(&self) -> u16 {
        self.state.count() as u16
    }

    fn maximum_element_count(&self) -> u16 {
        u16::try_from(N).unwrap_or(u16::MAX)
    }

    fn set_element_count(&mut self, count: u16) -> Result<(), PropertyError> {
        let mut addresses = [IndividualAddress::default(); N];
        self.state.write_into(&mut addresses);
        self.state.set(&addresses[..usize::from(count)]).map_err(|_| PropertyError::WriteNotAllowed)
    }

    fn write_element_range(&mut self, start: u16, data: &[u8], resulting_count: u16) -> Result<(), PropertyError> {
        let new_addresses = <[IndividualAddress]>::ref_from_bytes(data).map_err(|_| PropertyError::TypeMismatch)?;
        let mut addresses = [IndividualAddress::default(); N];
        self.state.write_into(&mut addresses);

        let start = usize::from(start);
        let end = start + new_addresses.len();
        addresses[start..end].copy_from_slice(new_addresses);

        self.state.set(&addresses[..usize::from(resulting_count)]).map_err(|_| PropertyError::WriteNotAllowed)
    }
}

impl<const N: usize> TunnellingAugment<'_, N> {
    fn read_additional_addrs(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        // The response buffer may hold only the requested suffix. Determine
        // the active count from the state itself rather than using that small
        // buffer as temporary storage; otherwise a count probe reports at most
        // one address and reads starting later in the array fail spuriously.
        let mut addresses = [IndividualAddress::default(); N];
        let addr_count = self.state.write_into(&mut addresses);

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

        for (offset, address) in addresses[start..end].iter().enumerate() {
            buf[offset * 2..offset * 2 + 2].copy_from_slice(address.as_bytes());
        }

        Ok(needed)
    }

    fn write_additional_addrs(&self, start_idx: u16, data: &[u8]) -> Result<WriteResponse, PropertyError> {
        let mut array = AdditionalAddressesPropertyArray { state: self.state };
        array.write_property_value(start_idx, data)?;

        Ok(WriteResponse::Echo)
    }

    fn read_tunnelling_devices(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let mut addresses = [IndividualAddress::default(); N];
        let addr_count = self.state.write_into(&mut addresses);

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

        for i in 0..needed {
            buf[i] = addresses[start + i].as_bytes()[1];
        }

        Ok(needed)
    }
}

// ----------------------------------------------------------------------------
// Manual fallback thunks — invoked by the macro-generated dispatch.
// ----------------------------------------------------------------------------
//
// The macro emits an unconditional call to
// `handle_extra_pid_descriptor` whenever any PID is declared `manual`,
// even when (as here) every descriptor lives in the static
// `DESCRIPTORS` table. We just answer `None` so the static lookup
// remains authoritative.

impl<const N: usize> TunnellingAugment<'_, N> {
    pub fn handle_extra_pid_descriptor(
        &self,
        _object_type: InterfaceObjectType,
        _prop_id: u16,
    ) -> Option<PropertyDescriptor> {
        None
    }

    pub fn handle_extra_pid_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        Some(match req.pid {
            pid::ip::ADDITIONAL_INDIVIDUAL_ADDRESSES => self.read_additional_addrs(req.start_idx, req.count, buf),
            pid::ip::TUNNELLING_ADDRESSES => self.read_tunnelling_devices(req.start_idx, req.count, buf),
            _ => return None,
        })
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        Some(match req.pid {
            pid::ip::ADDITIONAL_INDIVIDUAL_ADDRESSES => self.write_additional_addrs(req.start_idx, req.data),
            pid::ip::TUNNELLING_ADDRESSES => Err(PropertyError::WriteNotAllowed),
            _ => return None,
        })
    }
}

// ============================================================================
// Extension — produces the augment from the borrowed state
// ============================================================================

impl<const N: usize> Extension<()> for TunnellingExtension<N> {
    type Augment<'a, D: StackDefinition>
        = TunnellingAugment<'a, N>
    where
        Self: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, _platform: &'a ()) -> Self::Augment<'a, D>
    where
        (): 'a,
    {
        TunnellingAugment::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> TunnellingExtension<4> {
        TunnellingExtension::from_config(TunnellingExtensionConfig::default(), ())
    }

    #[test]
    fn additional_address_count_zero_resets_the_array() {
        let state = state();
        state.set(&[IndividualAddress::new(1, 1, 10)]).expect("one address fits");
        let mut array = AdditionalAddressesPropertyArray { state: &state };

        array.write_property_value(0, &[0, 0]).expect("zero resets a writable array");

        assert_eq!(state.count(), 0);
    }

    #[test]
    fn additional_address_write_beyond_the_tail_extends_its_count() {
        let state = state();
        let mut array = AdditionalAddressesPropertyArray { state: &state };
        let address = IndividualAddress::new(1, 1, 10);

        array.write_property_value(2, address.as_bytes()).expect("the second address fits");

        let mut addresses = [IndividualAddress::default(); 4];
        assert_eq!(state.write_into(&mut addresses), 2);
        assert_eq!(addresses[0], IndividualAddress::default());
        assert_eq!(addresses[1], address);
    }

    #[test]
    fn small_buffers_can_probe_and_read_the_address_list_tail() {
        let state = state();
        let addresses =
            [IndividualAddress::new(1, 1, 10), IndividualAddress::new(1, 1, 11), IndividualAddress::new(1, 1, 12)];
        state.set(&addresses).expect("three addresses fit");
        let augment = TunnellingAugment::new(&state);

        let mut count = [0u8; 2];
        augment.read_additional_addrs(0, 1, &mut count).expect("the count fits");
        assert_eq!(count, [0, 3]);

        let mut additional = [0u8; 2];
        augment.read_additional_addrs(3, 1, &mut additional).expect("the third address fits");
        assert_eq!(additional, *addresses[2].as_bytes());

        let mut tunnelling = [0u8; 1];
        augment.read_tunnelling_devices(3, 1, &mut tunnelling).expect("the third device index fits");
        assert_eq!(tunnelling, [addresses[2].as_bytes()[1]]);
    }
}
