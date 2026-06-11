//! `IpAugment` and its `Augment<D>` implementation.
//!
//! [`IpAugment`] is a passive bundle of two borrows — `config: &IpExtensionState`
//! for persisted ETS-programmable IP parameters and `platform: &P` for
//! current platform/OS network state. The macro-generated property
//! dispatch reads and writes those references directly; the augment
//! itself carries no behaviour beyond storing the two pointers.
//!
//! Tunnelling-only PIDs (53 `ADDITIONAL_INDIVIDUAL_ADDRESSES`,
//! 79 `TUNNELLING_ADDRESSES`) are *not* owned by this augment; they
//! live on [`TunnellingAugment`](super::TunnellingAugment), composed
//! alongside `IpAugment` via
//! [`IpInterfaceExtension`](super::IpInterfaceExtension) on
//! tunnelling-capable devices.

use core::net::Ipv4Addr;

use crate::{
    IpPlatform, IpStateView, StackDefinition, StackState,
    objects::interface::{
        FullPropertyWriteRequest, Ipv4Property, PropertyError, StatePropertyValue, WriteResponse,
        interface_object_augment, pid,
    },
    service::ServiceCtx,
};
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_Bitset8, PDT_Bitset16, PDT_Generic06, PDT_UnsignedChar, PDT_UnsignedInt,
};

use super::IpExtensionState;

// ============================================================================
// IpAugment — combines config + platform
// ============================================================================

/// Combines an [`IpExtensionState`] reference (persisted config) with a
/// platform reference (current network values) for property dispatch.
///
/// Implements [`Augment<D>`](crate::service::Augment)
/// to provide the IP Parameter Object (Type 11) with all IP PIDs
/// including tunneling.
///
/// PID 68 (`KNXNETIP_DEVICE_CAPABILITIES`) is read from the extension
/// state, which the stack sets on boot from
/// [`LinkLayerCapabilities`](crate::layers::LinkLayerCapabilities).
///
/// # Construction
///
/// Normally created automatically via the [`Extension`](crate::bcus::system_b::Extension)
/// trait. Manual construction is still possible:
///
/// ```rust,ignore
/// let augment = IpAugment::new(state.extension_state(), platform);
/// ```
// Macro: declare every base IP PID's descriptor metadata. Most PIDs
// dispatch through inline `read` / `write` (or `*_with_ctx`) closures
// adjacent to the descriptor — keeping the descriptor and the
// behaviour in one place so the two cannot drift. One PID stays
// `manual`:
//
// - `FRIENDLY_NAME` — read-modify-write across an arbitrary
//   array-index range with custom length tracking that the closure →
//   `PropertyRead` / `PropertyWrite` framing can't express.
//
// `additional_objects` lists `IPParameter`: the augment owns the IP
// Parameter Object (it adds it to the device's IO list) and dispatches
// PIDs targeting that same object.
#[interface_object_augment(
    additional_objects = [InterfaceObjectType::IPParameter],
    where_bounds(D::State: StackState),
)]
pub struct IpAugment<'a, P: IpPlatform, const CAPS: u16 = 0> {
    /// Persisted IP configuration (from extension state).
    pub config: &'a IpExtensionState<CAPS>,
    /// Platform for querying current network values.
    pub platform: &'a P,

    // ---- Base IP Parameter Object PIDs ----
    #[io(pid = pid::OBJECT_TYPE, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |_this: &Self| -> [u8; 2] {
             let v: u16 = InterfaceObjectType::IPParameter.into();
             v.to_be_bytes()
         })]
    _object_type_io: (),

    #[io(pid = pid::ip::PROJECT_INSTALLATION_ID, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 2] { this.config.project_installation_id().to_be_bytes() },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <PDT_UnsignedInt as StatePropertyValue>::from_bytes(data)?;
             this.config.set_project_installation_id(v);
             Ok(WriteResponse::Echo)
         })]
    _project_installation_id_io: (),

    // KNX_INDIVIDUAL_ADDRESS lives on the device state, not the IP config,
    // so it needs `ctx.state` access on both sides.
    #[io(pid = pid::ip::KNX_INDIVIDUAL_ADDRESS, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read_with_ctx = |_this: &Self, ctx: &ServiceCtx<'_, D>| -> [u8; 2] {
             ctx.state.individual_address().0
         },
         write_with_ctx = |_this: &Self, ctx: &ServiceCtx<'_, D>, req: &FullPropertyWriteRequest<'_>|
             -> Result<WriteResponse, PropertyError>
         {
             if req.data.len() < 2 {
                 return Err(PropertyError::BufferTooSmall);
             }
             ctx.state.set_individual_address(IndividualAddress::from_bytes(req.data));
             Ok(WriteResponse::Echo)
         })]
    _knx_individual_address_io: (),

    #[io(pid = pid::ip::CURRENT_IP_ASSIGNMENT_METHOD, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 1] { [this.platform.current_ip_assignment_method()] })]
    _current_ip_assignment_method_io: (),

    #[io(pid = pid::ip::IP_ASSIGNMENT_METHOD, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 1] { [this.config.ip_assignment_method()] },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <PDT_UnsignedChar as StatePropertyValue>::from_bytes(data)?;
             this.config.set_ip_assignment_method(v);
             Ok(WriteResponse::Echo)
         })]
    _ip_assignment_method_io: (),

    #[io(pid = pid::ip::IP_CAPABILITIES, pdt = PDT_Bitset8, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 1] { [this.platform.ip_capabilities()] })]
    _ip_capabilities_io: (),

    #[io(pid = pid::ip::CURRENT_IP_ADDRESS, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.platform.current_ip_address()) })]
    _current_ip_address_io: (),

    #[io(pid = pid::ip::CURRENT_SUBNET_MASK, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.platform.current_subnet_mask()) })]
    _current_subnet_mask_io: (),

    #[io(pid = pid::ip::CURRENT_DEFAULT_GATEWAY, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.platform.current_default_gateway()) })]
    _current_default_gateway_io: (),

    #[io(pid = pid::ip::IP_ADDRESS, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.config.configured_ip_address()) },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <Ipv4Property as StatePropertyValue>::from_bytes(data)?;
             this.config.set_configured_ip_address(v);
             Ok(WriteResponse::Echo)
         })]
    _ip_address_io: (),

    #[io(pid = pid::ip::SUBNET_MASK, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.config.configured_subnet_mask()) },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <Ipv4Property as StatePropertyValue>::from_bytes(data)?;
             this.config.set_configured_subnet_mask(v);
             Ok(WriteResponse::Echo)
         })]
    _subnet_mask_io: (),

    #[io(pid = pid::ip::DEFAULT_GATEWAY, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.config.configured_default_gateway()) },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <Ipv4Property as StatePropertyValue>::from_bytes(data)?;
             this.config.set_configured_default_gateway(v);
             Ok(WriteResponse::Echo)
         })]
    _default_gateway_io: (),

    #[io(pid = pid::ip::MAC_ADDRESS, pdt = PDT_Generic06, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 6] { this.platform.mac_address() })]
    _mac_address_io: (),

    #[io(pid = pid::ip::SYSTEM_SETUP_MULTICAST_ADDRESS, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |_this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&SYSTEM_SETUP_MULTICAST) })]
    _system_setup_multicast_address_io: (),

    #[io(pid = pid::ip::ROUTING_MULTICAST_ADDRESS, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.config.routing_multicast_address()) },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <Ipv4Property as StatePropertyValue>::from_bytes(data)?;
             this.config.set_routing_multicast_address(v);
             Ok(WriteResponse::Echo)
         })]
    _routing_multicast_address_io: (),

    #[io(pid = pid::ip::TTL, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 1] { [this.config.ttl()] },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <PDT_UnsignedChar as StatePropertyValue>::from_bytes(data)?;
             this.config.set_ttl(v);
             Ok(WriteResponse::Echo)
         })]
    _ttl_io: (),

    #[io(pid = pid::ip::KNXNETIP_DEVICE_CAPABILITIES, pdt = PDT_Bitset16, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 2] { this.knxnetip_device_capabilities().to_be_bytes() })]
    _knxnetip_device_capabilities_io: (),

    // PID_FRIENDLY_NAME — array property (max 30 bytes). `manual` because
    // the read/write does its own count-probe + arbitrary-index handling
    // that the generic `PropertyRead` / `PropertyWrite` framing doesn't
    // accommodate.
    #[io(pid = pid::ip::FRIENDLY_NAME, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         array(max = 30), manual)]
    _friendly_name_io: (),
    // Tunnelling-conditional PIDs (53, 79). The descriptor for these is
    // built at lookup time in `handle_extra_pid_descriptor` because the
    // `max_elements` value comes from the const-generic `N`. They are
    // *not* listed in the macro's static descriptor table.
}

impl<'a, P: IpPlatform, const CAPS: u16> IpAugment<'a, P, CAPS> {
    /// Create a new `IpAugment` combining config and platform references.
    ///
    /// PID 68 (device capabilities) is a compile-time constant from the
    /// `CAPS` const generic, which propagates from
    /// [`IpExtensionState<CAPS>`](IpExtensionState).
    pub fn new(config: &'a IpExtensionState<CAPS>, platform: &'a P) -> Self {
        Self { config, platform }
    }

    /// KNXnet/IP device capabilities bitfield (PID 68).
    ///
    /// Compile-time constant from the `CAPS` const generic.
    pub const fn knxnetip_device_capabilities(&self) -> u16 {
        CAPS
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Default KNX System Setup multicast address: 224.0.23.12
const SYSTEM_SETUP_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

// ============================================================================
// FRIENDLY_NAME (manual)
// ============================================================================
//
// `PID_FRIENDLY_NAME` is an array property up to 30 bytes whose
// `start_idx == 0` branch returns the current length as a 16-bit
// big-endian word, while `start_idx >= 1` reads or writes a slice of
// the byte array. That start-index-zero count branch can't be
// expressed by the macro's `read` / `read_with_ctx` closures (their
// return type must satisfy `PropertyRead`, which has a single
// (start_idx, count) → bytes shape), so the PID is declared `manual`
// and dispatched here. The descriptor still lives in the static
// `DESCRIPTORS` table — `array(max = 30)` is a literal — so there's
// no parallel descriptor lookup.

impl<P: IpPlatform, const CAPS: u16> IpAugment<'_, P, CAPS> {
    fn read_friendly_name(
        &self,
        req: &crate::objects::interface::FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        let name = self.config.friendly_name();
        let len = self.config.friendly_name_len();

        if req.start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&(len as u16).to_be_bytes());
            return Ok(2);
        }

        let start = (req.start_idx - 1) as usize;
        if start >= len {
            return Err(PropertyError::InvalidStartIndex);
        }
        let end = (start + req.count as usize).min(len);
        let needed = end - start;
        if buf.len() < needed {
            return Err(PropertyError::BufferTooSmall);
        }
        buf[..needed].copy_from_slice(&name[start..end]);
        Ok(needed)
    }

    fn write_friendly_name(&self, req: &FullPropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        if req.start_idx == 0 || req.data.is_empty() {
            return Err(PropertyError::InvalidStartIndex);
        }

        // Read-modify-write: KNX array properties support writes at
        // arbitrary indices within the array.
        let mut name = self.config.friendly_name();
        let mut len = self.config.friendly_name_len();

        let start = (req.start_idx - 1) as usize;
        let end = (start + req.data.len()).min(30);
        if start >= 30 {
            return Err(PropertyError::InvalidStartIndex);
        }

        name[start..end].copy_from_slice(&req.data[..end - start]);

        // Extend the length if we wrote past the current end.
        if end > len {
            len = end;
        }

        self.config.set_friendly_name(&name[..len]);
        Ok(WriteResponse::Echo)
    }
}

// ============================================================================
// Manual fallback thunks invoked by the macro-generated dispatch.
// ============================================================================
//
// `handle_extra_pid_descriptor` is a stub — `FRIENDLY_NAME`'s
// descriptor lives in the static `DESCRIPTORS` table, and `IpAugment`
// has no other runtime-conditional descriptors. The method exists
// only because the `interface_object_augment` codegen unconditionally
// emits a call into it whenever any PID is declared `manual`.

impl<P: IpPlatform, const CAPS: u16> IpAugment<'_, P, CAPS> {
    pub fn handle_extra_pid_descriptor(
        &self,
        _object_type: InterfaceObjectType,
        _prop_id: u16,
    ) -> Option<crate::objects::interface::PropertyDescriptor> {
        None
    }

    pub fn handle_extra_pid_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &crate::objects::interface::FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        match req.pid {
            pid::ip::FRIENDLY_NAME => Some(self.read_friendly_name(req, buf)),
            _ => None,
        }
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        match req.pid {
            pid::ip::FRIENDLY_NAME => Some(self.write_friendly_name(req)),
            _ => None,
        }
    }
}
