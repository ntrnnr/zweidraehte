//! `IpAugment` and its `Augment<D>` implementation.
//!
//! [`IpAugment`] combines an [`IpExtensionState`] reference (persisted config)
//! with a platform reference (current network state). It provides:
//!
//! - [`IpStackState`] — delegates config methods to the inner extension state
//! - [`IpPlatformState`] — delegates current values to the platform
//! - [`Augment<D>`](crate::service::Augment) — the IP
//!   Parameter Object (Type 11) with all IP PIDs including tunneling

use core::net::Ipv4Addr;

use zerocopy::FromBytes;

use crate::{
    IpPlatform, IpPlatformState, IpStackState, StackDefinition, StackState,
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, Ipv4Property, PropertyAccess, PropertyDescriptor,
        PropertyError, StatePropertyValue, WriteResponse, interface_object_augment, pid,
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
// behaviour in one place so the two cannot drift. Three PIDs stay
// `manual` because their value-side dispatch needs bespoke buffer
// manipulation that doesn't fit the closure → `PropertyRead` /
// `PropertyWrite` framing:
//
// - `FRIENDLY_NAME` — read-modify-write across an arbitrary
//   array-index range with custom length tracking.
// - `ADDITIONAL_INDIVIDUAL_ADDRESSES` (PID 53), `TUNNELLING_ADDRESSES`
//   (PID 79) — zerocopy reinterpretation of the buffer plus a
//   tunnelling-conditional guard. Their descriptors are also
//   conditional on the const-generic `N` and produced by
//   `handle_extra_pid_descriptor`, not the static `DESCRIPTORS` table.
//
// `additional_objects` lists `IPParameter`: the augment owns the IP
// Parameter Object (it adds it to the device's IO list) and dispatches
// PIDs targeting that same object.
#[interface_object_augment(
    additional_objects = [InterfaceObjectType::IPParameter],
    where_bounds(D::State: StackState),
)]
pub struct IpAugment<'a, P: IpPlatform, const N: usize = 0, const CAPS: u16 = 0> {
    /// Persisted IP configuration (from extension state).
    pub config: &'a IpExtensionState<N, CAPS>,
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

    #[io(pid = pid::PROJECT_INSTALLATION_ID, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 2] { this.project_installation_id().to_be_bytes() },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <PDT_UnsignedInt as StatePropertyValue>::from_bytes(data)?;
             this.set_project_installation_id(v);
             Ok(WriteResponse::Echo)
         })]
    _project_installation_id_io: (),

    // KNX_INDIVIDUAL_ADDRESS lives on the device state, not the IP config,
    // so it needs `ctx.state` access on both sides.
    #[io(pid = pid::KNX_INDIVIDUAL_ADDRESS, pdt = PDT_UnsignedInt, access = RW,
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

    #[io(pid = pid::CURRENT_IP_ASSIGNMENT_METHOD, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 1] { [this.current_ip_assignment_method()] })]
    _current_ip_assignment_method_io: (),

    #[io(pid = pid::IP_ASSIGNMENT_METHOD, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 1] { [this.ip_assignment_method()] },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <PDT_UnsignedChar as StatePropertyValue>::from_bytes(data)?;
             this.set_ip_assignment_method(v);
             Ok(WriteResponse::Echo)
         })]
    _ip_assignment_method_io: (),

    #[io(pid = pid::IP_CAPABILITIES, pdt = PDT_Bitset8, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 1] { [this.ip_capabilities()] })]
    _ip_capabilities_io: (),

    #[io(pid = pid::CURRENT_IP_ADDRESS, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.current_ip_address()) })]
    _current_ip_address_io: (),

    #[io(pid = pid::CURRENT_SUBNET_MASK, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.current_subnet_mask()) })]
    _current_subnet_mask_io: (),

    #[io(pid = pid::CURRENT_DEFAULT_GATEWAY, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.current_default_gateway()) })]
    _current_default_gateway_io: (),

    #[io(pid = pid::IP_ADDRESS, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.configured_ip_address()) },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <Ipv4Property as StatePropertyValue>::from_bytes(data)?;
             this.set_configured_ip_address(v);
             Ok(WriteResponse::Echo)
         })]
    _ip_address_io: (),

    #[io(pid = pid::SUBNET_MASK, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.configured_subnet_mask()) },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <Ipv4Property as StatePropertyValue>::from_bytes(data)?;
             this.set_configured_subnet_mask(v);
             Ok(WriteResponse::Echo)
         })]
    _subnet_mask_io: (),

    #[io(pid = pid::DEFAULT_GATEWAY, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.configured_default_gateway()) },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <Ipv4Property as StatePropertyValue>::from_bytes(data)?;
             this.set_configured_default_gateway(v);
             Ok(WriteResponse::Echo)
         })]
    _default_gateway_io: (),

    #[io(pid = pid::MAC_ADDRESS, pdt = PDT_Generic06, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 6] { this.mac_address() })]
    _mac_address_io: (),

    #[io(pid = pid::SYSTEM_SETUP_MULTICAST_ADDRESS, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |_this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&SYSTEM_SETUP_MULTICAST) })]
    _system_setup_multicast_address_io: (),

    #[io(pid = pid::ROUTING_MULTICAST_ADDRESS, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 4] { Ipv4Property::to_bytes(&this.routing_multicast_address()) },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <Ipv4Property as StatePropertyValue>::from_bytes(data)?;
             this.set_routing_multicast_address(v);
             Ok(WriteResponse::Echo)
         })]
    _routing_multicast_address_io: (),

    #[io(pid = pid::TTL, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 1] { [this.ttl()] },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let v = <PDT_UnsignedChar as StatePropertyValue>::from_bytes(data)?;
             this.set_ttl(v);
             Ok(WriteResponse::Echo)
         })]
    _ttl_io: (),

    #[io(pid = pid::KNXNETIP_DEVICE_CAPABILITIES, pdt = PDT_Bitset16, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |this: &Self| -> [u8; 2] { this.knxnetip_device_capabilities().to_be_bytes() })]
    _knxnetip_device_capabilities_io: (),

    // PID_FRIENDLY_NAME — array property (max 30 bytes). `manual` because
    // the read/write does its own count-probe + arbitrary-index handling
    // that the generic `PropertyRead` / `PropertyWrite` framing doesn't
    // accommodate.
    #[io(pid = pid::FRIENDLY_NAME, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         array(max = 30), manual)]
    _friendly_name_io: (),
    // Tunnelling-conditional PIDs (53, 79). The descriptor for these is
    // built at lookup time in `handle_extra_pid_descriptor` because the
    // `max_elements` value comes from the const-generic `N`. They are
    // *not* listed in the macro's static descriptor table.
}

impl<'a, P: IpPlatform, const N: usize, const CAPS: u16> IpAugment<'a, P, N, CAPS> {
    /// Create a new `IpAugment` combining config and platform references.
    ///
    /// PID 68 (device capabilities) is a compile-time constant from the
    /// `CAPS` const generic, which propagates from
    /// [`IpExtensionState<N, CAPS>`](IpExtensionState).
    pub fn new(config: &'a IpExtensionState<N, CAPS>, platform: &'a P) -> Self {
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
// IpStackState delegation (config methods → inner extension state)
// ============================================================================

impl<P: IpPlatform, const N: usize, const CAPS: u16> IpStackState for IpAugment<'_, P, N, CAPS> {
    fn configured_ip_address(&self) -> Ipv4Addr {
        self.config.configured_ip_address()
    }

    fn set_configured_ip_address(&self, addr: Ipv4Addr) {
        self.config.set_configured_ip_address(addr);
    }

    fn configured_subnet_mask(&self) -> Ipv4Addr {
        self.config.configured_subnet_mask()
    }

    fn set_configured_subnet_mask(&self, mask: Ipv4Addr) {
        self.config.set_configured_subnet_mask(mask);
    }

    fn configured_default_gateway(&self) -> Ipv4Addr {
        self.config.configured_default_gateway()
    }

    fn set_configured_default_gateway(&self, gw: Ipv4Addr) {
        self.config.set_configured_default_gateway(gw);
    }

    fn ip_assignment_method(&self) -> u8 {
        self.config.ip_assignment_method()
    }

    fn set_ip_assignment_method(&self, method: u8) {
        self.config.set_ip_assignment_method(method);
    }

    fn routing_multicast_address(&self) -> Ipv4Addr {
        self.config.routing_multicast_address()
    }

    fn set_routing_multicast_address(&self, addr: Ipv4Addr) {
        self.config.set_routing_multicast_address(addr);
    }

    fn ttl(&self) -> u8 {
        self.config.ttl()
    }

    fn set_ttl(&self, ttl: u8) {
        self.config.set_ttl(ttl);
    }

    fn friendly_name_len(&self) -> usize {
        self.config.friendly_name_len()
    }

    fn friendly_name(&self) -> [u8; 30] {
        self.config.friendly_name()
    }

    fn set_friendly_name(&self, name: &[u8]) {
        self.config.set_friendly_name(name);
    }

    fn project_installation_id(&self) -> u16 {
        self.config.project_installation_id()
    }

    fn set_project_installation_id(&self, id: u16) {
        self.config.set_project_installation_id(id);
    }

    fn additional_individual_address_capacity(&self) -> usize {
        self.config.additional_individual_address_capacity()
    }

    fn write_additional_individual_addresses(&self, buf: &mut [IndividualAddress]) -> usize {
        self.config.write_additional_individual_addresses(buf)
    }

    fn set_additional_individual_addresses(&self, addrs: &[IndividualAddress]) -> Result<(), ()> {
        self.config.set_additional_individual_addresses(addrs)
    }
}

// ============================================================================
// IpPlatformState delegation (current values → platform)
// ============================================================================

impl<P: IpPlatform, const N: usize, const CAPS: u16> IpPlatformState for IpAugment<'_, P, N, CAPS> {
    fn current_ip_address(&self) -> Ipv4Addr {
        self.platform.current_ip_address()
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.platform.current_subnet_mask()
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        self.platform.current_default_gateway()
    }

    fn mac_address(&self) -> [u8; 6] {
        self.platform.mac_address()
    }

    fn current_ip_assignment_method(&self) -> u8 {
        self.platform.current_ip_assignment_method()
    }

    fn ip_capabilities(&self) -> u8 {
        self.platform.ip_capabilities()
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Default KNX System Setup multicast address: 224.0.23.12
const SYSTEM_SETUP_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

/// Tunneling capability bit in KNXnet/IP Device Capabilities.
const KNXNETIP_CAP_TUNNELING_BIT: u16 = 1 << 1;

// ============================================================================
// Helper functions
// ============================================================================

impl<P: IpPlatform, const N: usize, const CAPS: u16> IpAugment<'_, P, N, CAPS> {
    /// Whether tunneling is enabled on this device.
    fn tunneling_enabled(&self) -> bool {
        (self.knxnetip_device_capabilities() & KNXNETIP_CAP_TUNNELING_BIT) != 0
    }

    /// Look up tunnelling-conditional descriptors at runtime — the macro's
    /// static `Self::DESCRIPTORS` table covers the 18 base PIDs; the two
    /// tunnelling-only PIDs (53, 79) need const-generic `N` for their
    /// `max_elements`, so they're built fresh on each lookup here.
    pub fn handle_extra_pid_descriptor(
        &self,
        object_type: InterfaceObjectType,
        prop_id: u16,
    ) -> Option<PropertyDescriptor> {
        if object_type != InterfaceObjectType::IPParameter || !self.tunneling_enabled() {
            return None;
        }
        let max_addrs = N as u16;
        match prop_id {
            // PID 53 PID_ADDITIONAL_INDIVIDUAL_ADDRESSES — AN193
            // §"Object Type 11" lists `3FF/0CC` (READ_OPEN_WRITE_TOOL).
            pid::ADDITIONAL_INDIVIDUAL_ADDRESSES => Some(PropertyDescriptor::array::<PDT_UnsignedInt>(
                prop_id,
                max_addrs,
                PropertyAccess::ReadWrite,
                3,
                3,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            )),
            // PID 79 PID_TUNNELLING_ADDRESSES — AN193 §"Object Type 11"
            // lists `15F/04C` (RESTRICTED): the tunnelling-client list
            // is security-sensitive, so plain unlisted reads are
            // forbidden once Security Mode is on.
            pid::TUNNELLING_ADDRESSES => Some(PropertyDescriptor::array::<PDT_UnsignedChar>(
                prop_id,
                max_addrs,
                PropertyAccess::ReadOnly,
                3,
                3,
                AccessPolicy::RESTRICTED,
            )),
            _ => None,
        }
    }

    // ========================================================================
    // Manual-PID dispatch (FRIENDLY_NAME + tunnelling array PIDs only)
    // ========================================================================
    //
    // Every other base IP PID dispatches through inline `read` / `write`
    // closures on the struct above. The three PIDs handled here all use
    // bespoke buffer layouts that the generic `PropertyRead` /
    // `PropertyWrite` framing can't express (read-modify-write across
    // arbitrary array indices, zerocopy reinterpretation, conditional
    // visibility tied to `tunneling_enabled()`).

    fn read_ip_property(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Option<Result<usize, PropertyError>> {
        Some(match req.pid {
            pid::FRIENDLY_NAME => self.read_friendly_name(req, buf),
            pid::ADDITIONAL_INDIVIDUAL_ADDRESSES if self.tunneling_enabled() => {
                self.read_additional_addrs(req.start_idx, req.count, buf)
            }
            pid::TUNNELLING_ADDRESSES if self.tunneling_enabled() => {
                self.read_tunnelling_devices(req.start_idx, req.count, buf)
            }
            _ => return None,
        })
    }

    fn write_ip_property(&self, req: &FullPropertyWriteRequest<'_>) -> Option<Result<WriteResponse, PropertyError>> {
        Some(match req.pid {
            pid::FRIENDLY_NAME => self.write_friendly_name(req),
            pid::ADDITIONAL_INDIVIDUAL_ADDRESSES if self.tunneling_enabled() => {
                self.write_additional_addrs(req.start_idx, req.data)
            }
            pid::TUNNELLING_ADDRESSES if self.tunneling_enabled() => Err(PropertyError::WriteNotAllowed),
            _ => return None,
        })
    }

    // ========================================================================
    // Friendly Name (array property)
    // ========================================================================

    fn read_friendly_name(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let name = self.friendly_name();
        let len = self.friendly_name_len();

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
        let mut name = self.friendly_name();
        let mut len = self.friendly_name_len();

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

        self.set_friendly_name(&name[..len]);
        Ok(WriteResponse::Echo)
    }

    // ========================================================================
    // Tunneling Properties (PID 53 + PID 79)
    // ========================================================================

    fn read_additional_addrs(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let addr_cap = buf.len() / 2;
        let addr_buf = <[IndividualAddress]>::mut_from_bytes(&mut buf[..addr_cap * 2])
            .expect("IndividualAddress is Unaligned; length rounded to even");
        let addr_count = self.write_additional_individual_addresses(addr_buf);

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

        buf.copy_within(start * 2..end * 2, 0);
        Ok(needed)
    }

    fn write_additional_addrs(&self, start_idx: u16, data: &[u8]) -> Result<WriteResponse, PropertyError> {
        if start_idx == 0 {
            return Err(PropertyError::InvalidStartIndex);
        }

        let new_addrs = <[IndividualAddress]>::ref_from_bytes(data).map_err(|_| PropertyError::TypeMismatch)?;
        let start = (start_idx - 1) as usize;
        let end = start + new_addrs.len();
        let capacity = self.additional_individual_address_capacity();

        if end > capacity {
            return Err(PropertyError::InvalidStartIndex);
        }

        // Read-modify-write: read current addresses, patch the range, write back.
        let mut buf = [IndividualAddress::default(); N];
        let current_len = self.write_additional_individual_addresses(&mut buf);

        // Extend with zeros if writing past the current populated range.
        let new_len = end.max(current_len);
        buf[start..end].copy_from_slice(new_addrs);

        self.set_additional_individual_addresses(&buf[..new_len]).map_err(|_| PropertyError::WriteNotAllowed)?;
        Ok(WriteResponse::Echo)
    }

    fn read_tunnelling_devices(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let addr_cap = buf.len() / 2;
        let addr_buf = <[IndividualAddress]>::mut_from_bytes(&mut buf[..addr_cap * 2])
            .expect("IndividualAddress is Unaligned; length rounded to even");
        let addr_count = self.write_additional_individual_addresses(addr_buf);

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
            buf[i] = buf[(start + i) * 2 + 1];
        }

        Ok(needed)
    }
}

// ============================================================================
// Manual fallback thunks invoked by the macro-generated dispatch.
// ============================================================================

impl<P: IpPlatform, const N: usize, const CAPS: u16> IpAugment<'_, P, N, CAPS> {
    pub fn handle_extra_pid_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        self.read_ip_property(req, buf)
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        self.write_ip_property(req)
    }
}
