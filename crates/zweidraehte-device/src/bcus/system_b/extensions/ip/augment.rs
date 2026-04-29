//! `IpAugment` and its `InterfaceObjectAugment` implementation.
//!
//! [`IpAugment`] combines an [`IpExtensionState`] reference (persisted config)
//! with a platform reference (current network state). It provides:
//!
//! - [`IpStackState`] — delegates config methods to the inner extension state
//! - [`IpPlatformState`] — delegates current values to the platform
//! - [`InterfaceObjectAugment`] — the IP Parameter Object (Type 11) with all
//!   IP PIDs including tunneling

use core::net::Ipv4Addr;

use zerocopy::FromBytes;

use crate::{
    IpPlatform, IpPlatformState, IpStackState, StackDefinition, StackState,
    objects::interface::{
        AugmentContext, FullPropertyReadRequest, FullPropertyWriteRequest, Ipv4Property, PropertyAccess,
        PropertyDescriptor, PropertyError, StatePropertyValue, WriteResponse, interface_object_augment, pid,
    },
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
/// Implements [`InterfaceObjectAugment`] to provide the IP Parameter
/// Object (Type 11) with all IP PIDs including tunneling.
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
// Macro: declare every base PID's descriptor metadata (closes the
// access-policy audit gap that the previous hand-written impl left
// open by not implementing `get_property_descriptor`). All PIDs are
// `manual` because the actual dispatch routes through
// `read_ip_property` / `write_ip_property` helpers that need
// `ctx.state` for `KNX_INDIVIDUAL_ADDRESS` and runtime conditionals
// for the tunnelling-only PIDs.
//
// `target_objects` and `additional_objects` both list `IPParameter`:
// the augment owns the IP Parameter Object (it adds it to the device's
// IO list) AND its PID dispatch targets that same object. The
// tunnelling-conditional descriptors (PID 53, 79) cannot be encoded as
// const data because their `max_elements` comes from the const-generic
// `N`; they are looked up via `handle_extra_pid_descriptor` instead.
#[interface_object_augment(
    additional_objects = [InterfaceObjectType::IPParameter],
    where_bounds(__AugmentD::State: StackState),
)]
pub struct IpAugment<'a, P: IpPlatform, const N: usize = 0, const CAPS: u16 = 0> {
    /// Persisted IP configuration (from extension state).
    pub config: &'a IpExtensionState<N, CAPS>,
    /// Platform for querying current network values.
    pub platform: &'a P,

    // ---- Base IP Parameter Object PIDs (descriptor only; dispatch in handle_extra_pid_*) ----

    #[io(pid = pid::OBJECT_TYPE, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _object_type_io: (),
    #[io(pid = pid::PROJECT_INSTALLATION_ID, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, manual)]
    _project_installation_id_io: (),
    #[io(pid = pid::KNX_INDIVIDUAL_ADDRESS, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, manual)]
    _knx_individual_address_io: (),
    #[io(pid = pid::CURRENT_IP_ASSIGNMENT_METHOD, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _current_ip_assignment_method_io: (),
    #[io(pid = pid::IP_ASSIGNMENT_METHOD, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, manual)]
    _ip_assignment_method_io: (),
    #[io(pid = pid::IP_CAPABILITIES, pdt = PDT_Bitset8, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _ip_capabilities_io: (),
    #[io(pid = pid::CURRENT_IP_ADDRESS, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _current_ip_address_io: (),
    #[io(pid = pid::CURRENT_SUBNET_MASK, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _current_subnet_mask_io: (),
    #[io(pid = pid::CURRENT_DEFAULT_GATEWAY, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _current_default_gateway_io: (),
    #[io(pid = pid::IP_ADDRESS, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, manual)]
    _ip_address_io: (),
    #[io(pid = pid::SUBNET_MASK, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, manual)]
    _subnet_mask_io: (),
    #[io(pid = pid::DEFAULT_GATEWAY, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, manual)]
    _default_gateway_io: (),
    #[io(pid = pid::MAC_ADDRESS, pdt = PDT_Generic06, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _mac_address_io: (),
    #[io(pid = pid::SYSTEM_SETUP_MULTICAST_ADDRESS, pdt = Ipv4Property, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _system_setup_multicast_address_io: (),
    #[io(pid = pid::ROUTING_MULTICAST_ADDRESS, pdt = Ipv4Property, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, manual)]
    _routing_multicast_address_io: (),
    #[io(pid = pid::TTL, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, manual)]
    _ttl_io: (),
    #[io(pid = pid::KNXNETIP_DEVICE_CAPABILITIES, pdt = PDT_Bitset16, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0, manual)]
    _knxnetip_device_capabilities_io: (),
    // PID_FRIENDLY_NAME — array property (max 30 bytes).
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
    // Property Read Helpers
    // ========================================================================

    fn read_simple<V: StatePropertyValue>(
        &self,
        value: &V::Value,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        if req.start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[0] = 0;
            buf[1] = 1;
            return Ok(2);
        }
        if req.start_idx != 1 || req.count != 1 {
            return Err(PropertyError::InvalidStartIndex);
        }
        let bytes = V::to_bytes(value);
        let b = bytes.as_ref();
        if buf.len() < b.len() {
            return Err(PropertyError::BufferTooSmall);
        }
        buf[..b.len()].copy_from_slice(b);
        Ok(b.len())
    }

    fn write_simple<V: StatePropertyValue>(data: &[u8]) -> Result<V::Value, PropertyError> {
        V::from_bytes(data)
    }

    fn read_ip_property(
        &self,
        state: &impl StackState,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        Some(match req.pid {
            pid::OBJECT_TYPE => {
                let ot: u16 = InterfaceObjectType::IPParameter.into();
                self.read_simple::<PDT_UnsignedInt>(&ot, req, buf)
            }
            pid::PROJECT_INSTALLATION_ID => {
                self.read_simple::<PDT_UnsignedInt>(&self.project_installation_id(), req, buf)
            }
            pid::KNX_INDIVIDUAL_ADDRESS => {
                let addr = state.individual_address();
                let bytes = addr.as_bytes();
                let val = u16::from_be_bytes([bytes[0], bytes[1]]);
                self.read_simple::<PDT_UnsignedInt>(&val, req, buf)
            }
            pid::CURRENT_IP_ASSIGNMENT_METHOD => {
                self.read_simple::<PDT_UnsignedChar>(&self.current_ip_assignment_method(), req, buf)
            }
            pid::IP_ASSIGNMENT_METHOD => self.read_simple::<PDT_UnsignedChar>(&self.ip_assignment_method(), req, buf),
            pid::IP_CAPABILITIES => self.read_simple::<PDT_Bitset8>(&self.ip_capabilities(), req, buf),
            pid::CURRENT_IP_ADDRESS => self.read_simple::<Ipv4Property>(&self.current_ip_address(), req, buf),
            pid::CURRENT_SUBNET_MASK => self.read_simple::<Ipv4Property>(&self.current_subnet_mask(), req, buf),
            pid::CURRENT_DEFAULT_GATEWAY => self.read_simple::<Ipv4Property>(&self.current_default_gateway(), req, buf),
            pid::IP_ADDRESS => self.read_simple::<Ipv4Property>(&self.configured_ip_address(), req, buf),
            pid::SUBNET_MASK => self.read_simple::<Ipv4Property>(&self.configured_subnet_mask(), req, buf),
            pid::DEFAULT_GATEWAY => self.read_simple::<Ipv4Property>(&self.configured_default_gateway(), req, buf),
            pid::MAC_ADDRESS => self.read_simple::<PDT_Generic06>(&self.mac_address(), req, buf),
            pid::SYSTEM_SETUP_MULTICAST_ADDRESS => self.read_simple::<Ipv4Property>(&SYSTEM_SETUP_MULTICAST, req, buf),
            pid::ROUTING_MULTICAST_ADDRESS => {
                self.read_simple::<Ipv4Property>(&self.routing_multicast_address(), req, buf)
            }
            pid::TTL => self.read_simple::<PDT_UnsignedChar>(&self.ttl(), req, buf),
            pid::KNXNETIP_DEVICE_CAPABILITIES => {
                self.read_simple::<PDT_Bitset16>(&self.knxnetip_device_capabilities(), req, buf)
            }
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

    fn write_ip_property(
        &self,
        state: &impl StackState,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        Some(match req.pid {
            pid::PROJECT_INSTALLATION_ID => Self::write_simple::<PDT_UnsignedInt>(req.data).map(|v| {
                self.set_project_installation_id(v);
                WriteResponse::Echo
            }),
            pid::KNX_INDIVIDUAL_ADDRESS => {
                if req.data.len() < 2 {
                    Err(PropertyError::BufferTooSmall)
                } else {
                    state.set_individual_address(IndividualAddress::from_bytes(req.data));
                    Ok(WriteResponse::Echo)
                }
            }
            pid::IP_ASSIGNMENT_METHOD => Self::write_simple::<PDT_UnsignedChar>(req.data).map(|v| {
                self.set_ip_assignment_method(v);
                WriteResponse::Echo
            }),
            pid::TTL => Self::write_simple::<PDT_UnsignedChar>(req.data).map(|v| {
                self.set_ttl(v);
                WriteResponse::Echo
            }),
            pid::IP_ADDRESS => Self::write_simple::<Ipv4Property>(req.data).map(|v| {
                self.set_configured_ip_address(v);
                WriteResponse::Echo
            }),
            pid::SUBNET_MASK => Self::write_simple::<Ipv4Property>(req.data).map(|v| {
                self.set_configured_subnet_mask(v);
                WriteResponse::Echo
            }),
            pid::DEFAULT_GATEWAY => Self::write_simple::<Ipv4Property>(req.data).map(|v| {
                self.set_configured_default_gateway(v);
                WriteResponse::Echo
            }),
            pid::ROUTING_MULTICAST_ADDRESS => Self::write_simple::<Ipv4Property>(req.data).map(|v| {
                self.set_routing_multicast_address(v);
                WriteResponse::Echo
            }),
            pid::FRIENDLY_NAME => self.write_friendly_name(req),
            pid::ADDITIONAL_INDIVIDUAL_ADDRESSES if self.tunneling_enabled() => {
                self.write_additional_addrs(req.start_idx, req.data)
            }
            pid::TUNNELLING_ADDRESSES if self.tunneling_enabled() => Err(PropertyError::WriteNotAllowed),
            pid::OBJECT_TYPE
            | pid::CURRENT_IP_ASSIGNMENT_METHOD
            | pid::IP_CAPABILITIES
            | pid::CURRENT_IP_ADDRESS
            | pid::CURRENT_SUBNET_MASK
            | pid::CURRENT_DEFAULT_GATEWAY
            | pid::MAC_ADDRESS
            | pid::SYSTEM_SETUP_MULTICAST_ADDRESS
            | pid::KNXNETIP_DEVICE_CAPABILITIES => Err(PropertyError::WriteNotAllowed),
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
        ctx: &AugmentContext<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        self.read_ip_property(ctx.state, req, buf)
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        ctx: &AugmentContext<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        self.write_ip_property(ctx.state, req)
    }

    pub fn handle_extra_pid_function_command<D: StackDefinition>(
        &self,
        _ctx: &AugmentContext<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &crate::objects::interface::FunctionPropertyRequest<'_>,
    ) -> Option<crate::objects::interface::FunctionPropertyResult> {
        None
    }

    pub fn handle_extra_pid_function_state_read<D: StackDefinition>(
        &self,
        _ctx: &AugmentContext<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &crate::objects::interface::FunctionPropertyRequest<'_>,
    ) -> Option<crate::objects::interface::FunctionPropertyResult> {
        None
    }
}
