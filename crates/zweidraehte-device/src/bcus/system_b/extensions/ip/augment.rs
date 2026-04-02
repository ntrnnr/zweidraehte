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
    IpPlatform, IpPlatformState, IpStackState, StackState,
    address::IndividualAddress,
    dpt::{
        InterfaceObjectType, PDT_Bitset8, PDT_Bitset16, PDT_Generic06, PDT_UnsignedChar, PDT_UnsignedInt,
        PropertyDataDefinition,
    },
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, InterfaceObjectAugment, Ipv4Property, PropertyAccess,
        PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup, StatePropertyValue,
        WriteResponse, pid,
    },
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
pub struct IpAugment<'a, P: IpPlatform, const N: usize = 0, const CAPS: u16 = 0> {
    /// Persisted IP configuration (from extension state).
    pub config: &'a IpExtensionState<N, CAPS>,
    /// Platform for querying current network values.
    pub platform: &'a P,
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
// Property Table
// ============================================================================

// Helper to build a simple non-array property descriptor.
const fn simple_desc(pid: u8, pdt_id: u8, access: PropertyAccess) -> PropertyDescriptor {
    let (read_level, write_level) = match access {
        PropertyAccess::ReadOnly | PropertyAccess::WriteOnly => (3, 0),
        PropertyAccess::ReadWrite => (3, 3),
    };
    PropertyDescriptor::new(pid, pdt_id, 1, access, read_level, write_level)
}

/// All base IP Parameter Object properties (not tunneling-conditional).
///
/// Listed in index-scan order.
static BASE_PROPS: &[PropertyDescriptor] = &[
    simple_desc(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, PropertyAccess::ReadOnly),
    simple_desc(pid::PROJECT_INSTALLATION_ID, PDT_UnsignedInt::ID, PropertyAccess::ReadWrite),
    simple_desc(pid::KNX_INDIVIDUAL_ADDRESS, PDT_UnsignedInt::ID, PropertyAccess::ReadWrite),
    simple_desc(pid::CURRENT_IP_ASSIGNMENT_METHOD, PDT_UnsignedChar::ID, PropertyAccess::ReadOnly),
    simple_desc(pid::IP_ASSIGNMENT_METHOD, PDT_UnsignedChar::ID, PropertyAccess::ReadWrite),
    simple_desc(pid::IP_CAPABILITIES, PDT_Bitset8::ID, PropertyAccess::ReadOnly),
    simple_desc(pid::CURRENT_IP_ADDRESS, Ipv4Property::ID, PropertyAccess::ReadOnly),
    simple_desc(pid::CURRENT_SUBNET_MASK, Ipv4Property::ID, PropertyAccess::ReadOnly),
    simple_desc(pid::CURRENT_DEFAULT_GATEWAY, Ipv4Property::ID, PropertyAccess::ReadOnly),
    simple_desc(pid::IP_ADDRESS, Ipv4Property::ID, PropertyAccess::ReadWrite),
    simple_desc(pid::SUBNET_MASK, Ipv4Property::ID, PropertyAccess::ReadWrite),
    simple_desc(pid::DEFAULT_GATEWAY, Ipv4Property::ID, PropertyAccess::ReadWrite),
    simple_desc(pid::MAC_ADDRESS, PDT_Generic06::ID, PropertyAccess::ReadOnly),
    simple_desc(pid::SYSTEM_SETUP_MULTICAST_ADDRESS, Ipv4Property::ID, PropertyAccess::ReadOnly),
    simple_desc(pid::ROUTING_MULTICAST_ADDRESS, Ipv4Property::ID, PropertyAccess::ReadWrite),
    simple_desc(pid::TTL, PDT_UnsignedChar::ID, PropertyAccess::ReadWrite),
    simple_desc(pid::KNXNETIP_DEVICE_CAPABILITIES, PDT_Bitset16::ID, PropertyAccess::ReadOnly),
    PropertyDescriptor::array::<PDT_UnsignedChar>(pid::FRIENDLY_NAME, 30, PropertyAccess::ReadWrite, 3, 3),
];

// ============================================================================
// Helper functions
// ============================================================================

impl<P: IpPlatform, const N: usize, const CAPS: u16> IpAugment<'_, P, N, CAPS> {
    /// Whether tunneling is enabled on this device.
    fn tunneling_enabled(&self) -> bool {
        (self.knxnetip_device_capabilities() & KNXNETIP_CAP_TUNNELING_BIT) != 0
    }

    /// Total property count for index scanning.
    #[allow(dead_code)] // TODO: useful for property count queries
    fn ip_property_count(&self) -> u8 {
        let base = BASE_PROPS.len() as u8;
        if self.tunneling_enabled() {
            base + 2 // PID 53 + PID 79
        } else {
            base
        }
    }

    /// Look up a property descriptor by PID.
    fn ip_descriptor_by_pid(&self, prop_id: u8) -> Option<PropertyDescriptor> {
        if self.tunneling_enabled() {
            let max_addrs = N as u16;
            match prop_id {
                pid::ADDITIONAL_INDIVIDUAL_ADDRESSES => {
                    return Some(PropertyDescriptor::array::<PDT_UnsignedInt>(
                        prop_id,
                        max_addrs,
                        PropertyAccess::ReadWrite,
                        3,
                        3,
                    ));
                }
                pid::TUNNELLING_ADDRESSES => {
                    return Some(PropertyDescriptor::array::<PDT_UnsignedChar>(
                        prop_id,
                        max_addrs,
                        PropertyAccess::ReadOnly,
                        3,
                        3,
                    ));
                }
                _ => {}
            }
        }

        BASE_PROPS.iter().find(|d| d.pid == prop_id).copied()
    }

    /// Look up a property descriptor by augment-local 0-based index.
    fn ip_descriptor_by_index(&self, idx: u16) -> Option<PropertyDescriptor> {
        let base_len = BASE_PROPS.len() as u16;
        if idx < base_len {
            return Some(BASE_PROPS[idx as usize]);
        }

        if self.tunneling_enabled() {
            let tunneling_idx = idx - base_len;
            let max_addrs = N as u16;
            return match tunneling_idx {
                0 => Some(PropertyDescriptor::array::<PDT_UnsignedInt>(
                    pid::ADDITIONAL_INDIVIDUAL_ADDRESSES,
                    max_addrs,
                    PropertyAccess::ReadWrite,
                    3,
                    3,
                )),
                1 => Some(PropertyDescriptor::array::<PDT_UnsignedChar>(
                    pid::TUNNELLING_ADDRESSES,
                    max_addrs,
                    PropertyAccess::ReadOnly,
                    3,
                    3,
                )),
                _ => None,
            };
        }

        None
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
        if start_idx != 1 {
            return Err(PropertyError::InvalidStartIndex);
        }

        let addrs = <[IndividualAddress]>::ref_from_bytes(data).map_err(|_| PropertyError::TypeMismatch)?;

        self.set_additional_individual_addresses(addrs).map_err(|_| PropertyError::WriteNotAllowed)?;
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
// InterfaceObjectAugment — provides IP Parameter Object (Type 11)
// ============================================================================

impl<S: StackState, P: IpPlatform, const N: usize, const CAPS: u16> InterfaceObjectAugment<S>
    for IpAugment<'_, P, N, CAPS> {
    fn additional_object_count(&self) -> u16 {
        1 // IP Parameter Object
    }

    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType> {
        match index {
            0 => Some(InterfaceObjectType::IPParameter),
            _ => None,
        }
    }

    fn property_description_read(
        &self,
        _state: &S,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        if object_type != InterfaceObjectType::IPParameter {
            return None;
        }

        let desc = match lookup {
            PropertyLookup::ByPid(prop_id) => self.ip_descriptor_by_pid(prop_id)?,
            PropertyLookup::ByIndex(idx) => self.ip_descriptor_by_index(idx)?,
        };
        Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &desc)))
    }

    // Access checks are centralized in dispatch.rs (lines 183-196 for reads,
    // 233-246 for writes) using get_descriptor() which queries this augment's
    // get_property_descriptor(). No per-augment access check needed here.

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
        self.read_ip_property(state, req, buf)
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
        self.write_ip_property(state, req)
    }
}
