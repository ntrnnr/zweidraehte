//! Full KNX Stack with KNX/IP Link Layer
//!
//! This test utility demonstrates the complete KNX stack with a real KNX/IP link layer.
//! It combines:
//! - Application Layer with communication objects
//! - Transport Layer
//! - Network Layer
//! - KNX/IP Link Layer with Discovery and Routing Servers
//!
//! The stack loads configuration from `stack_test_data.json` and provides:
//! - 8 communication objects (4 inputs, 4 outputs)
//! - KNX/IP discovery on multicast 224.0.23.12:3671
//! - KNX/IP routing with congestion control (RoutingIndication, RoutingBusy, RoutingLostMessage)
//! - Full bidirectional KNX message handling
//!
//! ## Comprehensive Test Configuration (stack_test_data.json)
//!
//! ### Address Table (8 group addresses)
//! - TSAP 1 → Group Address 1/0/1 (0x0801) - Controls CO1
//! - TSAP 2 → Group Address 1/0/2 (0x0802) - Controls CO2
//! - TSAP 3 → Group Address 1/0/3 (0x0803) - Controls CO3
//! - TSAP 4 → Group Address 1/0/4 (0x0804) - Controls CO4
//! - TSAP 5 → Group Address 1/1/1 (0x0901) - Controls CO5
//! - TSAP 6 → Group Address 1/1/2 (0x0902) - Controls CO6
//! - TSAP 7 → Group Address 1/1/3 (0x0903) - Controls CO3 and CO7 (multi-address)
//! - TSAP 8 → Group Address 1/1/4 (0x0904) - Broadcast to CO1, CO2, CO5, CO6
//!
//! ### Association Table (12 associations)
//! Maps Transport SAPs (TSAPs) to Application SAPs (ASAPs/Communication Objects):
//! - TSAP 1 → ASAP 1 (CO 1: co_in0)
//! - TSAP 2 → ASAP 2 (CO 2: co_in1)
//! - TSAP 3 → ASAP 3 (CO 3: co_in2)
//! - TSAP 4 → ASAP 4 (CO 4: co_in3)
//! - TSAP 5 → ASAP 5 (CO 5: co_out0)
//! - TSAP 6 → ASAP 6 (CO 6: co_out1)
//! - TSAP 7 → ASAP 3 (CO 3: co_in2) - 1/1/3 also controls CO3
//! - TSAP 7 → ASAP 7 (CO 7: co_out2)
//! - TSAP 8 → ASAP 1 (CO 1: co_in0) - Broadcast
//! - TSAP 8 → ASAP 2 (CO 2: co_in1) - Broadcast
//! - TSAP 8 → ASAP 5 (CO 5: co_out0) - Broadcast
//! - TSAP 8 → ASAP 6 (CO 6: co_out1) - Broadcast
//!
//! ### Communication Object Table (8 configured objects)
//! Flag legend: CE=Communication Enable, TE=Transmit Enable, RE=Read Enable,
//!              WE=Write Enable, UE=Update Enable, Priority=Low (bits 3-2 = 0b11)
//!
//! - CO 1: Type Uint1, Flags 0xDF (CE|TE|RE|WE|UE) - Full bidirectional
//! - CO 2: Type Uint1, Flags 0xDF (CE|TE|RE|WE|UE) - Full bidirectional
//! - CO 3: Type Uint1, Flags 0x5F (CE|TE|RE|WE) - No UE, won't auto-transmit on update
//! - CO 4: Type Uint1, Flags 0x4F (CE|TE|RE) - Read-only from bus (no WE)
//! - CO 5: Type Uint1, Flags 0xCF (CE|TE|RE|WE) - Can write to bus, no UE
//! - CO 6: Type Uint1, Flags 0xCF (CE|TE|RE|WE) - Can write to bus, no UE
//! - CO 7: Type Uint1, Flags 0x4F (CE|TE|RE) - Read-only from bus (no WE)
//! - CO 8: Type Uint1, Flags 0x00 - Disabled, application-local only
//!
//! ## Comprehensive Test Cases
//!
//! ### Test 1: Basic Input Control
//! - **Action**: Send `1` to address 1/0/1
//! - **Expected**: CO1 (co_in0) updates to `1`, triggers output CO5 to toggle
//!
//! ### Test 2: Independent Input Control
//! - **Action**: Send `0` to address 1/0/2
//! - **Expected**: CO2 (co_in1) updates to `0`, triggers output CO6 to toggle
//!
//! ### Test 3: Multi-Address Control (same object, different addresses)
//! - **Action**: Send `1` to address 1/0/3
//! - **Expected**: CO3 (co_in2) updates to `1`
//! - **Action**: Send `0` to address 1/1/3
//! - **Expected**: CO3 (co_in2) updates to `0` (same object controlled by two addresses)
//! - Also updates CO7 (co_out2) since 1/1/3 is also mapped to it
//!
//! ### Test 4: Broadcast Address
//! - **Action**: Send `1` to address 1/1/4
//! - **Expected**: CO1, CO2, CO5, CO6 all update to `1` simultaneously
//!
//! ### Test 5: Output Object Control
//! - **Action**: Send `1` to address 1/1/1
//! - **Expected**: CO5 (co_out0) updates to `1`
//! - **Action**: Send `0` to address 1/1/2
//! - **Expected**: CO6 (co_out1) updates to `0`
//!
//! ### Test 6: Read Request
//! - **Action**: Send GroupValueRead to address 1/0/1
//! - **Expected**: CO1 responds with GroupValueResponse containing current value
//! - All objects with RE flag set should respond to read requests on their addresses
//!
//! ### Test 7: Write to Read-Only Object (should be rejected)
//! - **Action**: Send `1` to address 1/0/4
//! - **Expected**: CO4 should NOT update (WE flag not set, read-only from bus)
//!
//! ### Test 8: Update Flag Behavior
//! - **Action**: Application updates CO3 locally
//! - **Expected**: NO automatic transmission (UE flag not set)
//! - **Action**: Application updates CO1 locally
//! - **Expected**: Automatic GroupValueWrite transmitted to 1/0/1 (UE flag is set)
//!
//! ### Test 9: Application-Local Object
//! - **Action**: Application updates CO8 (co_out3)
//! - **Expected**: No KNX bus activity (flags 0x00, not connected to any group address)
//!
//! ### Test 10: Stress Test - Rapid Updates
//! - **Action**: Send rapid alternating `0`/`1` to address 1/1/4 (broadcast)
//! - **Expected**: All 4 mapped objects (CO1, CO2, CO5, CO6) track changes
//! - May trigger RoutingBusy if congestion occurs

#![feature(adt_const_params)]

use core::cell::{Cell, RefCell};

use const_default::ConstDefault;
use embassy_executor::Spawner;
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use static_cell::StaticCell;
use std::net::{Ipv4Addr, SocketAddrV4};
use zweidraehte::prelude::*;
use zweidraehte::{
    dpt::{DPT_Switch, InterfaceObjectType},
    layers::linklayers::knxip::{KnxNetIpBuilder, features::KnxIpDeviceUdp},
    objects::interface::{
        AddressTableObject, ApplicationProgramObject, AssociationTableObject, DeviceObject, GroupObjectTableObject,
        IpParameterObject,
    },
    objects::tables::Application,
};

#[derive(Debug, ConstDefault)]
pub struct AppParameters {
    _delay_time: u16,
}

pub mod comm_objs {
    use super::*;
    #[derive(EtsComObjects)]
    pub struct AppComObjects {
        #[ets(index = 1)]
        pub co_in0: ComObject<DPT_Switch>,
        #[ets(index = 2)]
        pub co_in1: ComObject<DPT_Switch>,
        #[ets(index = 3)]
        pub co_in2: ComObject<DPT_Switch>,
        #[ets(index = 4)]
        pub co_in3: ComObject<DPT_Switch>,
        #[ets(index = 5)]
        pub co_out0: ComObject<DPT_Switch>,
        #[ets(index = 6)]
        pub co_out1: ComObject<DPT_Switch>,
        #[ets(index = 7)]
        pub co_out2: ComObject<DPT_Switch>,
        #[ets(index = 8)]
        pub co_out3: ComObject<DPT_Switch>,
    }
}

// Define stack configuration using the new macro
mod stack_test_config {
    use zweidraehte::config::{CE, RE, TE, UE, WE};
    use zweidraehte::knx_stack_config;

    knx_stack_config! {
        name: StackTestConfig,
        individual_address: "1.1.0",

        group_addresses: {
            1 => "1/0/1",
            2 => "1/0/2",
            3 => "1/0/3",
            4 => "1/0/4",
            5 => "1/1/1",
            6 => "1/1/2",
            7 => "1/1/3",
            8 => "1/1/4",
        },

        comm_objects: {
            1 => (0, CE | TE | RE | WE | UE),  // CO1: Full bidirectional with auto-transmit
            2 => (0, CE | TE | RE | WE | UE),  // CO2: Full bidirectional with auto-transmit
            3 => (0, CE | TE | RE | WE),       // CO3: No UE, won't auto-transmit on update
            4 => (0, CE | TE | RE),            // CO4: Read-only from bus (no WE)
            5 => (0, CE | TE | RE | WE),       // CO5: Can write to bus, no UE
            6 => (0, CE | TE | RE | WE),       // CO6: Can write to bus, no UE
            7 => (0, CE | TE | RE),            // CO7: Read-only from bus (no WE)
            8 => (0, 0),                       // CO8: Disabled, application-local only
        },

        associations: {
            1 => [1],        // TSAP 1 (1/0/1) → ASAP 1 (CO1)
            2 => [2],        // TSAP 2 (1/0/2) → ASAP 2 (CO2)
            3 => [3],        // TSAP 3 (1/0/3) → ASAP 3 (CO3)
            4 => [4],        // TSAP 4 (1/0/4) → ASAP 4 (CO4)
            5 => [5],        // TSAP 5 (1/1/1) → ASAP 5 (CO5)
            6 => [6],        // TSAP 6 (1/1/2) → ASAP 6 (CO6)
            7 => [3, 7],     // TSAP 7 (1/1/3) → ASAP 3 (CO3) and ASAP 7 (CO7)
            8 => [1, 2, 5, 6], // TSAP 8 (1/1/4) → Broadcast to CO1, CO2, CO5, CO6
        },
    }
}

// ============================================================================
// Mock IP Platform
// ============================================================================

/// Mock platform for testing that provides static IP configuration.
#[derive(Debug, Clone)]
pub struct MockIpPlatform {
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mac_address: [u8; 6],
}

impl Default for MockIpPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl MockIpPlatform {
    pub fn new() -> Self {
        Self {
            ip_address: Ipv4Addr::new(192, 168, 1, 100),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            mac_address: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        }
    }
}

impl IpPlatform for MockIpPlatform {
    fn current_ip_address(&self) -> Ipv4Addr {
        self.ip_address
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.subnet_mask
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    fn current_ip_assignment_method(&self) -> u8 {
        0x02 // Manual
    }

    fn ip_capabilities(&self) -> u8 {
        0x07 // BootP, DHCP, Manual supported
    }

    fn knxnetip_device_capabilities(&self) -> u16 {
        0x003F // Supports routing, tunneling, etc.
    }
}

impl platform::NetworkConfig for MockIpPlatform {
    type Error = core::convert::Infallible;

    fn apply_ip_config(&self, _config: &platform::IpConfig) -> Result<(), Self::Error> {
        Ok(()) // No-op — OS manages networking on Linux.
    }
}

// ============================================================================
// Interface Objects Configuration
// ============================================================================

/// Device-specific constants for Interface Objects
mod device_info {
    /// Device serial number (6 bytes)
    /// Format: bytes 0-1 = manufacturer ID (0x00FA), bytes 2-5 = device-specific
    pub const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

    /// Project Installation ID for KNXnet/IP
    pub const PROJECT_INSTALLATION_ID: u16 = 0x1234;
}

/// Interface Objects container for a KNXnet/IP device
///
/// This struct holds all the interface objects required for a standard
/// KNXnet/IP device. It implements `PropertyServiceHandler` to dispatch
/// property requests to the correct object by index:
///
/// - Index 0: Device Object
/// - Index 1: Address Table Object
/// - Index 2: Association Table Object
/// - Index 3: Application Program Object  (TODO: should be GOT per spec)
/// - Index 4: Group Object Table Object   (TODO: should be App per spec)
/// - Index 5: IP Parameter Object
///
/// NOTE: Indices 3 and 4 are swapped compared to the standard System B
/// ordering. This is a legacy issue — the conformance harness and
/// `create_knxip_objects` use the correct ordering (GOT=3, App=4).
/// Also missing: PEI Program Object (index 5 in standard ordering).
pub struct KnxIpInterfaceObjects<'a, S>
where
    S: StackState + IpStackState,
{
    state: &'a S,
    pub device: RefCell<DeviceObject<'a, S>>,
    pub addr_table: RefCell<AddressTableObject<'a, stack_test_config::AddrTab>>,
    pub asso_table: RefCell<AssociationTableObject<'a, stack_test_config::AssoTab>>,
    pub app_program: RefCell<ApplicationProgramObject<'a, Application<()>>>,
    pub group_object_table: RefCell<GroupObjectTableObject<'a, stack_test_config::CoTab>>,
    pub ip_parameter: RefCell<IpParameterObject<'a, S>>,
}

impl<'a, S> KnxIpInterfaceObjects<'a, S>
where
    S: StackState
        + IpStackState
        + HasAddressTable<ADT = stack_test_config::AddrTab>
        + HasAssociationTable<AST = stack_test_config::AssoTab>
        + HasCommunicationObjectTable<COT = stack_test_config::CoTab>
        + HasApplication<APP = Application<()>>,
{
    /// Create new interface objects from unified state
    pub fn new(state: &'a S) -> Self {
        // Create Device Object with device information and state reference
        let device = DeviceObject::with_values(state, KNXIP_DEVICE_DESCRIPTOR.hardware_type);

        // Create Application Program Object wrapping the application table
        // Using 0 for alloc address since NoMemoryMap is used (no memory-mapped access)
        let mut app_program = ApplicationProgramObject::new(state.app(), 0);
        app_program.set_program_version(KNXIP_DEVICE_DESCRIPTOR.program_version().into());
        app_program.set_pei_type(KNXIP_DEVICE_DESCRIPTOR.pei_type.into());

        // Create IP Parameter Object
        let ip_parameter = IpParameterObject::with_state(state);

        // Using 0 for alloc addresses since NoMemoryMap is used (no memory-mapped access)
        Self {
            state,
            device: RefCell::new(device),
            addr_table: RefCell::new(AddressTableObject::new(state.adt(), 0)),
            asso_table: RefCell::new(AssociationTableObject::new(state.ast(), 0)),
            app_program: RefCell::new(app_program),
            group_object_table: RefCell::new(GroupObjectTableObject::new(state.cot(), 0)),
            ip_parameter: RefCell::new(ip_parameter),
        }
    }
}

impl<'a, S> PropertyServiceHandler for KnxIpInterfaceObjects<'a, S>
where
    S: StackState + IpStackState,
{
    fn object_count(&self) -> u16 {
        6 // Device, AddrTable, AssoTable, AppProgram, GroupObjectTable, IpParameter
    }

    fn object_type_at(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        match object_idx {
            0 => Some(InterfaceObjectType::Device),
            1 => Some(InterfaceObjectType::AddressTable),
            2 => Some(InterfaceObjectType::AssociationTable),
            3 => Some(InterfaceObjectType::ApplicationProgram),
            4 => Some(InterfaceObjectType::GroupObjectTable),
            5 => Some(InterfaceObjectType::IPParameter),
            _ => None,
        }
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        match object_idx {
            0 => self.device.borrow().property_description(object_idx, prop_id, prop_idx),
            1 => self.addr_table.borrow().property_description(object_idx, prop_id, prop_idx),
            2 => self.asso_table.borrow().property_description(object_idx, prop_id, prop_idx),
            3 => self.app_program.borrow().property_description(object_idx, prop_id, prop_idx),
            4 => self.group_object_table.borrow().property_description(object_idx, prop_id, prop_idx),
            5 => self.ip_parameter.borrow().property_description(object_idx, prop_id, prop_idx),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_read(
        &self,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        // Check access level first (in separate scope to release borrow)
        {
            let desc = match req.object_idx {
                0 => self.device.borrow().property_descriptor_by_id(req.pid),
                1 => self.addr_table.borrow().property_descriptor_by_id(req.pid),
                2 => self.asso_table.borrow().property_descriptor_by_id(req.pid),
                3 => self.app_program.borrow().property_descriptor_by_id(req.pid),
                4 => self.group_object_table.borrow().property_descriptor_by_id(req.pid),
                5 => self.ip_parameter.borrow().property_descriptor_by_id(req.pid),
                _ => return Err(PropertyError::InvalidObjectIndex),
            };
            if let Some((_, desc)) = desc
                && !desc.can_read(req.ctx) {
                    return Err(PropertyError::AccessDenied);
                }
        }

        let prop_req = req.property_request();
        match req.object_idx {
            0 => self.device.borrow().read_property(prop_req, buf),
            1 => self.addr_table.borrow().read_property(prop_req, buf),
            2 => self.asso_table.borrow().read_property(prop_req, buf),
            3 => self.app_program.borrow().read_property(prop_req, buf),
            4 => self.group_object_table.borrow().read_property(prop_req, buf),
            5 => self.ip_parameter.borrow().read_property(prop_req, buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_write(
        &self,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Result<WriteResponse, PropertyError> {
        // Check access level first (in separate scope to release borrow)
        {
            let desc = match req.object_idx {
                0 => self.device.borrow().property_descriptor_by_id(req.pid),
                1 => self.addr_table.borrow().property_descriptor_by_id(req.pid),
                2 => self.asso_table.borrow().property_descriptor_by_id(req.pid),
                3 => self.app_program.borrow().property_descriptor_by_id(req.pid),
                4 => self.group_object_table.borrow().property_descriptor_by_id(req.pid),
                5 => self.ip_parameter.borrow().property_descriptor_by_id(req.pid),
                _ => return Err(PropertyError::InvalidObjectIndex),
            };
            if let Some((_, desc)) = desc
                && !desc.can_write(req.ctx) {
                    return Err(PropertyError::AccessDenied);
                }
        }

        let prop_req = req.property_request();
        match req.object_idx {
            0 => self.device.borrow_mut().write_property(prop_req),
            1 => self.addr_table.borrow_mut().write_property(prop_req),
            2 => self.asso_table.borrow_mut().write_property(prop_req),
            3 => self.app_program.borrow_mut().write_property(prop_req),
            4 => self.group_object_table.borrow_mut().write_property(prop_req),
            5 => self.ip_parameter.borrow_mut().write_property(prop_req),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }
}

use zweidraehte::dpt::{DeviceControl, ProgrammingMode, RoutingCount};

impl<'a, S> HasDeviceObject for KnxIpInterfaceObjects<'a, S>
where
    S: StackState + IpStackState,
{
    fn device_control(&self) -> DeviceControl {
        self.device.borrow().device_control
    }

    fn set_device_control(&self, value: DeviceControl) {
        self.device.borrow_mut().device_control = value;
    }

    fn programming_mode(&self) -> ProgrammingMode {
        ProgrammingMode::from(self.state.is_programming_mode())
    }

    fn set_programming_mode(&self, value: ProgrammingMode) {
        self.state.set_programming_mode(value.enabled());
    }

    fn routing_count(&self) -> RoutingCount {
        self.device.borrow().routing_count
    }

    fn set_routing_count(&self, value: RoutingCount) {
        self.device.borrow_mut().routing_count = value;
    }
}

// ============================================================================
// Interface Objects Creation
// ============================================================================

/// Create KNX/IP interface objects for the stack.
pub fn create_knxip_interface_objects<'a, S>(state: &'a S) -> KnxIpInterfaceObjects<'a, S>
where
    S: StackState
        + IpStackState
        + HasAddressTable<ADT = stack_test_config::AddrTab>
        + HasAssociationTable<AST = stack_test_config::AssoTab>
        + HasCommunicationObjectTable<COT = stack_test_config::CoTab>
        + HasApplication<APP = Application<()>>,
{
    KnxIpInterfaceObjects::new(state)
}

/// Unified state container for MyKnxStackWithKnxIp
///
/// Combines tables + IP state into a single struct.
pub struct KnxIpState<P: IpPlatform> {
    // Runtime state
    individual_address: Cell<IndividualAddress>,
    platform: P,
    // Tables
    pub adt: RefCell<stack_test_config::AddrTab>,
    pub ast: RefCell<stack_test_config::AssoTab>,
    pub cot: RefCell<stack_test_config::CoTab>,
    /// Application program table (holds both load and run state machines)
    pub app: RefCell<Application<()>>,
    /// Per-connection access level store
    access_store: zweidraehte::ConnectionAuthLevels<1>,
}

impl<P: IpPlatform> KnxIpState<P> {
    pub fn new(platform: P, individual_address: IndividualAddress) -> Self {
        Self {
            individual_address: Cell::new(individual_address),
            platform,
            adt: RefCell::new(stack_test_config::AddrTab::new()),
            ast: RefCell::new(stack_test_config::AssoTab::new()),
            cot: RefCell::new(stack_test_config::CoTab::new()),
            app: RefCell::new(Application::new()),
            access_store: zweidraehte::ConnectionAuthLevels::<1>::new(),
        }
    }

    pub fn with_tables(
        platform: P,
        individual_address: IndividualAddress,
        adt: stack_test_config::AddrTab,
        ast: stack_test_config::AssoTab,
        cot: stack_test_config::CoTab,
        app: Application<()>,
    ) -> Self {
        Self {
            individual_address: Cell::new(individual_address),
            platform,
            adt: RefCell::new(adt),
            ast: RefCell::new(ast),
            cot: RefCell::new(cot),
            app: RefCell::new(app),
            access_store: zweidraehte::ConnectionAuthLevels::<1>::new(),
        }
    }
}

impl<P: IpPlatform + Default> Default for KnxIpState<P> {
    fn default() -> Self {
        Self::new(P::default(), IndividualAddress::new(1, 1, 0))
    }
}

impl<P: IpPlatform + Default> StackState for KnxIpState<P> {
    fn individual_address(&self) -> IndividualAddress {
        self.individual_address.get()
    }

    fn set_individual_address(&self, addr: IndividualAddress) {
        self.individual_address.set(addr);
    }

    fn serial_number(&self) -> &[u8; 6] {
        &device_info::SERIAL_NUMBER
    }
}

impl<P: IpPlatform + Default> IpStackState for KnxIpState<P> {
    fn current_ip_address(&self) -> core::net::Ipv4Addr {
        self.platform.current_ip_address()
    }

    fn current_subnet_mask(&self) -> core::net::Ipv4Addr {
        self.platform.current_subnet_mask()
    }

    fn current_default_gateway(&self) -> core::net::Ipv4Addr {
        self.platform.current_default_gateway()
    }

    fn mac_address(&self) -> [u8; 6] {
        self.platform.mac_address()
    }

    fn current_ip_assignment_method(&self) -> u8 {
        self.platform.current_ip_assignment_method()
    }

    fn ip_assignment_method(&self) -> u8 {
        0x02 // Manual
    }

    fn set_ip_assignment_method(&self, _method: u8) {
        // Not implemented for this simple state
    }

    fn ip_capabilities(&self) -> u8 {
        self.platform.ip_capabilities()
    }

    fn knxnetip_device_capabilities(&self) -> u16 {
        self.platform.knxnetip_device_capabilities()
    }

    fn friendly_name_len(&self) -> usize {
        0
    }

    fn friendly_name(&self, _buf: &mut [u8]) -> usize {
        0 // No friendly name set
    }

    fn set_friendly_name(&self, _name: &[u8]) {
        // Not implemented for this simple state
    }

    fn configured_ip_address(&self) -> core::net::Ipv4Addr {
        self.platform.current_ip_address()
    }

    fn set_configured_ip_address(&self, _addr: core::net::Ipv4Addr) {
        // Not implemented for this simple state
    }

    fn configured_subnet_mask(&self) -> core::net::Ipv4Addr {
        self.platform.current_subnet_mask()
    }

    fn set_configured_subnet_mask(&self, _mask: core::net::Ipv4Addr) {
        // Not implemented for this simple state
    }

    fn configured_default_gateway(&self) -> core::net::Ipv4Addr {
        self.platform.current_default_gateway()
    }

    fn set_configured_default_gateway(&self, _gateway: core::net::Ipv4Addr) {
        // Not implemented for this simple state
    }

    fn routing_multicast_address(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::new(224, 0, 23, 12)
    }

    fn set_routing_multicast_address(&self, _addr: core::net::Ipv4Addr) {
        // Not implemented for this simple state
    }

    fn ttl(&self) -> u8 {
        16
    }

    fn set_ttl(&self, _ttl: u8) {
        // Not implemented for this simple state
    }

    fn project_installation_id(&self) -> u16 {
        device_info::PROJECT_INSTALLATION_ID
    }

    fn set_project_installation_id(&self, _id: u16) {
        // Not implemented for this simple state
    }
}

impl<P: IpPlatform> HasAddressTable for KnxIpState<P> {
    type ADT = stack_test_config::AddrTab;
    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl<P: IpPlatform> HasAssociationTable for KnxIpState<P> {
    type AST = stack_test_config::AssoTab;
    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl<P: IpPlatform> HasCommunicationObjectTable for KnxIpState<P> {
    type COT = stack_test_config::CoTab;
    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

impl<P: IpPlatform> HasRoutingCount for KnxIpState<P> {
    fn routing_count(&self) -> u8 { 6 }
    fn set_routing_count(&self, _value: u8) { /* demo device — not persisted */ }
}

impl<P: IpPlatform> HasApplication for KnxIpState<P> {
    type APP = Application<()>;
    fn app(&self) -> &RefCell<Self::APP> {
        &self.app
    }
}

impl<P: IpPlatform> zweidraehte::HasConnectionAuth for KnxIpState<P> {
    fn connection_access(&self, slot: u8) -> zweidraehte::AccessContext {
        self.access_store.get(slot)
    }

    fn set_connection_access(&self, slot: u8, ctx: zweidraehte::AccessContext) {
        self.access_store.set(slot, ctx);
    }

    fn reset_connection_access(&self, slot: u8, default_level: u8) {
        self.access_store.reset(slot, default_level);
    }
}

/// Unified state type for this test stack.
pub type MyState = KnxIpState<MockIpPlatform>;

/// Device descriptor for KNX/IP test stack
const KNXIP_DEVICE_DESCRIPTOR: DeviceDescriptor = DeviceDescriptor {
    mask_version: MaskVersion::SystemBKnxIp,
    manufacturer_id: 0x00FA,
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    application_id: 0x0100,
    application_version: 0x01,
    max_address_table_entries: 30,
    max_association_table_entries: 30,
    max_com_objects: 30,
    pei_type: 0,
};

#[derive(Debug, Clone, Copy)]
pub struct MyKnxStackWithKnxIp;
impl StackDefinition for MyKnxStackWithKnxIp {
    const DEVICE: &'static DeviceDescriptor = &KNXIP_DEVICE_DESCRIPTOR;
    const TL_STYLE: TlStyle = TlStyle::Style1;
    type P = AppParameters;
    type CO = comm_objs::AppComObjects;
    type LLB = KnxNetIpBuilder<platform::LinuxIpTransport, KnxIpDeviceUdp, 2>;
    type State = MyState;
    type Mem = NoMemoryMap;

    type InterfaceObjects<'a> = KnxIpInterfaceObjects<'a, Self::State>;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_knxip_interface_objects(state)
    }

    type LayerFactory = InsecureIpDeviceFactory;
}

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, MyKnxStackWithKnxIp>) {
    println!("Running KNX stack with KNX/IP link layer...");
    runner.run().await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    println!("=== KNX Stack with KNX/IP Link Layer ===");

    // Create configuration using the compile-time macro
    const CONFIG: stack_test_config::StackTestConfig = stack_test_config::StackTestConfig::new();

    println!("Configuration loaded from compile-time macro:");
    println!("  - Individual Address: {}", CONFIG.individual_address);
    println!("  - Address Table: {} entries", (CONFIG.addr7_data().len() - 2) / 2);
    println!("  - Association Table: {} entries", (CONFIG.asso6_data().len() - 2) / 4); // 4 bytes per entry
    println!("  - Communication Objects: {} objects", (CONFIG.co7_data().len() - 2) / 2);

    // Create KNX/IP link layer
    let control_endpoint = SocketAddrV4::new("192.168.106.6".parse().unwrap(), 3671);

    let interface_addr = platform::get_interface_address("knxdevbridgeif").expect("Failed to get interface address");
    let link_layer_builder =
        KnxNetIpBuilder::<platform::LinuxIpTransport, _, 2>::new("knxdevbridgeif", interface_addr, control_endpoint, ())
            .enable_routing_server()
            .enable_remote_config_server();

    println!("KNX/IP Configuration:");
    println!("  - Interface: knxdevbridgeif");
    println!("  - Multicast: 224.0.23.12:3671");
    println!("  - Unicast: 0.0.0.0:3671");
    println!("  - Individual Address: 1.1.0");
    println!("  - Control Endpoint: {:?}", control_endpoint);
    println!("  - Discovery Server: SearchRequest, DescriptionRequest");
    println!("  - Routing Server: RoutingIndication, RoutingBusy, RoutingLostMessage");

    // Create table instances with configuration data loaded
    // Define table reference addresses for memory-mapped access
    // These match a typical System B memory layout
    const ADT_BASE: u32 = 0x0100;
    const AST_BASE: u32 = 0x0200;
    const COT_BASE: u32 = 0x0300;
    let (addr_tab, asso_tab, co_tab) = stack_test_config::StackTestConfig::create_tables(ADT_BASE, AST_BASE, COT_BASE);

    // Create application table - starts loaded and running for this demo
    let mut app_table = Application::<()>::new();
    // Load and start the application
    app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
    app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
    app_table.write_rsm(&[RunEvent::Restart.into()]);

    // Create the unified state container (tables + IP state)
    let state = KnxIpState::with_tables(
        MockIpPlatform::default(),
        CONFIG.individual_address,
        addr_tab,
        asso_tab,
        co_tab,
        app_table,
    );

    // Create stack resources - the stack takes ownership of the state
    // and stores it so we can access via the Stack handle
    static RESOURCES: StaticCell<
        StackResources<
            MyKnxStackWithKnxIp,
            { zweidraehte::config::buffer_size_for_apdu(MyKnxStackWithKnxIp::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();
    let (stack, runner) = zweidraehte::new(
        RESOURCES.init(StackResources::new()),
        comm_objs::AppComObjects::new(),
        (), // hook_context
        link_layer_builder,
        state,
        NoMemoryMap,
    );

    // The interface objects are now stored inside the stack (in StackResources)
    // and can be accessed via stack.interface_objects()
    let interface_objects = stack.interface_objects();

    // Demonstrate accessing the interface objects
    // The container implements PropertyServiceHandler to handle management requests
    println!("Interface Objects created via builder:");
    println!("  - Device Object: hardware_type = {:02X?}", interface_objects.device.borrow().hardware_type.as_ref());
    println!("  - Address Table Object: wraps stack's address table");
    println!("  - Association Table Object: wraps stack's association table");
    println!(
        "  - Application Program Object: program_version = {:02X?}",
        interface_objects.app_program.borrow().program_version().as_ref()
    );
    println!("  - Group Object Table Object: wraps stack's CO table");
    // TODO: Re-enable once IpParameterObject supports InterfaceObjectsBuilder trait bounds
    // println!(
    //     "  - IP Parameter Object: project_installation_id = {:04X}",
    //     interface_objects.ip_parameter.borrow().project_installation_id.value()
    // );

    // Spawn the stack runner
    spawner.spawn(run_stack(runner)).unwrap();

    println!("\n=== Stack Running ===");
    println!("Communication Objects:");
    println!("  CO 1-4: Inputs  (co_in0-3)");
    println!("  CO 5-8: Outputs (co_out0-3)");
    println!("\nListening for KNX/IP discovery requests...");
    println!("Test with: knxtool search\n");

    // Main application loop - monitor and control communication objects
    let mut events = stack.events();
    let mut last_print = embassy_time::Instant::now();

    loop {
        // Print stack status every 5 seconds
        if embassy_time::Instant::now().duration_since(last_print) > Duration::from_secs(5) {
            let objects = stack.objects();
            let co_borrow = objects.borrow();

            println!("\n--- Stack Status ---");
            println!("Inputs:");
            for i in 1..=4 {
                let value = co_borrow.value(i);
                let status = co_borrow.status(i);
                println!("  CO {}: {:?} (status: {:?})", i, value, status);
            }
            println!("Outputs:");
            for i in 5..=8 {
                let value = co_borrow.value(i);
                let status = co_borrow.status(i);
                println!("  CO {}: {:?} (status: {:?})", i, value, status);
            }
            println!("--------------------\n");

            last_print = embassy_time::Instant::now();
        }

        // Process events with a timeout
        match embassy_time::with_timeout(Duration::from_millis(100), events.next_message()).await {
            Ok(WaitResult::Message((index, event))) => {
                println!("Event: {:?} on CO {:?}", event, index);

                // Example: Toggle output when input changes
                if let ComObjectEvent::Updated = event {
                    let idx = index.index();
                    if (1..=4).contains(&idx) {
                        // Input updated - toggle corresponding output
                        let output_idx = comm_objs::Index::from_index(idx + 4).unwrap();
                        let current = {
                            let objects = stack.objects();
                            let co_borrow = objects.borrow();
                            let value_bytes = co_borrow.value(idx + 4);
                            // DPT_Switch is stored as a single byte, bit 0 is the value
                            !value_bytes.is_empty() && (value_bytes[0] & 0x01) != 0
                        };
                        let _ = stack.update_object(output_idx, DPT_Switch::from(!current)).await;
                        println!("Toggled output CO {} in response to input CO {}", idx + 4, idx);
                    }
                }
            }
            Ok(WaitResult::Lagged(count)) => {
                println!("Warning: Missed {} events (processing too slow)", count);
            }
            Err(_) => {
                // Timeout - continue
            }
        }
    }
}
