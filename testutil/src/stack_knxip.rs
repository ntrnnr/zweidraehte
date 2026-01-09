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

use core::cell::RefCell;

use const_default::ConstDefault;
use embassy_executor::Spawner;
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use platform::address::EthernetAddress;
use static_cell::StaticCell;
use std::net::Ipv4Addr;
use zweidraehte::{
    BasicIpStackState, IpPlatform, IpStackState, Runner, StackDefinition, StackResources,
    address::IndividualAddress,
    define_com_objects,
    dpt::DPT_Switch,
    layers::linklayers::knxip::{EndpointType, KnxNetIpBuilder, KnxNetIpResources, servers},
    memory::{HasAddressTable, HasAssociationTable, HasCommunicationObjectTable},
    messages::knxip::KNXnetIPServiceType,
    messages::knxip::substructs::{DeviceInformation, DeviceStatus, HPAI, KNXMedium, ServiceFamily, SupportedService},
    objects::comm::{ComObjectIndex, ComObjects},
    objects::interface::{
        AddressTableObject, ApplicationProgramObject, AssociationTableObject, DeviceObject, GroupObjectTableObject,
        InterfaceObject, InterfaceObjectsBuilder, IpParameterObject, PropertyDescriptionResponse, PropertyError,
        PropertyServiceHandler,
    },
    objects::tables::{LoadableTable, RunnableTable, LoadEvent, RunEvent, app::Application},
};

#[derive(Debug, ConstDefault)]
pub struct AppParameters {
    _delay_time: u16,
}

define_com_objects! {
    pub mod comm_objs {
        pub struct AppComObjects {
            1 => pub co_in0: DPT_Switch = DPT_Switch::from(false),
            2 => pub co_in1: DPT_Switch = DPT_Switch::from(false),
            3 => pub co_in2: DPT_Switch = DPT_Switch::from(false),
            4 => pub co_in3: DPT_Switch = DPT_Switch::from(false),
            5 => pub co_out0: DPT_Switch = DPT_Switch::from(false),
            6 => pub co_out1: DPT_Switch = DPT_Switch::from(false),
            7 => pub co_out2: DPT_Switch = DPT_Switch::from(false),
            8 => pub co_out3: DPT_Switch = DPT_Switch::from(false),
        }
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

// ============================================================================
// Interface Objects Configuration
// ============================================================================

/// Device-specific constants for Interface Objects
mod device_info {
    /// Device serial number (6 bytes)
    /// Format: bytes 0-1 = manufacturer ID (0x00FA), bytes 2-5 = device-specific
    pub const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

    /// Hardware type identifier (6 bytes)
    pub const HARDWARE_TYPE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

    /// Application program version (5 bytes: manufacturer, app_id, version)
    pub const PROGRAM_VERSION: [u8; 5] = [0x00, 0xFA, 0x01, 0x00, 0x01];

    /// PEI type (0 = no PEI)
    pub const PEI_TYPE: u8 = 0x00;

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
/// - Index 3: Application Program Object
/// - Index 4: Group Object Table Object
/// - Index 5: IP Parameter Object
pub struct KnxIpInterfaceObjects<'a, S>
where
    S: IpStackState,
{
    pub device: RefCell<DeviceObject<'a, S>>,
    pub addr_table: RefCell<AddressTableObject<'a, stack_test_config::AddrTab>>,
    pub asso_table: RefCell<AssociationTableObject<'a, stack_test_config::AssoTab>>,
    pub app_program: RefCell<ApplicationProgramObject<'a, Application<()>>>,
    pub group_object_table: RefCell<GroupObjectTableObject<'a, stack_test_config::CoTab>>,
    pub ip_parameter: RefCell<IpParameterObject<'a, S>>,
}

impl<'a, S> KnxIpInterfaceObjects<'a, S>
where
    S: IpStackState,
{
    /// Create new interface objects wrapping the provided tables
    pub fn new(tables: &'a KnxIpTables, state: &'a S) -> Self {
        // Create Device Object with device information and state reference
        // Note: serial_number and manufacturer_id are read dynamically from StackState
        let device = DeviceObject::with_values(state, device_info::HARDWARE_TYPE);

        // Create Application Program Object wrapping the application table
        // Using 0 for alloc address since NoMemoryMap is used (no memory-mapped access)
        let mut app_program = ApplicationProgramObject::new(tables.app(), 0);
        app_program.set_program_version(device_info::PROGRAM_VERSION.into());
        app_program.set_pei_type(device_info::PEI_TYPE.into());

        // Create IP Parameter Object
        let ip_parameter = IpParameterObject::with_state(state);

        // Using 0 for alloc addresses since NoMemoryMap is used (no memory-mapped access)
        Self {
            device: RefCell::new(device),
            addr_table: RefCell::new(AddressTableObject::new(tables.adt(), 0)),
            asso_table: RefCell::new(AssociationTableObject::new(tables.ast(), 0)),
            app_program: RefCell::new(app_program),
            group_object_table: RefCell::new(GroupObjectTableObject::new(tables.cot(), 0)),
            ip_parameter: RefCell::new(ip_parameter),
        }
    }
}

impl<'a, S> PropertyServiceHandler for KnxIpInterfaceObjects<'a, S>
where
    S: IpStackState,
{
    fn object_count(&self) -> u16 {
        6 // Device, AddrTable, AssoTable, AppProgram, GroupObjectTable, IpParameter
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
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
        access_level: u8,
    ) -> Result<usize, PropertyError> {
        // Check access level first (in separate scope to release borrow)
        {
            let desc = match object_idx {
                0 => self.device.borrow().property_descriptor_by_id(prop_id),
                1 => self.addr_table.borrow().property_descriptor_by_id(prop_id),
                2 => self.asso_table.borrow().property_descriptor_by_id(prop_id),
                3 => self.app_program.borrow().property_descriptor_by_id(prop_id),
                4 => self.group_object_table.borrow().property_descriptor_by_id(prop_id),
                5 => self.ip_parameter.borrow().property_descriptor_by_id(prop_id),
                _ => return Err(PropertyError::InvalidObjectIndex),
            };
            if let Some((_, desc)) = desc {
                if !desc.can_read(access_level) {
                    return Err(PropertyError::AccessDenied);
                }
            }
        }

        match object_idx {
            0 => self.device.borrow().read_property(prop_id, start_idx, count, buf),
            1 => self.addr_table.borrow().read_property(prop_id, start_idx, count, buf),
            2 => self.asso_table.borrow().read_property(prop_id, start_idx, count, buf),
            3 => self.app_program.borrow().read_property(prop_id, start_idx, count, buf),
            4 => self.group_object_table.borrow().read_property(prop_id, start_idx, count, buf),
            5 => self.ip_parameter.borrow().read_property(prop_id, start_idx, count, buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        data: &[u8],
        response_buf: &mut [u8],
        access_level: u8,
    ) -> Result<usize, PropertyError> {
        // Check access level first (in separate scope to release borrow)
        {
            let desc = match object_idx {
                0 => self.device.borrow().property_descriptor_by_id(prop_id),
                1 => self.addr_table.borrow().property_descriptor_by_id(prop_id),
                2 => self.asso_table.borrow().property_descriptor_by_id(prop_id),
                3 => self.app_program.borrow().property_descriptor_by_id(prop_id),
                4 => self.group_object_table.borrow().property_descriptor_by_id(prop_id),
                5 => self.ip_parameter.borrow().property_descriptor_by_id(prop_id),
                _ => return Err(PropertyError::InvalidObjectIndex),
            };
            if let Some((_, desc)) = desc {
                if !desc.can_write(access_level) {
                    return Err(PropertyError::AccessDenied);
                }
            }
        }

        match object_idx {
            0 => self.device.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            1 => self.addr_table.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            2 => self.asso_table.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            3 => self.app_program.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            4 => self.group_object_table.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            5 => self.ip_parameter.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }
}

// ============================================================================
// Interface Objects Builder
// ============================================================================

/// Builder for KNXnet/IP interface objects
///
/// This builder is consumed during stack initialization to create the
/// `KnxIpInterfaceObjects` container with all required interface objects.
#[derive(Debug, Clone, Copy)]
pub struct KnxIpInterfaceObjectsBuilder;

impl<S> InterfaceObjectsBuilder<S, KnxIpTables> for KnxIpInterfaceObjectsBuilder
where
    S: IpStackState,
{
    type Objects<'a>
        = KnxIpInterfaceObjects<'a, S>
    where
        KnxIpTables: 'a,
        S: 'a;

    fn build<'a>(self, tables: &'a KnxIpTables, state: &'a S) -> Self::Objects<'a>
    where
        KnxIpTables: 'a,
        S: 'a,
    {
        KnxIpInterfaceObjects::new(tables, state)
    }
}

/// Tables container for MyKnxStackWithKnxIp
pub struct KnxIpTables {
    pub adt: RefCell<stack_test_config::AddrTab>,
    pub ast: RefCell<stack_test_config::AssoTab>,
    pub cot: RefCell<stack_test_config::CoTab>,
    /// Application program table (holds both load and run state machines)
    pub app: RefCell<Application<()>>,
}

impl HasAddressTable for KnxIpTables {
    type ADT = stack_test_config::AddrTab;
    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl HasAssociationTable for KnxIpTables {
    type AST = stack_test_config::AssoTab;
    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl HasCommunicationObjectTable for KnxIpTables {
    type COT = stack_test_config::CoTab;
    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

impl KnxIpTables {
    /// Get a reference to the application program table
    pub fn app(&self) -> &RefCell<Application<()>> {
        &self.app
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MyKnxStackWithKnxIp;
impl StackDefinition for MyKnxStackWithKnxIp {
    const MASK_VERSION: &'static [u8; 2] = &[0x57, 0xb0];
    type Tables = KnxIpTables;
    type P = AppParameters;
    type CO = comm_objs::AppComObjects;
    type LLB = KnxNetIpBuilder<2, 2>; // 2 sockets, 2 servers
    type IOB = KnxIpInterfaceObjectsBuilder;
    type State = BasicIpStackState<MockIpPlatform>;
    type Mem = zweidraehte::memory::NoMemoryMap;
}

#[embassy_executor::task]
async fn run_stack(
    runner: Runner<'static, MyKnxStackWithKnxIp>,
    link_layer_resources: &'static mut KnxNetIpResources<2>,
) {
    println!("Running KNX stack with KNX/IP link layer...");
    runner.run(link_layer_resources).await;
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

    // Create KNX/IP Discovery Server configuration
    const SUPPORTED_SERVICES: &[SupportedService] = &[
        SupportedService { family: ServiceFamily::Core, version: 1 },
        //SupportedService { family: ServiceFamily::DeviceManagement, version: 1 },
        //SupportedService { family: ServiceFamily::Tunneling, version: 1 },
        SupportedService { family: ServiceFamily::Routing, version: 1 },
    ];

    let control_endpoint = HPAI::Ipv4Udp { addr: "192.168.106.6".parse().unwrap(), port: 3671 };

    let device_info = DeviceInformation {
        medium: KNXMedium::KNXIP,
        device_status: DeviceStatus::None,
        individual_address: IndividualAddress::new(1, 1, 0),
        project_installation_identifier: 0x1234,
        knx_serial_number: [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78],
        routing_multicast_address: core::net::Ipv4Addr::new(224, 0, 23, 12),
        mac_address: EthernetAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        friendly_name: *b"KNX Stack Test\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    let discovery_server = servers::DiscoveryServer::new(control_endpoint, device_info, SUPPORTED_SERVICES);

    // Create routing server for KNX/IP routing
    let routing_server = servers::RoutingServer::new(core::net::Ipv4Addr::new(224, 0, 23, 12), 3671);

    // Create KNX/IP link layer builder with both discovery and routing servers
    let link_layer_builder = KnxNetIpBuilder::<2, 2>::new("knxdevbridgeif")
        .add_server(
            discovery_server,
            &[KNXnetIPServiceType::SearchRequest, KNXnetIPServiceType::DescriptionRequest],
            &[
                EndpointType::new_udp(core::net::Ipv4Addr::new(224, 0, 23, 12), 3671), // KNX multicast
                EndpointType::new_udp_any(3671),                                       // Unicast on 3671
            ],
        )
        .add_server(
            routing_server,
            &[
                KNXnetIPServiceType::RoutingIndication,
                KNXnetIPServiceType::RoutingBusy,
                KNXnetIPServiceType::RoutingLostMessage,
            ],
            &[
                EndpointType::new_udp(core::net::Ipv4Addr::new(224, 0, 23, 12), 3671), // KNX multicast
            ],
        );

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

    // Create the tables container
    let tables = KnxIpTables {
        adt: RefCell::new(addr_tab),
        ast: RefCell::new(asso_tab),
        cot: RefCell::new(co_tab),
        app: RefCell::new(app_table),
    };

    // Create stack resources - the stack takes ownership of the tables
    // and stores them in RefCells that we can access via the Stack handle
    static RESOURCES: StaticCell<StackResources<MyKnxStackWithKnxIp>> = StaticCell::new();
    let (stack, runner) = zweidraehte::new(
        RESOURCES.init(StackResources::new()),
        tables,
        comm_objs::AppComObjects::new(),
        (), // hook_context
        link_layer_builder,
        KnxIpInterfaceObjectsBuilder,
        BasicIpStackState::default(),
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

    // Create link layer resources
    let ll_resources = Box::leak(Box::new(KnxNetIpResources::<2>::new()));

    // Spawn the stack runner
    spawner.spawn(run_stack(runner, ll_resources)).unwrap();

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
                use zweidraehte::objects::comm::ComObjectEvent;
                if let ComObjectEvent::Updated = event {
                    let idx = index.index();
                    if idx >= 1 && idx <= 4 {
                        // Input updated - toggle corresponding output
                        let output_idx = comm_objs::Index::from_index(idx + 4).unwrap();
                        let current = {
                            let objects = stack.objects();
                            let co_borrow = objects.borrow();
                            let value_bytes = co_borrow.value(idx + 4);
                            // DPT_Switch is stored as a single byte, bit 0 is the value
                            value_bytes.len() > 0 && (value_bytes[0] & 0x01) != 0
                        };
                        stack.update_object(output_idx, DPT_Switch::from(!current)).await;
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
