//! Full Stack Test Harness
//!
//! This module provides the infrastructure to run the complete KNX stack
//! with a MockLinkLayer for conformance testing.
//!
//! Unlike the network layer harness, this tests the entire stack end-to-end:
//! - Application Layer
//! - Transport Layer
//! - Network Layer
//! - MockLinkLayer (for injection/capture)
//!
//! This is required for EITT tests that expect full device responses
//! (e.g., GroupValue_Read → GroupValue_Response).

use core::cell::RefCell;
use std::net::Ipv4Addr;

use const_default::ConstDefault;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use static_cell::StaticCell;

use zweidraehte::{
    BasicIpStackState, IpPlatform, IpStackState, define_com_objects,
    messages::buffers::{Buffer, BufferManager, DynBufferManager, MessageBuffer},
    messages::knx::{KnxMessageBuffer, ServiceType},
    objects::comm::ComObjects,
    objects::interface::{
        AddressTableObject, ApplicationProgramObject, AssociationTableObject, DeviceObject,
        GroupObjectTableObject, InterfaceObject, InterfaceObjectsBuilder, IpParameterObject,
        PropertyDescriptionResponse, PropertyError, PropertyServiceHandler,
    },
    objects::tables::LoadableTable,
    Runner, StackDefinition, StackResources,
};

use super::mock::{CapturedLinkLayerMessage, MockLinkLayerBuilder, MockLinkLayerHandle, MockLinkLayerResources};

// ============================================================================
// Test Communication Objects
// ============================================================================

define_com_objects! {
    pub mod test_comm_objs {
        pub struct TestComObjects {
            // 1-byte objects for long format responses (network layer tests 3.x)
            // DPT_Value_1_Ucount is 1 byte (8 bits), forcing long format GroupValue_Response
            1 => pub co_1: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),
            2 => pub co_2: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),
            3 => pub co_3: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),
            4 => pub co_4: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),

            // 1-bit object for short format responses (transport layer tests 2.x)
            // DPT_Switch is 1 bit, uses short format with value in APCI field
            5 => pub co_switch: DPT_Switch = DPT_Switch::from(false),
        }
    }
}

// ============================================================================
// Test Stack Configuration
// ============================================================================

mod conformance_config {
    use zweidraehte::config::{CE, RE, TE, UE, WE};
    use zweidraehte::knx_stack_config;

    knx_stack_config! {
        name: ConformanceTestConfig,
        individual_address: "1.0.1",  // DUT individual address matching EITT tests (BDUT = 1.0.1 = 0x1001)

        group_addresses: {
            // Group address 2/0/1 = 0x1001 for network layer tests (long format)
            1 => "2/0/1",
            2 => "2/0/2",
            3 => "2/0/3",
            4 => "2/0/4",
            // Group address 5/5/5 = 0x2D05 for transport layer tests (short format)
            // This matches GO_ADDR in transport_layer_general.rs test variables
            5 => "5/5/5",
        },

        comm_objects: {
            // 1-byte objects for long format GroupValue_Response (network layer tests)
            // Size 7 = 1 byte
            1 => (7, CE | TE | RE | WE | UE),
            2 => (7, CE | TE | RE | WE | UE),
            3 => (7, CE | TE | RE | WE | UE),
            4 => (7, CE | TE | RE | WE | UE),
            // 1-bit object for short format GroupValue_Response (transport layer tests)
            // Size 1 = 1 bit (fits in 6-bit APCI field)
            5 => (1, CE | TE | RE | WE | UE),
        },

        associations: {
            1 => [1],  // TSAP 1 (2/0/1) → CO 1 (1-byte)
            2 => [2],  // TSAP 2 (2/0/2) → CO 2 (1-byte)
            3 => [3],  // TSAP 3 (2/0/3) → CO 3 (1-byte)
            4 => [4],  // TSAP 4 (2/0/4) → CO 4 (1-byte)
            5 => [5],  // TSAP 5 (5/5/5) → CO 5 (1-bit, short format)
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
// Device Information
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
}

// ============================================================================
// KNX/IP Interface Objects
// ============================================================================

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
pub struct KnxIpInterfaceObjects<'a, ADT, AST, COT, S>
where
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
    S: IpStackState,
{
    pub device: RefCell<DeviceObject<'a, S>>,
    pub addr_table: RefCell<AddressTableObject<'a, ADT>>,
    pub asso_table: RefCell<AssociationTableObject<'a, AST>>,
    pub app_program: RefCell<ApplicationProgramObject>,
    pub group_object_table: RefCell<GroupObjectTableObject<'a, COT>>,
    pub ip_parameter: RefCell<IpParameterObject<'a, S>>,
}

impl<'a, ADT, AST, COT, S> KnxIpInterfaceObjects<'a, ADT, AST, COT, S>
where
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
    S: IpStackState,
{
    /// Create new interface objects wrapping the provided tables
    pub fn new(
        addr_table: &'a RefCell<ADT>,
        asso_table: &'a RefCell<AST>,
        co_table: &'a RefCell<COT>,
        state: &'a S,
    ) -> Self {
        // Create Device Object with device information and state reference
        let device = DeviceObject::with_values(state, device_info::SERIAL_NUMBER, device_info::HARDWARE_TYPE);

        // Create Application Program Object
        let mut app_program = ApplicationProgramObject::new();
        app_program.program_version = device_info::PROGRAM_VERSION.into();
        app_program.pei_type = device_info::PEI_TYPE.into();
        // Load state starts as "loaded" for this demo
        app_program.load_state = 0x01.into(); // Loaded
        app_program.run_state = 0x01.into(); // Running

        // Create IP Parameter Object
        let ip_parameter = IpParameterObject::with_state(state);

        Self {
            device: RefCell::new(device),
            addr_table: RefCell::new(AddressTableObject::new(addr_table)),
            asso_table: RefCell::new(AssociationTableObject::new(asso_table)),
            app_program: RefCell::new(app_program),
            group_object_table: RefCell::new(GroupObjectTableObject::new(co_table)),
            ip_parameter: RefCell::new(ip_parameter),
        }
    }
}

impl<'a, ADT, AST, COT, S> PropertyServiceHandler for KnxIpInterfaceObjects<'a, ADT, AST, COT, S>
where
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
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
    ) -> Result<usize, PropertyError> {
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
    ) -> Result<(), PropertyError> {
        match object_idx {
            0 => self.device.borrow_mut().write_property(prop_id, start_idx, data),
            1 => self.addr_table.borrow_mut().write_property(prop_id, start_idx, data),
            2 => self.asso_table.borrow_mut().write_property(prop_id, start_idx, data),
            3 => self.app_program.borrow_mut().write_property(prop_id, start_idx, data),
            4 => self.group_object_table.borrow_mut().write_property(prop_id, start_idx, data),
            5 => self.ip_parameter.borrow_mut().write_property(prop_id, start_idx, data),
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

impl<S: IpStackState> InterfaceObjectsBuilder<S> for KnxIpInterfaceObjectsBuilder {
    type Objects<'a, ADT, AST, COT>
        = KnxIpInterfaceObjects<'a, ADT, AST, COT, S>
    where
        ADT: LoadableTable + 'a,
        AST: LoadableTable + 'a,
        COT: LoadableTable + 'a,
        S: 'a;

    fn build<'a, ADT, AST, COT>(
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
        S: 'a,
    {
        KnxIpInterfaceObjects::new(addr_table, asso_table, co_table, state)
    }
}

// ============================================================================
// Test Parameters
// ============================================================================

#[derive(Debug)]
pub struct TestParameters;

impl ConstDefault for TestParameters {
    const DEFAULT: Self = TestParameters;
}

// ============================================================================
// Stack Definition
// ============================================================================

/// Stack definition for conformance testing
#[derive(Debug, Clone, Copy)]
pub struct ConformanceTestStack;

impl StackDefinition for ConformanceTestStack {
    const MASK_VERSION: &'static [u8; 2] = &[0x57, 0xb0];
    type ADT = conformance_config::AddrTab;
    type AST = conformance_config::AssoTab;
    type COT = conformance_config::CoTab;
    type P = TestParameters;
    type CO = test_comm_objs::TestComObjects;
    type LLB = MockLinkLayerBuilder<16, 16>;
    type IOB = KnxIpInterfaceObjectsBuilder;
    type State = BasicIpStackState<MockIpPlatform>;
}

// ============================================================================
// Static Resources
// ============================================================================

// Injection channel for sending messages into the stack
static INJECTION_CHANNEL: StaticCell<Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, 16>> = StaticCell::new();

// Capture channel for receiving messages from the stack
static CAPTURE_CHANNEL: StaticCell<Channel<NoopRawMutex, CapturedLinkLayerMessage, 16>> = StaticCell::new();

// Stack resources
static STACK_RESOURCES: StaticCell<StackResources<ConformanceTestStack>> = StaticCell::new();

// Link layer resources
static LL_RESOURCES: StaticCell<MockLinkLayerResources> = StaticCell::new();

// Buffer manager for test injections
static INJECTION_BUFFERS: StaticCell<[[u8; 64]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();

// ============================================================================
// Full Stack Harness
// ============================================================================

/// Full stack test harness with MockLinkLayer
///
/// This harness runs the complete KNX stack and provides methods to:
/// - Inject telegrams (simulating incoming messages from the bus)
/// - Capture outgoing telegrams (messages the stack sends to the bus)
/// - Control device state (programming mode, etc.)
pub struct FullStackHarness {
    handle: MockLinkLayerHandle<16, 16>,
    buffer_manager: DynBufferManager<'static>,
    stack: zweidraehte::Stack<'static, ConformanceTestStack>,
}

impl FullStackHarness {
    /// Create a new full stack harness
    ///
    /// Returns the harness and a runner that must be spawned as a task.
    pub fn new() -> (Self, Runner<'static, ConformanceTestStack>, &'static mut MockLinkLayerResources) {
        // Initialize static channels
        let injection_channel = INJECTION_CHANNEL.init(Channel::new());
        let capture_channel = CAPTURE_CHANNEL.init(Channel::new());

        // Initialize buffer manager for test injections
        let buffers = INJECTION_BUFFERS.init([[0u8; 64]; 16]);
        // SAFETY: We're initializing the buffer manager with our static buffers
        let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
        let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
        // SAFETY: We're transmuting to 'static because the buffer manager lives for the entire program
        let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

        // Create MockLinkLayerBuilder with capture support
        let (link_layer_builder, handle) =
            MockLinkLayerBuilder::<16, 16>::with_capture(injection_channel, capture_channel);

        // Create tables from configuration
        let (addr_tab, asso_tab, co_tab) = conformance_config::ConformanceTestConfig::create_tables();

        // Create stack resources
        let resources = STACK_RESOURCES.init(StackResources::new());

        // Create stack
        let (stack, runner) = zweidraehte::new(
            resources,
            addr_tab,
            asso_tab,
            co_tab,
            test_comm_objs::TestComObjects::new(),
            link_layer_builder,
            KnxIpInterfaceObjectsBuilder,
        );

        let ll_resources = LL_RESOURCES.init(MockLinkLayerResources::new());

        let harness = Self { handle, buffer_manager: dyn_buffer_manager, stack };
        (harness, runner, ll_resources)
    }

    /// Allocate a buffer and create a KnxMessageBuffer from raw bytes
    pub async fn create_message(&self, data: &[u8], service_type: ServiceType) -> KnxMessageBuffer<Buffer<'static>> {
        let mut buffer = self.buffer_manager.alloc().await;
        buffer.fill_from_slice(data);
        KnxMessageBuffer::new(buffer, service_type)
    }

    /// Inject a raw telegram into the stack (simulating incoming message from bus)
    ///
    /// This creates an L_Data.ind message with the given bytes.
    pub async fn inject_raw(&self, data: &[u8]) {
        let msg = self.create_message(data, ServiceType::L_Data_Ind).await;
        self.handle.inject(msg).await;
    }

    /// Inject a telegram into the stack (simulating incoming message from bus)
    pub async fn inject(&self, msg: KnxMessageBuffer<Buffer<'static>>) {
        self.handle.inject(msg).await;
    }

    /// Wait for and receive a captured outgoing telegram
    pub async fn receive_captured(&self) -> Option<CapturedLinkLayerMessage> {
        self.handle.receive_captured().await
    }

    /// Try to receive a captured telegram without blocking
    pub fn try_receive_captured(&self) -> Option<CapturedLinkLayerMessage> {
        self.handle.try_receive_captured()
    }

    /// Set the programming mode flag on the DUT
    ///
    /// When enabled, the device responds to A_IndividualAddress_Read broadcasts.
    pub fn set_programming_mode(&self, enabled: bool) {
        self.stack.set_programming_mode(enabled);
    }

    /// Drain all pending captured messages from the channel
    ///
    /// This is useful for clearing leftover messages between tests.
    /// Returns the number of messages drained.
    pub fn drain_captured(&self) -> usize {
        self.handle.drain_captured()
    }
}
