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

use const_default::ConstDefault;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use static_cell::StaticCell;

use zweidraehte::{
    define_com_objects,
    messages::buffers::{Buffer, BufferManager, DynBufferManager, MessageBuffer},
    messages::knx::{KnxMessageBuffer, ServiceType},
    objects::comm::ComObjects,
    objects::interface::{InterfaceObjectsBuilder, PropertyDescriptionResponse, PropertyError, PropertyServiceHandler},
    objects::tables::LoadableTable,
    Runner, StackDefinition, StackResources,
};

use super::mock::{
    CapturedLinkLayerMessage, MockLinkLayerBuilder, MockLinkLayerHandle, MockLinkLayerResources,
};

// ============================================================================
// Test Communication Objects
// ============================================================================

define_com_objects! {
    pub mod test_comm_objs {
        pub struct TestComObjects {
            // For conformance testing, we need objects > 6 bits to use long format responses
            // DPT_Value_1_Ucount is 1 byte (8 bits), forcing long format GroupValue_Response
            1 => pub co_1: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),   // For GroupValue_Response tests
            2 => pub co_2: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),
            3 => pub co_3: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),
            4 => pub co_4: DPT_Value_1_Ucount = DPT_Value_1_Ucount::from(0u8),
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
            // Group address 2/0/1 = 0x1001 (matches GO_ADDR in test variables)
            1 => "2/0/1",  // For GroupValue tests
            2 => "2/0/2",
            3 => "2/0/3",
            4 => "2/0/4",
        },

        comm_objects: {
            // All objects have full flags for read/write/response testing
            // Use size 7 (Byte1 = 1 byte) to force long format GroupValue_Response
            1 => (7, CE | TE | RE | WE | UE),
            2 => (7, CE | TE | RE | WE | UE),
            3 => (7, CE | TE | RE | WE | UE),
            4 => (7, CE | TE | RE | WE | UE),
        },

        associations: {
            1 => [1],  // TSAP 1 (2/0/1) → CO 1
            2 => [2],  // TSAP 2 (2/0/2) → CO 2
            3 => [3],  // TSAP 3 (2/0/3) → CO 3
            4 => [4],  // TSAP 4 (2/0/4) → CO 4
        },
    }
}

// ============================================================================
// Minimal Interface Objects
// ============================================================================

/// Minimal interface objects container for conformance testing
///
/// This provides the bare minimum interface objects needed for the stack to run.
pub struct MinimalInterfaceObjects;

impl PropertyServiceHandler for MinimalInterfaceObjects {
    fn object_count(&self) -> u16 {
        0
    }

    fn property_description_read(
        &self,
        _object_idx: u16,
        _prop_id: u8,
        _prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }

    fn property_value_read(
        &self,
        _object_idx: u16,
        _prop_id: u8,
        _start_idx: u16,
        _count: u16,
        _buf: &mut [u8],
    ) -> Result<usize, PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }

    fn property_value_write(
        &self,
        _object_idx: u16,
        _prop_id: u8,
        _start_idx: u16,
        _data: &[u8],
    ) -> Result<(), PropertyError> {
        Err(PropertyError::InvalidObjectIndex)
    }
}

/// Builder for minimal interface objects
#[derive(Debug, Clone, Copy)]
pub struct MinimalInterfaceObjectsBuilder;

impl InterfaceObjectsBuilder for MinimalInterfaceObjectsBuilder {
    type Objects<'a, ADT, AST, COT>
        = MinimalInterfaceObjects
    where
        ADT: LoadableTable + 'a,
        AST: LoadableTable + 'a,
        COT: LoadableTable + 'a;

    fn build<'a, ADT, AST, COT>(
        self,
        _addr_table: &'a RefCell<ADT>,
        _asso_table: &'a RefCell<AST>,
        _co_table: &'a RefCell<COT>,
    ) -> Self::Objects<'a, ADT, AST, COT>
    where
        ADT: LoadableTable,
        AST: LoadableTable,
        COT: LoadableTable,
    {
        MinimalInterfaceObjects
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
    type ADT = conformance_config::AddrTab;
    type AST = conformance_config::AssoTab;
    type COT = conformance_config::CoTab;
    type P = TestParameters;
    type CO = test_comm_objs::TestComObjects;
    type LLB = MockLinkLayerBuilder<8, 8>;
    type IOB = MinimalInterfaceObjectsBuilder;
}

// ============================================================================
// Static Resources
// ============================================================================

// Injection channel for sending messages into the stack
static INJECTION_CHANNEL: StaticCell<Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, 8>> = StaticCell::new();

// Capture channel for receiving messages from the stack
static CAPTURE_CHANNEL: StaticCell<Channel<NoopRawMutex, CapturedLinkLayerMessage, 8>> = StaticCell::new();

// Stack resources
static STACK_RESOURCES: StaticCell<StackResources<ConformanceTestStack>> = StaticCell::new();

// Link layer resources
static LL_RESOURCES: StaticCell<MockLinkLayerResources> = StaticCell::new();

// Buffer manager for test injections
static INJECTION_BUFFERS: StaticCell<[[u8; 64]; 8]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<8>> = StaticCell::new();

// ============================================================================
// Full Stack Harness
// ============================================================================

/// Full stack test harness with MockLinkLayer
///
/// This harness runs the complete KNX stack and provides methods to:
/// - Inject telegrams (simulating incoming messages from the bus)
/// - Capture outgoing telegrams (messages the stack sends to the bus)
pub struct FullStackHarness {
    handle: MockLinkLayerHandle<8, 8>,
    buffer_manager: DynBufferManager<'static>,
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
        let buffers = INJECTION_BUFFERS.init([[0u8; 64]; 8]);
        // SAFETY: We're initializing the buffer manager with our static buffers
        let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
        let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
        // SAFETY: We're transmuting to 'static because the buffer manager lives for the entire program
        let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

        // Create MockLinkLayerBuilder with capture support
        let (link_layer_builder, handle) =
            MockLinkLayerBuilder::<8, 8>::with_capture(injection_channel, capture_channel);

        // Create tables from configuration
        let (addr_tab, asso_tab, co_tab) = conformance_config::ConformanceTestConfig::create_tables();

        // Create stack resources
        let resources = STACK_RESOURCES.init(StackResources::new());

        // Create stack
        let (_stack, runner) = zweidraehte::new(
            resources,
            addr_tab,
            asso_tab,
            co_tab,
            test_comm_objs::TestComObjects::new(),
            link_layer_builder,
            MinimalInterfaceObjectsBuilder,
        );

        let ll_resources = LL_RESOURCES.init(MockLinkLayerResources::new());

        let harness = Self { handle, buffer_manager: dyn_buffer_manager };
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
}
