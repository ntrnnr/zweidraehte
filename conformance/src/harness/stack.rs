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
    BasicStackState, define_com_objects,
    messages::buffers::{Buffer, BufferManager, DynBufferManager, MessageBuffer},
    messages::knx::{KnxMessageBuffer, ServiceType},
    objects::comm::ComObjects,
    objects::interface::{
        DeviceObject, InterfaceObject, InterfaceObjectsBuilder, PropertyDescriptionResponse, PropertyError,
        PropertyServiceHandler,
    },
    objects::tables::LoadableTable,
    Runner, StackDefinition, StackResources, StackState,
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
// Minimal Interface Objects
// ============================================================================

use zweidraehte::objects::interface::pid;

/// PID for programming mode (Device Object specific, PID 54)
const PID_PROGMODE: u8 = pid::PROGMODE;

/// Minimal interface objects container for conformance testing
///
/// This provides the bare minimum interface objects needed for the stack to run.
/// Contains a DeviceObject (Object Index 0) which is mandatory for all KNX devices.
/// Also holds a reference to the stack state for PID_PROGMODE read/write.
pub struct MinimalInterfaceObjects<'a, S: StackState> {
    device: DeviceObject,
    state: &'a S,
}

impl<'a, S: StackState> MinimalInterfaceObjects<'a, S> {
    pub fn new(state: &'a S) -> Self {
        Self { device: DeviceObject::new(), state }
    }
}

impl<S: StackState> PropertyServiceHandler for MinimalInterfaceObjects<'_, S> {
    fn object_count(&self) -> u16 {
        1 // Just the DeviceObject at index 0
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        match object_idx {
            0 => self.device.property_description(object_idx, prop_id, prop_idx),
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
            0 => {
                // Handle PID_PROGMODE specially - read from stack state
                if prop_id == PID_PROGMODE {
                    if start_idx != 1 || count != 1 {
                        return Err(PropertyError::InvalidStartIndex);
                    }
                    if buf.is_empty() {
                        return Err(PropertyError::BufferTooSmall);
                    }
                    buf[0] = if self.state.programming_mode() { 1 } else { 0 };
                    return Ok(1);
                }
                self.device.read_property(prop_id, start_idx, count, buf)
            }
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        _start_idx: u16,
        data: &[u8],
    ) -> Result<(), PropertyError> {
        match object_idx {
            0 => {
                // Handle PID_PROGMODE - write to stack state
                if prop_id == PID_PROGMODE {
                    if data.is_empty() {
                        return Err(PropertyError::InvalidElementCount);
                    }
                    self.state.set_programming_mode(data[0] != 0);
                    return Ok(());
                }
                // Other properties are read-only
                Err(PropertyError::WriteNotAllowed)
            }
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }
}

/// Builder for minimal interface objects
#[derive(Debug, Clone, Copy)]
pub struct MinimalInterfaceObjectsBuilder;

impl InterfaceObjectsBuilder for MinimalInterfaceObjectsBuilder {
    type Objects<'a, ADT, AST, COT>
        = MinimalInterfaceObjects<'a, BasicStackState>
    where
        ADT: LoadableTable + 'a,
        AST: LoadableTable + 'a,
        COT: LoadableTable + 'a;

    fn build<'a, ADT, AST, COT, S>(
        self,
        _addr_table: &'a RefCell<ADT>,
        _asso_table: &'a RefCell<AST>,
        _co_table: &'a RefCell<COT>,
        state: &'a S,
    ) -> Self::Objects<'a, ADT, AST, COT>
    where
        ADT: LoadableTable,
        AST: LoadableTable,
        COT: LoadableTable,
        S: StackState,
    {
        // SAFETY: We know S is BasicStackState from the StackDefinition
        // This is a workaround for the GAT lifetime constraints
        let state_ref: &'a BasicStackState = unsafe { &*(state as *const S as *const BasicStackState) };
        MinimalInterfaceObjects::new(state_ref)
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
    type IOB = MinimalInterfaceObjectsBuilder;
    type State = BasicStackState;
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
            MinimalInterfaceObjectsBuilder,
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
}
