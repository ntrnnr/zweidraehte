//! System B Device Test Utility
//!
//! This module provides both library definitions and a binary entry point
//! for a System B KNX/IP device.
//!
//! ## As Library
//!
//! Used by `mtxml_modifier` and `ets_export` binaries for ETS export.
//!
//! ## As Binary
//!
//! Run with: `cargo run --bin stack_system_b`

#![cfg_attr(not(test), feature(adt_const_params))]

use core::net::Ipv4Addr;

use embassy_executor::Spawner;
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use platform::address::EthernetAddress;
use static_cell::StaticCell;
use zweidraehte::{
    IpPlatform, Runner, StackDefinition, StackResources, StackState,
    address::IndividualAddress,
    bcus::system_b::{
        DeviceStorage, IpSystemBDeviceState, KnxIpDevice, KnxIpInterfaceObjects, MemoryLayout, PersistedState,
        SystemBDevice, SystemBMemoryMap, create_knxip_objects,
    },
    layers::linklayers::knxip::{EndpointType, KnxNetIpBuilder, KnxNetIpResources, servers},
    messages::knxip::KNXnetIPServiceType,
    messages::knxip::substructs::{DeviceInformation, DeviceStatus, HPAI, KNXMedium, ServiceFamily, SupportedService},
    objects::comm::ComObjects,
    objects::interface::HasDeviceObject,
    objects::tables::{HasLoadStateMachine, HasRunStateMachine, LoadEvent, RunEvent},
};

// Import storage from the library module
use testutil::storage::JsonStorage;
use testutil::util::keyboard;

// ============================================================================
// Communication Objects Definition - use demo device comm objects
// ============================================================================

pub use testutil::devices::comm_objs;
pub use testutil::devices::OutputConfig;

// ============================================================================
// Device Constants - use demo device definitions
// ============================================================================

/// Device descriptor - use from demo device
pub const MY_DEVICE_DESCRIPTOR: zweidraehte::ets::DeviceDescriptor = testutil::devices::DEVICE_DESCRIPTOR;

/// Serial number - use from demo device
pub const MY_SERIAL_NUMBER: [u8; 6] = testutil::devices::SERIAL_NUMBER;

/// Network interface name for KNX/IP communication.
pub const INTERFACE_NAME: &'static str = "knxdevbridgeif";

// ============================================================================
// Mock IP Platform
// ============================================================================

#[derive(Debug, Clone)]
pub struct MockIpPlatform {
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mac_address: [u8; 6],
}

impl Default for MockIpPlatform {
    fn default() -> Self {
        Self {
            ip_address: Ipv4Addr::new(192, 168, 1, 200),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            mac_address: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
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
        0x003F
    }
}

// ============================================================================
// Application Parameters with ETS Export
// ============================================================================

// ============================================================================
// Application Parameters
// ============================================================================

/// Type alias for application parameters - use DemoParams which matches the generated XML
type AppParams = testutil::devices::DemoParams;

// ============================================================================
// State type alias using IpSystemBDeviceState
// ============================================================================

// Table sizes computed from DeviceDescriptor
const ADT_SIZE: usize = MY_DEVICE_DESCRIPTOR.address_table_size();
const AST_SIZE: usize = MY_DEVICE_DESCRIPTOR.association_table_size();
const COT_SIZE: usize = MY_DEVICE_DESCRIPTOR.comm_object_table_size();
const APP_DATA_SIZE: usize = core::mem::size_of::<AppParams>();

/// Unified state type combining tables + runtime state.
///
/// The const generics are computed from the device descriptor's table capacities:
/// - ADT_SIZE = 2 + max_address_table_entries * 2 = 34 bytes
/// - AST_SIZE = 2 + max_association_table_entries * 4 = 66 bytes
/// - COT_SIZE = 2 + max_com_objects * 2 = 18 bytes
/// - AppParams = application parameter type (size determines app data area)
pub type MyState = IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, AppParams, MySystemBStack>;

/// Type alias for the persisted state with our device's table sizes.
pub type MyPersistedState = PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE>;

/// Default path for the device state JSON file.
const STATE_FILE_PATH: &str = "system_b_device_state.json";

/// Memory layout for our System B device.
pub const MY_MEMORY_LAYOUT: MemoryLayout = MemoryLayout::calculate(
    SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
    MY_DEVICE_DESCRIPTOR.max_address_table_entries as usize,
    MY_DEVICE_DESCRIPTOR.max_association_table_entries as usize,
    MY_DEVICE_DESCRIPTOR.max_com_objects as usize,
    APP_DATA_SIZE,
);

/// Memory map for our System B device.
///
/// Maps memory addresses to the device tables for A_Memory_Read/Write services.
pub const MY_MEMORY_MAP: SystemBMemoryMap = SystemBMemoryMap::new(MY_MEMORY_LAYOUT);

// ============================================================================
// Stack Definition
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct MySystemBStack;

impl SystemBDevice for MySystemBStack {
    type Storage = JsonStorage;
}

impl KnxIpDevice for MySystemBStack {
    const INTERFACE_NAME: &'static str = INTERFACE_NAME;
    type Platform = MockIpPlatform;
}

impl StackDefinition for MySystemBStack {
    const DEVICE: &'static zweidraehte::ets::DeviceDescriptor = &MY_DEVICE_DESCRIPTOR;

    type P = AppParams;
    type CO = comm_objs::DemoComObjects;
    type LLB = KnxNetIpBuilder<2, 2>;
    type State = MyState;
    type Mem = SystemBMemoryMap;

    type InterfaceObjects<'a> = KnxIpInterfaceObjects<
        'a,
        Self::State,
        <Self::State as zweidraehte::memory::HasAddressTable>::ADT,
        <Self::State as zweidraehte::memory::HasAssociationTable>::AST,
        <Self::State as zweidraehte::memory::HasCommunicationObjectTable>::COT,
        <Self::State as zweidraehte::memory::HasApplication>::APP,
        <Self::State as zweidraehte::memory::HasPeiApplication>::PEI,
    >;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_knxip_objects::<MySystemBStack, _>(state, &MY_MEMORY_LAYOUT)
    }
}

// ============================================================================
// Main Entry Point (when run as binary)
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, MySystemBStack>, link_layer_resources: &'static mut KnxNetIpResources<2>) {
    println!("Running System B KNX/IP stack...");
    runner.run(link_layer_resources).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    println!("=== System B Device Test Utility ===\n");

    // Print device information
    println!("Device Configuration:");
    println!("  Mask Version: {:04X} (KNX/IP System B)", MY_DEVICE_DESCRIPTOR.mask_version);
    println!("  Serial Number: {:02X?}", MY_SERIAL_NUMBER);
    println!("  Manufacturer ID: {:04X}", MY_DEVICE_DESCRIPTOR.manufacturer_id);
    println!();

    // Create storage and try to load persisted state
    let mut storage = JsonStorage::new(STATE_FILE_PATH);
    let device_state: MyState = match storage.load::<ADT_SIZE, AST_SIZE, COT_SIZE, AppParams>() {
        Ok(Some(persisted)) => {
            println!("Loaded persisted state from {}", STATE_FILE_PATH);
            MyState::from_persisted(
                JsonStorage::new(STATE_FILE_PATH),
                MockIpPlatform::default(),
                MY_SERIAL_NUMBER,
                persisted,
            )
        }
        Ok(None) => {
            println!("No persisted state found, using test configuration");
            let state = MyState::new(JsonStorage::new(STATE_FILE_PATH), MockIpPlatform::default(), MY_SERIAL_NUMBER);
            state.set_individual_address(IndividualAddress::new(1, 2, 3));
            load_test_configuration(&state);
            if let Err(e) = storage.save(&state.to_persisted()) {
                log::error!("Failed to save initial state: {}", e);
            }
            state
        }
        Err(e) => {
            println!("Error loading persisted state: {}", e);
            let state = MyState::new(JsonStorage::new(STATE_FILE_PATH), MockIpPlatform::default(), MY_SERIAL_NUMBER);
            state.set_individual_address(IndividualAddress::new(1, 2, 3));
            load_test_configuration(&state);
            state
        }
    };

    // Create KNX/IP servers
    let control_endpoint = HPAI::Ipv4Udp { addr: "192.168.1.200".parse().unwrap(), port: 3671 };
    let device_info = DeviceInformation {
        medium: KNXMedium::KNXIP,
        device_status: DeviceStatus::None,
        individual_address: device_state.individual_address(),
        project_installation_identifier: 0x5678,
        knx_serial_number: MY_SERIAL_NUMBER,
        routing_multicast_address: Ipv4Addr::new(224, 0, 23, 12),
        mac_address: EthernetAddress([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]),
        friendly_name: *b"System B Test\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    let supported_services = &[SupportedService { family: ServiceFamily::Core, version: 1 }, SupportedService {
        family: ServiceFamily::Routing,
        version: 1,
    }];

    let discovery_server = servers::DiscoveryServer::new(control_endpoint, device_info, supported_services);
    let routing_server = servers::RoutingServer::new(Ipv4Addr::new(224, 0, 23, 12), 3671);

    let link_layer_builder = KnxNetIpBuilder::<2, 2>::new(INTERFACE_NAME)
        .add_server(
            discovery_server,
            &[KNXnetIPServiceType::SearchRequest, KNXnetIPServiceType::DescriptionRequest],
            &[EndpointType::new_udp(Ipv4Addr::new(224, 0, 23, 12), 3671), EndpointType::new_udp_any(3671)],
        )
        .add_server(
            routing_server,
            &[
                KNXnetIPServiceType::RoutingIndication,
                KNXnetIPServiceType::RoutingBusy,
                KNXnetIPServiceType::RoutingLostMessage,
            ],
            &[EndpointType::new_udp(Ipv4Addr::new(224, 0, 23, 12), 3671)],
        );

    // Create stack resources and initialize the stack
    static RESOURCES: StaticCell<
        StackResources<MySystemBStack, { zweidraehte::config::buffer_size_for_apdu(MySystemBStack::MAX_APDU_LENGTH) }>,
    > = StaticCell::new();
    let (stack, runner) = zweidraehte::new(
        RESOURCES.init(StackResources::new()),
        comm_objs::DemoComObjects::new(),
        (),
        link_layer_builder,
        device_state,
        MY_MEMORY_MAP,
    );

    let ll_resources = Box::leak(Box::new(KnxNetIpResources::<2>::new()));
    spawner.spawn(run_stack(runner, ll_resources)).unwrap();

    println!("=== Stack Running ===");
    println!("Listening for KNX messages...");
    println!("Press 'p' to toggle programming mode, 'q' to quit\n");

    // Main application loop
    let mut events = stack.events();
    let mut last_print = embassy_time::Instant::now();

    loop {
        // Check for keyboard input (non-blocking)
        if let Some(key) = keyboard::poll_key() {
            match key {
                'p' | 'P' => {
                    let interface_objects = stack.interface_objects();
                    let current_mode = interface_objects.is_programming_mode();
                    interface_objects.set_programming_mode_enabled(!current_mode);
                    let new_mode = interface_objects.is_programming_mode();
                    let current_addr = stack.state().individual_address();
                    println!("\n********************************************");
                    println!("*** Programming mode: {} ***", if new_mode { "ENABLED" } else { "DISABLED" });
                    println!("*** Current address: {} ***", current_addr);
                    println!("*** Device will respond to IndividualAddress_Read ***");
                    println!("*** Device will accept IndividualAddress_Write ***");
                    println!("********************************************\n");
                }
                'q' | 'Q' => {
                    println!("\nShutting down...");
                    break;
                }
                _ => {}
            }
        }

        if embassy_time::Instant::now().duration_since(last_print) > Duration::from_secs(10) {
            use zweidraehte::memory::HasApplication;

            let objects = stack.objects();
            let co_borrow = objects.borrow();
            let interface_objects = stack.interface_objects();
            let state = stack.state();
            let app = state.app().borrow();

            println!("\n--- Device Status ---");
            println!(
                "  Programming mode: {}",
                if interface_objects.is_programming_mode() { "ENABLED" } else { "DISABLED" }
            );
            println!("  Application state: Loaded={}, Running={}", app.is_loaded(), app.is_running());

            println!("  Communication Objects:");
            for i in 1..=4u16 {
                println!("    CO {}: {:02X?}", i, co_borrow.value(i));
            }

            // Print application parameters if loaded
            if app.is_loaded() {
                let params = app.params();
                // Print raw bytes to debug layout issues
                let raw_bytes: &[u8] = unsafe {
                    core::slice::from_raw_parts(
                        params as *const _ as *const u8,
                        core::mem::size_of_val(params),
                    )
                };
                println!("  Application Parameters (raw {} bytes): {:02X?}", raw_bytes.len(), raw_bytes);
                println!("  Application Parameters:");

                // Channel A settings
                print!("    Channel A Config: ");
                match &params.channel_a_config {
                    OutputConfig::Disabled => println!("Disabled"),
                    OutputConfig::Switch { invert } => println!("Switch (invert: {:?})", invert),
                    OutputConfig::Dimmer { min_level, max_level } => println!("Dimmer (range: {}-{})", min_level, max_level),
                    OutputConfig::Pwm { frequency, duty_cycle } => println!("PWM (freq: {} Hz, duty: {}%)", frequency, duty_cycle),
                }

                // Channel B settings
                print!("    Channel B Config: ");
                match &params.channel_b_config {
                    OutputConfig::Disabled => println!("Disabled"),
                    OutputConfig::Switch { invert } => println!("Switch (invert: {:?})", invert),
                    OutputConfig::Dimmer { min_level, max_level } => println!("Dimmer (range: {}-{})", min_level, max_level),
                    OutputConfig::Pwm { frequency, duty_cycle } => println!("PWM (freq: {} Hz, duty: {}%)", frequency, duty_cycle),
                }

                // General settings
                println!("    Send Cycle Time: {}s", params.send_cycle_time);
                println!("    Lock Behavior: {}", match params.lock_behavior {
                    0 => "No Action",
                    1 => "Lock Off",
                    2 => "Lock On",
                    3 => "Lock Toggle",
                    _ => "Unknown",
                });

                match &params.scene_config {
                    testutil::devices::SceneConfig::Disabled => {
                        println!("    Scene Config: Disabled");
                    }
                    testutil::devices::SceneConfig::RecallOnly { scene_number } => {
                        println!("    Scene Config: Recall Only (Scene: {})", scene_number);
                    }
                    testutil::devices::SceneConfig::StoreAndRecall { scene_number, store_time } => {
                        println!("    Scene Config: Store & Recall (Scene: {}, Store Time: {}00ms)", scene_number, store_time);
                    }
                }
            } else {
                println!("  Application Parameters: Not loaded");
            }

            println!("---------------------\n");
            last_print = embassy_time::Instant::now();
        }

        match embassy_time::with_timeout(Duration::from_millis(100), events.next_message()).await {
            Ok(WaitResult::Message((index, event))) => {
                use zweidraehte::objects::comm::ComObjectIndex;
                println!("Event: {:?} on CO {}", event, index.index());
            }
            Ok(WaitResult::Lagged(count)) => println!("Warning: Missed {} events", count),
            Err(_) => {}
        }
    }
}

/// Load test configuration into the state's tables.
fn load_test_configuration(state: &MyState) {
    use zweidraehte::memory::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable};
    use zweidraehte::objects::tables::TableMemory;

    let layout = MY_MEMORY_MAP.layout();
    let adt_addr = layout.adt_address() as u32;
    let ast_addr = layout.ast_address() as u32;
    let cot_addr = layout.cot_address() as u32;

    // Load Address Table
    {
        let mut adt = state.adt().borrow_mut();
        adt.write_lsm(&[LoadEvent::StartLoading.into()], None);
        adt.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x0A, 0x01, 0xFF, 0x00, 0x00],
            Some(adt_addr),
        );
        let table_data = adt.data_ref_mut();
        table_data[0..2].copy_from_slice(&[0x00, 0x04]);
        table_data[2..4].copy_from_slice(&[0x08, 0x01]);
        table_data[4..6].copy_from_slice(&[0x08, 0x02]);
        table_data[6..8].copy_from_slice(&[0x09, 0x01]);
        table_data[8..10].copy_from_slice(&[0x09, 0x02]);
        adt.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
    }

    // Load Association Table
    {
        let mut ast = state.ast().borrow_mut();
        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ast.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x12, 0x01, 0xFF, 0x00, 0x00],
            Some(ast_addr),
        );
        let table_data = ast.data_ref_mut();
        table_data[0..2].copy_from_slice(&[0x00, 0x04]);
        table_data[2..4].copy_from_slice(&[0x00, 0x01]);
        table_data[4..6].copy_from_slice(&[0x00, 0x01]);
        table_data[6..8].copy_from_slice(&[0x00, 0x02]);
        table_data[8..10].copy_from_slice(&[0x00, 0x02]);
        table_data[10..12].copy_from_slice(&[0x00, 0x03]);
        table_data[12..14].copy_from_slice(&[0x00, 0x03]);
        table_data[14..16].copy_from_slice(&[0x00, 0x04]);
        table_data[16..18].copy_from_slice(&[0x00, 0x04]);
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
    }

    // Load Group Object Table
    {
        let mut cot = state.cot().borrow_mut();
        cot.write_lsm(&[LoadEvent::StartLoading.into()], None);
        cot.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x0A, 0x01, 0xFF, 0x00, 0x00],
            Some(cot_addr),
        );
        let table_data = cot.data_ref_mut();
        table_data[0..2].copy_from_slice(&[0x00, 0x04]);
        table_data[2..4].copy_from_slice(&[0x00, 0xDF]);
        table_data[4..6].copy_from_slice(&[0x00, 0x5F]);
        table_data[6..8].copy_from_slice(&[0x00, 0xDF]);
        table_data[8..10].copy_from_slice(&[0x00, 0x5F]);
        cot.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
    }

    // Load Application
    {
        let mut app = state.app().borrow_mut();
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        app.write_rsm(&[RunEvent::Restart.into()]);
    }

    println!("Test configuration loaded");
}
