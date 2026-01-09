//! System B Device Test Utility
//!
//! This test utility demonstrates how to use the System B device abstraction
//! to create a KNX/IP device with minimal boilerplate. It uses:
//!
//! - `SystemBDevice` trait for device identity constants
//! - `KnxIpDevice` trait for KNX/IP configuration
//! - `SystemBTables` for automatic table container creation
//! - `KnxIpInterfaceObjectsBuilder` for interface objects
//! - `IpDeviceState` for runtime state
//!
//! ## Architecture
//!
//! The System B abstraction groups all building blocks:
//!
//! 1. **Device Definition** (compile-time constants via `SystemBDevice`):
//!    - Mask version (57B0 for KNX/IP)
//!    - Serial number, hardware type, program version
//!    - Table capacities (addresses, associations, com objects)
//!
//! 2. **Tables** (`SystemBTables`):
//!    - Address Table (group address → TSAP mapping)
//!    - Association Table (TSAP → ASAP mapping)
//!    - Group Object Table (communication object config)
//!    - Application Program (load + run state machines)
//!
//! 3. **Interface Objects** (`KnxIpInterfaceObjects`):
//!    - Device Object (index 0)
//!    - Address Table Object (index 1)
//!    - Association Table Object (index 2)
//!    - Group Object Table Object (index 3)
//!    - Application Program Object (index 4)
//!    - IP Parameter Object (index 5)
//!
//! 4. **Runtime State** (`IpDeviceState`):
//!    - Individual address
//!    - Programming mode
//!    - IP configuration
//!    - Access level

#![feature(adt_const_params)]

use core::net::Ipv4Addr;
use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;

use embassy_executor::Spawner;
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use platform::address::EthernetAddress;
use static_cell::StaticCell;
use zweidraehte::{
    IpPlatform, Runner, StackDefinition, StackResources,
    address::IndividualAddress,
    bcus::system_b::{
        DeviceStorage, IpDeviceState, KnxIpDevice,
        KnxIpInterfaceObjectsBuilder, PersistedState, SystemBDevice, SystemBDeviceExt,
        SystemBMemoryMap, SystemBTables,
    },
    define_com_objects,
    layers::linklayers::knxip::{EndpointType, KnxNetIpBuilder, KnxNetIpResources, servers},
    messages::knxip::KNXnetIPServiceType,
    messages::knxip::substructs::{DeviceInformation, DeviceStatus, HPAI, KNXMedium, ServiceFamily, SupportedService},
    objects::comm::ComObjects,
    objects::tables::{LoadEvent, LoadableTable, RunEvent, RunnableTable},
};

// ============================================================================
// JSON File Storage Implementation
// ============================================================================

/// JSON file-based storage for device state.
///
/// Persists device configuration to a JSON file. Suitable for development
/// and testing on systems with a filesystem.
///
/// # Usage
///
/// ```rust,ignore
/// let storage = JsonStorage::new("device_state.json");
/// ```
pub struct JsonStorage {
    /// Path to the JSON file.
    path: PathBuf,
    /// Whether there are unsaved changes.
    dirty: bool,
}

impl Default for JsonStorage {
    fn default() -> Self {
        Self::new("device_state.json")
    }
}

impl JsonStorage {
    /// Create a new JSON storage with the given file path.
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            dirty: false,
        }
    }

    /// Get the path to the storage file.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// Error type for JSON storage operations.
#[derive(Debug)]
pub enum JsonStorageError {
    /// I/O error during file operations.
    Io(io::Error),
    /// JSON serialization/deserialization error.
    Json(serde_json::Error),
}

impl From<io::Error> for JsonStorageError {
    fn from(e: io::Error) -> Self {
        JsonStorageError::Io(e)
    }
}

impl From<serde_json::Error> for JsonStorageError {
    fn from(e: serde_json::Error) -> Self {
        JsonStorageError::Json(e)
    }
}

impl std::fmt::Display for JsonStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonStorageError::Io(e) => write!(f, "I/O error: {}", e),
            JsonStorageError::Json(e) => write!(f, "JSON error: {}", e),
        }
    }
}

impl std::error::Error for JsonStorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JsonStorageError::Io(e) => Some(e),
            JsonStorageError::Json(e) => Some(e),
        }
    }
}

impl DeviceStorage for JsonStorage {
    type Error = JsonStorageError;

    fn load<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize>(
        &mut self,
    ) -> Result<Option<PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE>>, Self::Error> {
        // Check if the file exists
        if !self.path.exists() {
            log::info!("No saved state at {:?}, using factory defaults", self.path);
            return Ok(None);
        }

        // Read the file contents
        let mut file = File::open(&self.path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the JSON
        let state: PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE> =
            serde_json::from_str(&contents)?;

        log::info!("Loaded device state from {:?}", self.path);
        Ok(Some(state))
    }

    fn save<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize>(
        &mut self,
        state: &PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE>,
    ) -> Result<(), Self::Error> {
        // Serialize to JSON with pretty printing for readability
        let json = serde_json::to_string_pretty(state)?;

        // Write to a temporary file first for atomic replacement
        let tmp_path = self.path.with_extension("json.tmp");
        let mut file = File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;

        // Atomically replace the old file
        fs::rename(&tmp_path, &self.path)?;

        self.dirty = false;
        log::info!("Saved device state to {:?}", self.path);
        Ok(())
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // Note: This just clears the dirty flag. The actual save must be done
        // by calling save() with the current state. The stack should call save()
        // when it detects changes, not flush().
        self.dirty = false;
        Ok(())
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }
}

// ============================================================================
// Communication Objects Definition
// ============================================================================

define_com_objects! {
    pub mod comm_objs {
        pub struct SystemBComObjects {
            1 => pub switch_in: DPT_Switch = DPT_Switch::from(false),
            2 => pub switch_out: DPT_Switch = DPT_Switch::from(false),
            3 => pub dimmer_in: DPT_Switch = DPT_Switch::from(false),
            4 => pub dimmer_out: DPT_Switch = DPT_Switch::from(false),
        }
    }
}

// ============================================================================
// Device Definition using SystemBDevice trait
// ============================================================================

/// Our System B device definition.
///
/// This struct contains only the compile-time constants that identify the device.
/// All runtime configuration (individual address, IP config) is in `IpDeviceState`.
#[derive(Copy, Clone)]
pub struct MySystemBDevice;

impl SystemBDevice for MySystemBDevice {
    // Device identity
    const MASK_VERSION: [u8; 2] = [0x57, 0xB0]; // KNX/IP System B
    const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF];
    const HARDWARE_TYPE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
    const PROGRAM_VERSION: [u8; 5] = [0x00, 0xFA, 0x02, 0x00, 0x01];

    // Table capacities
    const MAX_ADDRESSES: usize = 16;
    const MAX_ASSOCIATIONS: usize = 16;
    const MAX_COM_OBJECTS: usize = 8;

    // Associated types
    type ComObjects = comm_objs::SystemBComObjects;
    type Storage = JsonStorage;
}

impl KnxIpDevice for MySystemBDevice {
    const INTERFACE_NAME: &'static str = "knxdevbridgeif";
    type Platform = MockIpPlatform;
}

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
// Tables type alias using SystemBTables
// ============================================================================

/// Tables container using System B sizing.
///
/// The const generics are computed from the device's MAX_* constants:
/// - ADT_SIZE = 2 + MAX_ADDRESSES * 2 = 34 bytes
/// - AST_SIZE = 2 + MAX_ASSOCIATIONS * 4 = 66 bytes
/// - COT_SIZE = 2 + MAX_COM_OBJECTS * 2 = 18 bytes
/// - APP_SIZE = MAX_APP_DATA = 256 bytes
pub type MyTables = SystemBTables<
    { MySystemBDevice::ADT_SIZE },
    { MySystemBDevice::AST_SIZE },
    { MySystemBDevice::COT_SIZE },
    { MySystemBDevice::APP_SIZE },
>;

/// Type alias for the persisted state with our device's table sizes.
pub type MyPersistedState = PersistedState<
    { MySystemBDevice::ADT_SIZE },
    { MySystemBDevice::AST_SIZE },
    { MySystemBDevice::COT_SIZE },
    { MySystemBDevice::APP_SIZE },
>;

/// Default path for the device state JSON file.
const STATE_FILE_PATH: &str = "system_b_device_state.json";

/// Memory map for our System B device.
///
/// Maps memory addresses to the device tables for A_Memory_Read/Write services.
/// The layout is:
/// - 0x0100 + 0x0000: Address Table (34 bytes)
/// - 0x0100 + 0x0022: Association Table (66 bytes)
/// - 0x0100 + 0x0064: Group Object Table (18 bytes)
/// - 0x0100 + 0x0076: Application Data (256 bytes)
pub const MY_MEMORY_MAP: SystemBMemoryMap = SystemBMemoryMap::for_device(
    MySystemBDevice::MAX_ADDRESSES,
    MySystemBDevice::MAX_ASSOCIATIONS,
    MySystemBDevice::MAX_COM_OBJECTS,
    MySystemBDevice::MAX_APP_DATA,
);

// ============================================================================
// Stack Definition
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct MySystemBStack;

impl StackDefinition for MySystemBStack {
    const MASK_VERSION: &'static [u8; 2] = &MySystemBDevice::MASK_VERSION;

    type Tables = MyTables;
    type P = ();
    type CO = comm_objs::SystemBComObjects;
    type LLB = KnxNetIpBuilder<2, 2>;
    type IOB = KnxIpInterfaceObjectsBuilder<MySystemBDevice>;
    type State = IpDeviceState<MySystemBDevice>;
    type Mem = SystemBMemoryMap;
}

// ============================================================================
// Main
// ============================================================================

#[embassy_executor::task]
async fn run_stack(
    runner: Runner<'static, MySystemBStack>,
    link_layer_resources: &'static mut KnxNetIpResources<2>,
) {
    println!("Running System B KNX/IP stack...");
    runner.run(link_layer_resources).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    println!("=== System B Device Test Utility ===\n");

    // Print device information
    println!("Device Configuration:");
    println!("  Mask Version: {:02X}{:02X} (KNX/IP System B)",
        MySystemBDevice::MASK_VERSION[0], MySystemBDevice::MASK_VERSION[1]);
    println!("  Serial Number: {:02X?}", MySystemBDevice::SERIAL_NUMBER);
    println!("  Manufacturer ID: {:04X}", MySystemBDevice::manufacturer_id());
    println!("  Hardware Type: {:02X?}", MySystemBDevice::HARDWARE_TYPE);
    println!("  Program Version: {:02X?}", MySystemBDevice::PROGRAM_VERSION);
    println!();
    println!("Table Capacities:");
    println!("  Max Addresses: {}", MySystemBDevice::MAX_ADDRESSES);
    println!("  Max Associations: {}", MySystemBDevice::MAX_ASSOCIATIONS);
    println!("  Max Com Objects: {}", MySystemBDevice::MAX_COM_OBJECTS);
    println!();
    println!("Computed Table Sizes:");
    println!("  ADT Size: {} bytes", MySystemBDevice::ADT_SIZE);
    println!("  AST Size: {} bytes", MySystemBDevice::AST_SIZE);
    println!("  COT Size: {} bytes", MySystemBDevice::COT_SIZE);
    println!("  APP Size: {} bytes", MySystemBDevice::APP_SIZE);
    println!();
    println!("Memory Map Layout (base: 0x{:04X}):", MY_MEMORY_MAP.layout().base_address);
    println!("  Address Table:     0x{:04X} - 0x{:04X} ({} bytes)",
        MY_MEMORY_MAP.layout().adt_address(),
        MY_MEMORY_MAP.layout().adt_address() + MY_MEMORY_MAP.layout().adt_size as u16 - 1,
        MY_MEMORY_MAP.layout().adt_size);
    println!("  Association Table: 0x{:04X} - 0x{:04X} ({} bytes)",
        MY_MEMORY_MAP.layout().ast_address(),
        MY_MEMORY_MAP.layout().ast_address() + MY_MEMORY_MAP.layout().ast_size as u16 - 1,
        MY_MEMORY_MAP.layout().ast_size);
    println!("  Group Object Table: 0x{:04X} - 0x{:04X} ({} bytes)",
        MY_MEMORY_MAP.layout().cot_address(),
        MY_MEMORY_MAP.layout().cot_address() + MY_MEMORY_MAP.layout().cot_size as u16 - 1,
        MY_MEMORY_MAP.layout().cot_size);
    println!("  Application Data:  0x{:04X} - 0x{:04X} ({} bytes)",
        MY_MEMORY_MAP.layout().app_address(),
        MY_MEMORY_MAP.layout().app_address() + MY_MEMORY_MAP.layout().app_size as u16 - 1,
        MY_MEMORY_MAP.layout().app_size);
    println!("  Total mapped:      {} bytes", MY_MEMORY_MAP.layout().total_size);
    println!();

    // Create storage and try to load persisted state
    let mut storage = JsonStorage::new(STATE_FILE_PATH);
    let (tables, persisted_state) = match storage.load::<
        { MySystemBDevice::ADT_SIZE },
        { MySystemBDevice::AST_SIZE },
        { MySystemBDevice::COT_SIZE },
        { MySystemBDevice::APP_SIZE },
    >() {
        Ok(Some(state)) => {
            println!("Loaded persisted state from {}", STATE_FILE_PATH);
            println!("  Individual Address: {}", state.individual_address);
            println!("  Address Table: {:?}", state.address_table.load_state);
            println!("  Association Table: {:?}", state.association_table.load_state);
            println!("  Group Object Table: {:?}", state.group_object_table.load_state);
            println!("  Application: {:?}", state.application.load_state);
            println!();

            let tables = MyTables::from_persisted(&state);
            (tables, state)
        }
        Ok(None) => {
            println!("No persisted state found, using test configuration");
            println!();

            // Create tables and load test configuration
            let mut tables = MyTables::new();
            load_test_configuration(&mut tables);

            // Create initial persisted state with test configuration
            let (adt, ast, cot, app) = tables.to_persisted();
            let state = MyPersistedState {
                version: MyPersistedState::VERSION,
                individual_address: IndividualAddress::new(1, 2, 3),
                auth_keys: [[0xFF; 4]; 3],
                address_table: adt,
                association_table: ast,
                group_object_table: cot,
                application: app,
                ip_config: Some(Default::default()),
            };

            // Save the initial state
            if let Err(e) = storage.save(&state) {
                log::error!("Failed to save initial state: {}", e);
            }

            (tables, state)
        }
        Err(e) => {
            println!("Error loading persisted state: {}", e);
            println!("Using test configuration instead");
            println!();

            // Create tables with test configuration as fallback
            let mut tables = MyTables::new();
            load_test_configuration(&mut tables);

            let (adt, ast, cot, app) = tables.to_persisted();
            let state = MyPersistedState {
                version: MyPersistedState::VERSION,
                individual_address: IndividualAddress::new(1, 2, 3),
                auth_keys: [[0xFF; 4]; 3],
                address_table: adt,
                association_table: ast,
                group_object_table: cot,
                application: app,
                ip_config: Some(Default::default()),
            };

            (tables, state)
        }
    };

    // Keep reference to the current individual address
    let individual_address = persisted_state.individual_address;

    // Create KNX/IP servers
    let control_endpoint = HPAI::Ipv4Udp {
        addr: "192.168.1.200".parse().unwrap(),
        port: 3671
    };

    let device_info = DeviceInformation {
        medium: KNXMedium::KNXIP,
        device_status: DeviceStatus::None,
        individual_address,
        project_installation_identifier: 0x5678,
        knx_serial_number: MySystemBDevice::SERIAL_NUMBER,
        routing_multicast_address: Ipv4Addr::new(224, 0, 23, 12),
        mac_address: EthernetAddress([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]),
        friendly_name: *b"System B Test\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    let supported_services = &[
        SupportedService { family: ServiceFamily::Core, version: 1 },
        SupportedService { family: ServiceFamily::Routing, version: 1 },
    ];

    let discovery_server = servers::DiscoveryServer::new(
        control_endpoint,
        device_info,
        supported_services
    );
    let routing_server = servers::RoutingServer::new(
        Ipv4Addr::new(224, 0, 23, 12),
        3671
    );

    let link_layer_builder = KnxNetIpBuilder::<2, 2>::new(MySystemBDevice::INTERFACE_NAME)
        .add_server(
            discovery_server,
            &[KNXnetIPServiceType::SearchRequest, KNXnetIPServiceType::DescriptionRequest],
            &[
                EndpointType::new_udp(Ipv4Addr::new(224, 0, 23, 12), 3671),
                EndpointType::new_udp_any(3671),
            ],
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

    println!("KNX/IP Configuration:");
    println!("  Interface: {}", MySystemBDevice::INTERFACE_NAME);
    println!("  Multicast: 224.0.23.12:3671");
    println!();

    // Create the interface objects builder
    let iob = KnxIpInterfaceObjectsBuilder::<MySystemBDevice>::new();

    // Create device state from persisted data
    let device_state = IpDeviceState::<MySystemBDevice>::from_persisted(
        JsonStorage::new(STATE_FILE_PATH),
        MockIpPlatform::default(),
        persisted_state.individual_address,
        persisted_state.auth_keys,
        persisted_state.ip_config.clone(),
    );

    // Create stack resources and initialize the stack
    static RESOURCES: StaticCell<StackResources<MySystemBStack>> = StaticCell::new();
    let (stack, runner) = zweidraehte::new(
        RESOURCES.init(StackResources::new()),
        tables,
        comm_objs::SystemBComObjects::new(),
        (),
        link_layer_builder,
        iob,
        device_state,
    );

    // Print interface objects info
    println!("Interface Objects (6 total):");
    println!("  [0] Device Object");
    println!("  [1] Address Table Object");
    println!("  [2] Association Table Object");
    println!("  [3] Group Object Table Object");
    println!("  [4] Application Program Object");
    println!("  [5] IP Parameter Object");
    println!();

    // Create link layer resources
    let ll_resources = Box::leak(Box::new(KnxNetIpResources::<2>::new()));

    // Spawn the stack runner
    spawner.spawn(run_stack(runner, ll_resources)).unwrap();

    println!("=== Stack Running ===");
    println!("Communication Objects:");
    println!("  CO 1: switch_in");
    println!("  CO 2: switch_out");
    println!("  CO 3: dimmer_in");
    println!("  CO 4: dimmer_out");
    println!();
    println!("Listening for KNX messages...");
    println!("Test with: knxtool search\n");

    // Main application loop
    let mut events = stack.events();
    let mut last_print = embassy_time::Instant::now();

    loop {
        if embassy_time::Instant::now().duration_since(last_print) > Duration::from_secs(10) {
            let objects = stack.objects();
            let co_borrow = objects.borrow();

            println!("\n--- Communication Object Status ---");
            for i in 1..=4u16 {
                let value = co_borrow.value(i);
                println!("  CO {}: {:02X?}", i, value);
            }
            println!("-----------------------------------\n");

            last_print = embassy_time::Instant::now();
        }

        match embassy_time::with_timeout(Duration::from_millis(100), events.next_message()).await {
            Ok(WaitResult::Message((index, event))) => {
                use zweidraehte::objects::comm::ComObjectIndex;
                println!("Event: {:?} on CO {}", event, index.index());
            }
            Ok(WaitResult::Lagged(count)) => {
                println!("Warning: Missed {} events", count);
            }
            Err(_) => {}
        }
    }
}

/// Load test configuration into the tables.
///
/// This simulates ETS configuration loading via the Load State Machine.
fn load_test_configuration(tables: &mut MyTables) {
    use zweidraehte::objects::tables::TableMemory;

    // Load Address Table
    {
        let mut adt = tables.adt.borrow_mut();
        adt.write_lsm(&[LoadEvent::StartLoading.into()], None);

        // Allocate table space
        adt.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B, // AllocAbsDataSeg
            0x00, 0x00, 0x00, 0x0A, // Size: 10 bytes (2 count + 4 addresses)
            0x01, // Fill
            0xFF, // Fill value
            0x00, 0x00,
        ], None);

        // Write address data: 4 group addresses
        // [count:2][ga1:2][ga2:2][ga3:2][ga4:2]
        let table_data = adt.data_ref_mut();
        table_data[0..2].copy_from_slice(&[0x00, 0x04]); // 4 entries
        table_data[2..4].copy_from_slice(&[0x08, 0x01]); // GA 1/0/1
        table_data[4..6].copy_from_slice(&[0x08, 0x02]); // GA 1/0/2
        table_data[6..8].copy_from_slice(&[0x09, 0x01]); // GA 1/1/1
        table_data[8..10].copy_from_slice(&[0x09, 0x02]); // GA 1/1/2

        adt.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
    }

    // Load Association Table
    {
        let mut ast = tables.ast.borrow_mut();
        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);

        ast.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B, // AllocAbsDataSeg
            0x00, 0x00, 0x00, 0x12, // Size: 18 bytes (2 count + 4 assoc * 4)
            0x01, // Fill
            0xFF, // Fill value
            0x00, 0x00,
        ], None);

        let table_data = ast.data_ref_mut();
        // [count:2][tsap1:2][asap1:2][tsap2:2][asap2:2]...
        table_data[0..2].copy_from_slice(&[0x00, 0x04]); // 4 associations
        // TSAP 1 → ASAP 1
        table_data[2..4].copy_from_slice(&[0x00, 0x01]); // TSAP
        table_data[4..6].copy_from_slice(&[0x00, 0x01]); // ASAP
        // TSAP 2 → ASAP 2
        table_data[6..8].copy_from_slice(&[0x00, 0x02]);
        table_data[8..10].copy_from_slice(&[0x00, 0x02]);
        // TSAP 3 → ASAP 3
        table_data[10..12].copy_from_slice(&[0x00, 0x03]);
        table_data[12..14].copy_from_slice(&[0x00, 0x03]);
        // TSAP 4 → ASAP 4
        table_data[14..16].copy_from_slice(&[0x00, 0x04]);
        table_data[16..18].copy_from_slice(&[0x00, 0x04]);

        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
    }

    // Load Group Object Table
    {
        let mut cot = tables.cot.borrow_mut();
        cot.write_lsm(&[LoadEvent::StartLoading.into()], None);

        cot.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B, // AllocAbsDataSeg
            0x00, 0x00, 0x00, 0x0A, // Size: 10 bytes (2 count + 4 co * 2)
            0x01, // Fill
            0xFF, // Fill value
            0x00, 0x00,
        ], None);

        let table_data = cot.data_ref_mut();
        // [count:2][type1:1][flags1:1][type2:1][flags2:1]...
        table_data[0..2].copy_from_slice(&[0x00, 0x04]); // 4 com objects
        // CO 1: Type Uint1, Flags RTWU (CE|TE|RE|WE|UE)
        table_data[2..4].copy_from_slice(&[0x00, 0xDF]);
        // CO 2: Type Uint1, Flags RTW (CE|TE|RE|WE)
        table_data[4..6].copy_from_slice(&[0x00, 0x5F]);
        // CO 3: Type Uint1, Flags RTWU
        table_data[6..8].copy_from_slice(&[0x00, 0xDF]);
        // CO 4: Type Uint1, Flags RTW
        table_data[8..10].copy_from_slice(&[0x00, 0x5F]);

        cot.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
    }

    // Load Application
    {
        let mut app = tables.app.borrow_mut();
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        // Start the application
        app.write_rsm(&[RunEvent::Restart.into()]);
    }

    println!("Test configuration loaded:");
    println!("  Address Table: 4 group addresses");
    println!("  Association Table: 4 associations");
    println!("  Group Object Table: 4 communication objects");
    println!("  Application: Loaded and Running");
    println!();
}
