//! System B Demo Device Definition
//!
//! Complete device definition for a KNX/IP System B demo device.
//! This module contains everything needed to define the device for
//! both runtime and ETS export purposes.

use core::net::Ipv4Addr;

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use zweidraehte::ets::{EtsParams, EtsUnion};
use zweidraehte::{
    IpPlatform, StackDefinition,
    bcus::system_b::{
        IpSystemBDeviceState, KnxIpDevice, KnxIpInterfaceObjects, MemoryLayout, SystemBDevice, SystemBMemoryMap,
        create_knxip_objects,
    },
    define_com_objects,
    layers::linklayers::knxip::KnxNetIpBuilder,
};

use crate::storage::JsonStorage;

// ============================================================================
// Device Descriptor
// ============================================================================

/// Device descriptor - single source of truth for device metadata.
pub const DEVICE_DESCRIPTOR: zweidraehte::ets::DeviceDescriptor = zweidraehte::ets::DeviceDescriptor {
    mask_version: 0x57B0, // KNX/IP System B
    manufacturer_id: 0x00FA,
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
    application_id: 0x0200,
    application_version: 0x01,
    max_address_table_entries: 16,
    max_association_table_entries: 16,
    max_com_objects: 8,
};

/// Serial number for test device.
pub const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF];

/// Network interface name for KNX/IP communication.
pub const INTERFACE_NAME: &str = "knxdevbridgeif";

// ============================================================================
// Communication Objects
// ============================================================================

define_com_objects! {
    pub mod comm_objs {
        pub struct DemoComObjects {
            @ets(display = "Switch Input", function = "Switching input from bus")
            1 => pub switch_in: DPT_Switch = DPT_Switch::from(false),

            @ets(display = "Switch Output", function = "Switching output to bus", flags = 0x5F)
            2 => pub switch_out: DPT_Switch = DPT_Switch::from(false),

            @ets(display = "Dimmer Input", function = "Dimmer control input")
            3 => pub dimmer_in: DPT_Switch = DPT_Switch::from(false),

            @ets(display = "Dimmer Output", function = "Dimmer control output", flags = 0x5F)
            4 => pub dimmer_out: DPT_Switch = DPT_Switch::from(false),
        }
    }
}

// ============================================================================
// Application Parameters
// ============================================================================

/// Demo union for testing ETS union export.
///
/// The `#[derive(EtsUnion)]` macro generates:
/// - `ETS_UNION_INFO`: Union metadata including variant parameters
/// - `ETS_SELECTOR_VARIANTS`: Enum variants for the discriminant/selector
/// - `EtsUnionType` trait implementation
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum OutputConfig {
    /// Output disabled
    #[ets(display = "Disabled")]
    Disabled = 0,

    /// Switch output mode
    #[ets(display = "Switch Mode")]
    Switch {
        /// Invert the switch output
        #[ets(display = "Invert Output")]
        invert: u8,
    },

    /// Dimmer output mode
    #[ets(display = "Dimmer Mode")]
    Dimmer {
        /// Minimum dimmer level (0-100%)
        #[ets(display = "Min Level")]
        min_level: u8,
        /// Maximum dimmer level (0-100%)
        #[ets(display = "Max Level")]
        max_level: u8,
    },

    /// PWM output mode
    #[ets(display = "PWM Mode")]
    Pwm {
        /// PWM frequency in Hz
        #[ets(display = "Frequency")]
        frequency: u16,
        /// PWM duty cycle (0-100%)
        #[ets(display = "Duty Cycle")]
        duty_cycle: u8,
    },
}

impl ConstDefault for OutputConfig {
    const DEFAULT: Self = OutputConfig::Disabled;
}

/// Input source configuration union.
///
/// Demonstrates a union with different input types, each with their own parameters.
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum InputSource {
    /// No input source configured
    #[ets(display = "None")]
    None = 0,

    /// Binary input (digital)
    #[ets(display = "Binary Input")]
    Binary {
        /// Debounce time in milliseconds
        #[ets(display = "Debounce Time")]
        debounce_ms: u16,
        /// Invert input logic
        #[ets(display = "Invert")]
        invert: u8,
    },

    /// Analog input (0-10V or 4-20mA)
    #[ets(display = "Analog Input")]
    Analog {
        /// Input type: 0 = 0-10V, 1 = 4-20mA
        #[ets(display = "Input Type")]
        input_type: u8,
        /// Low threshold value
        #[ets(display = "Low Threshold")]
        low_threshold: u16,
        /// High threshold value
        #[ets(display = "High Threshold")]
        high_threshold: u16,
    },

    /// Temperature sensor input
    #[ets(display = "Temperature Sensor")]
    Temperature {
        /// Sensor type: 0 = PT100, 1 = PT1000, 2 = NTC10K
        #[ets(display = "Sensor Type")]
        sensor_type: u8,
        /// Offset calibration in 0.1°C
        #[ets(display = "Offset")]
        offset: i8,
    },
}

impl ConstDefault for InputSource {
    const DEFAULT: Self = InputSource::None;
}

/// Scene configuration union.
///
/// Demonstrates a simple union for scene recall/store behavior.
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum SceneConfig {
    /// Scene disabled
    #[ets(display = "Disabled")]
    Disabled = 0,

    /// Recall scene on trigger
    #[ets(display = "Recall Only")]
    RecallOnly {
        /// Scene number to recall (1-64)
        #[ets(display = "Scene Number")]
        scene_number: u8,
    },

    /// Store and recall scene
    #[ets(display = "Store & Recall")]
    StoreAndRecall {
        /// Scene number (1-64)
        #[ets(display = "Scene Number")]
        scene_number: u8,
        /// Long press time for store in 100ms units
        #[ets(display = "Store Time")]
        store_time: u8,
    },
}

impl ConstDefault for SceneConfig {
    const DEFAULT: Self = SceneConfig::Disabled;
}

/// Application parameters for the demo device.
///
/// The `#[derive(EtsParams)]` macro generates:
/// - `ETS_PARAMS`: Basic parameter definitions
/// - `ETS_PARAMS_EXT`: Extended definitions with enum variants
/// - `MODE_VARIANTS`: Auto-generated const for enum variants (named after the field)
/// - `ETS_UNIONS`: Union field information for union parameters
///
/// NOTE: Union fields must be placed at the END of the struct because the macro
/// cannot determine union sizes at compile time. Regular fields after a union
/// will have incorrect offsets.
#[derive(Debug, Clone, Copy, EtsParams, ConstDefault, Serialize, Deserialize)]
#[repr(C)]
pub struct DemoParams {
    /// Operating mode with enum variants for ETS dropdown
    #[ets(display = "Operating Mode", enum_variants("Off" => 0, "Normal" => 1, "Eco" => 2, "Night" => 3))]
    pub mode: u8,

    /// Switch-on delay in seconds (0-255)
    #[ets(display = "Switch-On Delay")]
    pub switch_on_delay: u8,

    /// Switch-off delay in seconds (0-255)
    #[ets(display = "Switch-Off Delay")]
    pub switch_off_delay: u8,

    /// Enable dimmer function
    #[ets(display = "Dimmer Enabled")]
    pub dimmer_enabled: bool,

    /// Minimum dimmer value (0-255)
    #[ets(display = "Min Dim Value")]
    pub min_dim_value: u8,

    /// Maximum dimmer value (0-255)
    #[ets(display = "Max Dim Value")]
    pub max_dim_value: u8,

    /// Send cycle time in seconds (0 = disabled)
    #[ets(display = "Send Cycle Time", enum_variants("Disabled" => 0, "10s" => 10, "30s" => 30, "60s" => 60, "300s" => 300))]
    pub send_cycle_time: u16,

    /// Lock behavior with enum variants
    #[ets(display = "Lock Behavior", enum_variants("No Action" => 0, "Lock Off" => 1, "Lock On" => 2, "Lock Toggle" => 3))]
    pub lock_behavior: u8,

    /// Output configuration union - MUST be at the end of the struct!
    #[ets(union, display = "Output Configuration")]
    pub output_config: OutputConfig,

    // NOTE: The following union fields are commented out for now because
    // the EtsParams macro cannot track offsets after the first union.
    // To support multiple unions, we need to either:
    // 1. Add explicit offset attributes: #[ets(union, offset = N)]
    // 2. Use a build script to compute sizes
    // 3. Place all unions in a separate nested struct
    //
    // /// Input source configuration union
    // #[ets(union, display = "Input Source")]
    // pub input_source: InputSource,
    //
    // /// Scene configuration union
    // #[ets(union, display = "Scene Config")]
    // pub scene_config: SceneConfig,
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
        0x02
    }
    fn ip_capabilities(&self) -> u8 {
        0x07
    }
    fn knxnetip_device_capabilities(&self) -> u16 {
        0x003F
    }
}

// ============================================================================
// Stack Definition
// ============================================================================

/// Table sizes computed from DeviceDescriptor
pub const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
pub const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
pub const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();
pub const APP_DATA_SIZE: usize = core::mem::size_of::<DemoParams>();

/// Unified state type
pub type DemoState = IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, DemoParams, DemoStack>;

/// Memory layout for the device
pub const MEMORY_LAYOUT: MemoryLayout = MemoryLayout::calculate(
    SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
    DEVICE_DESCRIPTOR.max_address_table_entries as usize,
    DEVICE_DESCRIPTOR.max_association_table_entries as usize,
    DEVICE_DESCRIPTOR.max_com_objects as usize,
    APP_DATA_SIZE,
);

/// Memory map for the device
pub const MEMORY_MAP: SystemBMemoryMap = SystemBMemoryMap::new(MEMORY_LAYOUT);

#[derive(Debug, Clone, Copy)]
pub struct DemoStack;

impl SystemBDevice for DemoStack {
    type Storage = JsonStorage;
}

impl KnxIpDevice for DemoStack {
    const INTERFACE_NAME: &'static str = INTERFACE_NAME;
    type Platform = MockIpPlatform;
}

impl StackDefinition for DemoStack {
    const DEVICE: &'static zweidraehte::ets::DeviceDescriptor = &DEVICE_DESCRIPTOR;

    type P = DemoParams;
    type CO = comm_objs::DemoComObjects;
    type LLB = KnxNetIpBuilder<2, 2>;
    type State = DemoState;
    type Mem = SystemBMemoryMap;

    type InterfaceObjects<'a> = KnxIpInterfaceObjects<
        'a,
        Self::State,
        <Self::State as zweidraehte::memory::HasAddressTable>::ADT,
        <Self::State as zweidraehte::memory::HasAssociationTable>::AST,
        <Self::State as zweidraehte::memory::HasCommunicationObjectTable>::COT,
        <Self::State as zweidraehte::memory::HasApplication>::APP,
    >;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_knxip_objects::<DemoStack, _>(state, &MEMORY_LAYOUT)
    }
}
