//! KNX Interface Objects
//!
//! This module implements the KNX Interface Object model as per KNX specification.
//! Interface Objects provide a standardized way to access device properties and
//! configuration through the management layer.
//!
//! # Architecture
//!
//! The design separates concerns between the stack and application:
//!
//! - **Stack side**: Uses [`PropertyServiceHandler`] trait to access interface objects.
//!   This trait is object-safe and allows the stack to handle property read/write
//!   requests without knowing the concrete container type.
//!
//! - **Application side**: Defines interface object containers that implement
//!   [`PropertyServiceHandler`]. The container manages the objects internally and
//!   dispatches requests by object index.
//!
//! # Usage Pattern
//!
//! Applications implement `create_interface_objects` on their `StackDefinition` type:
//!
//! ```rust,ignore
//! impl StackDefinition for MyDevice {
//!     type InterfaceObjects<'a> = MyInterfaceObjects<'a, Self::State>;
//!
//!     fn create_interface_objects<'a>(tables: &'a Self::Tables, state: &'a Self::State) -> Self::InterfaceObjects<'a>
//!     where
//!         Self::Tables: 'a,
//!         Self::State: 'a,
//!     {
//!         MyInterfaceObjects::new(tables, state)
//!     }
//! }
//! ```
//!
//! The `InterfaceObjects` type must implement [`PropertyServiceHandler`], which handles
//! property requests by dispatching to the appropriate object based on index.
//!
//! # Standard Object Layout
//!
//! A typical KNX device has these interface objects:
//!
//! | Index | Object Type | Description |
//! |-------|-------------|-------------|
//! | 0 | Device Object | Basic device information (mandatory) |
//! | 1 | Address Table Object | Group address table |
//! | 2 | Association Table Object | TSAP/ASAP mapping |
//! | 3 | Application Program Object | Application info |
//! | 4 | Group Object Table Object | Communication object descriptors |
//! | 5 | IP Parameter Object | KNXnet/IP configuration (for KNXnet/IP devices) |

mod standard;
mod traits;

pub use standard::*;
pub use traits::*;
pub use zweidraehte_proto::properties::*;

// Re-export the attribute macros so users can write
// `#[interface_object(object_type = ...)]` without depending on
// `zweidraehte-device-macros` directly.
pub use zweidraehte_device_macros::{interface_object, interface_object_augment};

/// Property ID constants as defined in KNX specification
pub mod pid {
    //==========================================================================
    // Common Properties (available in all/most interface objects)
    //==========================================================================

    /// Object Type (PID 1) - Identifies the interface object type
    /// PDT: PDT_UNSIGNED_INT
    pub const OBJECT_TYPE: u16 = 1;

    /// Object Name (PID 2) - Optional name string
    /// PDT: PDT_UNSIGNED_CHAR[]
    pub const OBJECT_NAME: u16 = 2;

    // /// Semaphor (PID 3)
    // /// PDT: ?
    // pub const SEMAPHOR: u16 = 3;

    // /// Group Object Link (PID 4)
    // /// PDT: ?
    // pub const GROUP_OBJECT_REFERENCE: u16 = 4;

    /// Load State Control (PID 5) - Controls loading of loadable objects
    /// PDT: PDT_CONTROL
    pub const LOAD_STATE_CONTROL: u16 = 5;

    /// Run State Control (PID 6) - Controls execution state
    /// PDT: PDT_CONTROL
    pub const RUN_STATE_CONTROL: u16 = 6;

    /// Table Reference (PID 7) - Pointer to table data
    /// PDT: PDT_UNSIGNED_LONG
    pub const TABLE_REFERENCE: u16 = 7;

    /// Service Control (PID 8) - Service enable flags
    /// PDT: PDT_UNSIGNED_INT
    pub const SERVICE_CONTROL: u16 = 8;

    /// Firmware Revision (PID 9) - Firmware version
    /// PDT: PDT_UNSIGNED_CHAR
    pub const FIRMWARE_REVISION: u16 = 9;

    /// Services Supported (PID 10) - Bitmask of supported services
    /// PDT: -
    pub const SERVICES_SUPPORTED: u16 = 10;

    /// Serial Number (PID 11) - Device serial number
    /// PDT: PDT_GENERIC_06
    pub const SERIAL_NUMBER: u16 = 11;

    /// Manufacturer ID (PID 12) - KNX manufacturer code
    /// PDT: PDT_UNSIGNED_INT
    pub const MANUFACTURER_ID: u16 = 12;

    /// Program Version (PID 13) - Application program version
    /// PDT: PDT_GENERIC_05
    pub const PROGRAM_VERSION: u16 = 13;

    /// Device Control (PID 14) - Device control flags
    /// PDT: PDT_GENERIC_01 / PDT_BISET8
    /// DPT: DPT_Device_Control (DPT_ID = 21.002)
    pub const DEVICE_CONTROL: u16 = 14;

    /// Order Info (PID 15) - Order/catalog number
    /// PDT: PDT_GENERIC_10
    pub const ORDER_INFO: u16 = 15;

    /// PEI Type (PID 16) - Physical External Interface type
    /// PDT: PDT_UNSIGNED_CHAR
    pub const PEI_TYPE: u16 = 16;

    /// Port Configuration (PID 17) - Port/interface configuration
    /// PDT: PDT_UNSIGNED_CHAR
    pub const PORT_CONFIGURATION: u16 = 17;

    /// Polling Group Settings (PID 18)
    /// PDT: PDT_POLL_GROUP_SETTINGS
    pub const POLL_GROUP_SETTINGS: u16 = 18;

    /// Manufacturer Data (PID 19)
    /// PDT: -
    pub const MANUFACTURER_DATA: u16 = 19;

    // /// Enable (PID 20)
    // /// PDT: ?
    // pub const ENABLE: u16 = 20;

    /// Description (PID 21)
    /// PDT: PDT_UNSIGNED_CHAR[] / PDT_REFERENCE
    /// DPT: Every character: DPT_UTF_8 (DPT_ID: 28.001)
    pub const DESCRIPTION: u16 = 21;

    // /// File (PID 22)
    // /// PDT: ?
    // pub const FILE: u16 = 22;

    /// Table (PID 23) - Direct access to table data as array property
    /// PDT: Variable (depends on table type)
    /// For Address Table: 2 bytes per entry (Group Address)
    /// For Association Table: 4 bytes per entry (TSAP + ASAP)
    /// For Group Object Table: 2 bytes per entry (Type + Flags)
    pub const TABLE: u16 = 23;

    /// Version (PID 25)
    /// PDT: PDT_VERSION / PDT_GENERIC_02
    /// DPT: DPT_Version (DPT_ID = 217.001)
    pub const VERSION: u16 = 25;

    // /// Group Object Link (PID 26)
    // /// PDT: ?
    // pub const GROUP_OBJECT_LINK: u16 = 26;

    /// Memory Control Block Table (PID 27)
    /// PDT: PDT_GENERIC_08
    pub const MCB_TABLE: u16 = 27;

    /// Error Code (PID 28)
    /// PDT: PDT_UNSIGNED_CHAR
    /// DPT: DPT_ErrorClass_System (DPT_ID = 22.001)
    pub const ERROR_CODE: u16 = 28;

    /// Object Index (AN124) (PID 29)
    /// PDT: ?
    pub const OBJECT_INDEX: u16 = 29;

    /// Download Counter (AN137) (PID 30)
    /// PDT: ?
    pub const DOWNLOAD_COUNTER: u16 = 30;

    /// Device Object PIDs (Object Type 0).
    pub mod device {
        /// Routing Count (PID 51)
        pub const ROUTING_COUNT: u16 = 51;

        /// Max Retry Count (PID 52)
        pub const MAX_RETRY_COUNT: u16 = 52;

        /// Error Flags (PID 53)
        pub const ERROR_FLAGS: u16 = 53;

        /// Program Mode (PID 54)
        pub const PROGMODE: u16 = 54;

        /// Product ID (PID 55)
        pub const PRODUCT_ID: u16 = 55;

        /// Max Supported APDU Length (PID 56)
        pub const MAX_APDU_LENGTH: u16 = 56;

        /// Subnet Address (PID 57)
        pub const SUBNET_ADDRESS: u16 = 57;

        /// Device Address (PID 58) - Individual address component
        pub const DEVICE_ADDRESS: u16 = 58;

        /// Config Link (PID 59)
        /// Also known as PB_CONFIG
        pub const CONFIG_LINK: u16 = 59;

        /// Address Report (PID 60)
        pub const ADDR_REPORT: u16 = 60;

        /// Address Check (PID 61)
        pub const ADDR_CHECK: u16 = 61;

        /// Object Value (PID 62)
        pub const OBJECT_VALUE: u16 = 62;

        /// Object Link (PID 63)
        pub const OBJECT_LINK: u16 = 63;

        /// Application (PID 64)
        pub const APPLICATION: u16 = 64;

        /// Parameter (PID 65)
        pub const PARAMETER: u16 = 65;

        /// Object Address (PID 66)
        pub const OBJECT_ADDRESS: u16 = 66;

        /// PSU Type (PID 67)
        pub const PSU_TYPE: u16 = 67;

        /// PSU Status (PID 68)
        pub const PSU_STATUS: u16 = 68;

        /// PSU Enable (PID 69)
        pub const PSU_ENABLE: u16 = 69;

        /// Domain Address (PID 70)
        pub const DOMAIN_ADDRESS: u16 = 70;

        /// Interface Object List (PID 71)
        pub const IO_LIST: u16 = 71;

        /// Management Descriptor (PID 72)
        pub const MGT_DESCRIPTOR: u16 = 72;

        /// PL110 Parameter (PID 73)
        pub const PL110_PARAM: u16 = 73;

        /// RF Repetition Counter (PID 74)
        pub const RF_REPEAT_COUNTER: u16 = 74;

        /// Receive Block Table (PID 75)
        pub const RECEIVE_BLOCK_TABLE: u16 = 75;

        /// Random Pause Table (PID 76)
        pub const RANDOM_PAUSE_TABLE: u16 = 76;

        /// Receive Block Number (PID 77)
        pub const RECEIVE_BLOCK_NR: u16 = 77;

        /// Hardware Type (PID 78)
        pub const HARDWARE_TYPE: u16 = 78;

        /// Retransmitter Number (PID 79)
        pub const RETRANSMITTER_NUMBER: u16 = 79;

        /// Serial Number Table (PID 80)
        pub const SERIAL_NR_TABLE: u16 = 80;

        /// BiBat Master Address (PID 81)
        pub const BIBAT_MASTER_ADDRESS: u16 = 81;

        /// RF Domain Address (Legacy) (PID 82)
        pub const RF_DOMAIN_ADDRESS_LEGACY: u16 = 82;

        /// Device Descriptor (PID 83)
        pub const DEVICE_DESCRIPTOR: u16 = 83;

        /// Metering Filter Table (PID 84)
        pub const METERING_FILTER_TABLE: u16 = 84;

        /// Group Telegram Rate Limitation: Time Base (PID 85)
        pub const GROUP_TELEGR_RATE_LIMIT_TIME_BASE: u16 = 85;

        /// Group Telegram Rate Limitation: Number of Telegrams (PID 86)
        pub const GROUP_TELEGR_RATE_LIMIT_NO_OF_TELEGR: u16 = 86;

        /// Easy Configuration: Parameter of Channel 1 (PID 101)
        pub const CHANNEL_01_PARAM: u16 = 101;

        /// Easy Configuration: Parameter of Channel 32 (PID 132)
        pub const CHANNEL_32_PARAM: u16 = 132;

        // /// Compile Time Stack (PID 240)
        // pub const COMPILE_TIME_STACK: u16 = 240;

        // /// Compile Time App (PID 241)
        // pub const COMPILE_TIME_APP: u16 = 241;

        // /// Bootloader Function (PID 242)
        // pub const BOOTLOADER_FUNC: u16 = 242;
    }

    /// Address Table Object PIDs (Object Type 1).
    pub mod address_table {
        /// Extended Frame Format (PID 51)
        pub const EXT_FRAMEFORMAT: u16 = 51;

        /// Max Address Table 1 (PID 52)
        pub const MAX_ADDRTAB1: u16 = 52;

        /// Group Responser Table (PID 53) - PL specific
        pub const GROUP_RESPONSER_TABLE: u16 = 53;
    }

    /// Application Program Object PIDs (Object Type 3).
    pub mod application {
        /// Parameter Reference (PID 51)
        pub const PARAM_REFERENCE: u16 = 51;

        /// Operation Mode (PID 52) - Normal / Diagnostic
        pub const OPERATION_MODE: u16 = 52;
    }

    /// Group Object Table PIDs (Object Type 9).
    pub mod group_object {
        /// GO Diagnostics (PID 66) - Diagnostic control of group objects
        pub const GO_DIAGNOSTICS: u16 = 66;
    }

    /// Router Object PIDs (Object Type 6).
    pub mod router {
        /// Line Status / Medium Status (PID 51) - State of bus line
        pub const LINE_STATUS: u16 = 51;

        /// Main Line Coupler Configuration (PID 52)
        pub const MAIN_LCCONFIG: u16 = 52;

        /// Sub Line Coupler Configuration (PID 53)
        pub const SUB_LCCONFIG: u16 = 53;

        /// Main Line Coupler Group Configuration (PID 54)
        pub const MAIN_LCGRPCONFIG: u16 = 54;

        /// Sub Line Coupler Group Configuration (PID 55)
        pub const SUB_LCGRPCONFIG: u16 = 55;

        /// Route Table Control (PID 56)
        pub const ROUTE_TABLE_CONTROL: u16 = 56;

        /// Coupler Services Control (PID 57)
        pub const COUPLER_SERVICES_CONTROL: u16 = 57;

        /// Max APDU Length Router (PID 58) - Max APDU length for routing
        pub const MAX_APDU_LENGTH_ROUTER: u16 = 58;

        /// L2 Coupler Type (PID 59)
        pub const L2_COUPLER_TYPE: u16 = 59;

        /// Hop Count (PID 61) - Hop count for router
        pub const HOP_COUNT: u16 = 61;

        /// Medium Type (PID 63)
        pub const MEDIUM: u16 = 63;

        /// Filter Table Use (PID 67) - Flag if filter table is in use
        pub const FILTER_TABLE_USE: u16 = 67;

        /// PL110 System Broadcast Control (PID 104)
        pub const PL110_SBC_CONTROL: u16 = 104;

        /// PL110 DOA (PID 105)
        pub const PL110_DOA: u16 = 105;

        /// RF System Broadcast Control (PID 112)
        pub const RF_SBC_CONTROL: u16 = 112;

        /// IP System Broadcast Control (PID 120)
        pub const IP_SBC_CONTROL: u16 = 120;

        /// LK1 Sub Lock Config (PID 200) - Block configuration from subline
        pub const LK1_SUB_LOCK_CONFIG: u16 = 200;
    }

    /// IP Parameter Object PIDs (Object Type 11 / 0x0B).
    pub mod ip {
        /// Project Installation ID (PID 51)
        pub const PROJECT_INSTALLATION_ID: u16 = 51;

        /// KNX Individual Address (PID 52)
        pub const KNX_INDIVIDUAL_ADDRESS: u16 = 52;

        /// Additional Individual Addresses (PID 53)
        pub const ADDITIONAL_INDIVIDUAL_ADDRESSES: u16 = 53;

        /// Current IP Assignment Method (PID 54)
        pub const CURRENT_IP_ASSIGNMENT_METHOD: u16 = 54;

        /// IP Assignment Method (PID 55)
        pub const IP_ASSIGNMENT_METHOD: u16 = 55;

        /// IP Capabilities (PID 56)
        pub const IP_CAPABILITIES: u16 = 56;

        /// Current IP Address (PID 57)
        pub const CURRENT_IP_ADDRESS: u16 = 57;

        /// Current Subnet Mask (PID 58)
        pub const CURRENT_SUBNET_MASK: u16 = 58;

        /// Current Default Gateway (PID 59)
        pub const CURRENT_DEFAULT_GATEWAY: u16 = 59;

        /// IP Address (PID 60)
        pub const IP_ADDRESS: u16 = 60;

        /// Subnet Mask (PID 61)
        pub const SUBNET_MASK: u16 = 61;

        /// Default Gateway (PID 62)
        pub const DEFAULT_GATEWAY: u16 = 62;

        /// DHCP/BootP Server (PID 63)
        pub const DHCP_BOOTP_SERVER: u16 = 63;

        /// MAC Address (PID 64)
        pub const MAC_ADDRESS: u16 = 64;

        /// System Setup Multicast Address (PID 65)
        pub const SYSTEM_SETUP_MULTICAST_ADDRESS: u16 = 65;

        /// Routing Multicast Address (PID 66)
        pub const ROUTING_MULTICAST_ADDRESS: u16 = 66;

        /// TTL (PID 67)
        pub const TTL: u16 = 67;

        /// KNXnet/IP Device Capabilities (PID 68)
        pub const KNXNETIP_DEVICE_CAPABILITIES: u16 = 68;

        /// KNXnet/IP Device State (PID 69)
        pub const KNXNETIP_DEVICE_STATE: u16 = 69;

        /// KNXnet/IP Routing Capabilities (PID 70)
        pub const KNXNETIP_ROUTING_CAPABILITIES: u16 = 70;

        /// Priority FIFO Enabled (PID 71)
        pub const PRIORITY_FIFO_ENABLED: u16 = 71;

        /// Queue Overflow to IP (PID 72)
        pub const QUEUE_OVERFLOW_TO_IP: u16 = 72;

        /// Queue Overflow to KNX (PID 73)
        pub const QUEUE_OVERFLOW_TO_KNX: u16 = 73;

        /// Message Transmitted to IP (PID 74)
        pub const MSG_TRANSMIT_TO_IP: u16 = 74;

        /// Message Transmitted to KNX (PID 75)
        pub const MSG_TRANSMIT_TO_KNX: u16 = 75;

        /// Friendly Name (PID 76)
        pub const FRIENDLY_NAME: u16 = 76;

        /// Routing Busy Wait Time (PID 78)
        pub const ROUTING_BUSY_WAIT_TIME: u16 = 78;

        /// Tunnelling Addresses (PID 79) - Reference to tunneling addresses
        pub const TUNNELLING_ADDRESSES: u16 = 79;

        /// Backbone Key (PID 91) - IP Security: Secure backbone key
        pub const BACKBONE_KEY: u16 = 91;

        /// Device Authentication Code (PID 92) - IP Security
        pub const DEVICE_AUTHENTICATION_CODE: u16 = 92;

        /// Password Hashes (PID 93) - IP Security
        pub const PASSWORD_HASHES: u16 = 93;

        /// Secured Service Families (PID 94) - IP Security
        pub const SECURED_SERVICE_FAMILIES: u16 = 94;

        /// Multicast Latency Tolerance (PID 95) - IP Security
        pub const MULTICAST_LATENCY_TOLERANCE: u16 = 95;

        /// Sync Latency Fraction (PID 96) - IP Security
        pub const SYNC_LATENCY_FRACTION: u16 = 96;

        /// Tunneling Users (PID 97) - IP Security
        pub const TUNNELING_USERS: u16 = 97;
    }

    /// Security Object PIDs (Object Type 17 / 0x11).
    pub mod security {
        /// Security Mode (PID 51)
        pub const SECURITY_MODE: u16 = 51;

        /// P2P Key Table (PID 52)
        pub const P2P_KEY_TABLE: u16 = 52;

        /// Group Key Table (PID 53)
        pub const GROUP_KEY_TABLE: u16 = 53;

        /// Security Individual Address Table (PID 54)
        pub const SECURITY_INDIVIDUAL_ADDRESS_TABLE: u16 = 54;

        /// Security Failures Log (PID 55)
        pub const SECURITY_FAILURES_LOG: u16 = 55;

        /// Tool Key (PID 56)
        pub const TOOL_KEY: u16 = 56;

        /// Security Report (PID 57)
        pub const SECURITY_REPORT: u16 = 57;

        /// Security Report Control (PID 58)
        pub const SECURITY_REPORT_CONTROL: u16 = 58;

        /// Sequence Number Sending (PID 59)
        pub const SEQUENCE_NUMBER_SENDING: u16 = 59;

        /// Zone Key Table (PID 60)
        pub const ZONE_KEY_TABLE: u16 = 60;

        /// GO Security Flags (PID 61)
        pub const GO_SECURITY_FLAGS: u16 = 61;

        /// Test-only manufacturer-specific PID exposing the four 16-bit
        /// `PID_SECURITY_FAILURES_LOG` counters as a writable array, used by
        /// the Data Security conformance test 3.8.12.6 to set them to FFFFh
        /// before provoking errors and observing saturation.
        ///
        /// PDT_GENERIC_02, four elements (one per failure-type counter), R/W.
        /// Spec TSS J §3.8.12.6 says: "Set error counters to FFFFh (e.g. use
        /// manufacturer specific PID – e.g. PID = 203 in the KNX Secure
        /// Object with 4 Elements, each 16 Bits wide)".
        pub const TEST_FAILURE_COUNTERS: u16 = 203;

        /// Role Table (PID 62)
        pub const ROLE_TABLE: u16 = 62;

        /// Reconstruction Mode (PID 63)
        pub const RECONSTRUCTION_MODE: u16 = 63;

        /// PB Key Establish Request (PID 70)
        pub const PB_KEY_ESTABLISH_REQUEST: u16 = 70;

        /// PB Key Establish Response (PID 71)
        pub const PB_KEY_ESTABLISH_RESPONSE: u16 = 71;

        /// PB Security Confirm (PID 72)
        pub const PB_SECURITY_CONFIRM: u16 = 72;
    }
}
