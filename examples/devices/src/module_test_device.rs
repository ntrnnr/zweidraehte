//! Module Test Device Definition
//!
//! A simple 4-channel dimmer device that demonstrates KNX module usage.
//! Each channel is defined as a module instance with its own parameters
//! and communication objects.
//!
//! # Overview
//!
//! KNX modules allow you to define reusable templates for multi-channel devices.
//! Instead of duplicating parameter and comm object definitions for each channel,
//! you define them once in a module and instantiate it multiple times.
//!
//! # Defining a Module
//!
//! A module consists of two parts:
//!
//! ## 1. Communication Objects (`DimmerChannelObjects`)
//!
//! Define comm objects FIRST with `#[ets_com_objects]`. This single type serves both
//! ETS metadata generation AND runtime storage:
//!
//! ```rust,ignore
//! #[ets_com_objects]
//! pub struct DimmerChannelObjects {
//!     #[ets(index = 0, display = "Switch", function = "Switch on/off",
//!           flags = C | R | W | T, text_template = "Ch{{ChNo}} Switch: {{0}}")]
//!     pub switch: ComObject<DPT_Switch>,
//!
//!     #[ets(index = 1, display = "Dimming", function = "Dimming value %",
//!           flags = C | R | W | T)]
//!     pub dim_value: ComObject<DPT_Scaling>,
//!
//!     #[ets(index = 2, display = "Status", function = "Status feedback",
//!           flags = C | T)]
//!     pub status: ComObject<DPT_State>,
//! }
//! ```
//!
//! ## 2. Module Definition (`define_module!` macro)
//!
//! Use the `define_module!` macro to define the module with its parameters:
//!
//! ```rust,ignore
//! zweidraehte_knxprod::define_module! {
//!     pub module DimmerChannelModule {
//!         name = "DimmerChannel",
//!         description = "Dimmer channel module",
//!
//!         // Module arguments
//!         args {
//!             ParamBase: param_offset,    // Memory offset for parameters
//!             ObjBase: object_number,     // First communication object number
//!             ChNo: display(1),           // For {{ChNo}} in text templates
//!         }
//!
//!         // Virtual parameters - ETS-only, not stored in device memory
//!         // Syntax: name: Type(size) = "display" [modifier],
//!         virtual_params {
//!             channel_name: String(30) = "Channel name" [text_source],
//!         }
//!
//!         // Regular parameters - stored in device memory
//!         params {
//!             #[ets(display = "Minimum brightness", suffix = "%")]
//!             min_brightness: u8,
//!
//!             #[ets(display = "Maximum brightness", suffix = "%")]
//!             max_brightness: u8,
//!         }
//!
//!         // Reference the comm objects type defined above
//!         objects: DimmerChannelObjects,
//!
//!         // Optional ETS page layout with conditional pictures
//!         layout {
//!             block "DimmerChannel" => "{{ChNo}}: {{0}}" {
//!                 param channel_name
//!                 param icon_selection
//!                 // Conditional picture based on parameter value
//!                 when @icon_selection {
//!                     [1] => {
//!                         picture "xmas.png"
//!                     }
//!                     [2] => {
//!                         picture "night.png"
//!                     }
//!                 }
//!                 param min_brightness
//!                 obj switch
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## Conditional Pictures
//!
//! Pictures can be conditionally displayed based on parameter values using `when` blocks.
//! The selector parameter (e.g., `icon_selection`) is stored on the device and controls
//! which picture is shown in ETS. This generates a `choose/when` XML structure:
//!
//! ```xml
//! <choose ParamRefId="...icon_selection_R-2">
//!   <when test="1">
//!     <ParameterRefRef RefId="...xmas_png_R-7"/>
//!   </when>
//!   <when test="2">
//!     <ParameterRefRef RefId="...night_png_R-8"/>
//!   </when>
//! </choose>
//! ```
//!
//! The macro generates:
//! - `DimmerChannelModuleParams` - params struct with `#[ets_params]`
//! - `DIMMER_CHANNEL_MODULE_VIRTUAL_PARAMS` - virtual params constant
//! - `DimmerChannelModule` - module struct implementing `KnxModule`
//!
//! # Using Modules in Device Parameters
//!
//! Use `#[ets(module = ModuleType)]` on array fields to generate compile-time helpers:
//!
//! ```rust,ignore
//! #[ets_params]
//! pub struct DeviceParams {
//!     pub enable_ch1: u8,
//!     pub enable_ch2: u8,
//!     pub global_dim_speed: u8,
//!
//!     #[ets(module = DimmerChannelModule)]
//!     pub channels: [DimmerChannelModuleParams; 4],
//! }
//!
//! // Auto-generated helpers:
//! DeviceParams::CHANNELS_COUNT              // = 4
//! DeviceParams::channel_param_offset(2)     // = offset for channel 2 (1-indexed)
//! DeviceParams::channel_object_base(2)      // = first obj index for channel 2
//! DeviceParams::channel_object_index(2, 1)  // = absolute index for ch2, obj 1
//! ```
//!
//! # Using Modules for Runtime Comm Objects
//!
//! Use `#[ets(module = ModuleType)]` on comm object arrays too:
//!
//! ```rust,ignore
//! #[ets_com_objects]
//! pub struct DimmerCommObjects {
//!     #[ets(module = DimmerChannelModule)]
//!     pub channels: [DimmerChannelObjects; 4],
//! }
//!
//! // Auto-generated:
//! DimmerCommObjects::channel_object_index(2, 0)  // ch2 switch index
//! DimmerCommObjects::CHANNELS_INSTANCE_COUNT     // = 4
//! ```
//!
//! # Runtime vs Configuration Time
//!
//! **Important:** Modules are purely an ETS/configuration-time concept!
//!
//! At runtime, the firmware sees a flat memory layout:
//! - Parameters are stored contiguously in memory
//! - Communication objects are numbered sequentially
//! - The module abstraction has been "flattened" by ETS during download
//!
//! ## Memory Layout
//!
//! ```text
//! Offset 0-4:   Global params (5 bytes)
//!   - enable_ch1, enable_ch2, enable_ch3, enable_ch4, global_dim_speed
//!
//! Offset 5-9:   Channel 1 DimmerChannelModuleParams (5 bytes)
//! Offset 10-14: Channel 2 DimmerChannelModuleParams (5 bytes)
//! Offset 15-19: Channel 3 DimmerChannelModuleParams (5 bytes)
//! Offset 20-24: Channel 4 DimmerChannelModuleParams (5 bytes)
//!
//! Total: 25 bytes (5 global + 4 channels × 5 bytes)
//! ```
//!
//! ## Communication Object Layout
//!
//! ```text
//! Object 0-2:  Channel 1 (switch, dim_value, status)
//! Object 3-5:  Channel 2 (switch, dim_value, status)
//! Object 6-8:  Channel 3 (switch, dim_value, status)
//! Object 9-11: Channel 4 (switch, dim_value, status)
//! ```
//!
//! # Accessing Parameters at Runtime
//!
//! ```rust,ignore
//! let params: DeviceParams = read_from_memory();
//!
//! // Direct array access (0-indexed)
//! let ch2_min = params.channels[1].min_brightness;
//!
//! // Global params
//! let speed = params.global_dim_speed;
//!
//! // Or use the array index directly
//! let ch2_params = &params.channels[1];  // &DimmerChannelModuleParams for ch2
//! ```
//!
//! # Accessing Communication Objects at Runtime
//!
//! ```rust,ignore
//! use comm_objs::{DimmerCommObjects, Index};
//!
//! let mut comm_objs = DimmerCommObjects::new();
//!
//! // Direct field access (0-indexed channel)
//! comm_objs.channels[0].switch.value = DPT_Switch::from(true);
//!
//! // Via ComObjects trait with index calculation
//! // channel_object_index(instance, local_obj): instance is 1-indexed, local_obj is 0-indexed
//! let ch2_switch_idx = DimmerCommObjects::channel_object_index(2, 0) as u16;
//! comm_objs.value_mut(ch2_switch_idx).unwrap()[0] = 1;  // Turn on
//!
//! // Type-safe Index (0-indexed for both)
//! let idx = Index::for_instance(1, 0).unwrap();  // ch2 (0-indexed), switch
//! comm_objs.value_mut(idx.index()).unwrap()[0] = 1;
//! ```
//!
//! # Module Structure Note
//!
//! The `comm_objs` module contains nested submodules to avoid `Index` type name
//! collisions from multiple `#[ets_com_objects]` invocations. Each derive
//! generates its own `Index` type, so they need separate namespaces.

use serde::{Deserialize, Serialize};
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use zweidraehte_device::prelude::*;
use zweidraehte_ets_model::{EtsEnum, ets_com_objects, ets_params};
use zweidraehte_proto::dpt::{DPT_Scaling, DPT_State, DPT_Switch};

use zweidraehte_ets_files::schema::BaggageDef;
use zweidraehte_knxprod::definition::module::ModuleCollection;
use zweidraehte_knxprod::definition::page_layout::EtsPageLayout;
use zweidraehte_knxprod::ets_pages;

// ============================================================================
// Translations
// ============================================================================

// German translations for the dimmer module device
zweidraehte_ets_model::ets_translations! {
    pub MODULE_TRANSLATIONS_DE;

    "de-DE" {
        // ========== Enum variants ==========
        // ChannelEnable enum
        ChannelEnable::Disabled => "Deaktiviert",
        ChannelEnable::Enabled => "Aktiviert",

        // IconSelection enum
        IconSelection::Christmas => "Weihnachten",
        IconSelection::Night => "Nacht",

        // ========== Device-level parameters ==========
        param device_name => "Gerätename",
        param enable_ch1 => "Kanal 1 aktivieren",
        param enable_ch2 => "Kanal 2 aktivieren",
        param enable_ch3 => "Kanal 3 aktivieren",
        param enable_ch4 => "Kanal 4 aktivieren",
        param global_dim_speed => "Globale Dimmgeschwindigkeit",

        // ========== Module parameters ==========
        param channel_name => "Kanalname",
        param icon_selection => "Symbol",
        param min_brightness => "Minimale Helligkeit",
        param max_brightness => "Maximale Helligkeit",
        param dim_speed => "Dimmgeschwindigkeit",
        param power_on_level => "Einschalthelligkeit",

        // ========== Communication objects ==========
        obj switch { text: "Schalten", function: "Ein/Aus schalten" },
        obj dim_value { text: "Dimmwert", function: "Dimmwert %" },
        obj status { text: "Status", function: "Statusrückmeldung" },
    }
}

// English translations (for completeness / as reference)
zweidraehte_ets_model::ets_translations! {
    pub MODULE_TRANSLATIONS_EN;

    "en-US" {
        // ========== Enum variants ==========
        // ChannelEnable enum
        ChannelEnable::Disabled => "Disabled",
        ChannelEnable::Enabled => "Enabled",

        // IconSelection enum
        IconSelection::Christmas => "Christmas",
        IconSelection::Night => "Night",

        // ========== Device-level parameters ==========
        param device_name => "Device name",
        param enable_ch1 => "Enable channel 1",
        param enable_ch2 => "Enable channel 2",
        param enable_ch3 => "Enable channel 3",
        param enable_ch4 => "Enable channel 4",
        param global_dim_speed => "Global dimming speed",

        // ========== Module parameters ==========
        param channel_name => "Channel name",
        param icon_selection => "Icon",
        param min_brightness => "Minimum brightness",
        param max_brightness => "Maximum brightness",
        param dim_speed => "Dimming speed",
        param power_on_level => "Power-on level",

        // ========== Communication objects ==========
        obj switch { text: "Switch", function: "Switch on/off" },
        obj dim_value { text: "Dimming value", function: "Dimming value %" },
        obj status { text: "Status", function: "Status feedback" },
    }
}

// ============================================================================
// Baggages
// ============================================================================

/// Baggage definitions for the module test device.
/// These are image files that can be displayed in ETS UI.
pub const BAGGAGES: &[BaggageDef<'static>] = &[
    BaggageDef::embedded("xmas.png", include_bytes!("baggages/xmas.png")),
    BaggageDef::embedded("night.png", include_bytes!("baggages/night.png")),
];

// ============================================================================
// Device Descriptor
// ============================================================================

/// Device descriptor for 4-channel dimmer.
pub const DEVICE_DESCRIPTOR: DeviceDescriptor = DeviceDescriptor {
    mask_version: MaskVersion::SystemBKnxIp,
    manufacturer_id: 0x00FA,
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x10],
    application_id: 0x1000,
    application_version: 0x01,
    max_address_table_entries: 32,
    max_association_table_entries: 32,
    max_com_objects: 16, // 4 channels * 3 objects each + some extras
    pei_type: 0,
};

/// Serial number for test device.
pub const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x10, 0x00, 0x00, 0x01];

// ============================================================================
// Device-Level Virtual Parameters
// ============================================================================

// Device-level virtual parameters that exist only in ETS (not stored in device memory).
// These appear at the top of the parameter list, before regular parameters.
//
// Use cases:
// - Device name for display in ETS
// - Location/room information
// - Any text that's only needed in ETS, not on the device
zweidraehte_ets_model::ets_virtual_params! {
    pub DEVICE_VIRTUAL_PARAMS {
        device_name: String(50) => "Device name" [text_source],
    }
}

// ============================================================================
// Global Device Parameters (non-module)
// ============================================================================

/// Number of dimmer channels in this device.
pub const NUM_CHANNELS: usize = 4;

/// Enable/Disable enum for channel activation.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, EtsEnum, Serialize, Deserialize, KnownLayout, Immutable, IntoBytes,
)]
#[repr(u8)]
pub enum ChannelEnable {
    #[default]
    #[ets(display = "Disabled")]
    Disabled = 0,
    #[ets(display = "Enabled")]
    Enabled = 1,
}

/// Icon selection enum - stored on device to select which icon to display in ETS.
/// The default variant (Christmas = 1) is automatically used as the parameter default.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, EtsEnum, Serialize, Deserialize, KnownLayout, Immutable, IntoBytes,
)]
#[repr(u8)]
pub enum IconSelection {
    #[default]
    #[ets(display = "Christmas")]
    Christmas = 1,
    #[ets(display = "Night")]
    Night = 2,
}

/// Complete device parameters including global settings and all channel modules.
///
/// This struct represents the flattened memory layout that ETS downloads
/// to the device. The `#[ets(module = DimmerChannelModule)]` attribute
/// automatically generates compile-time helper methods:
///
/// - `CHANNELS_COUNT: usize = 4` - Number of module instances
/// - `channel_param_offset(instance)` - Parameter offset for instance N (1-indexed)
/// - `channel_object_base(instance)` - First object index for instance N (1-indexed)
/// - `channel_object_index(instance, local_index)` - Absolute object index
///
/// # Example
///
/// ```rust,ignore
/// let params: DeviceParams = read_from_memory();
///
/// // Access global params
/// let speed = params.global_dim_speed;
///
/// // Access channel params by array index (0-indexed)
/// let ch2_min = params.channels[1].min_brightness;
///
/// // Use generated helpers for offset calculations (1-indexed)
/// let ch2_offset = DeviceParams::channel_param_offset(2); // = 10
/// let ch2_obj0 = DeviceParams::channel_object_index(2, 0); // = 3
/// ```
#[ets_params]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DeviceParams {
    /// Enable channel 1
    #[ets(display = "Enable channel 1", ets_enum)]
    pub enable_ch1: ChannelEnable,

    /// Enable channel 2
    #[ets(display = "Enable channel 2", ets_enum)]
    pub enable_ch2: ChannelEnable,

    /// Enable channel 3
    #[ets(display = "Enable channel 3", ets_enum)]
    pub enable_ch3: ChannelEnable,

    /// Enable channel 4
    #[ets(display = "Enable channel 4", ets_enum)]
    pub enable_ch4: ChannelEnable,

    /// Global dimming speed (affects all channels)
    #[ets(display = "Global dimming speed", suffix = "ms")]
    pub global_dim_speed: u8,

    /// Per-channel parameters - module helpers generated automatically
    #[ets(module = DimmerChannelModule)]
    pub channels: [DimmerChannelModuleParams; NUM_CHANNELS],
}

impl DeviceParams {
    /// Check if a channel is enabled (0-indexed).
    pub fn is_channel_enabled(&self, channel: usize) -> bool {
        [self.enable_ch1, self.enable_ch2, self.enable_ch3, self.enable_ch4]
            .get(channel)
            .is_some_and(|&v| v == ChannelEnable::Enabled)
    }
}

// Auto-generated by #[ets(module = DimmerChannelModule)]:
// - DeviceParams::CHANNELS_COUNT
// - DeviceParams::channel_param_offset(instance)  // 1-indexed
// - DeviceParams::channel_object_base(instance)   // 1-indexed
// - DeviceParams::channel_object_index(instance, local_index)  // 1-indexed instance

// ============================================================================
// Dimmer Channel Communication Objects
// ============================================================================
//
// Define the communication objects FIRST using #[ets_com_objects].
// This single type provides BOTH ETS metadata AND runtime storage.

/// Communication objects for a dimmer channel.
///
/// This type provides both ETS metadata (via `HasModuleCommObjects`) and
/// runtime storage (via `ComObjects` trait). Define it once, use it in
/// `define_module!` with `objects: DimmerChannelObjects,`.
///
/// Text template substitution in ETS:
/// - `{{ChNo}}` is replaced by the channel number argument
/// - `{{0}}` is replaced by the value of the parameter referenced by `TextParameterRefId`
#[ets_com_objects]
pub struct DimmerChannelObjects {
    #[ets(
        index = 0,
        display = "Switch",
        function = "Switch on/off",
        flags = C | R | W | T,
        text_template = "Ch{{ChNo}} Switch: {{0}}"
    )]
    pub switch: DPT_Switch,

    #[ets(
        index = 1,
        display = "Dimming value",
        function = "Dimming value %",
        flags = C | R | W | T,
        text_template = "Ch{{ChNo}} Dim: {{0}}"
    )]
    pub dim_value: DPT_Scaling,

    #[ets(
        index = 2,
        display = "Status",
        function = "Status feedback",
        flags = C | T,
        text_template = "Ch{{ChNo}} Status: {{0}}"
    )]
    pub status: DPT_State,
}

// ============================================================================
// Dimmer Channel Module (using define_module! macro)
// ============================================================================
//
// The define_module! macro generates:
// - DimmerChannelModuleParams - parameter struct with EtsParams
// - DIMMER_CHANNEL_MODULE_VIRTUAL_PARAMS - virtual params constant
// - DimmerChannelModule - module struct implementing KnxModule
//
// Communication objects are provided by referencing the DimmerChannelObjects
// type defined above with `objects: DimmerChannelObjects,`

zweidraehte_knxprod::define_module! {
    /// Module definition for a dimmer channel.
    ///
    /// This module encapsulates all the parameters and communication objects
    /// for a single dimmer channel. It can be instantiated multiple times
    /// with different argument values for multi-channel devices.
    pub module DimmerChannelModule {
        name = "DimmerChannel",
        description = "Dimmer channel module",

        args {
            ParamBase: param_offset,
            ObjBase: object_number,
            ChNo: display(1),
        }

        virtual_params {
            // Inline syntax: name: Type(size) = "display" [modifier],
            channel_name: String(30) = "Channel name" [text_source],
        }

        params {
            /// Icon selection - stored on device, controls which icon is shown in ETS
            #[ets(display = "Icon", ets_enum)]
            icon_selection: IconSelection,

            /// Minimum brightness level (0-100%)
            #[ets(display = "Minimum brightness", suffix = "%")]
            min_brightness: u8,

            /// Maximum brightness level (0-100%)
            #[ets(display = "Maximum brightness", suffix = "%")]
            max_brightness: u8,

            /// Dimming speed for this channel (0-255, in 10ms steps)
            #[ets(display = "Dimming speed", suffix = "x10ms")]
            dim_speed: u8,

            /// Power-on brightness level
            #[ets(display = "Power-on level", suffix = "%")]
            power_on_level: u8,
        }

        // Reference the objects type defined above - provides both ETS metadata and runtime storage
        objects: DimmerChannelObjects,

        layout {
            block "DimmerChannel" => "{{ChNo}}: {{0}}" {
                param channel_name
                param icon_selection
                // Conditional picture display based on icon_selection parameter
                when @icon_selection {
                    [1] => {
                        picture "xmas.png"
                    }
                    [2] => {
                        picture "night.png"
                    }
                }
                sep "Dimming Settings"
                param min_brightness
                param max_brightness
                param dim_speed
                param power_on_level
                obj switch
                obj dim_value
                obj status
            }
        }
    }
}

// ============================================================================
// Device-Level Communication Objects
// ============================================================================
//
// At runtime, modules are flattened - the device sees a single flat array of
// communication objects. This struct aggregates all channel instances.
//
// Object layout (4 channels × 3 objects = 12 total):
//   0: Ch1 Switch     3: Ch2 Switch     6: Ch3 Switch     9:  Ch4 Switch
//   1: Ch1 Dim        4: Ch2 Dim        7: Ch3 Dim        10: Ch4 Dim
//   2: Ch1 Status     5: Ch2 Status     8: Ch3 Status     11: Ch4 Status

/// Communication objects module - provides separate namespace for Index type.
pub mod comm_objs {
    use super::*;

    /// Runtime communication objects for all 4 dimmer channels (12 objects total).
    ///
    /// Auto-generates `ComObjects` impl and `channel_object_index(instance, local_obj)` helper.
    /// See module-level docs for usage examples.
    #[ets_com_objects]
    pub struct DimmerCommObjects {
        #[ets(module = DimmerChannelModule)]
        pub channels: [DimmerChannelObjects; NUM_CHANNELS],
    }
}

// ============================================================================
// Device Definition
// ============================================================================

/// The complete 4-channel dimmer device.
pub struct ModuleTestDevice;

impl ModuleTestDevice {
    /// Create the module collection with the DimmerChannelModule definition.
    pub fn create_modules() -> ModuleCollection {
        ModuleCollection::with_definition::<DimmerChannelModule>()
    }
}

impl EtsPageLayout for ModuleTestDevice {
    fn page_layout() -> zweidraehte_knxprod::definition::page_layout::PageStructure {
        use zweidraehte_knxprod::definition::module::module_instances;

        // Build entire page structure using the ets_pages! macro
        // - Device settings: global dimming speed only
        // - Channel tab: enable params + conditional module instances
        ets_pages! {
            device {
                block "general" => "General Settings" {
                    picture "night.png"
                    param global_dim_speed
                }
            }

            channel "channels" => "Dimmer Channels" (1) {
                block "channel_modules" => "Channel Configuration" {
                    param enable_ch1
                    param enable_ch2
                    param enable_ch3
                    param enable_ch4

                    // Use module_instances helper for ergonomic multi-channel module instantiation
                    // This automatically computes ParamBase, ObjBase, and ChNo from DeviceParams helpers
                    raw module_instances::<DimmerChannelModule, DeviceParams>("enable_ch")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_collection_creation() {
        let modules = ModuleTestDevice::create_modules();
        // Collection contains only the definition - instances are generated at XML time
        assert_eq!(modules.definition_count(), 1);
        assert_eq!(modules.instance_count(), 0); // No instances stored in collection
    }

    #[test]
    fn test_page_layout() {
        let layout = ModuleTestDevice::page_layout();
        // 1 device setting block (general), channel enable moved to Dimmer Channels tab
        assert_eq!(layout.device_settings.len(), 1);
        assert_eq!(layout.channels.len(), 1);
    }

    #[test]
    fn test_param_size() {
        // Global: 5 bytes, Channels: 4 * 5 = 20 bytes, Total: 25 bytes
        // (channel_name is a virtual-only param, not in struct)
        assert_eq!(core::mem::size_of::<DeviceParams>(), 25);
    }

    // ========================================================================
    // Runtime Access Tests
    // ========================================================================

    #[test]
    fn test_all_device_params_layout() {
        // Rust struct sizes (NO virtual channel_name - it's ETS-only metadata):
        // DeviceParams = 5 global bytes + 4 * 5 channel bytes = 25 bytes
        // DimmerChannelModuleParams = 5 bytes (icon_selection, min_brightness, max_brightness, dim_speed, power_on_level)
        //
        // The Rust struct layout now exactly matches device memory layout.
        // Virtual parameters like channel_name exist only in ETS metadata
        // (see DIMMER_CHANNEL_VIRTUAL_PARAMS).
        assert_eq!(core::mem::size_of::<DeviceParams>(), 25);
        assert_eq!(core::mem::size_of::<DimmerChannelModuleParams>(), 5);
    }

    #[test]
    fn test_all_device_params_access() {
        // Set up some test values
        let mut params = DeviceParams {
            enable_ch1: ChannelEnable::Enabled,
            enable_ch2: ChannelEnable::Enabled,
            enable_ch3: ChannelEnable::Disabled,
            enable_ch4: ChannelEnable::Enabled,
            global_dim_speed: 50,
            ..Default::default()
        };

        params.channels[0].min_brightness = 10;
        params.channels[0].max_brightness = 100;
        params.channels[1].min_brightness = 20;
        params.channels[1].max_brightness = 80;

        // Test channel enabled checks
        assert!(params.is_channel_enabled(0));
        assert!(params.is_channel_enabled(1));
        assert!(!params.is_channel_enabled(2));
        assert!(params.is_channel_enabled(3));

        // Test channel array access
        assert_eq!(params.channels[0].min_brightness, 10);
        assert_eq!(params.channels[1].min_brightness, 20);

        // Test mutable access
        params.channels[2].dim_speed = 100;
        assert_eq!(params.channels[2].dim_speed, 100);
    }

    #[test]
    fn test_all_device_params_memory_representation() {
        // Create params with known values
        // Write raw bytes directly to test memory layout
        // DeviceParams is now 25 bytes: 5 global + 4 * 5 channel
        let mut raw_bytes = [0u8; core::mem::size_of::<DeviceParams>()];

        // Set global params (using valid enum values for ChannelEnable)
        raw_bytes[0] = 0x01; // enable_ch1 = Enabled
        raw_bytes[1] = 0x00; // enable_ch2 = Disabled
        raw_bytes[2] = 0x01; // enable_ch3 = Enabled
        raw_bytes[3] = 0x00; // enable_ch4 = Disabled
        raw_bytes[4] = 0x55; // global_dim_speed

        // Set channel 1 data (starts at offset 5)
        // DimmerChannelModuleParams is 5 bytes: icon_selection, min_brightness, max_brightness, dim_speed, power_on_level
        raw_bytes[5] = 0x01; // ch1.icon_selection = Christmas (1)
        raw_bytes[6] = 0xA1; // ch1.min_brightness
        raw_bytes[7] = 0xA2; // ch1.max_brightness
        raw_bytes[8] = 0xA3; // ch1.dim_speed
        raw_bytes[9] = 0xA4; // ch1.power_on_level

        // Set channel 2 data (starts at offset 5 + 5 = 10)
        raw_bytes[10] = 0x02; // ch2.icon_selection = Night (2)
        raw_bytes[11] = 0xB1; // ch2.min_brightness
        raw_bytes[12] = 0xB2; // ch2.max_brightness

        // Interpret as DeviceParams
        let params: &DeviceParams = unsafe { &*(raw_bytes.as_ptr() as *const DeviceParams) };

        // Verify the struct sees the correct values
        assert_eq!(params.enable_ch1, ChannelEnable::Enabled);
        assert_eq!(params.enable_ch2, ChannelEnable::Disabled);
        assert_eq!(params.enable_ch3, ChannelEnable::Enabled);
        assert_eq!(params.enable_ch4, ChannelEnable::Disabled);
        assert_eq!(params.global_dim_speed, 0x55);

        // Verify channel data
        assert_eq!(params.channels[0].icon_selection, IconSelection::Christmas);
        assert_eq!(params.channels[0].min_brightness, 0xA1);
        assert_eq!(params.channels[0].max_brightness, 0xA2);
        assert_eq!(params.channels[0].dim_speed, 0xA3);
        assert_eq!(params.channels[0].power_on_level, 0xA4);
        assert_eq!(params.channels[1].icon_selection, IconSelection::Night);
        assert_eq!(params.channels[1].min_brightness, 0xB1);
        assert_eq!(params.channels[1].max_brightness, 0xB2);
    }

    #[test]
    fn test_generated_helpers() {
        // Test the helpers automatically generated by #[ets(module = DimmerChannelModule)]

        // Test CHANNELS_COUNT constant
        assert_eq!(DeviceParams::CHANNELS_COUNT, 4);

        // Test channel_param_offset (1-indexed)
        // Global params are 5 bytes, DimmerChannelModuleParams is 5 bytes each
        assert_eq!(DeviceParams::channel_param_offset(1), 5);
        assert_eq!(DeviceParams::channel_param_offset(2), 5 + 5);
        assert_eq!(DeviceParams::channel_param_offset(3), 5 + 2 * 5);
        assert_eq!(DeviceParams::channel_param_offset(4), 5 + 3 * 5);

        // Test channel_object_base (1-indexed)
        assert_eq!(DeviceParams::channel_object_base(1), 0);
        assert_eq!(DeviceParams::channel_object_base(2), 3);
        assert_eq!(DeviceParams::channel_object_base(3), 6);
        assert_eq!(DeviceParams::channel_object_base(4), 9);

        // Test channel_object_index (1-indexed instance, 0-indexed local)
        assert_eq!(DeviceParams::channel_object_index(1, 0), 0); // ch1 switch
        assert_eq!(DeviceParams::channel_object_index(1, 1), 1); // ch1 dim
        assert_eq!(DeviceParams::channel_object_index(1, 2), 2); // ch1 status
        assert_eq!(DeviceParams::channel_object_index(2, 0), 3); // ch2 switch
        assert_eq!(DeviceParams::channel_object_index(2, 1), 4); // ch2 dim
        assert_eq!(DeviceParams::channel_object_index(3, 2), 8); // ch3 status
    }

    #[test]
    fn test_has_channel_helpers_trait() {
        // Verify the HasChannelHelpers trait is correctly implemented
        use zweidraehte_knxprod::definition::module::HasChannelHelpers;

        // Test COUNT matches NUM_CHANNELS
        assert_eq!(<DeviceParams as HasChannelHelpers<DimmerChannelModule>>::COUNT, NUM_CHANNELS);

        // Test param_offset matches channel_param_offset helper
        for ch in 1..=NUM_CHANNELS {
            assert_eq!(
                <DeviceParams as HasChannelHelpers<DimmerChannelModule>>::param_offset(ch),
                DeviceParams::channel_param_offset(ch),
                "Channel {} param_offset mismatch",
                ch
            );

            assert_eq!(
                <DeviceParams as HasChannelHelpers<DimmerChannelModule>>::object_base(ch),
                DeviceParams::channel_object_base(ch),
                "Channel {} object_base mismatch",
                ch
            );
        }
    }

    #[test]
    fn test_param_offset_matches_struct_layout() {
        // Verify the generated helpers match actual struct memory layout
        use core::mem::offset_of;

        // Channel array starts after the 5 global param bytes
        let channels_offset = offset_of!(DeviceParams, channels);
        assert_eq!(channels_offset, 5); // 5 global param bytes (enable_ch1-4, global_dim_speed)

        // Each channel's offset in raw bytes
        let param_size = core::mem::size_of::<DimmerChannelModuleParams>();
        for ch in 1..=NUM_CHANNELS {
            let expected = channels_offset + (ch - 1) * param_size;
            let from_helper = DeviceParams::channel_param_offset(ch);
            assert_eq!(from_helper, expected, "Channel {} offset mismatch", ch);
        }
    }

    // ========================================================================
    // Communication Object Runtime Access Tests
    // ========================================================================
    //
    // These tests demonstrate how to work with module communication objects
    // at runtime. The key insight is that modules are purely an ETS/configuration
    // abstraction - at runtime, communication objects are a flat array.

    /// Object indices within a dimmer channel module (for documentation/readability)
    mod channel_objects {
        pub const SWITCH: usize = 0;
        pub const DIM_VALUE: usize = 1;
        pub const STATUS: usize = 2;
    }

    #[test]
    fn test_comm_object_index_calculation() {
        // This test demonstrates how to calculate communication object indices
        // for module instances at runtime.
        //
        // The `channel_object_index(instance, local_index)` helper converts:
        //   - instance: 1-indexed channel number (1..=NUM_CHANNELS)
        //   - local_index: 0-indexed object within the module (0..OBJECTS_PER_CHANNEL)
        // into an absolute object index for the flat comm object array.

        const OBJECTS_PER_CHANNEL: usize = 3; // switch, dim_value, status

        // Example: Getting object indices for channel 2
        let ch2_switch = DeviceParams::channel_object_index(2, channel_objects::SWITCH);
        let ch2_dim = DeviceParams::channel_object_index(2, channel_objects::DIM_VALUE);
        let ch2_status = DeviceParams::channel_object_index(2, channel_objects::STATUS);

        // Channel 2 objects start at index 3 (after channel 1's 3 objects)
        assert_eq!(ch2_switch, 3);
        assert_eq!(ch2_dim, 4);
        assert_eq!(ch2_status, 5);

        // Verify the pattern: object_index = (channel - 1) * OBJECTS_PER_CHANNEL + local_index
        for ch in 1..=NUM_CHANNELS {
            for local_obj in 0..OBJECTS_PER_CHANNEL {
                let expected = (ch - 1) * OBJECTS_PER_CHANNEL + local_obj;
                let actual = DeviceParams::channel_object_index(ch, local_obj);
                assert_eq!(actual, expected, "ch{} obj{} mismatch", ch, local_obj);
            }
        }
    }

    #[test]
    fn test_comm_object_runtime_workflow() {
        // This test demonstrates a realistic runtime workflow for handling
        // communication objects from module instances.
        //
        // Scenario: Device receives a group telegram for the dimming value
        // of channel 3. The firmware needs to:
        // 1. Identify which channel's object was updated
        // 2. Apply min/max brightness constraints from that channel's params
        // 3. Update the status object for that channel

        // Simulated device state
        let params = DeviceParams {
            enable_ch1: ChannelEnable::Enabled,
            enable_ch2: ChannelEnable::Enabled,
            enable_ch3: ChannelEnable::Enabled,
            enable_ch4: ChannelEnable::Disabled, // Channel 4 disabled
            global_dim_speed: 50,
            channels: [
                DimmerChannelModuleParams {
                    icon_selection: IconSelection::Christmas,
                    min_brightness: 0,
                    max_brightness: 100,
                    dim_speed: 30,
                    power_on_level: 50,
                    ..Default::default()
                },
                DimmerChannelModuleParams {
                    icon_selection: IconSelection::Christmas,
                    min_brightness: 10,
                    max_brightness: 90,
                    dim_speed: 40,
                    power_on_level: 60,
                    ..Default::default()
                },
                DimmerChannelModuleParams {
                    icon_selection: IconSelection::Night,
                    min_brightness: 20,
                    max_brightness: 80,
                    dim_speed: 50,
                    power_on_level: 70,
                    ..Default::default()
                },
                DimmerChannelModuleParams {
                    icon_selection: IconSelection::Christmas,
                    min_brightness: 0,
                    max_brightness: 100,
                    dim_speed: 60,
                    power_on_level: 80,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        // Simulated comm object values (flat array, 4 channels * 3 objects = 12 objects)
        let mut comm_object_values: [u8; 12] = [0; 12];

        // --- Scenario: Telegram arrives for channel 3 dim_value object ---

        // The incoming telegram targets object index 7
        let incoming_object_index = 7;
        let requested_brightness = 15u8; // User requested 15%

        // Step 1: Find which channel this object belongs to
        let channel = find_channel_for_object(incoming_object_index);
        assert_eq!(channel, Some(3)); // It's channel 3 (1-indexed)

        // Step 2: Verify this is indeed a dim_value object
        let local_index = incoming_object_index - DeviceParams::channel_object_base(channel.unwrap());
        assert_eq!(local_index, channel_objects::DIM_VALUE);

        // Step 3: Apply channel's brightness constraints
        let ch_params = &params.channels[channel.unwrap() - 1]; // 0-indexed for array access
        let constrained_brightness = requested_brightness.max(ch_params.min_brightness).min(ch_params.max_brightness);
        assert_eq!(constrained_brightness, 20); // Clamped to min of 20%

        // Step 4: Update the dim_value object
        let dim_obj_idx = DeviceParams::channel_object_index(channel.unwrap(), channel_objects::DIM_VALUE);
        comm_object_values[dim_obj_idx] = constrained_brightness;

        // Step 5: Update the status object for this channel
        let status_obj_idx = DeviceParams::channel_object_index(channel.unwrap(), channel_objects::STATUS);
        comm_object_values[status_obj_idx] = if constrained_brightness > 0 { 1 } else { 0 };

        // Verify final state
        assert_eq!(comm_object_values[7], 20); // dim_value at 20%
        assert_eq!(comm_object_values[8], 1); // status is ON
    }

    /// Helper function to find which channel (1-indexed) an object index belongs to.
    /// Returns None if the index is out of range.
    fn find_channel_for_object(object_index: usize) -> Option<usize> {
        const OBJECTS_PER_CHANNEL: usize = 3;
        let total_objects = NUM_CHANNELS * OBJECTS_PER_CHANNEL;

        if object_index >= total_objects {
            return None;
        }

        // Channel number (1-indexed)
        Some(object_index / OBJECTS_PER_CHANNEL + 1)
    }

    #[test]
    fn test_iterate_enabled_channel_objects() {
        // This test demonstrates how to iterate over communication objects
        // for only the enabled channels.

        let params = DeviceParams {
            enable_ch1: ChannelEnable::Enabled,
            enable_ch2: ChannelEnable::Disabled, // Disabled
            enable_ch3: ChannelEnable::Enabled,
            enable_ch4: ChannelEnable::Disabled, // Disabled
            ..DeviceParams::default()
        };

        // Collect all switch object indices for enabled channels
        let mut enabled_switch_objects = Vec::new();

        for ch in 1..=NUM_CHANNELS {
            if params.is_channel_enabled(ch - 1) {
                // is_channel_enabled is 0-indexed
                let switch_idx = DeviceParams::channel_object_index(ch, channel_objects::SWITCH);
                enabled_switch_objects.push((ch, switch_idx));
            }
        }

        // Only channels 1 and 3 are enabled
        assert_eq!(enabled_switch_objects, vec![(1, 0), (3, 6)]);
    }

    #[test]
    fn test_comm_object_to_channel_mapping() {
        // This test shows how to build a reverse mapping from object index
        // to channel number, useful for handling incoming telegrams.

        // Build mapping table: object_index -> (channel, local_obj_name)
        let mut object_map: Vec<(usize, &'static str)> = Vec::new();
        const OBJ_NAMES: [&str; 3] = ["switch", "dim_value", "status"];

        for ch in 1..=NUM_CHANNELS {
            for (local_idx, name) in OBJ_NAMES.iter().enumerate() {
                let obj_idx = DeviceParams::channel_object_index(ch, local_idx);
                // Extend vector if needed
                while object_map.len() <= obj_idx {
                    object_map.push((0, ""));
                }
                object_map[obj_idx] = (ch, name);
            }
        }

        // Verify mapping
        assert_eq!(object_map[0], (1, "switch"));
        assert_eq!(object_map[1], (1, "dim_value"));
        assert_eq!(object_map[2], (1, "status"));
        assert_eq!(object_map[3], (2, "switch"));
        assert_eq!(object_map[7], (3, "dim_value"));
        assert_eq!(object_map[11], (4, "status"));
    }

    // ========================================================================
    // Runtime ComObjects Tests
    // ========================================================================
    //
    // These tests demonstrate using the actual `DimmerCommObjects` struct
    // with the `ComObjects` trait - the real runtime API.

    #[test]
    fn test_dimmer_comm_objects_creation() {
        use crate::module_test_device::comm_objs::DimmerCommObjects;
        use zweidraehte_device::objects::comm::ComObjects;

        // Create the comm objects instance (this is what you pass to the stack)
        let comm_objs = DimmerCommObjects::new();

        // Verify we can access individual objects through the channels array
        // (useful for direct field access when you know the channel at compile time)
        // DPT types use From<T> conversions: DPT_Switch -> bool, DPT_Scaling -> u8
        let switch_val: bool = comm_objs.channels[0].switch.value.into();
        assert!(!switch_val);

        // Access raw bytes via AsRef
        let dim_bytes: &[u8] = comm_objs.channels[1].dim_value.value.as_ref();
        assert_eq!(dim_bytes[0], 0);
    }

    #[test]
    fn test_dimmer_comm_objects_index_helpers() {
        use crate::module_test_device::comm_objs::DimmerCommObjects;

        // Use channel_object_index(instance, local_obj) where instance is 1-indexed
        // and local_obj is 0-indexed (0=switch, 1=dim_value, 2=status)
        assert_eq!(DimmerCommObjects::channel_object_index(1, 0), 0); // ch1 switch
        assert_eq!(DimmerCommObjects::channel_object_index(2, 0), 3); // ch2 switch
        assert_eq!(DimmerCommObjects::channel_object_index(3, 1), 7); // ch3 dim
        assert_eq!(DimmerCommObjects::channel_object_index(4, 2), 11); // ch4 status
    }

    #[test]
    fn test_dimmer_comm_objects_trait_access() {
        use crate::module_test_device::comm_objs::DimmerCommObjects;
        use zweidraehte_device::objects::comm::{ComObjectStatus, ComObjects};

        let mut comm_objs = DimmerCommObjects::new();

        // === Reading and writing via ComObjects trait ===
        // This is how the stack accesses objects by index (u16)

        // Get channel 2 switch index (1-indexed channel, 0=switch)
        let ch2_switch_idx = DimmerCommObjects::channel_object_index(2, 0) as u16;
        assert_eq!(ch2_switch_idx, 3);

        // Read current value via trait method
        let value_bytes = comm_objs.value(ch2_switch_idx).unwrap();
        assert_eq!(value_bytes, &[0]); // Default is off (0)

        // Write a new value via trait method
        comm_objs.value_mut(ch2_switch_idx).unwrap()[0] = 1; // Turn on

        // Verify write
        assert_eq!(comm_objs.value(ch2_switch_idx).unwrap(), &[1]);

        // === Status management ===
        // Objects track their status (idle, updated, write request, etc.)

        assert!(comm_objs.status(ch2_switch_idx).unwrap().is_idle());

        // Mark as remotely updated (this happens when stack receives GroupValueWrite)
        comm_objs.set_status(ch2_switch_idx, ComObjectStatus::Updated);
        assert_eq!(comm_objs.status(ch2_switch_idx), Some(ComObjectStatus::Updated));

        // Application acknowledges the update
        comm_objs.acknowledge_update(ch2_switch_idx);
        assert!(comm_objs.status(ch2_switch_idx).unwrap().is_idle());
    }

    #[test]
    fn test_dimmer_comm_objects_runtime_scenario() {
        //! Complete runtime scenario: handle incoming dimmer value update
        //!
        //! This test shows the full workflow for handling a communication object
        //! update from the KNX bus, including:
        //! 1. Receiving the update notification
        //! 2. Reading the new value
        //! 3. Applying business logic (brightness constraints)
        //! 4. Updating related objects (status)
        //! 5. Sending the status to the bus

        use crate::module_test_device::comm_objs::DimmerCommObjects;
        use zweidraehte_device::objects::comm::{ComObjectStatus, ComObjects};

        // Setup: comm objects and params
        let mut comm_objs = DimmerCommObjects::new();
        let params = DeviceParams {
            enable_ch1: ChannelEnable::Enabled,
            enable_ch2: ChannelEnable::Enabled,
            enable_ch3: ChannelEnable::Enabled,
            enable_ch4: ChannelEnable::Disabled,
            global_dim_speed: 50,
            channels: [
                DimmerChannelModuleParams {
                    icon_selection: IconSelection::Christmas,
                    min_brightness: 0,
                    max_brightness: 100,
                    dim_speed: 30,
                    power_on_level: 50,
                    ..Default::default()
                },
                DimmerChannelModuleParams {
                    icon_selection: IconSelection::Christmas,
                    min_brightness: 10,
                    max_brightness: 90,
                    dim_speed: 40,
                    power_on_level: 60,
                    ..Default::default()
                },
                DimmerChannelModuleParams {
                    icon_selection: IconSelection::Night,
                    min_brightness: 20,
                    max_brightness: 80,
                    dim_speed: 50,
                    power_on_level: 70,
                    ..Default::default()
                },
                DimmerChannelModuleParams {
                    icon_selection: IconSelection::Christmas,
                    min_brightness: 0,
                    max_brightness: 100,
                    dim_speed: 60,
                    power_on_level: 80,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        // === Simulate: Remote device sends GroupValueWrite to channel 3 dim object ===

        // The stack would call this when a GroupValueWrite arrives
        // channel_object_index(3, 1) = ch3 dim_value = 7
        let updated_obj_idx = DimmerCommObjects::channel_object_index(3, 1) as u16;
        let received_value: u8 = 15; // 15% brightness requested

        // Stack writes the value and marks it as updated
        comm_objs.value_mut(updated_obj_idx).unwrap()[0] = received_value;
        comm_objs.set_status(updated_obj_idx, ComObjectStatus::Updated);

        // === Application event loop would receive ComObjectEvent::Updated ===

        // Check which object was updated
        assert_eq!(updated_obj_idx, 7);
        assert_eq!(comm_objs.status(updated_obj_idx), Some(ComObjectStatus::Updated));

        // Determine channel (1-indexed) from object index
        let channel = updated_obj_idx as usize / 3 + 1;
        assert_eq!(channel, 3);

        // Determine local object type
        let local_obj = updated_obj_idx as usize % 3;
        assert_eq!(local_obj, channel_objects::DIM_VALUE);

        // Read the new value (raw byte - DPT_Scaling is 0-255 for 0-100%)
        let raw_value = comm_objs.value(updated_obj_idx).unwrap()[0];
        assert_eq!(raw_value, 15);

        // Acknowledge the update (clear the Updated status)
        comm_objs.acknowledge_update(updated_obj_idx);
        assert!(comm_objs.status(updated_obj_idx).unwrap().is_idle());

        // === Apply business logic: brightness constraints ===

        let ch_params = &params.channels[channel - 1]; // 0-indexed for array access
        let constrained = raw_value.max(ch_params.min_brightness).min(ch_params.max_brightness);
        assert_eq!(constrained, 20); // Clamped to min of 20%

        // Update the dim value with constrained value
        comm_objs.value_mut(updated_obj_idx).unwrap()[0] = constrained;

        // === Update the status object ===

        // channel_object_index(3, 2) = ch3 status
        let status_idx = DimmerCommObjects::channel_object_index(3, 2) as u16;
        let is_on = constrained > 0;
        comm_objs.value_mut(status_idx).unwrap()[0] = if is_on { 1 } else { 0 };

        // Mark status for transmission (WriteRequest tells stack to send GroupValueWrite)
        comm_objs.set_status(status_idx, ComObjectStatus::WriteRequest);

        // Verify final state
        assert_eq!(comm_objs.value(updated_obj_idx).unwrap(), &[20]); // Dim at 20%
        assert_eq!(comm_objs.value(status_idx).unwrap(), &[1]); // Status is ON
        assert_eq!(comm_objs.status(status_idx), Some(ComObjectStatus::WriteRequest));

        // The stack would now see WriteRequest and send GroupValueWrite for status
        // After transmission, it would call:
        // comm_objs.set_status(status_idx, ComObjectStatus::IdleOk);
    }

    #[test]
    fn test_dimmer_comm_objects_typed_index() {
        //! Using the Index struct for type-safe object access.

        use crate::module_test_device::comm_objs::{DimmerCommObjects, Index};
        use zweidraehte_device::objects::comm::{ComObjectIndex, ComObjects};

        let mut comm_objs = DimmerCommObjects::new();

        // For module-based structs, Index is a simple wrapper that validates ranges
        // Use Index::for_instance(instance, local_obj) for type-safe access
        // instance is 0-indexed, local_obj is 0-indexed
        let ch1_switch = Index::for_instance(0, 0).unwrap(); // channel 0, switch
        let ch2_dim = Index::for_instance(1, 1).unwrap(); // channel 1, dim_value
        let ch3_status = Index::for_instance(2, 2).unwrap(); // channel 2, status

        // Get the numeric index from the wrapper
        assert_eq!(ch1_switch.index(), 0); // 0*3 + 0 = 0
        assert_eq!(ch2_dim.index(), 4); // 1*3 + 1 = 4
        assert_eq!(ch3_status.index(), 8); // 2*3 + 2 = 8

        // Use with ComObjects trait methods
        comm_objs.value_mut(ch1_switch.index()).unwrap()[0] = 1;
        assert_eq!(comm_objs.value(ch1_switch.index()).unwrap(), &[1]);

        // For dynamic access (when channel is known at runtime), use channel_object_index:
        // Instance is 1-indexed (ETS convention), local_obj is 0-indexed
        let runtime_channel = 2;
        let switch_idx = DimmerCommObjects::channel_object_index(runtime_channel, 0) as u16;
        comm_objs.value_mut(switch_idx).unwrap()[0] = 1;
        assert_eq!(comm_objs.value(switch_idx).unwrap(), &[1]);
    }
}
