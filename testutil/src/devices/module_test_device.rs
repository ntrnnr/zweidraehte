//! Module Test Device Definition
//!
//! A simple 4-channel dimmer device that demonstrates KNX module usage.
//! Each channel is defined as a module instance with its own parameters
//! and communication objects.

use serde::{Deserialize, Serialize};

use zweidraehte::ets::EtsParams;

use knxprod::module::{
    KnxModule, ModuleArgDef, ModuleArgValue, ModuleCollection,
    ConditionalModuleInstance,
};
use knxprod::page_layout::{
    EtsPageLayout, PageStructure, PageElement, PageBlock, PageItem,
    ConditionalItem, ItemCase, Condition, ChannelDef,
};

// ============================================================================
// Device Descriptor
// ============================================================================

/// Device descriptor for 4-channel dimmer.
pub const DEVICE_DESCRIPTOR: zweidraehte::ets::DeviceDescriptor = zweidraehte::ets::DeviceDescriptor {
    mask_version: 0x57B0, // KNX/IP System B
    manufacturer_id: 0x00FA,
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x10],
    application_id: 0x1000,
    application_version: 0x01,
    max_address_table_entries: 32,
    max_association_table_entries: 32,
    max_com_objects: 16, // 4 channels * 3 objects each + some extras
};

/// Serial number for test device.
pub const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x10, 0x00, 0x00, 0x01];

// ============================================================================
// Global Device Parameters (non-module)
// ============================================================================

/// Global device parameters.
#[derive(Debug, Clone, Copy, EtsParams, Serialize, Deserialize)]
#[repr(C)]
pub struct GlobalParams {
    /// Enable channel 1 (0=disabled, 1=enabled)
    #[ets(display = "Enable channel 1")]
    pub enable_ch1: u8,

    /// Enable channel 2 (0=disabled, 1=enabled)
    #[ets(display = "Enable channel 2")]
    pub enable_ch2: u8,

    /// Enable channel 3 (0=disabled, 1=enabled)
    #[ets(display = "Enable channel 3")]
    pub enable_ch3: u8,

    /// Enable channel 4 (0=disabled, 1=enabled)
    #[ets(display = "Enable channel 4")]
    pub enable_ch4: u8,

    /// Global dimming speed (affects all channels)
    #[ets(display = "Global dimming speed", suffix = "ms")]
    pub global_dim_speed: u8,
}


// ============================================================================
// Dimmer Channel Module
// ============================================================================

/// Parameters for a single dimmer channel.
///
/// These parameters are defined within the module and are instantiated
/// for each channel with different memory offsets.
#[derive(Debug, Clone, Copy, EtsParams, Serialize, Deserialize)]
#[repr(C)]
pub struct DimmerChannelParams {
    /// Minimum brightness level (0-100%)
    #[ets(display = "Minimum brightness", suffix = "%")]
    pub min_brightness: u8,

    /// Maximum brightness level (0-100%)
    #[ets(display = "Maximum brightness", suffix = "%")]
    pub max_brightness: u8,

    /// Dimming speed for this channel (0-255, in 10ms steps)
    #[ets(display = "Dimming speed", suffix = "x10ms")]
    pub dim_speed: u8,

    /// Power-on brightness level
    #[ets(display = "Power-on level", suffix = "%")]
    pub power_on_level: u8,
}


/// Module definition for a dimmer channel.
///
/// This module encapsulates all the parameters and communication objects
/// for a single dimmer channel. It can be instantiated multiple times
/// with different argument values for multi-channel devices.
pub struct DimmerChannelModule;

impl KnxModule for DimmerChannelModule {
    const NAME: &'static str = "DimmerChannel";

    const ARGUMENTS: &'static [ModuleArgDef] = &[
        // Base offset for parameter memory (4 bytes per channel)
        ModuleArgDef::param_offset("ParamBase", 4),
        // Base number for communication objects (3 objects per channel)
        ModuleArgDef::object_number("ObjBase", 3),
        // Channel number for display text (e.g., "Ch{{ChNo}} Switch")
        ModuleArgDef::channel_number("ChNo"),
    ];

    type Params = DimmerChannelParams;
    type Objects = (); // Simplified - no comm objects for this test

    const INTERNAL_DESCRIPTION: Option<&'static str> = Some("Dimmer channel module");
}

// ============================================================================
// Device Definition
// ============================================================================

/// The complete 4-channel dimmer device.
pub struct ModuleTestDevice;

impl ModuleTestDevice {
    /// Get the global parameter defaults.
    pub fn global_param_defaults() -> GlobalParams {
        GlobalParams::default()
    }

    /// Create the module collection with 4 channel instances.
    pub fn create_modules() -> ModuleCollection {
        let mut modules = ModuleCollection::new();

        // Create 4 channel instances with conditional visibility
        let instances: Vec<ConditionalModuleInstance<DimmerChannelModule>> = (1..=4i64)
            .map(|ch| {
                let instance = DimmerChannelModule::instance(&[
                    // ParamBase: global params (5 bytes) + (ch-1) * 4 bytes per channel
                    ModuleArgValue::numeric(5 + (ch - 1) * 4),
                    // ObjBase: (ch-1) * 3 objects per channel
                    ModuleArgValue::numeric((ch - 1) * 3),
                    // ChNo: channel number (1-based)
                    ModuleArgValue::numeric(ch),
                ]);

                // Each channel is visible when its enable flag is 1
                let selector = match ch {
                    1 => "enable_ch1",
                    2 => "enable_ch2",
                    3 => "enable_ch3",
                    4 => "enable_ch4",
                    _ => unreachable!(),
                };

                ConditionalModuleInstance::new(instance, selector, 1)
            })
            .collect();

        modules.add_conditional_instances(instances);
        modules
    }

    /// Calculate the total parameter size.
    pub fn param_size() -> usize {
        // Global params (5 bytes) + 4 channels * 4 bytes each
        core::mem::size_of::<GlobalParams>() + 4 * core::mem::size_of::<DimmerChannelParams>()
    }
}

impl EtsPageLayout for ModuleTestDevice {
    fn page_layout() -> PageStructure {
        PageStructure {
            device_settings: vec![
                PageElement::Block(PageBlock {
                    name: "general",
                    text: "General Settings",
                    items: vec![
                        PageItem::Param("global_dim_speed"),
                    ],
                }),
                PageElement::Block(PageBlock {
                    name: "channel_enable",
                    text: "Channel Selection",
                    items: vec![
                        PageItem::Param("enable_ch1"),
                        PageItem::Param("enable_ch2"),
                        PageItem::Param("enable_ch3"),
                        PageItem::Param("enable_ch4"),
                    ],
                }),
            ],
            channels: vec![
                ChannelDef {
                    name: "channels",
                    text: "Dimmer Channels",
                    number: None,
                    elements: vec![
                        PageElement::Block(PageBlock {
                            name: "channel_modules",
                            text: "Channel Configuration",
                            items: vec![
                                // Module instances with conditional visibility
                                PageItem::When(ConditionalItem {
                                    selector: "enable_ch1",
                                    cases: vec![ItemCase {
                                        condition: Condition::Values(vec![1]),
                                        items: vec![PageItem::Module {
                                            module_name: "DimmerChannel",
                                            instance_index: 0,
                                        }],
                                    }],
                                }),
                                PageItem::When(ConditionalItem {
                                    selector: "enable_ch2",
                                    cases: vec![ItemCase {
                                        condition: Condition::Values(vec![1]),
                                        items: vec![PageItem::Module {
                                            module_name: "DimmerChannel",
                                            instance_index: 1,
                                        }],
                                    }],
                                }),
                                PageItem::When(ConditionalItem {
                                    selector: "enable_ch3",
                                    cases: vec![ItemCase {
                                        condition: Condition::Values(vec![1]),
                                        items: vec![PageItem::Module {
                                            module_name: "DimmerChannel",
                                            instance_index: 2,
                                        }],
                                    }],
                                }),
                                PageItem::When(ConditionalItem {
                                    selector: "enable_ch4",
                                    cases: vec![ItemCase {
                                        condition: Condition::Values(vec![1]),
                                        items: vec![PageItem::Module {
                                            module_name: "DimmerChannel",
                                            instance_index: 3,
                                        }],
                                    }],
                                }),
                            ],
                        }),
                    ],
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_collection_creation() {
        let modules = ModuleTestDevice::create_modules();
        assert_eq!(modules.definition_count(), 1);
        assert_eq!(modules.instance_count(), 4);
    }

    #[test]
    fn test_page_layout() {
        let layout = ModuleTestDevice::page_layout();
        assert_eq!(layout.device_settings.len(), 2);
        assert_eq!(layout.channels.len(), 1);
    }

    #[test]
    fn test_param_size() {
        // Global: 5 bytes, Channels: 4 * 4 = 16 bytes, Total: 21 bytes
        assert_eq!(ModuleTestDevice::param_size(), 21);
    }
}
