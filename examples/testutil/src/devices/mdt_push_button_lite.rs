//! MDT Push Button Lite 55 1-fold Basic Device Definition
//!
//! This module is an EXACT replica of the MDT KP_BE_01 Push Button Lite 55 1-fold Basic
//! device (M-0083_A-009B-14-E59D) from the reference MTXML file.
//!
//! Features:
//! - 2 Push buttons (top/bottom) with multiple function modes
//! - Slap/Cleaning function
//! - 4-channel Logic unit
//! - 87 Communication objects

use core::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use zweidraehte_device::bcus::system_b::{
    DefaultSystemBInterfaceObjects, IpExtensionState, IpSystemBDeviceState, SystemBIpDeviceDef,
    SystemBMemoryMap, create_system_b_objects,
};
use zweidraehte_device::dpt::*;
use zweidraehte_device::ets::ets_range_enum;
use zweidraehte_device::layers::linklayers::knxip::{KnxNetIpBuilder, features::KnxIpDeviceUdp};
use zweidraehte_device::layers::transport::TlStyle;
use zweidraehte_device::prelude::*;
use zweidraehte_knxprod::definition::page_layout::{EtsPageLayout, PageStructure};
use zweidraehte_knxprod::ets_pages;

// ============================================================================
// Device Descriptor
// ============================================================================

/// Device descriptor - matches MDT Push Button Lite 55 1-fold Basic.
/// ApplicationNumber: 155 (0x009B)
/// ApplicationVersion: 20 (0x14)
/// MaskVersion: MV-0705 (System B TP BCU)
pub const DEVICE_DESCRIPTOR: DeviceDescriptor = DeviceDescriptor {
    mask_version: MaskVersion::System7Tp1, // MV-0705
    manufacturer_id: 0x0083,               // MDT
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    application_id: 0x009B,    // ApplicationNumber: 155
    application_version: 0x14, // ApplicationVersion: 20
    max_address_table_entries: 255,
    max_association_table_entries: 255,
    max_com_objects: 88, // 87 objects + 1 for header
    pei_type: 0,
};

/// Serial number for test device.
/// This matches the MDT reference InlineData: 00000000013900000000
/// The value 0x0139 (313) is MDT's device type identifier for this product.
pub const SERIAL_NUMBER: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x39];

/// Network interface name for KNX/IP communication.
pub const INTERFACE_NAME: &str = "knxdevbridgeif";

// ============================================================================
// Parameter Types (EtsEnum)
// ============================================================================

/// GEboolEnableDisable - 1-bit enable/disable toggle
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum GEboolEnableDisable {
    #[default]
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "active")]
    Active = 1,
}

/// ObjectType enum for send values mode - matches MDT's DPTType1Bit values
/// Used as selector_param values for ComObjectRefs in send values mode
/// Note: Switch is at value 10 (not 0) to match MDT's DPTType1Bit
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
#[ets(type_name = "ObjectType")]
pub enum ObjectType {
    /// 2Bit DPT 2.001 Forcible control
    #[ets(display = "2Bit DPT 2.001 Forcible control")]
    Bit2 = 1,
    /// 1Byte DPT 5.001 Percent (0...100%)
    #[ets(display = "1Byte DPT 5.001 Percent (0...100%)")]
    Percent = 2,
    /// 1Byte DPT 5.005 Decimal factor (0...255)
    #[ets(display = "1Byte DPT 5.005 Decimal factor (0...255)")]
    Decimal = 3,
    /// 1Byte DPT 17.001 Scene number
    #[ets(display = "1Byte DPT 17.001 Scene number")]
    Scene = 4,
    /// 2Byte DPT 7.600 Colour Temperature (Kelvin)
    #[ets(display = "2Byte DPT 7.600 Colour Temperature (Kelvin)")]
    ColourTemp = 6,
    /// 2Byte DPT 9.001 Temperature (°C)
    #[ets(display = "2Byte DPT 9.001 Temperature (°C)")]
    Temperature = 7,
    /// 2Byte DPT 9.004 Brightness (Lux)
    #[ets(display = "2Byte DPT 9.004 Brightness (Lux)")]
    Brightness = 8,
    /// 3Byte DPT 232.600 RGB value 3x(0...255)
    #[ets(display = "3Byte DPT 232.600 RGB value 3x(0...255)")]
    Rgb = 9,
    /// 1Bit DPT 1.001 Switch - value 10 to match MDT
    #[default]
    #[ets(display = "1Bit DPT 1.001 Switch")]
    Switch = 10,
}

/// DptType enum for cases where Switch (10) is not an option
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum DptType {
    /// 2Bit DPT 2.001 Forcible control
    #[ets(display = "2Bit DPT 2.001 Forcible control")]
    Bit2 = 1,
    /// 1Byte DPT 5.001 Percent (0...100%)
    #[default]
    #[ets(display = "1Byte DPT 5.001 Percent (0...100%)")]
    Percent = 2,
    /// 1Byte DPT 5.005 Decimal factor (0...255)
    #[ets(display = "1Byte DPT 5.005 Decimal factor (0...255)")]
    Decimal = 3,
    /// 1Byte DPT 17.001 Scene number
    #[ets(display = "1Byte DPT 17.001 Scene number")]
    Scene = 4,
    /// 2Byte DPT 7.600 Colour Temperature (Kelvin)
    #[ets(display = "2Byte DPT 7.600 Colour Temperature (Kelvin)")]
    ColourTemp = 6,
    /// 2Byte DPT 9.001 Temperature (°C)
    #[ets(display = "2Byte DPT 9.001 Temperature (°C)")]
    Temperature = 7,
    /// 2Byte DPT 9.004 Brightness (Lux)
    #[ets(display = "2Byte DPT 9.004 Brightness (Lux)")]
    Brightness = 8,
    /// 3Byte DPT 232.600 RGB value 3x(0...255)
    #[ets(display = "3Byte DPT 232.600 RGB value 3x(0...255)")]
    Rgb = 9,
}

/// Zwangsfuehrung - Priority/Forcible control
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum Zwangsfuehrung {
    #[default]
    #[ets(display = "00 - no priority, OFF")]
    NoPriorityOff = 0,
    #[ets(display = "01 - no priority, ON")]
    NoPriorityOn = 1,
    #[ets(display = "10 - priority, OFF")]
    PriorityOff = 2,
    #[ets(display = "11 - priority, ON")]
    PriorityOn = 3,
}

/// LogicObjectType - Logic output object type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum LogicObjectType {
    #[default]
    #[ets(display = "switch")]
    Switch = 1,
    #[ets(display = "scene")]
    Scene = 2,
    #[ets(display = "value")]
    Value = 3,
    #[ets(display = "forcible control 2Bit")]
    ForcibleControl = 4,
}

/// ExtInputLogicType - External logic input configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ExtInputLogicType {
    #[default]
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "normally active, with preallocation 0")]
    NormallyActivePrealloc0 = 1,
    #[ets(display = "inverted active, with preallocation 0")]
    InvertedActivePrealloc0 = 2,
    #[ets(display = "normally active, with preallocation 1")]
    NormallyActivePrealloc1 = 129,
    #[ets(display = "inverted active, with preallocation 1")]
    InvertedActivePrealloc1 = 130,
}

/// LogicButton - Button selection for logic inputs
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum LogicButton {
    #[default]
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "button 1")]
    Button1 = 1,
    #[ets(display = "button 2")]
    Button2 = 2,
}

// SceneValue - Scene number selection (1-64)
// Display shows 1-64, stored as 0-63 (DPT 17.001 format)
ets_range_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[ets(type_name = "SceneValue")]
    pub enum SceneValue {
        range 0..64 => "Scene{}";
        default = 0;
    }
}

// Select0to100Percent - Percentage selection (0-100%)
// Maps percentage display to byte values using formula: round(percent * 2.55)
ets_range_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[ets(type_name = "select0to100percent")]
    pub enum Select0to100Percent {
        range 0..=100 => percent_to_byte "P{}%";
        default = 0;
    }
}

/// GEDPT_Switch - Basic ON/OFF switch value
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[ets(type_name = "GEDPT_Switch")]
#[repr(u8)]
pub enum GedptSwitch {
    #[default]
    #[ets(display = "OFF")]
    Off = 0,
    #[ets(display = "ON")]
    On = 1,
}

/// ColourControl - RGB/HSV colour mode selector
/// Used for colour control parameters (12 occurrences)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ColourControl {
    #[default]
    #[ets(display = "RGB")]
    Rgb = 1,
    #[ets(display = "HSV")]
    Hsv = 2,
}

/// PressedOnOff - Which value is sent when pressed
/// Used for switch function configuration (8 occurrences)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum PressedOnOff {
    #[default]
    #[ets(display = "pressed = ON")]
    PressedOn = 1,
    #[ets(display = "pressed = OFF")]
    PressedOff = 2,
}

/// YesNo - Simple yes/no toggle
/// Used for various confirmation parameters (4 occurrences)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum YesNo {
    #[default]
    #[ets(display = "no")]
    No = 0,
    #[ets(display = "yes")]
    Yes = 1,
}

/// TipOperationCount - Number of tip operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum TipOperationCount {
    #[default]
    #[ets(display = "2")]
    Two = 1,
    #[ets(display = "3")]
    Three = 2,
}

/// ValueCount - Number of values/scenes
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ValueCount {
    #[default]
    #[ets(display = "2")]
    Two = 1,
    #[ets(display = "3")]
    Three = 2,
    #[ets(display = "4")]
    Four = 3,
}

/// TimeForLongKeypress - Time duration for long keypress detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum TimeForLongKeypress {
    #[ets(display = "basic setting")]
    BasicSetting = 0,
    #[ets(display = "0,1 s")]
    Ms100 = 32868,
    #[ets(display = "0,2 s")]
    Ms200 = 32968,
    #[ets(display = "0,3 s")]
    Ms300 = 33068,
    #[default]
    #[ets(display = "0,4 s")]
    Ms400 = 33168,
    #[ets(display = "0,5 s")]
    Ms500 = 33268,
    #[ets(display = "0,6 s")]
    Ms600 = 33368,
    #[ets(display = "0,7 s")]
    Ms700 = 33468,
    #[ets(display = "0,8 s")]
    Ms800 = 33568,
    #[ets(display = "0,9 s")]
    Ms900 = 33668,
    #[ets(display = "1,0 s")]
    S1 = 33768,
    #[ets(display = "1,5 s")]
    S1_5 = 34268,
    #[ets(display = "2,0 s")]
    S2 = 34768,
    #[ets(display = "2,5 s")]
    S2_5 = 35268,
    #[ets(display = "3,0 s")]
    S3 = 35768,
    #[ets(display = "3,5 s")]
    S3_5 = 36268,
    #[ets(display = "4,0 s")]
    S4 = 36768,
    #[ets(display = "4,5 s")]
    S4_5 = 37268,
    #[ets(display = "5,5 s")]
    S5_5 = 38268,
    #[ets(display = "6,5 s")]
    S6_5 = 39268,
    #[ets(display = "7,5 s")]
    S7_5 = 40268,
    #[ets(display = "8,5 s")]
    S8_5 = 41268,
    #[ets(display = "9,5 s")]
    S9_5 = 42268,
    #[ets(display = "12,0 s")]
    S12 = 12,
    #[ets(display = "15,0 s")]
    S15 = 15,
    #[ets(display = "20,0 s")]
    S20 = 20,
    #[ets(display = "25,0 s")]
    S25 = 25,
    #[ets(display = "30,0 s")]
    S30 = 30,
}

/// DelayTime1sTo60min - Delay time from 1 second to 60 minutes
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum DelayTime1sTo60min {
    #[default]
    #[ets(display = "1 s")]
    S1 = 1,
    #[ets(display = "2 s")]
    S2 = 2,
    #[ets(display = "3 s")]
    S3 = 3,
    #[ets(display = "4 s")]
    S4 = 4,
    #[ets(display = "5 s")]
    S5 = 5,
    #[ets(display = "10 s")]
    S10 = 10,
    #[ets(display = "15 s")]
    S15 = 15,
    #[ets(display = "20 s")]
    S20 = 20,
    #[ets(display = "25 s")]
    S25 = 25,
    #[ets(display = "30 s")]
    S30 = 30,
    #[ets(display = "35 s")]
    S35 = 35,
    #[ets(display = "40 s")]
    S40 = 40,
    #[ets(display = "45 s")]
    S45 = 45,
    #[ets(display = "60 s")]
    S60 = 60,
    #[ets(display = "2 min")]
    Min2 = 120,
    #[ets(display = "3 min")]
    Min3 = 180,
    #[ets(display = "4 min")]
    Min4 = 240,
    #[ets(display = "5 min")]
    Min5 = 300,
    #[ets(display = "6 min")]
    Min6 = 360,
    #[ets(display = "7 min")]
    Min7 = 420,
    #[ets(display = "8 min")]
    Min8 = 480,
    #[ets(display = "9 min")]
    Min9 = 540,
    #[ets(display = "10 min")]
    Min10 = 600,
    #[ets(display = "15 min")]
    Min15 = 900,
    #[ets(display = "20 min")]
    Min20 = 1200,
    #[ets(display = "25 min")]
    Min25 = 1500,
    #[ets(display = "30 min")]
    Min30 = 1800,
    #[ets(display = "35 min")]
    Min35 = 2100,
    #[ets(display = "40 min")]
    Min40 = 2400,
    #[ets(display = "45 min")]
    Min45 = 2700,
    #[ets(display = "60 min")]
    Min60 = 3600,
}

/// SceneToggleDelayTime - Delay time for scene toggling (0-10 seconds)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum SceneToggleDelayTime {
    #[default]
    #[ets(display = "0 s")]
    S0 = 0,
    #[ets(display = "0,5 s")]
    Ms500 = 5,
    #[ets(display = "1 s")]
    S1 = 10,
    #[ets(display = "2 s")]
    S2 = 20,
    #[ets(display = "3 s")]
    S3 = 30,
    #[ets(display = "4 s")]
    S4 = 40,
    #[ets(display = "5 s")]
    S5 = 50,
    #[ets(display = "6 s")]
    S6 = 60,
    #[ets(display = "7 s")]
    S7 = 70,
    #[ets(display = "8 s")]
    S8 = 80,
    #[ets(display = "9 s")]
    S9 = 90,
    #[ets(display = "10 s")]
    S10 = 100,
}

/// ExtraLongKeypressTime - Time for extra long keypress (no basic setting option)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum ExtraLongKeypressTime {
    #[ets(display = "0,1 s")]
    Ms100 = 32868,
    #[ets(display = "0,2 s")]
    Ms200 = 32968,
    #[ets(display = "0,3 s")]
    Ms300 = 33068,
    #[ets(display = "0,4 s")]
    Ms400 = 33168,
    #[ets(display = "0,5 s")]
    Ms500 = 33268,
    #[ets(display = "0,6 s")]
    Ms600 = 33368,
    #[ets(display = "0,7 s")]
    Ms700 = 33468,
    #[ets(display = "0,8 s")]
    Ms800 = 33568,
    #[ets(display = "0,9 s")]
    Ms900 = 33668,
    #[ets(display = "1,0 s")]
    S1 = 33768,
    #[ets(display = "1,5 s")]
    S1_5 = 34268,
    #[default]
    #[ets(display = "2,0 s")]
    S2 = 34768,
    #[ets(display = "2,5 s")]
    S2_5 = 35268,
    #[ets(display = "3,0 s")]
    S3 = 35768,
    #[ets(display = "3,5 s")]
    S3_5 = 36268,
    #[ets(display = "4,0 s")]
    S4 = 36768,
    #[ets(display = "4,5 s")]
    S4_5 = 37268,
    #[ets(display = "5,5 s")]
    S5_5 = 38268,
    #[ets(display = "6,5 s")]
    S6_5 = 39268,
    #[ets(display = "7,5 s")]
    S7_5 = 40268,
    #[ets(display = "8,5 s")]
    S8_5 = 41268,
    #[ets(display = "9,5 s")]
    S9_5 = 42268,
    #[ets(display = "12,0 s")]
    S12 = 12,
    #[ets(display = "15,0 s")]
    S15 = 15,
    #[ets(display = "20,0 s")]
    S20 = 20,
    #[ets(display = "25,0 s")]
    S25 = 25,
    #[ets(display = "30,0 s")]
    S30 = 30,
}

/// SendingCondition - When to send logic output
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum SendingCondition {
    #[ets(display = "not automatic")]
    NotAutomatic = 0,
    #[ets(display = "at input telegram")]
    AtInputTelegram = 1,
    #[default]
    #[ets(display = "at change output")]
    AtChangeOutput = 2,
    #[ets(display = "at change output (send only 0)")]
    AtChangeOutputSendOnly0 = 5,
    #[ets(display = "at change output (send only 1)")]
    AtChangeOutputSendOnly1 = 6,
}

/// NoYes - No/Yes toggle (different from YesNo)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum NoYes {
    #[default]
    #[ets(display = "No")]
    No = 0,
    #[ets(display = "Yes")]
    Yes = 1,
}

/// ForcibleControlValue - 2-bit forcible control value (used in unions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ForcibleControlValue {
    #[default]
    #[ets(display = "00 - no priority, OFF")]
    NoPriorityOff = 0,
    #[ets(display = "01 - no priority, ON")]
    NoPriorityOn = 1,
    #[ets(display = "10 - priority, OFF")]
    PriorityOff = 2,
    #[ets(display = "11 - priority, ON")]
    PriorityOn = 3,
}

/// ReactionTime - Reaction time on keypress
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ReactionTime {
    #[default]
    #[ets(display = "fast")]
    Fast = 80,
    #[ets(display = "medium")]
    Medium = 100,
    #[ets(display = "slow")]
    Slow = 150,
}

/// CyclicSendInterval - Cyclic sending interval
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum CyclicSendInterval {
    #[default]
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "1 min")]
    Min1 = 1,
    #[ets(display = "2 min")]
    Min2 = 2,
    #[ets(display = "5 min")]
    Min5 = 5,
    #[ets(display = "10 min")]
    Min10 = 10,
    #[ets(display = "20 min")]
    Min20 = 20,
    #[ets(display = "30 min")]
    Min30 = 30,
    #[ets(display = "1 h")]
    Hour1 = 60,
    #[ets(display = "2 h")]
    Hour2 = 120,
    #[ets(display = "4 h")]
    Hour4 = 240,
}

/// RequestNoRequest - Request/No request toggle
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum RequestNoRequest {
    #[ets(display = "no request")]
    NoRequest = 0,
    #[default]
    #[ets(display = "request")]
    Request = 1,
}

/// ButtonsType - Button 1/2 function type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ButtonsType {
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "two-button function")]
    TwoButton = 1,
    #[default]
    #[ets(display = "single-button function (2 functions, top/bottom)")]
    SingleButton2Functions = 2,
    #[ets(display = "single-button function (1 function, top/bottom together)")]
    SingleButton1Function = 3,
}

/// ButtonFunction - Main button function mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum ButtonFunction {
    #[ets(display = "not active")]
    NotActive = 255,
    #[default]
    #[ets(display = "switch")]
    Switch = 0,
    #[ets(display = "dimming")]
    Dimming = 1,
    #[ets(display = "blinds/shutter")]
    BlindsShutter = 2,
    #[ets(display = "scene")]
    Scene = 3,
    #[ets(display = "send values")]
    SendValues = 4,
    #[ets(display = "switch/send values short/long (with 2 objects)")]
    SwitchSendValuesShortLong = 7,
}

/// SwitchSubfunction - Switch subfunction type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum SwitchSubfunction {
    #[ets(display = "switch")]
    Switch = 0,
    #[default]
    #[ets(display = "toggle")]
    Toggle = 1,
    #[ets(display = "send status")]
    SendStatus = 2,
}

/// LogicType - Logic channel type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum LogicType {
    #[ets(display = "not active")]
    #[default]
    NotActive = 255,
    #[ets(display = "Or")]
    Or = 0,
    #[ets(display = "And")]
    And = 1,
    #[ets(display = "send value when button is pressed")]
    SendValueWhenPressed = 2,
}

/// SlapObjectType - Slap button object type selector
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum SlapObjectType {
    #[default]
    #[ets(display = "1Bit")]
    Bit1 = 0,
    #[ets(display = "2Bit")]
    Bit2 = 1,
    #[ets(display = "1Byte Char")]
    Byte1Char = 2,
    #[ets(display = "1Byte SignedChar")]
    Byte1SignedChar = 3,
    #[ets(display = "2Byte KNX_Float")]
    Byte2KnxFloat = 4,
    #[ets(display = "2Byte Short")]
    Byte2Short = 5,
    #[ets(display = "3Byte RGB")]
    Byte3Rgb = 6,
    #[ets(display = "3Byte HSV")]
    Byte3Hsv = 7,
    #[ets(display = "4Byte SignedLong")]
    Byte4SignedLong = 8,
    #[ets(display = "4Byte Long Float")]
    Byte4LongFloat = 9,
    #[ets(display = "1Byte Scene")]
    Byte1Scene = 10,
}

/// LogicOutputType - Logic output object type selector
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum LogicOutputType {
    #[default]
    #[ets(display = "switch")]
    Switch = 1,
    #[ets(display = "scene")]
    Scene = 2,
    #[ets(display = "value")]
    Value = 3,
    #[ets(display = "forcible control 2Bit")]
    ForcibleControl = 4,
}

/// ButtonValueFunction - Button value function mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ButtonValueFunction {
    #[default]
    #[ets(display = "send values")]
    SendValues = 0,
    #[ets(display = "send values by state")]
    SendValuesByState = 1,
    #[ets(display = "toggle values/scenes (up to 4 values)")]
    ToggleValues = 2,
    #[ets(display = "Multi-tip function (send values after number of operations)")]
    MultiTip = 3,
}

/// SpecialFunction - Button special function selector
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum SpecialFunction {
    #[default]
    #[ets(display = "Innovative group control")]
    InnovativeGroupControl = 0,
    #[ets(display = "Additional object")]
    AdditionalObject = 1,
}

/// BlindsOperationFunction - Operation function for blinds
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum BlindsOperationFunction {
    #[default]
    #[ets(display = "long=move / short=stop/slats Open/Close")]
    LongMoveShortStop = 0,
    #[ets(display = "short=move / long=stop/slats Open/Close")]
    ShortMoveLongStop = 1,
}

/// TipOutputObjects - Tip output objects mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum TipOutputObjects {
    #[default]
    #[ets(display = "common object /DPT")]
    CommonObject = 0,
    #[ets(display = "different objects / DPT")]
    DifferentObjects = 1,
}

/// SlapCleaningMode - Slap cleaning function mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum SlapCleaningMode {
    #[default]
    #[ets(display = "cleaning not active, slap active")]
    CleaningNotActive = 0,
    #[ets(display = "cleaning = long button, slap = short button")]
    CleaningLongSlapShort = 1,
    #[ets(display = "cleaning = short button, slap = long button")]
    CleaningShortSlapLong = 2,
}

/// TwoButtonValueFunction - Two-button value function mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum TwoButtonValueFunction {
    #[default]
    #[ets(display = "send values")]
    SendValues = 1,
    #[ets(display = "toggle values/scenes (up to 4 values)")]
    ToggleValues = 2,
    #[ets(display = "shift value")]
    ShiftValue = 3,
}

/// GroupSendOption - Group send option for two-button mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum GroupSendOption {
    #[default]
    #[ets(display = "value for upper and lower button")]
    UpperAndLower = 0,
    #[ets(display = "value for upper button")]
    UpperButton = 1,
    #[ets(display = "value for lower button")]
    LowerButton = 2,
}

/// LongAction - Action for long keypress
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum LongAction {
    #[default]
    #[ets(display = "switch OFF")]
    SwitchOff = 0,
    #[ets(display = "switch ON")]
    SwitchOn = 1,
    #[ets(display = "toggle")]
    Toggle = 2,
    #[ets(display = "send values")]
    SendValues = 3,
    #[ets(display = "not active")]
    NotActive = 255,
}

/// ShortAction - Action for short keypress in SwitchSendValuesShortLong mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ShortAction {
    #[default]
    #[ets(display = "switch OFF")]
    SwitchOff = 0,
    #[ets(display = "switch ON")]
    SwitchOn = 1,
    #[ets(display = "toggle")]
    Toggle = 2,
    #[ets(display = "send values")]
    SendValues = 3,
    #[ets(display = "not active")]
    NotActive = 255,
}

/// TwoButtonFunction - Two-button function selector
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum TwoButtonFunction {
    #[default]
    #[ets(display = "switch")]
    Switch = 0,
    #[ets(display = "dimming")]
    Dimming = 1,
    #[ets(display = "blinds/shutter")]
    BlindsShutter = 2,
    #[ets(display = "send values")]
    SendValues = 3,
    #[ets(display = "switch/send values short/long (with 2 objects)")]
    SwitchSendValues = 5,
}

/// ButtonAssignment - Button assignment for two-button mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum ButtonAssignment {
    #[default]
    #[ets(display = "ON/OFF")]
    OnOff = 0,
    #[ets(display = "OFF/ON")]
    OffOn = 1,
}

// ============================================================================
// EtsUnion Types - Union Parameters sharing memory locations
// ============================================================================

/// SubTypeH Union (8-bit) - Number of tip-operations or values
/// Used for multi-tip and toggle value modes
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum SubTypeHUnion {
    /// Number of tip-operations for Multi-tip mode (2 or 3 operations)
    /// MDT: TipValueCount enum - Value=1 means "2 operations", Value=2 means "3 operations"
    #[ets(default_variant, display = "Tip operations")]
    TipOperations {
        #[ets(display = "Number of tip-operations", ets_enum)]
        count: TipOperationCount,
    } = 0,

    /// Number of values for toggle values/scenes mode (2, 3, or 4 values)
    /// MDT: ValueCount enum - Value=1 means "2 values", Value=2 means "3 values", Value=3 means "4 values"
    #[ets(display = "Value count")]
    ValueCount {
        #[ets(display = "Number of values", ets_enum)]
        count: ValueCount,
    } = 1,
}

/// Button Value Union (32-bit) - Various value types for button output
/// This union allows the same memory to be interpreted as different value types
/// Discriminant values MUST match ObjectType enum for choose/when to work correctly!
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum ButtonValueUnion {
    /// Switch value (ON/OFF) - matches ObjectType::Switch = 0 (button_object_type "1Bit")
    #[ets(default_variant, display = "Switch")]
    Switch {
        #[ets(display = "Value", ets_enum)]
        value: GedptSwitch,
    } = 0,

    /// Forcible control (2-bit priority) - matches ObjectType::Bit2 = 1 (button_object_type "2Bit")
    #[ets(display = "Forcible control")]
    ForcibleControl {
        #[ets(display = "Value", ets_enum)]
        value: Zwangsfuehrung,
    } = 1,

    /// Percent value (0-100%) - matches ObjectType::Percent = 2 (button_object_type "1Byte Char")
    /// Default value is 64 (25%) for button1_value_00 "Value tip once"
    #[ets(display = "Percent")]
    Percent {
        #[ets(display = "Value", ets_enum, default = 64)]
        value: Select0to100Percent,
    } = 2,

    /// Decimal factor (0-255) - matches ObjectType::Decimal = 3 (button_object_type "1Byte SignedChar")
    /// Default value is 60 for "Value tip once"
    #[ets(display = "Decimal")]
    Decimal {
        #[ets(display = "Value", default = 60)]
        value: u8,
    } = 3,

    /// Scene number (1-64) - matches ObjectType::Scene = 4 (button_object_type "2Byte KNX_Float")
    #[ets(display = "Scene")]
    Scene {
        #[ets(display = "Scene number", ets_enum)]
        value: SceneValue,
    } = 4,

    /// Colour Temperature (2Byte) - matches ObjectType = 6 (DPT 7.600)
    #[ets(display = "Colour Temperature")]
    ColourTemp {
        #[ets(display = "Value", suffix = "Kelvin", default = 2700)]
        value: u16,
    } = 6,

    /// Temperature °C (2Byte Float) - matches ObjectType = 7 (DPT 9.001)
    /// Note: Default is 15°C (encoded as DPT 9 float value)
    #[ets(display = "Temperature")]
    Temperature {
        #[ets(display = "Value", suffix = "°C", default = 0)]
        value: u16,
    } = 7,

    /// Brightness Lux (2Byte Float) - matches ObjectType = 8 (DPT 9.004)
    /// Note: Default is 1000 Lux (encoded as DPT 9 float value)
    #[ets(display = "Brightness")]
    Brightness {
        #[ets(display = "Value", suffix = "Lux", default = 0)]
        value: u16,
    } = 8,

    /// RGB colour value (3 bytes) - matches ObjectType = 9 (DPT 232.600)
    /// ETS displays this as a single color picker with "#RRGGBB" format
    #[ets(display = "RGB")]
    Rgb {
        #[ets(display = "    RGB-Value", text_pattern = "^#[0-9a-fA-F]{6}$(?# TypeColor:RGB)")]
        value: [u8; 3],
    } = 9,

    /// Switch (1Bit) - matches ObjectType = 10 (DPT 1.001) - only in DPTType1Bit
    /// Note: This is value 10 in the enum because MDT uses 10 for Switch in DPTType1Bit
    #[ets(display = "Switch 1Bit")]
    Switch1Bit {
        #[ets(display = "Value", ets_enum)]
        value: GedptSwitch,
    } = 10,

    /// HSV colour value (3 bytes) - ObjectType sub-selection via ModeRGB/HSV param
    /// ETS displays this as a single color picker with "#HHSSVV" format
    /// Note: HSV is NOT a direct ObjectType value - it's selected via P-36 ModeRGB/HSV
    #[ets(display = "HSV")]
    Hsv {
        #[ets(display = "    HSV value", text_pattern = "^#[0-9a-fA-F]{6}$(?# TypeColor:HSV)")]
        value: [u8; 3],
    } = 11,

    /// Size anchor variant - ensures the data area is 4 bytes (largest real data is [u8; 3]).
    /// Never constructed in normal use.
    #[ets(skip)]
    _Reserved([u8; 4]),
}

/// Time Duration Union (16-bit) - Various time values
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum TimeDurationUnion {
    /// Time for long keypress (with "basic setting" option) - TimeforLongSwitchGroup0-30s
    #[ets(default_variant, display = "Long keypress time")]
    LongKeypressTime {
        #[ets(display = "Time for long keypress", ets_enum)]
        value: TimeForLongKeypress,
    } = 0,

    /// Delay time (1s to 60min) - DelayTime1s-60min
    #[ets(display = "Delay time")]
    DelayTime {
        #[ets(display = "Time delay", ets_enum, default = 1)]
        delay_time: DelayTime1sTo60min,
    } = 1,

    /// Scene toggle delay (0-10s) - DelayTime0-10s
    #[ets(display = "Scene toggle delay")]
    SceneToggleDelay {
        #[ets(display = "Time delay between scene toggling", ets_enum)]
        value: SceneToggleDelayTime,
    } = 2,

    /// Repeat time for switch
    #[ets(display = "Repeat time")]
    RepeatTime {
        #[ets(display = "Repetition time")]
        value: u16,
    } = 3,

    /// Raw value (hidden/internal)
    #[ets(display = "Raw")]
    Raw {
        #[ets(skip)]
        value: u16,
    } = 4,

    /// Time for extra long keypress (NO "basic setting" option) - TimeforLongSwitch0,1-30s
    #[ets(display = "Extra long keypress time")]
    ExtraLongKeypressTime {
        #[ets(display = "Time for extra long keypress", ets_enum, default = 34768)]
        extra_long_time: ExtraLongKeypressTime,
    } = 5,
}

/// Extra Long Values Union (16-bit) - Values for extra long keypress
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum ExtraLongValueUnion {
    /// Switch value
    #[ets(default_variant, display = "Switch")]
    Switch {
        #[ets(display = "Value", ets_enum)]
        value: GedptSwitch,
    } = 0,

    /// Forcible control value
    #[ets(display = "Forcible control")]
    ForcibleControl {
        #[ets(display = "Value", ets_enum)]
        value: ForcibleControlValue,
    } = 1,

    /// Percent value
    #[ets(display = "Percent")]
    Percent {
        #[ets(display = "Value")]
        value: u8,
    } = 2,

    /// Scene number
    #[ets(display = "Scene")]
    Scene {
        #[ets(display = "Scene number")]
        value: u8,
    } = 3,

    /// Colour temperature
    #[ets(display = "Colour temperature")]
    ColourTemp {
        #[ets(display = "Value")]
        value: u16,
    } = 4,

    /// Size anchor variant - ensures the data area is 2 bytes (largest real data is u16).
    /// Never constructed in normal use.
    #[ets(skip)]
    _Reserved([u8; 2]),
}

/// Send Condition Union (8-bit) - Condition for sending logic output
/// Used for logic channel configuration - determines when output is sent
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum SendConditionUnion {
    /// Standard send condition with enum selection
    #[ets(default_variant, display = "Send condition")]
    Condition {
        #[ets(display = "    Sending condition", ets_enum, default = 2)]
        value: SendingCondition,
    } = 0,

    /// Hidden/raw value (for "send value when pressed" mode)
    #[ets(display = "Raw")]
    Raw {
        #[ets(skip)]
        value: u8,
    } = 1,
}

/// Logic Value To Send Union (8-bit) - Value type for logic output
/// Used for logic channel "send value when pressed" mode
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum LogicValueUnion {
    /// Switch value (Yes/No)
    #[ets(display = "    Switch")]
    Switch {
        #[ets(display = "    Value", ets_enum)]
        value: NoYes,
    } = 0,

    /// Scene number (1-64) - uses SceneValue enum for dropdown
    #[ets(display = "    Scene")]
    Scene {
        #[ets(display = "    Scene number", ets_enum)]
        value: SceneValue,
    } = 1,

    /// Raw 1-byte value (0-255)
    #[ets(default_variant, display = "    1Byte Value")]
    ByteValue {
        #[ets(display = "    1Byte Value", unsigned)]
        value: u8,
    } = 2,

    /// Forcible control (2-bit priority)
    #[ets(display = "    Forcible control")]
    ForcibleControl {
        #[ets(display = "    Forcible control", ets_enum)]
        value: ForcibleControlValue,
    } = 3,
}

// ============================================================================
// Communication Objects
// ============================================================================

pub mod comm_objs {
    use super::*;
    // Import the ObjectType enum for selector values
    use super::ObjectType;
    use zweidraehte_device::objects::comm::ComObjectStorage;

    /// MDT Push Button Lite communication objects.
    /// Total: 87 objects (many are dummy placeholders)
    ///
    /// The main button objects (0-4, 10-14, 40-43) use ComObjectStorage<4>
    /// to support multiple DPT types based on configuration:
    /// - 1 Bit (DPT 1.001 Switch)
    /// - 2 Bit (DPT 2.001 Forcible control)
    /// - 1 Byte (DPT 5.001 Percent, DPT 5.005 Decimal, DPT 17.001 Scene)
    /// - 2 Bytes (DPT 7.600 Colour temp, DPT 9.001 Temp, DPT 9.004 Lux)
    /// - 3 Bytes (DPT 232.600 RGB)
    /// - 4 Bytes (reserved for future use)
    #[derive(EtsComObjects)]
    #[ets(selector_enum = ObjectType)]
    pub struct MdtComObjects {
        // ====================================================================
        // Status Objects
        // ====================================================================
        /// Presence - Button activation output
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(index = 72, name = "Presence", display = "Button activation", function = "Output", flags = C | T | LOW)]
        pub presence: ComObject<DPT_Switch>,

        /// Mode - Operation status (cyclic)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(index = 77, name = "Mode", display = "Operation", function = "Output", flags = C | R | T | LOW)]
        pub mode: ComObject<DPT_State>,

        // ====================================================================
        // Push Button 1 Objects (indices 0-9)
        // These use 4-byte storage to support multiple DPT types
        // ====================================================================
        /// Push button 1 - Main output (multi-DPT: 1 Bit to 4 Bytes based on ObjectType)
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(
            index = 0,
            name = "Eingang 0",
            display = "Push button 1",
            function = "Blind Up/Down",
            flags = C | T | LOW,
            object_size = "4 Bytes",
            selector_param = "button1_object_type"
        )]
        // PB1: prefix refs for single-button mode Switch function (3 contexts in MDT)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Send status")]
        // PB1: prefix refs for single-button mode Send value function - first context
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1: {{button1_description:Push button 1}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1: {{button1_description:Push button 1}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1: {{button1_description:Push button 1}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1: {{button1_description:Push button 1}}", function = "Colour temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1: {{button1_description:Push button 1}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1: {{button1_description:Push button 1}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1: {{button1_description:Push button 1}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1: {{button1_description:Push button 1}}", function = "HSV value")]
        // PB1: prefix refs - second context (MDT has duplicates)
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1: {{button1_description:Push button 1}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1: {{button1_description:Push button 1}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1: {{button1_description:Push button 1}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1: {{button1_description:Push button 1}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1: {{button1_description:Push button 1}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1: {{button1_description:Push button 1}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1: {{button1_description:Push button 1}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1: {{button1_description:Push button 1}}", function = "HSV value")]
        // PB1: prefix refs - third context (MDT has triplicates for some)
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1: {{button1_description:Push button 1}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1: {{button1_description:Push button 1}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1: {{button1_description:Push button 1}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1: {{button1_description:Push button 1}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1: {{button1_description:Push button 1}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1: {{button1_description:Push button 1}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1: {{button1_description:Push button 1}}", function = "HSV value")]
        // PB1 tip: prefix refs for tip function
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1 tip: {{button1_description:Push button 1}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1 tip: {{button1_description:Push button 1}}", function = "HSV value")]
        // PB1, 1x tip: prefix refs for multi-tip function
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "Colour temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1, 1x tip: {{button1_description:Push button 1}}", function = "HSV value")]
        // PB1 short: prefix refs for short/long switch function (MDT has 2 Switch refs)
        // Named refs for Mode 7 short action selection
        #[ets_ref(ref_name = "button1_main_switch_off", dpt = DPT_Switch, text = "PB1 short: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(ref_name = "button1_main_switch_on", dpt = DPT_Switch, text = "PB1 short: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(ref_name = "button1_main_toggle", dpt = DPT_Switch, text = "PB1 short: {{button1_description:Push button 1}}", function = "Toggle")]
        #[ets_ref(ref_name = "button1_main_bit2", dpt = DPT_Switch_Control, text = "PB1 short: {{button1_description:Push button 1}}", function = "Forcible control")]
        #[ets_ref(ref_name = "button1_main_percent", dpt = DPT_Scaling, text = "PB1 short: {{button1_description:Push button 1}}", function = "Percent value")]
        #[ets_ref(ref_name = "button1_main_decimal", dpt = DPT_DecimalFactor, text = "PB1 short: {{button1_description:Push button 1}}", function = "Decimal value")]
        #[ets_ref(ref_name = "button1_main_scene", dpt = DPT_SceneNumber, text = "PB1 short: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(ref_name = "button1_main_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1 short: {{button1_description:Push button 1}}", function = "Colour Temperature")]
        #[ets_ref(ref_name = "button1_main_temp", dpt = DPT_Value_Temp, text = "PB1 short: {{button1_description:Push button 1}}", function = "Temperature value")]
        #[ets_ref(ref_name = "button1_main_lux", dpt = DPT_Value_Lux, text = "PB1 short: {{button1_description:Push button 1}}", function = "Brightness value")]
        #[ets_ref(ref_name = "button1_main_rgb", dpt = DPT_Colour_RGB, text = "PB1 short: {{button1_description:Push button 1}}", function = "RGB value")]
        #[ets_ref(ref_name = "button1_main_hsv", dpt = DPT_Colour_RGB, text = "PB1 short: {{button1_description:Push button 1}}", function = "HSV value")]
        // PB1: prefix for dimming and blinds modes
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Blind Up/Down")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Dimming ON/OFF")]
        // PB1/2: prefix for two-button mode (MDT has duplicates for many of these)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Colour temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "HSV value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "HSV value")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Dimming ON/OFF")]
        // PB1/2 short: prefix for two-button short/long mode
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "HSV value")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Shutter Up/Down/Stop")]
        // Switch mode - named ref for direct lookup
        #[ets_ref(ref_name = "button1_main_switch", dpt = DPT_Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Switch")]
        // Dimming mode - named ref for direct lookup
        #[ets_ref(ref_name = "button1_main_dimming", dpt = DPT_Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Dimming ON/OFF")]
        // Blinds mode - named ref for direct lookup - 1 Bit DPT 1.8
        #[ets_ref(ref_name = "button1_main_blinds", dpt = DPT_UpDown, text = "PB1: {{button1_description:Push button 1}}")]
        // PB1 tip: prefix refs - for multi-tip mode 3 "different objects / DPT", tip 1 (uses O-0)
        #[ets_ref(ref_name = "button1_tip_switch", dpt = DPT_Switch, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(ref_name = "button1_tip_bit2", dpt = DPT_Switch_Control, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Forcible control")]
        #[ets_ref(ref_name = "button1_tip_percent", dpt = DPT_Scaling, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Percent value")]
        #[ets_ref(ref_name = "button1_tip_decimal", dpt = DPT_DecimalFactor, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Decimal value")]
        #[ets_ref(ref_name = "button1_tip_scene", dpt = DPT_SceneNumber, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(ref_name = "button1_tip_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Colour Temperature")]
        #[ets_ref(ref_name = "button1_tip_temp", dpt = DPT_Value_Temp, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Temperature value")]
        #[ets_ref(ref_name = "button1_tip_lux", dpt = DPT_Value_Lux, text = "PB1 tip: {{button1_description:Push button 1}}", function = "Brightness value")]
        #[ets_ref(ref_name = "button1_tip_rgb", dpt = DPT_Colour_RGB, text = "PB1 tip: {{button1_description:Push button 1}}", function = "RGB value")]
        #[ets_ref(ref_name = "button1_tip_hsv", dpt = DPT_Colour_RGB, text = "PB1 tip: {{button1_description:Push button 1}}", function = "HSV value")]
        pub button1_main: ComObject<ComObjectStorage<4>>,

        /// Push button 1 - Secondary output (stop/slats)
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(
            index = 1,
            name = "Eingang 0",
            display = "Push button 1",
            function = "Stop/Slats Open/Close",
            flags = C | T | LOW,
            object_size = "4 Bytes",
            selector_param = "button1_object_type"
        )]
        // PB1: prefix refs for status toggle/display
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle", read = false, write = true, update = true)]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1: {{button1_description:Push button 1}}", function = "Status of percent value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1: {{button1_description:Push button 1}}", function = "Status of decimal value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1: {{button1_description:Push button 1}}", function = "Status of colour temperature", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1: {{button1_description:Push button 1}}", function = "Status of temperature value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1: {{button1_description:Push button 1}}", function = "Status of brightness value", read = false, write = true, transmit = true, update = true)]
        // PB1: prefix for blinds mode
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Stop/Slats Open/Close")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Dimming relative")]
        // PB1, 2x tip: prefix for multi-tip function
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Switch", read = false)]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Forcible control", read = false)]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Percent value", read = false)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Decimal value", read = false)]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Scene", read = false)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Colour Temperature", read = false)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Temperature value", read = false)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Brightness value", read = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "RGB value", read = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "HSV value", read = false)]
        // PB1 short: prefix for short/long mode
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1 short: {{button1_description:Push button 1}}", function = "Status for toggle", read = false, write = true, transmit = true, update = true)]
        // PB1/2: prefix for two-button mode
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status of percent value", read = false, write = true, update = true)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status of decimal value", read = false, write = true, update = true)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status of colour temperature", read = false, write = true, update = true)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status of temperature value", read = false, write = true, update = true)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status of brightness value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 short: {{button1_description:Push buttons 1/2}}", function = "Status for toggle", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Central shutter Up/Down/Stop")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Stop/Slats Open/Close")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = ObjectType::Switch, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Dimming relative")]
        // Switch mode toggle - named ref for direct lookup
        #[ets_ref(ref_name = "button1_secondary_switch", dpt = DPT_Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        // Mode 7 toggle - status for toggle with "PB1 short:" prefix
        #[ets_ref(ref_name = "button1_secondary_toggle", dpt = DPT_Switch, text = "PB1 short: {{button1_description:Push button 1}}", function = "Status for toggle", read = false, write = true, update = true)]
        // Dimming mode - named ref for direct lookup - 4 Bit DPT 3.7
        #[ets_ref(ref_name = "button1_secondary_dimming", dpt = DPT_Control_Dimming, text = "PB1: {{button1_description:Push button 1}}", function = "Dimming relative")]
        // Blinds mode - named ref for direct lookup - 1 Bit DPT 1.9
        #[ets_ref(ref_name = "button1_secondary_blinds", dpt = DPT_OpenClose, text = "PB1: {{button1_description:Push button 1}}", function = "Stop/Slats Open/Close")]
        // RGB mode - named ref for colour control sub-selector (value 1)
        #[ets_ref(ref_name = "button1_secondary_rgb", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}}", function = "RGB status for toggle")]
        // HSV mode - named ref for colour control sub-selector (value 2)
        #[ets_ref(ref_name = "button1_secondary_hsv", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}}", function = "HSV status for toggle")]
        // Toggle values/scenes mode - named refs for status objects (PB1 short: prefix)
        #[ets_ref(ref_name = "button1_secondary_percent", dpt = DPT_Scaling, text = "PB1 short: {{button1_description:Push button 1}}", function = "Status of percent value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(ref_name = "button1_secondary_decimal", dpt = DPT_DecimalFactor, text = "PB1 short: {{button1_description:Push button 1}}", function = "Status of decimal value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(ref_name = "button1_secondary_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1 short: {{button1_description:Push button 1}}", function = "Status of colour temperature", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(ref_name = "button1_secondary_temp", dpt = DPT_Value_Temp, text = "PB1 short: {{button1_description:Push button 1}}", function = "Status of temperature value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(ref_name = "button1_secondary_lux", dpt = DPT_Value_Lux, text = "PB1 short: {{button1_description:Push button 1}}", function = "Status of brightness value", read = false, write = true, transmit = true, update = true)]
        // Additional object "(2. object)" named refs for secondary object
        #[ets_ref(ref_name = "button1_secondary_additional_switch", dpt = DPT_Switch, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Switch", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_bit2", dpt = DPT_Switch_Control, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Forcible control", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_percent", dpt = DPT_Scaling, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Percent value", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_decimal", dpt = DPT_DecimalFactor, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Decimal value", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_scene", dpt = DPT_SceneNumber, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Scene", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Colour Temperature", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_temp", dpt = DPT_Value_Temp, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Temperature value", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_lux", dpt = DPT_Value_Lux, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Brightness value", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_rgb", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "RGB value", read = false)]
        #[ets_ref(ref_name = "button1_secondary_additional_hsv", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "HSV value", read = false)]
        // PB1, 2x tip: prefix refs - for multi-tip mode 3 "different objects / DPT", tip 2 (uses O-1)
        #[ets_ref(ref_name = "button1_2x_tip_switch", dpt = DPT_Switch, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Switch", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_bit2", dpt = DPT_Switch_Control, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Forcible control", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_percent", dpt = DPT_Scaling, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Percent value", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_decimal", dpt = DPT_DecimalFactor, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Decimal value", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_scene", dpt = DPT_SceneNumber, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Scene", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Colour Temperature", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_temp", dpt = DPT_Value_Temp, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Temperature value", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_lux", dpt = DPT_Value_Lux, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "Brightness value", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_rgb", dpt = DPT_Colour_RGB, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "RGB value", read = false)]
        #[ets_ref(ref_name = "button1_2x_tip_hsv", dpt = DPT_Colour_RGB, text = "PB1, 2x tip: {{button1_description:Push button 1}}", function = "HSV value", read = false)]
        pub button1_secondary: ComObject<ComObjectStorage<4>>,

        /// Push button 1 - Status for toggle input
        /// MDT: C=1, T=1, R=0, W=1, U=0, ROI=0
        #[ets(
            index = 2,
            name = "Eingang 0",
            display = "Push button 1",
            function = "Status for toggle",
            flags = C | W | T | LOW,
            object_size = "4 Bytes",
            selector_param = "button1_object_type"
        )]
        // PB1: prefix refs (MDT has 14 total - 4 base + 10 "(2. object)", adding 4 more)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Status for change of direction")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1: {{button1_description:Push button 1}}")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1: {{button1_description:Push button 1}}", function = "RGB status for toggle")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1: {{button1_description:Push button 1}}", function = "HSV status for toggle")]
        // PB1 long: prefix refs (MDT has 12, adding 1 more Switch) - named refs for long keypress in single-button mode
        #[ets_ref(ref_name = "button1_long_switch_off", dpt = DPT_Switch, text = "PB1 long: {{button1_description:Push button 1}}", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_switch_on", dpt = DPT_Switch, text = "PB1 long: {{button1_description:Push button 1}}", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_toggle", dpt = DPT_Switch, text = "PB1 long: {{button1_description:Push button 1}}", function = "Toggle", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_bit2", dpt = DPT_Switch_Control, text = "PB1 long: {{button1_description:Push button 1}}", function = "Forcible control", update = false)]
        #[ets_ref(ref_name = "button1_long_percent", dpt = DPT_Scaling, text = "PB1 long: {{button1_description:Push button 1}}", function = "Percent value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_decimal", dpt = DPT_DecimalFactor, text = "PB1 long: {{button1_description:Push button 1}}", function = "Decimal value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_scene", dpt = DPT_SceneNumber, text = "PB1 long: {{button1_description:Push button 1}}", function = "Scene", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1 long: {{button1_description:Push button 1}}", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_temp", dpt = DPT_Value_Temp, text = "PB1 long: {{button1_description:Push button 1}}", function = "Temperature value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_lux", dpt = DPT_Value_Lux, text = "PB1 long: {{button1_description:Push button 1}}", function = "Brightness value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_rgb", dpt = DPT_Colour_RGB, text = "PB1 long: {{button1_description:Push button 1}}", function = "RGB value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_long_hsv", dpt = DPT_Colour_RGB, text = "PB1 long: {{button1_description:Push button 1}}", function = "HSV value", write = false, update = false)]
        // PB1 group long: prefix refs (MDT has 12, adding 1 more Switch) - named refs for group long keypress in single-button mode
        #[ets_ref(ref_name = "button1_group_long_switch_off", dpt = DPT_Switch, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(ref_name = "button1_group_long_switch_on", dpt = DPT_Switch, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(ref_name = "button1_group_long_toggle", dpt = DPT_Switch, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Toggle")]
        #[ets_ref(ref_name = "button1_group_long_bit2", dpt = DPT_Switch_Control, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Forcible control")]
        #[ets_ref(ref_name = "button1_group_long_percent", dpt = DPT_Scaling, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Percent value")]
        #[ets_ref(ref_name = "button1_group_long_decimal", dpt = DPT_DecimalFactor, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Decimal value")]
        #[ets_ref(ref_name = "button1_group_long_scene", dpt = DPT_SceneNumber, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Scene")]
        #[ets_ref(ref_name = "button1_group_long_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Colour Temperature")]
        #[ets_ref(ref_name = "button1_group_long_temp", dpt = DPT_Value_Temp, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Temperature value")]
        #[ets_ref(ref_name = "button1_group_long_lux", dpt = DPT_Value_Lux, text = "PB1 group long: {{button1_description:Push button 1}}", function = "Brightness value")]
        #[ets_ref(ref_name = "button1_group_long_rgb", dpt = DPT_Colour_RGB, text = "PB1 group long: {{button1_description:Push button 1}}", function = "RGB value")]
        #[ets_ref(ref_name = "button1_group_long_hsv", dpt = DPT_Colour_RGB, text = "PB1 group long: {{button1_description:Push button 1}}", function = "HSV value")]
        // PB1, 3x tip: prefix refs - named refs for multi-tip mode 3 "different objects / DPT", tip 3 (uses O-2)
        #[ets_ref(ref_name = "button1_3x_tip_switch", dpt = DPT_Switch, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_bit2", dpt = DPT_Switch_Control, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "Forcible control", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_percent", dpt = DPT_Scaling, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "Percent value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_decimal", dpt = DPT_DecimalFactor, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "Decimal value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_scene", dpt = DPT_SceneNumber, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "Scene", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_temp", dpt = DPT_Value_Temp, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "Temperature value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_lux", dpt = DPT_Value_Lux, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "Brightness value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_rgb", dpt = DPT_Colour_RGB, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "RGB value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_3x_tip_hsv", dpt = DPT_Colour_RGB, text = "PB1, 3x tip: {{button1_description:Push button 1}}", function = "HSV value", write = false, update = false)]
        // PB1/2: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "RGB status for toggle")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "HSV status for toggle")]
        // PB1/2 long: prefix refs (MDT has 12, adding 1 more Switch)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "HSV value")]
        // PB1/2 Group long: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2 Group long: {{button1_description:Push buttons 1/2}}", function = "HSV value")]
        // Switch mode - named ref for direct lookup
        #[ets_ref(ref_name = "button1_status_toggle_switch", dpt = DPT_Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Status for toggle")]
        // Dimming mode - named ref for direct lookup with UpdateFlag=Enabled
        #[ets_ref(ref_name = "button1_status_toggle_dimming", dpt = DPT_Switch, text = "PB1: {{button1_description:Push button 1}}", update = true)]
        // Blinds mode - named ref for direct lookup - 1 Bit DPT 1.8 with UpdateFlag
        #[ets_ref(ref_name = "button1_status_toggle_blinds", dpt = DPT_UpDown, text = "PB1: {{button1_description:Push button 1}}", function = "Status for change of direction", update = true)]
        // Scene mode (no save) - named ref - 1 Byte DPT 17.1
        #[ets_ref(ref_name = "button1_status_toggle_scene_no_save", dpt = DPT_SceneNumber, text = "PB1: {{button1_description:Push button 1}}", function = "Scene", write = false, update = false)]
        // Scene mode (save) - named ref - 1 Byte DPT 18.1
        #[ets_ref(ref_name = "button1_status_toggle_scene_save", dpt = DPT_SceneControl, text = "PB1: {{button1_description:Push button 1}}", function = "Scene", write = false, update = false)]
        // RGB mode - named ref for colour control sub-selector (value 1)
        #[ets_ref(ref_name = "button1_status_toggle_rgb", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}}", function = "RGB status for toggle")]
        // HSV mode - named ref for colour control sub-selector (value 2)
        #[ets_ref(ref_name = "button1_status_toggle_hsv", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}}", function = "HSV status for toggle")]
        // Additional object "(2. object)" named refs - MDT R-86 to R-95
        #[ets_ref(ref_name = "button1_additional_obj_switch", dpt = DPT_Switch, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_bit2", dpt = DPT_Switch_Control, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Forcible control", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_percent", dpt = DPT_Scaling, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Percent value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_decimal", dpt = DPT_DecimalFactor, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Decimal value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_scene", dpt = DPT_SceneNumber, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Scene", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_temp", dpt = DPT_Value_Temp, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Temperature value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_lux", dpt = DPT_Value_Lux, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "Brightness value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_rgb", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "RGB value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_additional_obj_hsv", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}} (2. object)", function = "HSV value", write = false, update = false)]
        pub button1_status_toggle: ComObject<ComObjectStorage<4>>,

        /// Push button 1 - Status for display input
        /// MDT: C=1, T=0, R=0, W=1, U=0, ROI=0 -> 0x10+0x04+0x03 = 0x17
        #[ets(
            index = 3,
            name = "Eingang 0",
            display = "Push button 1",
            function = "Status for display",
            flags = C | W | LOW,
            object_size = "4 Bytes",
            selector_param = "button1_object_type"
        )]
        // PB1 long: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1 long: {{button1_description:Push button 1}}", function = "Switch", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1 long: {{button1_description:Push button 1}}", function = "Forcible control", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1 long: {{button1_description:Push button 1}}", function = "Percent value", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1 long: {{button1_description:Push button 1}}", function = "Decimal value", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1 long: {{button1_description:Push button 1}}", function = "Scene", write = false, transmit = true, update = false)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1 long: {{button1_description:Push button 1}}", function = "Colour temperature", write = false, transmit = true, update = false)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1 long: {{button1_description:Push button 1}}", function = "Temperature value", write = false, transmit = true, update = false)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1 long: {{button1_description:Push button 1}}", function = "Brightness value", write = false, transmit = true, update = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1 long: {{button1_description:Push button 1}}", function = "RGB value", write = false, transmit = true, update = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1 long: {{button1_description:Push button 1}}", function = "HSV value", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button1_long_status_toggle", dpt = DPT_Switch, text = "PB1 long: {{button1_description:Push button 1}}", function = "Status for toggle", transmit = true, update = true)]
        // PB1 group extra long: prefix
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Blind Up/Down", write = false, transmit = true)]
        // Blinds mode - unconditional ref for extra long group - 1 Bit DPT 1.8
        #[ets_ref(dpt = DPT_UpDown, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Blind Up/Down", write = false, transmit = true)]
        // PB1/2: prefix refs
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status of percent value", read = false, write = true, update = true)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2: {{button1_description:Push buttons 1/2}}", function = "Status of decimal value", read = false, write = true, update = true)]
        // PB1/2 long: prefix
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 long: {{button1_description:Push buttons 1/2}}", function = "Status for toggle", transmit = true, update = true)]
        // PB1/2 Group extra long: prefix
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Blind Up/Down", write = false, transmit = true)]
        pub button1_status_display: ComObject<ComObjectStorage<4>>,

        /// Push button 1 - Extra long switch output
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(
            index = 4,
            name = "Eingang 0",
            display = "Push button 1",
            function = "Switch extra long",
            flags = C | T | LOW,
            object_size = "4 Bytes",
            selector_param = "button1_object_type"
        )]
        // PB1 group extra long: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Switch", write = false, update = false)]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Forcible control", write = false, update = false)]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Percent value", write = false, update = false)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Decimal value", write = false, update = false)]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Scene", write = false, update = false)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Temperature value", write = false, update = false)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Brightness value", write = false, update = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "RGB value", write = false, update = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "HSV value", write = false, update = false)]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Stop/Slats Open/Close", write = false, update = false)]
        // PB1/2 Group extra long: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Switch", write = false, update = false)]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Forcible control", write = false, update = false)]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Percent value", write = false, update = false)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Decimal value", write = false, update = false)]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Scene", write = false, update = false)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Temperature value", write = false, update = false)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Brightness value", write = false, update = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "RGB value", write = false, update = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "HSV value", write = false, update = false)]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB1/2 Group extra long: {{button1_description:Push buttons 1/2}}", function = "Stop/Slats Open/Close")]
        // Blinds mode - unconditional ref for extra long group slats - 1 Bit DPT 1.9
        #[ets_ref(dpt = DPT_OpenClose, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "Stop/Slats Open/Close", write = false, update = false)]
        // RGB mode - named ref for colour control sub-selector (value 1)
        #[ets_ref(ref_name = "button1_extra_long_rgb", dpt = DPT_Colour_RGB, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "RGB value", write = false, update = false)]
        // HSV mode - named ref for colour control sub-selector (value 2)
        #[ets_ref(ref_name = "button1_extra_long_hsv", dpt = DPT_Colour_RGB, text = "PB1 group extra long: {{button1_description:Push button 1}}", function = "HSV value", write = false, update = false)]
        // Multi-tip mode 3 "different objects / DPT" - named refs for tip 3 (each tip gets its own object)
        #[ets_ref(ref_name = "button1_extra_switch", dpt = DPT_Switch, text = "PB1: {{button1_description:Push button 1}}", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_bit2", dpt = DPT_Switch_Control, text = "PB1: {{button1_description:Push button 1}}", function = "Forcible control", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_percent", dpt = DPT_Scaling, text = "PB1: {{button1_description:Push button 1}}", function = "Percent value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_decimal", dpt = DPT_DecimalFactor, text = "PB1: {{button1_description:Push button 1}}", function = "Decimal value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_scene", dpt = DPT_SceneNumber, text = "PB1: {{button1_description:Push button 1}}", function = "Scene", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_colour_temp", dpt = DPT_Colour_Temperature, text = "PB1: {{button1_description:Push button 1}}", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_temp", dpt = DPT_Value_Temp, text = "PB1: {{button1_description:Push button 1}}", function = "Temperature value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_lux", dpt = DPT_Value_Lux, text = "PB1: {{button1_description:Push button 1}}", function = "Brightness value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_rgb", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}}", function = "RGB value", write = false, update = false)]
        #[ets_ref(ref_name = "button1_extra_hsv", dpt = DPT_Colour_RGB, text = "PB1: {{button1_description:Push button 1}}", function = "HSV value", write = false, update = false)]
        pub button1_extra_long: ComObject<ComObjectStorage<4>>,

        /// Push button 1 - Blocking object input
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        /// Note: MDT has 2 refs with different Text ("PB1:" and "PB1/2:") but same DPT
        #[ets(index = 9, name = "Eingang 0", display = "Push button 1", function = "Blocking Object", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Enable, text = "PB1: {{button1_description:Push button 1}}")]
        #[ets_ref(dpt = DPT_Enable, text = "PB1/2: {{button1_description:Push buttons 1/2}}")]
        pub button1_blocking: ComObject<DPT_Enable>,

        // ====================================================================
        // Push Button 2 Objects (indices 10-19)
        // ====================================================================
        /// Push button 2 - Main output (multi-DPT)
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(
            index = 10,
            name = "Eingang 1",
            display = "Push button 2",
            function = "Switch",
            flags = C | T | LOW,
            object_size = "4 Bytes",
            selector_param = "button2_object_type"
        )]
        // PB2: prefix refs for single-button mode (MDT has 33, need 19 more = duplicates for multiple contexts)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Send status")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2: {{button2_description:Push button 2}}", function = "Colour temperature")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2: {{button2_description:Push button 2}}", function = "Colour temperature")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2: {{button2_description:Push button 2}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2: {{button2_description:Push button 2}}", function = "HSV value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2: {{button2_description:Push button 2}}", function = "HSV value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2: {{button2_description:Push button 2}}", function = "HSV value")]
        // PB2 tip: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2 tip: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2 tip: {{button2_description:Push button 2}}", function = "HSV value")]
        // PB2, 1x tip: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "Colour temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2, 1x tip: {{button2_description:Push button 2}}", function = "HSV value")]
        // PB2 short: prefix refs for short/long switch function (MDT has 2 Switch refs)
        // Named refs for Mode 7 short action selection
        #[ets_ref(ref_name = "button2_main_switch_off", dpt = DPT_Switch, text = "PB2 short: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(ref_name = "button2_main_switch_on", dpt = DPT_Switch, text = "PB2 short: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(ref_name = "button2_main_toggle", dpt = DPT_Switch, text = "PB2 short: {{button2_description:Push button 2}}", function = "Toggle")]
        #[ets_ref(ref_name = "button2_main_bit2", dpt = DPT_Switch_Control, text = "PB2 short: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(ref_name = "button2_main_percent", dpt = DPT_Scaling, text = "PB2 short: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(ref_name = "button2_main_decimal", dpt = DPT_DecimalFactor, text = "PB2 short: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(ref_name = "button2_main_scene", dpt = DPT_SceneNumber, text = "PB2 short: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(ref_name = "button2_main_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2 short: {{button2_description:Push button 2}}", function = "Colour Temperature")]
        #[ets_ref(ref_name = "button2_main_temp", dpt = DPT_Value_Temp, text = "PB2 short: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(ref_name = "button2_main_lux", dpt = DPT_Value_Lux, text = "PB2 short: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(ref_name = "button2_main_rgb", dpt = DPT_Colour_RGB, text = "PB2 short: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(ref_name = "button2_main_hsv", dpt = DPT_Colour_RGB, text = "PB2 short: {{button2_description:Push button 2}}", function = "HSV value")]
        // PB2: prefix for dimming and blinds modes
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Blind Up/Down")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Dimming ON/OFF")]
        // Switch mode - named ref for direct lookup
        #[ets_ref(ref_name = "button2_main_switch", dpt = DPT_Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Switch")]
        // Dimming mode - named ref for direct lookup
        #[ets_ref(ref_name = "button2_main_dimming", dpt = DPT_Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Dimming ON/OFF")]
        // Blinds mode - named ref for direct lookup - 1 Bit DPT 1.8
        #[ets_ref(ref_name = "button2_main_blinds", dpt = DPT_UpDown, text = "PB2: {{button2_description:Push button 2}}", function = "Blind Up/Down")]
        // PB2 tip: prefix refs - for multi-tip mode 3 "different objects / DPT", tip 1 (uses O-10)
        #[ets_ref(ref_name = "button2_tip_switch", dpt = DPT_Switch, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(ref_name = "button2_tip_bit2", dpt = DPT_Switch_Control, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(ref_name = "button2_tip_percent", dpt = DPT_Scaling, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(ref_name = "button2_tip_decimal", dpt = DPT_DecimalFactor, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(ref_name = "button2_tip_scene", dpt = DPT_SceneNumber, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(ref_name = "button2_tip_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Colour Temperature")]
        #[ets_ref(ref_name = "button2_tip_temp", dpt = DPT_Value_Temp, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(ref_name = "button2_tip_lux", dpt = DPT_Value_Lux, text = "PB2 tip: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(ref_name = "button2_tip_rgb", dpt = DPT_Colour_RGB, text = "PB2 tip: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(ref_name = "button2_tip_hsv", dpt = DPT_Colour_RGB, text = "PB2 tip: {{button2_description:Push button 2}}", function = "HSV value")]
        pub button2_main: ComObject<ComObjectStorage<4>>,

        /// Push button 2 - Secondary output
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(
            index = 11,
            name = "Eingang 1",
            display = "Push button 2",
            function = "Stop/Slats Open/Close",
            flags = C | T | LOW,
            object_size = "4 Bytes",
            selector_param = "button2_object_type"
        )]
        // PB2: prefix refs for status toggle/display
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle", read = false, write = true, update = true)]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2: {{button2_description:Push button 2}}", function = "Status of percent value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2: {{button2_description:Push button 2}}", function = "Status of decimal value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2: {{button2_description:Push button 2}}", function = "Status of colour temperature", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2: {{button2_description:Push button 2}}", function = "Status of temperature value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2: {{button2_description:Push button 2}}", function = "Status of brightness value", read = false, write = true, transmit = true, update = true)]
        // PB2: prefix for blinds mode
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Stop/Slats Open/Close")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Dimming relative")]
        // PB2, 2x tip: prefix for multi-tip function
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Switch", read = false)]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Forcible control", read = false)]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Percent value", read = false)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Decimal value", read = false)]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Scene", read = false)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Colour Temperature", read = false)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Temperature value", read = false)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Brightness value", read = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "RGB value", read = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "HSV value", read = false)]
        // PB2 short: prefix for short/long mode
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2 short: {{button2_description:Push button 2}}", function = "Status for toggle", read = false, write = true, transmit = true, update = true)]
        // Switch mode toggle - named ref for direct lookup
        #[ets_ref(ref_name = "button2_secondary_switch", dpt = DPT_Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        // Mode 7 toggle - status for toggle with "PB2 short:" prefix
        #[ets_ref(ref_name = "button2_secondary_toggle", dpt = DPT_Switch, text = "PB2 short: {{button2_description:Push button 2}}", function = "Status for toggle", read = false, write = true, update = true)]
        // Dimming mode - named ref for explicit selection in page layout
        #[ets_ref(ref_name = "button2_secondary_dimming", dpt = DPT_Control_Dimming, text = "PB2: {{button2_description:Push button 2}}", function = "Dimming relative")]
        // Blinds mode - named ref for explicit selection in page layout
        #[ets_ref(ref_name = "button2_secondary_blinds", dpt = DPT_OpenClose, text = "PB2: {{button2_description:Push button 2}}", function = "Stop/Slats Open/Close")]
        // RGB mode - named ref for colour control sub-selector (value 1)
        #[ets_ref(ref_name = "button2_secondary_rgb", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}}", function = "RGB status for toggle")]
        // HSV mode - named ref for colour control sub-selector (value 2)
        #[ets_ref(ref_name = "button2_secondary_hsv", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}}", function = "HSV status for toggle")]
        // Toggle values/scenes mode - named refs for status objects (PB2 short: prefix)
        #[ets_ref(ref_name = "button2_secondary_percent", dpt = DPT_Scaling, text = "PB2 short: {{button2_description:Push button 2}}", function = "Status of percent value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(ref_name = "button2_secondary_decimal", dpt = DPT_DecimalFactor, text = "PB2 short: {{button2_description:Push button 2}}", function = "Status of decimal value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(ref_name = "button2_secondary_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2 short: {{button2_description:Push button 2}}", function = "Status of colour temperature", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(ref_name = "button2_secondary_temp", dpt = DPT_Value_Temp, text = "PB2 short: {{button2_description:Push button 2}}", function = "Status of temperature value", read = false, write = true, transmit = true, update = true)]
        #[ets_ref(ref_name = "button2_secondary_lux", dpt = DPT_Value_Lux, text = "PB2 short: {{button2_description:Push button 2}}", function = "Status of brightness value", read = false, write = true, transmit = true, update = true)]
        // Additional object "(2. object)" named refs for secondary object
        #[ets_ref(ref_name = "button2_secondary_additional_switch", dpt = DPT_Switch, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Switch", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_bit2", dpt = DPT_Switch_Control, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Forcible control", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_percent", dpt = DPT_Scaling, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Percent value", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_decimal", dpt = DPT_DecimalFactor, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Decimal value", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_scene", dpt = DPT_SceneNumber, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Scene", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Colour Temperature", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_temp", dpt = DPT_Value_Temp, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Temperature value", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_lux", dpt = DPT_Value_Lux, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Brightness value", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_rgb", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "RGB value", read = false, transmit = true)]
        #[ets_ref(ref_name = "button2_secondary_additional_hsv", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "HSV value", read = false, transmit = true)]
        // PB2, 2x tip: prefix refs - for multi-tip mode 3 "different objects / DPT", tip 2 (uses O-11)
        #[ets_ref(ref_name = "button2_2x_tip_switch", dpt = DPT_Switch, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Switch", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_bit2", dpt = DPT_Switch_Control, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Forcible control", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_percent", dpt = DPT_Scaling, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Percent value", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_decimal", dpt = DPT_DecimalFactor, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Decimal value", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_scene", dpt = DPT_SceneNumber, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Scene", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Colour Temperature", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_temp", dpt = DPT_Value_Temp, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Temperature value", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_lux", dpt = DPT_Value_Lux, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "Brightness value", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_rgb", dpt = DPT_Colour_RGB, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "RGB value", read = false)]
        #[ets_ref(ref_name = "button2_2x_tip_hsv", dpt = DPT_Colour_RGB, text = "PB2, 2x tip: {{button2_description:Push button 2}}", function = "HSV value", read = false)]
        pub button2_secondary: ComObject<ComObjectStorage<4>>,

        /// Push button 2 - Status for toggle input
        /// MDT O-12: C=1, T=0, R=0, W=1, U=0, ROI=0 (no transmit!) -> 0x17
        #[ets(
            index = 12,
            name = "Eingang 1",
            display = "Push button 2",
            function = "Status for toggle",
            flags = C | W | LOW,
            object_size = "4 Bytes",
            selector_param = "button2_object_type"
        )]
        // PB2: prefix refs (MDT has 14, adding 4 more)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Status for change of direction")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2: {{button2_description:Push button 2}}")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2: {{button2_description:Push button 2}}", function = "RGB status for toggle")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2: {{button2_description:Push button 2}}", function = "HSV status for toggle")]
        // PB2 long: prefix refs (MDT has 12, adding 1 more) - named refs for long keypress in single-button mode
        #[ets_ref(ref_name = "button2_long_switch_off", dpt = DPT_Switch, text = "PB2 long: {{button2_description:Push button 2}}", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_switch_on", dpt = DPT_Switch, text = "PB2 long: {{button2_description:Push button 2}}", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_toggle", dpt = DPT_Switch, text = "PB2 long: {{button2_description:Push button 2}}", function = "Toggle", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_bit2", dpt = DPT_Switch_Control, text = "PB2 long: {{button2_description:Push button 2}}", function = "Forcible control", update = false)]
        #[ets_ref(ref_name = "button2_long_percent", dpt = DPT_Scaling, text = "PB2 long: {{button2_description:Push button 2}}", function = "Percent value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_decimal", dpt = DPT_DecimalFactor, text = "PB2 long: {{button2_description:Push button 2}}", function = "Decimal value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_scene", dpt = DPT_SceneNumber, text = "PB2 long: {{button2_description:Push button 2}}", function = "Scene", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2 long: {{button2_description:Push button 2}}", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_temp", dpt = DPT_Value_Temp, text = "PB2 long: {{button2_description:Push button 2}}", function = "Temperature value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_lux", dpt = DPT_Value_Lux, text = "PB2 long: {{button2_description:Push button 2}}", function = "Brightness value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_rgb", dpt = DPT_Colour_RGB, text = "PB2 long: {{button2_description:Push button 2}}", function = "RGB value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_long_hsv", dpt = DPT_Colour_RGB, text = "PB2 long: {{button2_description:Push button 2}}", function = "HSV value", write = false, update = false)]
        // PB2 Group long: prefix refs (MDT has 12, adding 1 more) - named refs for group long keypress
        #[ets_ref(ref_name = "button2_group_long_switch_off", dpt = DPT_Switch, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(ref_name = "button2_group_long_switch_on", dpt = DPT_Switch, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(ref_name = "button2_group_long_toggle", dpt = DPT_Switch, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Toggle")]
        #[ets_ref(ref_name = "button2_group_long_bit2", dpt = DPT_Switch_Control, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(ref_name = "button2_group_long_percent", dpt = DPT_Scaling, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(ref_name = "button2_group_long_decimal", dpt = DPT_DecimalFactor, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(ref_name = "button2_group_long_scene", dpt = DPT_SceneNumber, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(ref_name = "button2_group_long_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Colour Temperature")]
        #[ets_ref(ref_name = "button2_group_long_temp", dpt = DPT_Value_Temp, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(ref_name = "button2_group_long_lux", dpt = DPT_Value_Lux, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(ref_name = "button2_group_long_rgb", dpt = DPT_Colour_RGB, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(ref_name = "button2_group_long_hsv", dpt = DPT_Colour_RGB, text = "PB2 Group long: {{button2_description:Push button 2}}", function = "HSV value")]
        // PB2, 3x tip: prefix refs (adding 1 more to reach 561 total)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "HSV value")]
        // Switch mode - named ref for direct lookup
        #[ets_ref(ref_name = "button2_status_toggle_switch", dpt = DPT_Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Status for toggle")]
        // Dimming mode - named ref for explicit selection in page layout
        #[ets_ref(ref_name = "button2_status_toggle_dimming", dpt = DPT_Switch, text = "PB2: {{button2_description:Push button 2}}", update = true)]
        // Blinds mode - named ref for explicit selection in page layout
        #[ets_ref(ref_name = "button2_status_toggle_blinds", dpt = DPT_UpDown, text = "PB2: {{button2_description:Push button 2}}", function = "Status for change of direction", transmit = true, update = true)]
        // Scene mode (no save) - named ref - 1 Byte DPT 17.1
        #[ets_ref(ref_name = "button2_status_toggle_scene_no_save", dpt = DPT_SceneNumber, text = "PB2: {{button2_description:Push button 2}}", function = "Scene", write = false, update = false)]
        // Scene mode (save) - named ref - 1 Byte DPT 18.1
        #[ets_ref(ref_name = "button2_status_toggle_scene_save", dpt = DPT_SceneControl, text = "PB2: {{button2_description:Push button 2}}", function = "Scene", write = false, update = false)]
        // RGB mode - named ref for colour control sub-selector (value 1)
        #[ets_ref(ref_name = "button2_status_toggle_rgb", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}}", function = "RGB status for toggle")]
        // HSV mode - named ref for colour control sub-selector (value 2)
        #[ets_ref(ref_name = "button2_status_toggle_hsv", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}}", function = "HSV status for toggle")]
        // Additional object "(2. object)" named refs - MDT R-262 to R-271
        #[ets_ref(ref_name = "button2_additional_obj_switch", dpt = DPT_Switch, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Switch", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_bit2", dpt = DPT_Switch_Control, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Forcible control", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_percent", dpt = DPT_Scaling, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Percent value", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_decimal", dpt = DPT_DecimalFactor, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Decimal value", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_scene", dpt = DPT_SceneNumber, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Scene", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Colour Temperature", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_temp", dpt = DPT_Value_Temp, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Temperature value", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_lux", dpt = DPT_Value_Lux, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "Brightness value", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_rgb", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "RGB value", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_additional_obj_hsv", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}} (2. object)", function = "HSV value", write = false, transmit = true, update = false)]
        // PB2, 3x tip: prefix refs - for multi-tip mode 3 "different objects / DPT", tip 3 (uses O-12)
        #[ets_ref(ref_name = "button2_3x_tip_switch", dpt = DPT_Switch, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_bit2", dpt = DPT_Switch_Control, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Forcible control", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_percent", dpt = DPT_Scaling, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Percent value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_decimal", dpt = DPT_DecimalFactor, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Decimal value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_scene", dpt = DPT_SceneNumber, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Scene", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_temp", dpt = DPT_Value_Temp, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Temperature value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_lux", dpt = DPT_Value_Lux, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "Brightness value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_rgb", dpt = DPT_Colour_RGB, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "RGB value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_3x_tip_hsv", dpt = DPT_Colour_RGB, text = "PB2, 3x tip: {{button2_description:Push button 2}}", function = "HSV value", write = false, update = false)]
        pub button2_status_toggle: ComObject<ComObjectStorage<4>>,

        /// Push button 2 - Status for display input
        /// MDT: C=1, T=0, R=0, W=1, U=0, ROI=0 -> 0x17
        #[ets(
            index = 13,
            name = "Eingang 1",
            display = "Push button 2",
            function = "Status for display",
            flags = C | W | LOW,
            object_size = "4 Bytes",
            selector_param = "button2_object_type"
        )]
        // PB2 long: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2 long: {{button2_description:Push button 2}}", function = "Switch", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2 long: {{button2_description:Push button 2}}", function = "Forcible control", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2 long: {{button2_description:Push button 2}}", function = "Percent value", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2 long: {{button2_description:Push button 2}}", function = "Decimal value", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2 long: {{button2_description:Push button 2}}", function = "Scene", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2 long: {{button2_description:Push button 2}}", function = "Colour Temperature", write = false, transmit = true)]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2 long: {{button2_description:Push button 2}}", function = "Temperature value", write = false, transmit = true, update = false)]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2 long: {{button2_description:Push button 2}}", function = "Brightness value", write = false, transmit = true, update = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2 long: {{button2_description:Push button 2}}", function = "RGB value", write = false, transmit = true, update = false)]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2 long: {{button2_description:Push button 2}}", function = "HSV value", write = false, transmit = true, update = false)]
        #[ets_ref(ref_name = "button2_long_status_toggle", dpt = DPT_Switch, text = "PB2 long: {{button2_description:Push button 2}}", function = "Status for toggle", transmit = true, update = true)]
        // PB2 Group extra long: prefix
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Blind Up/Down", write = false, transmit = true)]
        // Blinds mode - unconditional ref (no when selector) for extra long group O-13
        #[ets_ref(dpt = DPT_UpDown, text = "PB2 group extra long: {{button2_description:Push button 2}}", function = "Blind Up/Down", write = false, transmit = true)]
        pub button2_status_display: ComObject<ComObjectStorage<4>>,

        /// Push button 2 - Extra long switch output
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(
            index = 14,
            name = "Eingang 1",
            display = "Push button 2",
            function = "Switch extra long",
            flags = C | T | LOW,
            object_size = "4 Bytes",
            selector_param = "button2_object_type"
        )]
        // PB2 Group extra long: prefix refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Switch")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "HSV value")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "PB2 Group extra long: {{button2_description:Push button 2}}", function = "Stop/Slats Open/Close")]
        // Blinds mode - unconditional ref (no when selector) for extra long group O-14
        #[ets_ref(dpt = DPT_OpenClose, text = "PB2 group extra long: {{button2_description:Push button 2}}", function = "Stop/Slats Open/Close", write = false, update = false)]
        // Multi-tip mode 3 "different objects / DPT" - named refs for tip 3 (each tip gets its own object)
        #[ets_ref(ref_name = "button2_extra_switch", dpt = DPT_Switch, text = "PB2: {{button2_description:Push button 2}}", function = "Switch", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_bit2", dpt = DPT_Switch_Control, text = "PB2: {{button2_description:Push button 2}}", function = "Forcible control", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_percent", dpt = DPT_Scaling, text = "PB2: {{button2_description:Push button 2}}", function = "Percent value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_decimal", dpt = DPT_DecimalFactor, text = "PB2: {{button2_description:Push button 2}}", function = "Decimal value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_scene", dpt = DPT_SceneNumber, text = "PB2: {{button2_description:Push button 2}}", function = "Scene", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_colour_temp", dpt = DPT_Colour_Temperature, text = "PB2: {{button2_description:Push button 2}}", function = "Colour Temperature", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_temp", dpt = DPT_Value_Temp, text = "PB2: {{button2_description:Push button 2}}", function = "Temperature value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_lux", dpt = DPT_Value_Lux, text = "PB2: {{button2_description:Push button 2}}", function = "Brightness value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_rgb", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}}", function = "RGB value", write = false, update = false)]
        #[ets_ref(ref_name = "button2_extra_hsv", dpt = DPT_Colour_RGB, text = "PB2: {{button2_description:Push button 2}}", function = "HSV value", write = false, update = false)]
        pub button2_extra_long: ComObject<ComObjectStorage<4>>,

        /// Push button 2 - Blocking object input
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        /// Note: MDT has 1 ref with Text "PB2:" but same DPT
        #[ets(index = 19, name = "Eingang 1", display = "Push button 2", function = "Blocking Object", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Enable, text = "PB2: {{button2_description:Push button 2}}")]
        pub button2_blocking: ComObject<DPT_Enable>,

        // ====================================================================
        // Slap Button Objects (indices 40-49)
        // ====================================================================
        /// Slap button short - Main output (multi-DPT, 4 bytes)
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(
            index = 40,
            name = "Eingang Patsch",
            display = "Slap-button short",
            function = "Switch",
            flags = C | T | LOW,
            object_size = "4 Bytes",
            selector_param = "slap_object_type"
        )]
        // First set of switch mode refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Switch OFF")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Switch ON")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, function = "Scene")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, function = "HSV value")]
        // Second set of refs (same functions, different context)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Switch OFF")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Switch ON")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, function = "HSV value")]
        pub slap_short_main: ComObject<ComObjectStorage<4>>,

        /// Slap button short - Status for toggle (multi-DPT, matches main object type)
        /// MDT: C=1, T=0, R=0, W=1, U=0, ROI=0 -> 0x17
        #[ets(
            index = 41,
            name = "Eingang Patsch",
            display = "Slap-button short",
            function = "Status for toggle",
            flags = C | W | LOW,
            object_size = "2 Bytes",
            selector_param = "slap_short_object_type"
        )]
        // MDT has only 2 refs for O-41, both DPT_Switch with flag overrides
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Status for toggle", transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Status for toggle", transmit = true, update = true)]
        pub slap_short_status: ComObject<ComObjectStorage<4>>,

        /// Slap button long - Main output (multi-DPT, 4 bytes)
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(
            index = 42,
            name = "Eingang Patsch",
            display = "Slap-button long",
            function = "Switch",
            flags = C | T | LOW,
            object_size = "4 Bytes",
            selector_param = "slap_object_type"
        )]
        // First set of switch mode refs
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Switch OFF")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Switch ON")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, function = "Scene")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, function = "HSV value")]
        // Second set of refs (same functions, different context)
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Switch OFF")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Switch ON")]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Toggle")]
        #[ets_ref(dpt = DPT_Switch_Control, when = ObjectType::Bit2, function = "Forcible control")]
        #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, function = "Percent value")]
        #[ets_ref(dpt = DPT_DecimalFactor, when = ObjectType::Decimal, function = "Decimal value")]
        #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, function = "Scene")]
        #[ets_ref(dpt = DPT_Colour_Temperature, when = ObjectType::ColourTemp, function = "Colour Temperature")]
        #[ets_ref(dpt = DPT_Value_Temp, when = ObjectType::Temperature, function = "Temperature value")]
        #[ets_ref(dpt = DPT_Value_Lux, when = ObjectType::Brightness, function = "Brightness value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, function = "RGB value")]
        #[ets_ref(dpt = DPT_Colour_RGB, when = ObjectType::Rgb, function = "HSV value")]
        pub slap_long_main: ComObject<ComObjectStorage<4>>,

        /// Slap button long - Status for toggle (multi-DPT, matches main object type)
        /// MDT: C=1, T=0, R=0, W=1, U=0, ROI=0 -> 0x17
        #[ets(
            index = 43,
            name = "Eingang Patsch",
            display = "Slap-button long",
            function = "Status for toggle",
            flags = C | W | LOW,
            object_size = "2 Bytes",
            selector_param = "slap_long_object_type"
        )]
        // MDT has only 2 refs for O-43, both DPT_Switch with flag overrides
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Status for toggle", transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Status for toggle", transmit = true, update = true)]
        pub slap_long_status: ComObject<ComObjectStorage<4>>,

        /// Slap button - Blocking object
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(
            index = 49,
            name = "Eingang Patsch",
            display = "Slap-button",
            function = "Blocking Object",
            flags = C | W | T | U | LOW
        )]
        pub slap_blocking: ComObject<DPT_Enable>,

        // ====================================================================
        // Logic Objects (indices 50-61)
        // ====================================================================
        /// Logic 1 Input A
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 50, name = "Eingangslogik 1 A", display = "Logic", function = "Input 1 A", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 1 {{logic1_description:}}", function = "Input 1 A")]
        pub logic1_input_a: ComObject<DPT_Switch>,

        /// Logic 1 Input B
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 51, name = "Eingangslogik 1 B", display = "Logic", function = "Input 1 B", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 1 {{logic1_description:}}", function = "Input 1 B")]
        pub logic1_input_b: ComObject<DPT_Switch>,

        /// Logic 1 Output (multi-DPT based on LogicObjectType)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(
            index = 52,
            name = "Ausgangslogik 1",
            display = "Logic",
            function = "Output 1",
            flags = C | R | T | LOW,
            selector_param = "logic1_output_type"
        )]
        // MDT has 8 refs for each logic output (4 DPT variants * 2 contexts)
        #[ets_ref(dpt = DPT_Switch, when = LogicObjectType::Switch, text = "Logic 1 {{logic1_description:}}", function = "Output 1")]
        #[ets_ref(dpt = DPT_SceneNumber, when = LogicObjectType::Scene, text = "Logic 1 {{logic1_description:}}", function = "Output 1 Scene")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = LogicObjectType::Value, text = "Logic 1 {{logic1_description:}}", function = "Output 1 Value")]
        #[ets_ref(dpt = DPT_Switch_Control, when = LogicObjectType::ForcibleControl, text = "Logic 1 {{logic1_description:}}", function = "Output 1 Value")]
        #[ets_ref(dpt = DPT_Switch, when = LogicObjectType::Switch, text = "Logic 1 {{logic1_description:}}", function = "Output 1")]
        #[ets_ref(dpt = DPT_SceneNumber, when = LogicObjectType::Scene, text = "Logic 1 {{logic1_description:}}", function = "Output 1 Scene")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = LogicObjectType::Value, text = "Logic 1 {{logic1_description:}}", function = "Output 1 Value")]
        #[ets_ref(dpt = DPT_Switch_Control, when = LogicObjectType::ForcibleControl, text = "Logic 1 {{logic1_description:}}", function = "Output 1 Value")]
        pub logic1_output: ComObject<ComObjectStorage<1>>,

        /// Logic 2 Input A
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 53, name = "Eingangslogik 2 A", display = "Logic", function = "Input 2 A", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 2 {{logic2_description:}}", function = "Input 2 A")]
        pub logic2_input_a: ComObject<DPT_Switch>,

        /// Logic 2 Input B
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 54, name = "Eingangslogik 2 B", display = "Logic", function = "Input 2 B", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 2 {{logic2_description:}}", function = "Input 2 B")]
        pub logic2_input_b: ComObject<DPT_Switch>,

        /// Logic 2 Output (multi-DPT based on LogicObjectType)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(
            index = 55,
            name = "Ausgangslogik 2",
            display = "Logic",
            function = "Output 2",
            flags = C | R | T | LOW,
            selector_param = "logic2_output_type"
        )]
        // MDT has 8 refs for each logic output (4 DPT variants * 2 contexts)
        #[ets_ref(dpt = DPT_Switch, when = LogicObjectType::Switch, text = "Logic 2 {{logic2_description:}}", function = "Output 2")]
        #[ets_ref(dpt = DPT_SceneNumber, when = LogicObjectType::Scene, text = "Logic 2 {{logic2_description:}}", function = "Output 2 Scene")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = LogicObjectType::Value, text = "Logic 2 {{logic2_description:}}", function = "Output 2 Value")]
        #[ets_ref(dpt = DPT_Switch_Control, when = LogicObjectType::ForcibleControl, text = "Logic 2 {{logic2_description:}}", function = "Output 2 Value")]
        #[ets_ref(dpt = DPT_Switch, when = LogicObjectType::Switch, text = "Logic 2 {{logic2_description:}}", function = "Output 2")]
        #[ets_ref(dpt = DPT_SceneNumber, when = LogicObjectType::Scene, text = "Logic 2 {{logic2_description:}}", function = "Output 2 Scene")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = LogicObjectType::Value, text = "Logic 2 {{logic2_description:}}", function = "Output 2 Value")]
        #[ets_ref(dpt = DPT_Switch_Control, when = LogicObjectType::ForcibleControl, text = "Logic 2 {{logic2_description:}}", function = "Output 2 Value")]
        pub logic2_output: ComObject<ComObjectStorage<1>>,

        /// Logic 3 Input A
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 56, name = "Eingangslogik 3 A", display = "Logic", function = "Input 3 A", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 3 {{logic3_description:}}", function = "Input 3 A")]
        pub logic3_input_a: ComObject<DPT_Switch>,

        /// Logic 3 Input B
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 57, name = "Eingangslogik 3 B", display = "Logic", function = "Input 3 B", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 3 {{logic3_description:}}", function = "Input 3 B")]
        pub logic3_input_b: ComObject<DPT_Switch>,

        /// Logic 3 Output (multi-DPT based on LogicObjectType)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(
            index = 58,
            name = "Ausgangslogik 3",
            display = "Logic",
            function = "Output 3",
            flags = C | R | T | LOW,
            selector_param = "logic3_output_type"
        )]
        // MDT has 8 refs for each logic output (4 DPT variants * 2 contexts)
        #[ets_ref(dpt = DPT_Switch, when = LogicObjectType::Switch, text = "Logic 3 {{logic3_description:}}", function = "Output 3")]
        #[ets_ref(dpt = DPT_SceneNumber, when = LogicObjectType::Scene, text = "Logic 3 {{logic3_description:}}", function = "Output 3 Scene")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = LogicObjectType::Value, text = "Logic 3 {{logic3_description:}}", function = "Output 3 Value")]
        #[ets_ref(dpt = DPT_Switch_Control, when = LogicObjectType::ForcibleControl, text = "Logic 3 {{logic3_description:}}", function = "Output 3 Value")]
        #[ets_ref(dpt = DPT_Switch, when = LogicObjectType::Switch, text = "Logic 3 {{logic3_description:}}", function = "Output 3")]
        #[ets_ref(dpt = DPT_SceneNumber, when = LogicObjectType::Scene, text = "Logic 3 {{logic3_description:}}", function = "Output 3 Scene")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = LogicObjectType::Value, text = "Logic 3 {{logic3_description:}}", function = "Output 3 Value")]
        #[ets_ref(dpt = DPT_Switch_Control, when = LogicObjectType::ForcibleControl, text = "Logic 3 {{logic3_description:}}", function = "Output 3 Value")]
        pub logic3_output: ComObject<ComObjectStorage<1>>,

        /// Logic 4 Input A
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 59, name = "Eingangslogik 4 A", display = "Logic", function = "Input 4 A", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 4 {{logic4_description:}}", function = "Input 4 A")]
        pub logic4_input_a: ComObject<DPT_Switch>,

        /// Logic 4 Input B
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 60, name = "Eingangslogik 4 B", display = "Logic", function = "Input 4 B", flags = C | W | T | U | LOW)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 4 {{logic4_description:}}", function = "Input 4 B")]
        pub logic4_input_b: ComObject<DPT_Switch>,

        /// Logic 4 Output (multi-DPT based on LogicObjectType)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(
            index = 61,
            name = "Ausgangslogik 4",
            display = "Logic",
            function = "Output 4",
            flags = C | R | T | LOW,
            selector_param = "logic4_output_type"
        )]
        // MDT has 8 refs for each logic output (4 DPT variants * 2 contexts)
        #[ets_ref(dpt = DPT_Switch, when = LogicObjectType::Switch, text = "Logic 4 {{logic4_description:}}", function = "Output 4")]
        #[ets_ref(dpt = DPT_SceneNumber, when = LogicObjectType::Scene, text = "Logic 4 {{logic4_description:}}", function = "Output 4 Scene")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = LogicObjectType::Value, text = "Logic 4 {{logic4_description:}}", function = "Output 4 Value")]
        #[ets_ref(dpt = DPT_Switch_Control, when = LogicObjectType::ForcibleControl, text = "Logic 4 {{logic4_description:}}", function = "Output 4 Value")]
        #[ets_ref(dpt = DPT_Switch, when = LogicObjectType::Switch, text = "Logic 4 {{logic4_description:}}", function = "Output 4")]
        #[ets_ref(dpt = DPT_SceneNumber, when = LogicObjectType::Scene, text = "Logic 4 {{logic4_description:}}", function = "Output 4 Scene")]
        #[ets_ref(dpt = DPT_Value_1_Ucount, when = LogicObjectType::Value, text = "Logic 4 {{logic4_description:}}", function = "Output 4 Value")]
        #[ets_ref(dpt = DPT_Switch_Control, when = LogicObjectType::ForcibleControl, text = "Logic 4 {{logic4_description:}}", function = "Output 4 Value")]
        pub logic4_output: ComObject<ComObjectStorage<1>>,

        // ====================================================================
        // Dummy Objects (placeholders for future use / padding)
        // Complete list of all 88 MDT objects
        // ====================================================================
        // Button 1 dummies (5-8)
        #[ets(index = 5, name = "Obj5", display = "Dummy", function = "", flags = LOW)]
        pub dummy_5: ComObject<DPT_Switch>,
        #[ets(index = 6, name = "Obj6", display = "Dummy", function = "", flags = LOW)]
        pub dummy_6: ComObject<DPT_Switch>,
        #[ets(index = 7, name = "Obj7", display = "Dummy", function = "", flags = LOW)]
        pub dummy_7: ComObject<DPT_Switch>,
        #[ets(index = 8, name = "Obj8", display = "Dummy", function = "", flags = LOW)]
        pub dummy_8: ComObject<DPT_Switch>,

        // Button 2 dummies (15-18)
        #[ets(index = 15, name = "Obj15", display = "Dummy", function = "", flags = LOW)]
        pub dummy_15: ComObject<DPT_Switch>,
        #[ets(index = 16, name = "Obj16", display = "Dummy", function = "", flags = LOW)]
        pub dummy_16: ComObject<DPT_Switch>,
        #[ets(index = 17, name = "Obj17", display = "Dummy", function = "", flags = LOW)]
        pub dummy_17: ComObject<DPT_Switch>,
        #[ets(index = 18, name = "Obj18", display = "Dummy", function = "", flags = LOW)]
        pub dummy_18: ComObject<DPT_Switch>,

        // Button group 3 dummies (20-28) - 4-byte objects for future extension
        #[ets(index = 20, name = "Obj20", display = "Dummy", function = "", flags = LOW)]
        pub dummy_20: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 21, name = "Obj21", display = "Dummy", function = "", flags = LOW)]
        pub dummy_21: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 22, name = "Obj22", display = "Dummy", function = "", flags = LOW)]
        pub dummy_22: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 23, name = "Obj23", display = "Dummy", function = "", flags = LOW)]
        pub dummy_23: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 24, name = "Obj24", display = "Dummy", function = "", flags = LOW)]
        pub dummy_24: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 25, name = "Obj25", display = "Dummy", function = "", flags = LOW)]
        pub dummy_25: ComObject<DPT_Switch>,
        #[ets(index = 26, name = "Obj26", display = "Dummy", function = "", flags = LOW)]
        pub dummy_26: ComObject<DPT_Switch>,
        #[ets(index = 27, name = "Obj27", display = "Dummy", function = "", flags = LOW)]
        pub dummy_27: ComObject<DPT_Switch>,
        #[ets(index = 28, name = "Obj28", display = "Dummy", function = "", flags = LOW)]
        pub dummy_28: ComObject<DPT_Switch>,

        // Button group 4 dummies (29-39)
        #[ets(index = 29, name = "Obj29", display = "Dummy", function = "", flags = LOW)]
        pub dummy_29: ComObject<DPT_Switch>,
        #[ets(index = 30, name = "Obj30", display = "Dummy", function = "", flags = LOW)]
        pub dummy_30: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 31, name = "Obj31", display = "Dummy", function = "", flags = LOW)]
        pub dummy_31: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 32, name = "Obj32", display = "Dummy", function = "", flags = LOW)]
        pub dummy_32: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 33, name = "Obj33", display = "Dummy", function = "", flags = LOW)]
        pub dummy_33: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 34, name = "Obj34", display = "Dummy", function = "", flags = LOW)]
        pub dummy_34: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 35, name = "Obj35", display = "Dummy", function = "", flags = LOW)]
        pub dummy_35: ComObject<DPT_Switch>,
        #[ets(index = 36, name = "Obj36", display = "Dummy", function = "", flags = LOW)]
        pub dummy_36: ComObject<DPT_Switch>,
        #[ets(index = 37, name = "Obj37", display = "Dummy", function = "", flags = LOW)]
        pub dummy_37: ComObject<DPT_Switch>,
        #[ets(index = 38, name = "Obj38", display = "Dummy", function = "", flags = LOW)]
        pub dummy_38: ComObject<DPT_Switch>,
        #[ets(index = 39, name = "Obj39", display = "Dummy", function = "", flags = LOW)]
        pub dummy_39: ComObject<DPT_Switch>,

        // Slap button dummies (44-48)
        #[ets(index = 44, name = "Obj44", display = "Dummy", function = "", flags = LOW)]
        pub dummy_44: ComObject<DPT_Switch>,
        #[ets(index = 45, name = "Obj45", display = "Dummy", function = "", flags = LOW)]
        pub dummy_45: ComObject<DPT_Switch>,
        #[ets(index = 46, name = "Obj46", display = "Dummy", function = "", flags = LOW)]
        pub dummy_46: ComObject<DPT_Switch>,
        #[ets(index = 47, name = "Obj47", display = "Dummy", function = "", flags = LOW)]
        pub dummy_47: ComObject<DPT_Switch>,
        #[ets(index = 48, name = "Obj48", display = "Dummy", function = "", flags = LOW)]
        pub dummy_48: ComObject<DPT_Switch>,

        // Logic dummies (62-70)
        #[ets(index = 62, name = "Obj62", display = "Dummy", function = "", flags = LOW)]
        pub dummy_62: ComObject<DPT_Value_1_Ucount>,
        #[ets(index = 63, name = "Obj63", display = "Dummy", function = "", flags = LOW)]
        pub dummy_63: ComObject<DPT_Value_1_Ucount>,
        #[ets(index = 64, name = "Obj64", display = "Dummy", function = "", flags = LOW)]
        pub dummy_64: ComObject<DPT_Value_1_Ucount>,
        #[ets(index = 65, name = "Obj65", display = "Dummy", function = "", flags = LOW)]
        pub dummy_65: ComObject<DPT_Value_1_Ucount>,
        #[ets(index = 66, name = "Obj66", display = "Dummy", function = "", flags = LOW)]
        pub dummy_66: ComObject<DPT_Switch>,
        #[ets(index = 67, name = "Obj67", display = "Dummy", function = "", flags = LOW)]
        pub dummy_67: ComObject<DPT_Switch>,
        #[ets(index = 68, name = "Obj68", display = "Dummy", function = "", flags = LOW)]
        pub dummy_68: ComObject<DPT_Switch>,
        #[ets(index = 69, name = "Obj69", display = "Dummy", function = "", flags = LOW)]
        pub dummy_69: ComObject<DPT_Switch>,
        #[ets(index = 70, name = "Obj70", display = "Dummy", function = "", flags = LOW)]
        pub dummy_70: ComObject<DPT_Switch>,
        #[ets(index = 71, name = "Obj71", display = "Dummy", function = "", flags = LOW)]
        pub dummy_71: ComObject<DPT_Switch>,

        // Status area dummies (73-76)
        #[ets(index = 73, name = "Obj73", display = "Dummy", function = "", flags = LOW)]
        pub dummy_73: ComObject<DPT_PropDataType>,
        #[ets(index = 74, name = "Obj74", display = "Dummy", function = "", flags = LOW)]
        pub dummy_74: ComObject<DPT_PropDataType>,
        #[ets(index = 75, name = "Obj75", display = "Dummy", function = "", flags = LOW)]
        pub dummy_75: ComObject<DPT_Switch>,
        #[ets(index = 76, name = "Obj76", display = "Dummy", function = "", flags = LOW)]
        pub dummy_76: ComObject<DPT_Switch>,

        // Reserved area dummies (78-87)
        #[ets(index = 78, name = "Obj78", display = "Dummy", function = "", flags = LOW)]
        pub dummy_78: ComObject<DPT_Switch>,
        #[ets(index = 79, name = "Obj79", display = "Dummy", function = "", flags = LOW)]
        pub dummy_79: ComObject<DPT_PropDataType>,
        #[ets(index = 80, name = "Obj80", display = "Dummy", function = "", flags = LOW)]
        pub dummy_80: ComObject<DPT_Switch>,
        #[ets(index = 81, name = "Obj81", display = "Dummy", function = "", flags = LOW)]
        pub dummy_81: ComObject<DPT_Switch>,
        #[ets(index = 82, name = "Obj82", display = "Dummy", function = "", flags = LOW)]
        pub dummy_82: ComObject<DPT_Switch>,
        #[ets(index = 83, name = "Obj83", display = "Dummy", function = "", flags = LOW)]
        pub dummy_83: ComObject<DPT_Switch>,
        #[ets(index = 84, name = "Obj84", display = "Dummy", function = "", flags = LOW)]
        pub dummy_84: ComObject<DPT_Switch>,
        #[ets(index = 85, name = "Obj85", display = "Dummy", function = "", flags = LOW)]
        pub dummy_85: ComObject<DPT_Switch>,
        #[ets(index = 86, name = "Obj86", display = "Dummy", function = "", flags = LOW)]
        pub dummy_86: ComObject<DPT_Switch>,
        #[ets(index = 87, name = "Obj87", display = "Dummy", function = "", flags = LOW)]
        pub dummy_87: ComObject<DPT_Value_1_Ucount>,
    }
}

// ============================================================================
// Application Parameters
// ============================================================================

/// Application parameters for the MDT Push Button Lite device.
#[derive(Debug, Clone, Copy, EtsParams, Serialize, Deserialize)]
#[repr(C)]
pub struct MdtParams {
    /// Startup time in seconds (2-240), default 2s
    #[ets(display = "Startup time", suffix = "s", default = 2)]
    pub startup_timeout: u16,

    /// Debounce time (80=fast, 100=medium, 150=slow), default: fast (80)
    #[ets(display = "Reaction time on keypress", ets_enum)]
    pub debounce_time: ReactionTime,

    /// Time for long keypress (encoded value), default: 0.4s (33168)
    #[ets(display = "Time for long keypress (Basic setting)", ets_enum)]
    pub long_action_time: TimeForLongKeypress,

    /// Cyclic send mode for operation status, default: not active (0)
    #[ets(display = "Send 'Operation' cyclically", ets_enum)]
    pub mode_cyclic: CyclicSendInterval,

    /// Status for toggle after bus power return, default: request (1)
    #[ets(display = "Status for toggle after bus power return", ets_enum)]
    pub value_read_on_init: RequestNoRequest,

    /// Button 1/2 function type, default: single-button function 2 functions (2)
    #[ets(display = "Buttons 1/2 (top/bottom)", ets_enum)]
    pub eingang_type: ButtonsType,

    /// Slap/Cleaning function enable (hidden in 1-fold Basic - hardware doesn't support it)
    #[ets(display = "Slap / Cleaning function", hidden, ets_enum)]
    pub eingang_type_patsch: GEboolEnableDisable,

    /// Button 1 description text
    #[ets(display = "Description of buttons/objects", string)]
    pub button1_description: [u8; 30],

    /// Button 1 main function (matching MDT ButtonFunction type values)
    #[ets(display = "Single-button function", ets_enum)]
    pub button1_function: ButtonFunction,

    /// Button 1 switch subfunction (default: toggle)
    #[ets(display = "Subfunction", ets_enum)]
    pub button1_switch_type: SwitchSubfunction,

    /// Button 1 blocking object enable
    #[ets(display = "Blocking Object", ets_enum)]
    pub button1_blocking_enable: GEboolEnableDisable,

    /// Button 1 object type selector (for ComObjectRef DPT selection)
    /// Values match MDT's DPTType1Bit: 10=Switch, 1=Bit2, 2=Percent, 3=Decimal, 4=Scene, 6=ColourTemp, 7=Temperature, 8=Brightness, 9=RGB
    /// Default: 2 (Percent) to match MDT P-35
    #[ets(display = "Datapoint type", ets_enum, default = 2)]
    pub button1_object_type: ObjectType,

    /// Button 2 main function (matching MDT ButtonFunction type values)
    #[ets(display = "Single-button function", ets_enum)]
    pub button2_function: ButtonFunction,

    /// Button 2 switch subfunction (default: toggle)
    #[ets(display = "Subfunction", ets_enum)]
    pub button2_switch_type: SwitchSubfunction,

    /// Button 2 blocking object enable
    #[ets(display = "Blocking Object", ets_enum)]
    pub button2_blocking_enable: GEboolEnableDisable,

    /// Button 2 object type selector (for ComObjectRef DPT selection)
    /// Values match MDT's DPTType1Bit: 10=Switch, 1=Bit2, 2=Percent, 3=Decimal, 4=Scene, 6=ColourTemp, 7=Temperature, 8=Brightness, 9=RGB
    /// Default: 2 (Percent) to match MDT P-69
    #[ets(display = "Datapoint type", ets_enum, default = 2)]
    pub button2_object_type: ObjectType,

    /// Slap button object type selector (for ComObjectRef DPT selection)
    #[ets(display = "Object type", ets_enum)]
    pub slap_object_type: SlapObjectType,

    /// Logic 1 type
    #[ets(display = "Setting Logic 1", ets_enum)]
    pub logic1_type: LogicType,

    /// Logic 2 type
    #[ets(display = "Setting Logic 2", ets_enum)]
    pub logic2_type: LogicType,

    /// Logic 3 type
    #[ets(display = "Setting Logic 3", ets_enum)]
    pub logic3_type: LogicType,

    /// Logic 4 type
    #[ets(display = "Setting Logic 4", ets_enum)]
    pub logic4_type: LogicType,

    /// Logic 1 output object type
    #[ets(display = "    Object type 1", ets_enum)]
    pub logic1_output_type: LogicOutputType,

    /// Logic 2 output object type
    #[ets(display = "    Object type 2", ets_enum)]
    pub logic2_output_type: LogicOutputType,

    /// Logic 3 output object type
    #[ets(display = "    Object type 3", ets_enum)]
    pub logic3_output_type: LogicOutputType,

    /// Logic 4 output object type
    #[ets(display = "    Object type 4", ets_enum)]
    pub logic4_output_type: LogicOutputType,

    /// Slap short object type (for status ref selection)
    #[ets(display = "Object type", ets_enum)]
    pub slap_short_object_type: SlapObjectType,

    /// Slap long object type (for status ref selection)
    #[ets(display = "Object type", ets_enum)]
    pub slap_long_object_type: SlapObjectType,

    // ========================================================================
    // Button 1 Value Parameters
    // ========================================================================
    /// Button 1 value for released button (switch mode)
    #[ets(display = "Value released button", ets_enum)]
    pub button1_value_released: GedptSwitch,

    /// Button 1 value for pushed button (switch mode)
    #[ets(display = "Value pushed button", ets_enum)]
    pub button1_value_pushed: GedptSwitch,

    /// Button 1 scene save enable (P-53 equivalent)
    /// MDT: SaveScene_0
    #[ets(display = "Save scene", enum_variants("no save" => 0, "save" => 1))]
    pub button1_scene_save_enable: u8,

    // ========================================================================
    // Button 2 Value Parameters
    // ========================================================================
    /// Button 2 value for released button (switch mode)
    #[ets(display = "Value released button", ets_enum)]
    pub button2_value_released: GedptSwitch,

    /// Button 2 value for pushed button (switch mode)
    #[ets(display = "Value pushed button", ets_enum)]
    pub button2_value_pushed: GedptSwitch,

    /// Button 2 scene save enable (P-87 equivalent)
    /// MDT: SaveScene_1
    #[ets(display = "Save scene", enum_variants("no save" => 0, "save" => 1))]
    pub button2_scene_save_enable: u8,

    // ========================================================================
    // Slap Button Parameters
    // ========================================================================
    /// Slap cleaning mode
    #[ets(display = "Cleaning function", ets_enum)]
    pub slap_cleaning_mode: SlapCleaningMode,

    /// Slap LED colour
    #[ets(display = "LED colour for slap indication", enum_variants("off" => 0, "red" => 1, "green" => 2, "yellow" => 3, "blue" => 4, "pink" => 5, "cyan" => 6, "white" => 16, "no signal slap function over LEDs" => 31))]
    pub slap_led_colour: u8,

    /// Slap short DPT type
    #[ets(display = "Object type short", enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub slap_short_dpt_type: u8,

    /// Slap long DPT type
    #[ets(display = "Object type long", enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub slap_long_dpt_type: u8,

    /// Slap blocking enable
    #[ets(display = "Blocking Object", ets_enum)]
    pub slap_blocking_enable: GEboolEnableDisable,

    // ========================================================================
    // Logic Channel Parameters
    // ========================================================================
    /// Logic 1 external input A type
    #[ets(display = "    External Input A", ets_enum)]
    pub logic1_ext_input_a: ExtInputLogicType,

    /// Logic 1 external input B type
    #[ets(display = "    External Input B", ets_enum)]
    pub logic1_ext_input_b: ExtInputLogicType,

    /// Logic 2 external input A type
    #[ets(display = "    External Input A", ets_enum)]
    pub logic2_ext_input_a: ExtInputLogicType,

    /// Logic 2 external input B type
    #[ets(display = "    External Input B", ets_enum)]
    pub logic2_ext_input_b: ExtInputLogicType,

    /// Logic 3 external input A type
    #[ets(display = "    External Input A", ets_enum)]
    pub logic3_ext_input_a: ExtInputLogicType,

    /// Logic 3 external input B type
    #[ets(display = "    External Input B", ets_enum)]
    pub logic3_ext_input_b: ExtInputLogicType,

    /// Logic 4 external input A type
    #[ets(display = "    External Input A", ets_enum)]
    pub logic4_ext_input_a: ExtInputLogicType,

    /// Logic 4 external input B type
    #[ets(display = "    External Input B", ets_enum)]
    pub logic4_ext_input_b: ExtInputLogicType,

    /// Button 1 short action (P-48 equivalent)
    /// MDT: ButtonShort_0, ValueShort type
    #[ets(display = "Action short keypress", ets_enum)]
    pub button1_short_action: ShortAction,

    /// Button 1 long behavior (P-50 equivalent)
    /// MDT: NumberTelergamLong_0, NumberTelgram type
    #[ets(display = "Behavior on long keypress", enum_variants("do not send short button" => 0, "send short button" => 1))]
    pub button1_long_behavior: u8,

    /// Button 1 long action (P-51 equivalent)
    /// MDT: ButtonLong_0, ValueLong type
    #[ets(display = "Action long keypress", ets_enum)]
    pub button1_long_action: LongAction,

    /// Button 1 delay for released button
    #[ets(display = "Delay for released button", ets_enum)]
    pub button1_delay_state: GEboolEnableDisable,

    /// Button 1 LED color
    #[ets(display = "LED colour", enum_variants("off" => 0, "green" => 1, "red" => 2, "orange" => 3, "blue" => 4, "white" => 5, "pink" => 6))]
    pub button1_led_color: u8,

    /// Button 1 LED brightness
    #[ets(display = "LED brightness", enum_variants("off" => 0, "10%" => 1, "20%" => 2, "30%" => 3, "40%" => 4, "50%" => 5, "60%" => 6, "70%" => 7, "80%" => 8, "90%" => 9, "100%" => 10))]
    pub button1_led_brightness: u8,

    /// Button 1 group function (Group long keypress in MDT)
    #[ets(display = "Group long keypress", ets_enum)]
    pub button1_group_function: GEboolEnableDisable,

    /// Button 1 group send condition (Group extra long keypress in MDT)
    #[ets(display = "Group extra long keypress", ets_enum)]
    pub button1_group_send_condition: GEboolEnableDisable,

    /// Button 1 special function (P-37 equivalent)
    /// MDT: GroupSpecialFunction_0 - switches between "Innovative group control" and "Additional object"
    #[ets(display = "Special function", ets_enum)]
    pub button1_special_function: SpecialFunction,

    /// Button 1 additional object DPT type (P-39 equivalent)
    /// MDT: DPTButtonGrouptSendValue_0 - DPT type for the additional object
    /// Uses same enum values as button1_object_type for comm object ref selection
    #[ets(display = "Datapoint type (2. object)", ets_enum, default = 2)]
    pub button1_additional_object_type: ObjectType,

    /// Button 1 additional object RGB/HSV colour control (P-40 equivalent)
    /// MDT: ModeRGB_HSV_Long_0
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_additional_colour_control: ColourControl,

    /// Button 1 blinds operation function (P-54 equivalent)
    /// MDT: ShutterShortLongInv_0, 1-bit
    #[ets(display = "Operation function", ets_enum)]
    pub button1_operation_function: BlindsOperationFunction,

    /// Button 1 blinds group control extra long (P-55 equivalent)
    /// MDT: ShutterLongGroup_0
    #[ets(display = "Group control extra long", ets_enum)]
    pub button1_group_extra_long: GEboolEnableDisable,

    /// Button 1 RGB/HSV colour control mode (P-36 equivalent)
    /// MDT: ModeRGB_HSV_Short_0, ModeRGB/HSV type - RGB=1, HSV=2
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_colour_control: ColourControl,

    /// Button 1 value function (P-34 equivalent)
    /// MDT: Button_Value_Function_0, ButtonValueType
    #[ets(display = "Subfunction", ets_enum)]
    pub button1_value_function: ButtonValueFunction,

    /// Button 1 DPT type for "send values by state" mode (P-41 equivalent)
    /// MDT: DPTButton_0, DPTType (no Switch option - only for mode 1)
    #[ets(display = "Datapoint type", ets_enum)]
    pub button1_object_type_no_switch: DptType,

    /// Button 1 tip output objects (P-42 equivalent)
    /// MDT: TipOutputObjects_0 - selects common vs different objects/DPT for toggle mode
    #[ets(display = "Output objects", ets_enum)]
    pub button1_tip_output_objects: TipOutputObjects,

    /// Button 1 DPT type for tip 2 in "different objects" mode
    /// Separate selector for the second tip object
    #[ets(display = "Datapoint type", ets_enum, default = 2)]
    pub button1_tip2_object_type: ObjectType,

    /// Button 1 colour control for tip 2
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_tip2_colour_control: ColourControl,

    /// Button 1 DPT type for tip 3 in "different objects" mode
    /// Separate selector for the third tip object
    #[ets(display = "Datapoint type", ets_enum, default = 2)]
    pub button1_tip3_object_type: ObjectType,

    /// Button 1 colour control for tip 3
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_tip3_colour_control: ColourControl,

    /// Button 1 main type H (P-47 equivalent) - hidden dummy param for Mode 7
    /// MDT: OM_inputUsage_mainTypeH_0, dummy8u, Access="None"
    #[ets(display = "", hidden)]
    pub button1_main_type_h: u8,

    /// Button 1 short DPT type (P-49 equivalent) for Mode 7 short action
    /// MDT: Button_Value_short_0, DPTType (no Switch option)
    #[ets(display = "    Datapoint type", ets_enum)]
    pub button1_short_dpt_type: DptType,

    /// Button 1 long DPT type (P-52 equivalent) for Mode 7 long action
    /// MDT: Button_Value_long_0, DPTType (no Switch option)
    #[ets(display = "    Datapoint type", ets_enum)]
    pub button1_long_dpt_type: DptType,

    /// Button 1 long colour control (P-40 equivalent) for Mode 7 long RGB/HSV
    /// MDT: ModeRGB_HSV_Long_0
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_long_colour_control: ColourControl,

    // ========================================================================
    // Button 2 Extended Parameters
    // ========================================================================
    /// Button 2 description text
    #[ets(display = "Description of buttons/objects", string)]
    pub button2_description: [u8; 30],

    /// Button 2 short action (P-48 equivalent for button 2)
    /// MDT: ButtonShort_1, ValueShort type
    #[ets(display = "Action short keypress", ets_enum)]
    pub button2_short_action: ShortAction,

    /// Button 2 long behavior (P-50 equivalent for button 2)
    /// MDT: NumberTelergamLong_1, NumberTelgram type
    #[ets(display = "Behavior on long keypress", enum_variants("do not send short button" => 0, "send short button" => 1))]
    pub button2_long_behavior: u8,

    /// Button 2 long action (P-51 equivalent for button 2)
    /// MDT: ButtonLong_1, ValueLong type
    #[ets(display = "Action long keypress", ets_enum)]
    pub button2_long_action: LongAction,

    /// Button 2 delay for released button
    #[ets(display = "Delay for released button", ets_enum)]
    pub button2_delay_state: GEboolEnableDisable,

    /// Button 2 group function (Group long keypress in MDT)
    #[ets(display = "Group long keypress", ets_enum)]
    pub button2_group_function: GEboolEnableDisable,

    /// Button 2 group send condition (Group extra long keypress in MDT)
    #[ets(display = "Group extra long keypress", ets_enum)]
    pub button2_group_send_condition: GEboolEnableDisable,

    /// Button 2 special function (P-81 equivalent)
    /// MDT: GroupSpecialFunction_1 - switches between "Innovative group control" and "Additional object"
    #[ets(display = "Special function", ets_enum)]
    pub button2_special_function: SpecialFunction,

    /// Button 2 additional object DPT type (P-73 equivalent)
    /// MDT: DPTButtonGrouptSendValue_1 - DPT type for the additional object
    /// Uses same enum values as button2_object_type for comm object ref selection
    #[ets(display = "Datapoint type (2. object)", ets_enum, default = 2)]
    pub button2_additional_object_type: ObjectType,

    /// Button 2 additional object RGB/HSV colour control (P-74 equivalent)
    /// MDT: ModeRGB_HSV_Long_1
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_additional_colour_control: ColourControl,

    /// Button 2 blinds operation function (P-88 equivalent)
    /// MDT: ShutterShortLongInv_1, 1-bit
    #[ets(display = "Operation function", ets_enum)]
    pub button2_operation_function: BlindsOperationFunction,

    /// Button 2 blinds group control extra long (P-89 equivalent)
    /// MDT: ShutterLongGroup_1
    #[ets(display = "Group control extra long", ets_enum)]
    pub button2_group_extra_long: GEboolEnableDisable,

    /// Button 2 RGB/HSV colour control mode (P-70 equivalent)
    /// MDT: ModeRGB_HSV_Short_1, ModeRGB/HSV type - RGB=1, HSV=2
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_colour_control: ColourControl,

    /// Button 2 value function (P-68 equivalent)
    /// MDT: Button_Value_Function_1, ButtonValueType
    #[ets(display = "Subfunction", ets_enum)]
    pub button2_value_function: ButtonValueFunction,

    /// Button 2 DPT type for "send values by state" mode (P-74 equivalent)
    /// MDT: DPTButton_1, DPTType (no Switch option - only for mode 1)
    #[ets(display = "Datapoint type", ets_enum)]
    pub button2_object_type_no_switch: DptType,

    /// Button 2 tip output objects (P-75 equivalent)
    /// MDT: TipOutputObjects_1 - selects common vs different objects/DPT for toggle mode
    #[ets(display = "Output objects", ets_enum)]
    pub button2_tip_output_objects: TipOutputObjects,

    /// Button 2 DPT type for tip 2 in "different objects" mode
    /// Separate selector for the second tip object
    #[ets(display = "Datapoint type", ets_enum, default = 2)]
    pub button2_tip2_object_type: ObjectType,

    /// Button 2 colour control for tip 2
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_tip2_colour_control: ColourControl,

    /// Button 2 DPT type for tip 3 in "different objects" mode
    /// Separate selector for the third tip object
    #[ets(display = "Datapoint type", ets_enum, default = 2)]
    pub button2_tip3_object_type: ObjectType,

    /// Button 2 colour control for tip 3
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_tip3_colour_control: ColourControl,

    /// Button 2 main type H (P-81 equivalent) - hidden dummy param for Mode 7
    /// MDT: OM_inputUsage_mainTypeH_1, dummy8u, Access="None"
    #[ets(display = "", hidden)]
    pub button2_main_type_h: u8,

    /// Button 2 short DPT type (P-83 equivalent) for Mode 7 short action
    /// MDT: Button_Value_short_1, DPTType (no Switch option)
    #[ets(display = "    Datapoint type", ets_enum)]
    pub button2_short_dpt_type: DptType,

    /// Button 2 long DPT type (P-86 equivalent) for Mode 7 long action
    /// MDT: Button_Value_long_1, DPTType (no Switch option)
    #[ets(display = "    Datapoint type", ets_enum)]
    pub button2_long_dpt_type: DptType,

    /// Button 2 long colour control (P-74 equivalent) for Mode 7 long RGB/HSV
    /// MDT: ModeRGB_HSV_Long_1
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_long_colour_control: ColourControl,

    // ========================================================================
    // Two-Button Mode Parameters
    // ========================================================================
    /// Two-button function selector (P-91 equivalent)
    /// MDT: EnableGrupMain_0, EingangFunctionGroup type
    #[ets(display = "Two-button function", type_name = "EingangFunctionGroup", ets_enum)]
    pub two_button_function: TwoButtonFunction,

    /// Button assignment for two-button switch mode (P-92 equivalent)
    /// MDT: ConfigSwitch_0, SwitchType type
    #[ets(display = "Button assignment (1/2)", type_name = "SwitchType", ets_enum)]
    pub button_assignment: ButtonAssignment,

    /// Group long sends condition (P-93 equivalent)
    /// MDT: GroupSwitchLong_0, GroupLongSendCondition type
    #[ets(display = "Group long sends", type_name = "GroupLongSendCondition", enum_variants("send ON/OFF" => 0, "send OFF/ON" => 1, "send toggle" => 2))]
    pub group_long_send_cond: u8,

    /// Group extra long sends condition (P-94 equivalent)
    /// MDT: GroupSwitchExtraLong_0, GroupLongSendCondition type
    #[ets(display = "Group extra long sends", type_name = "GroupLongSendCondition", enum_variants("send ON/OFF" => 0, "send OFF/ON" => 1, "send toggle" => 2))]
    pub group_extra_long_send_cond: u8,

    /// Two-button value function (P-95 equivalent)
    /// MDT: ButtonGroupt_ValueFunction_0, ButtonGrouptValueType type
    #[ets(display = "Subfunction", type_name = "ButtonGrouptValueType", ets_enum)]
    pub two_button_value_function: TwoButtonValueFunction,

    /// Group send option (P-96 equivalent)
    /// MDT: GroupSend_0, GroupSend type
    #[ets(display = "    Group long sends", type_name = "GroupSend", ets_enum)]
    pub group_send_option: GroupSendOption,

    /// Two-button dimmer configuration
    #[ets(display = "Dimmer configuration", enum_variants("brighter/darker" => 0, "darker/brighter" => 1))]
    pub config_dimmer: u8,

    /// Two-button shutter configuration
    #[ets(display = "Shutter configuration", enum_variants("up/down" => 0, "down/up" => 1))]
    pub config_shutter: u8,

    /// Two-button toggle value configuration
    #[ets(display = "Toggle value configuration", enum_variants("value 1/value 2" => 0, "value 2/value 1" => 1))]
    pub config_toggle_value: u8,

    /// Two-button shift value configuration
    #[ets(display = "Shift value configuration", enum_variants("increment/decrement" => 0, "decrement/increment" => 1))]
    pub config_shift_value: u8,

    // ========================================================================
    // Logic Channel Parameters
    // ========================================================================
    /// Logic 1 output inversion
    #[ets(display = "    Invert output", ets_enum)]
    pub logic1_invert_output: YesNo,

    /// Logic 2 output inversion
    #[ets(display = "    Invert output", ets_enum)]
    pub logic2_invert_output: YesNo,

    /// Logic 3 output inversion
    #[ets(display = "    Invert output", ets_enum)]
    pub logic3_invert_output: YesNo,

    /// Logic 4 output inversion
    #[ets(display = "    Invert output", ets_enum)]
    pub logic4_invert_output: YesNo,

    /// Logic 1 description
    #[ets(display = "Description", string)]
    pub logic1_description: [u8; 30],

    /// Logic 2 description
    #[ets(display = "Description", string)]
    pub logic2_description: [u8; 30],

    /// Logic 3 description
    #[ets(display = "Description", string)]
    pub logic3_description: [u8; 30],

    /// Logic 4 description
    #[ets(display = "Description", string)]
    pub logic4_description: [u8; 30],

    /// Logic 1 additional description
    #[ets(display = "Additional description", string)]
    pub logic1_add_description: [u8; 30],

    /// Logic 2 additional description
    #[ets(display = "Additional description", string)]
    pub logic2_add_description: [u8; 30],

    /// Logic 3 additional description
    #[ets(display = "Additional description", string)]
    pub logic3_add_description: [u8; 30],

    /// Logic 4 additional description
    #[ets(display = "Additional description", string)]
    pub logic4_add_description: [u8; 30],

    /// Logic 1 button choice (internal input 0)
    #[ets(display = "Internal Input 1", ets_enum)]
    pub logic1_button_choose_0: LogicButton,

    /// Logic 1 button choice (internal input 1)
    #[ets(display = "Internal Input 1", ets_enum)]
    pub logic1_button_choose_1: LogicButton,

    /// Logic 2 button choice (internal input 0)
    #[ets(display = "Internal Input 1", ets_enum)]
    pub logic2_button_choose_0: LogicButton,

    /// Logic 2 button choice (internal input 1)
    #[ets(display = "Internal Input 1", ets_enum)]
    pub logic2_button_choose_1: LogicButton,

    /// Logic 3 button choice (internal input 0)
    #[ets(display = "Internal Input 1", ets_enum)]
    pub logic3_button_choose_0: LogicButton,

    /// Logic 3 button choice (internal input 1)
    #[ets(display = "Internal Input 1", ets_enum)]
    pub logic3_button_choose_1: LogicButton,

    /// Logic 4 button choice (internal input 0)
    #[ets(display = "Internal Input 1", ets_enum)]
    pub logic4_button_choose_0: LogicButton,

    /// Logic 4 button choice (internal input 1)
    #[ets(display = "Internal Input 1", ets_enum)]
    pub logic4_button_choose_1: LogicButton,

    /// Logic 1 internal button 1 mode
    #[ets(display = "    Push button 1", ets_enum)]
    pub logic1_int_button1: PressedOnOff,

    /// Logic 1 internal button 2 mode
    #[ets(display = "    Push button 2", ets_enum)]
    pub logic1_int_button2: PressedOnOff,

    /// Logic 2 internal button 1 mode
    #[ets(display = "    Push button 1", ets_enum)]
    pub logic2_int_button1: PressedOnOff,

    /// Logic 2 internal button 2 mode
    #[ets(display = "    Push button 2", ets_enum)]
    pub logic2_int_button2: PressedOnOff,

    /// Logic 3 internal button 1 mode
    #[ets(display = "    Push button 1", ets_enum)]
    pub logic3_int_button1: PressedOnOff,

    /// Logic 3 internal button 2 mode
    #[ets(display = "    Push button 2", ets_enum)]
    pub logic3_int_button2: PressedOnOff,

    /// Logic 4 internal button 1 mode
    #[ets(display = "    Push button 1", ets_enum)]
    pub logic4_int_button1: PressedOnOff,

    /// Logic 4 internal button 2 mode
    #[ets(display = "    Push button 2", ets_enum)]
    pub logic4_int_button2: PressedOnOff,

    /// Behaviour on bus power return for logic
    #[ets(display = "Behaviour on bus power return", enum_variants("no request ext. logic objects" => 0, "request ext. logic objects" => 1))]
    pub logic_read_on_init: u8,

    // ========================================================================
    // Union Parameters - Button 1 Values (share same memory locations)
    // ========================================================================
    /// Button 1 sub-type configuration (tip count or value count)
    #[ets(display = "Sub type configuration", union)]
    pub button1_sub_type_h: SubTypeHUnion,

    /// Button 1 value 0 (pushed button / 1st toggle value)
    #[ets(display = "Value pushed button", union)]
    pub button1_value_00: ButtonValueUnion,

    /// Button 1 value 1 (released button / 2nd toggle value / long value)
    #[ets(display = "Value released button", union)]
    pub button1_value_01: ButtonValueUnion,

    /// Button 1 value 2 (3rd toggle value / extra long value)
    #[ets(display = "Value", union)]
    pub button1_value_02: ButtonValueUnion,

    /// Button 1 value 3 (4th toggle value / button 1 value)
    #[ets(display = "Value 3", union)]
    pub button1_value_03: ButtonValueUnion,

    /// Button 1 time duration (long keypress / delay / repeat)
    #[ets(display = "Time for long keypress", union)]
    pub button1_time_duration: TimeDurationUnion,

    /// Button 1 extra long value (switch/forcible control/percent)
    #[ets(display = "Extra long value", union)]
    pub button1_extra_long_value: ExtraLongValueUnion,

    /// Button 1 extra long time (time for extra long keypress)
    #[ets(display = "Time for extra long keypress", union)]
    pub button1_extra_long_time: TimeDurationUnion,

    // ========================================================================
    // Union Parameters - Button 2 Values (share same memory locations)
    // ========================================================================
    /// Button 2 sub-type configuration (tip count or value count)
    #[ets(display = "Sub type configuration", union)]
    pub button2_sub_type_h: SubTypeHUnion,

    /// Button 2 value 0 (pushed button / 1st toggle value)
    #[ets(display = "Value pushed button", union)]
    pub button2_value_00: ButtonValueUnion,

    /// Button 2 value 1 (released button / 2nd toggle value / long value)
    #[ets(display = "Value released button", union)]
    pub button2_value_01: ButtonValueUnion,

    /// Button 2 value 2 (3rd toggle value / extra long value)
    #[ets(display = "Value", union)]
    pub button2_value_02: ButtonValueUnion,

    /// Button 2 value 3 (4th toggle value / button 1 value)
    #[ets(display = "Value 3", union)]
    pub button2_value_03: ButtonValueUnion,

    /// Button 2 time duration (long keypress / delay / repeat)
    #[ets(display = "Time duration", union)]
    pub button2_time_duration: TimeDurationUnion,

    /// Button 2 extra long value
    #[ets(display = "Extra long value", union)]
    pub button2_extra_long_value: ExtraLongValueUnion,

    /// Button 2 extra long time (time for extra long keypress)
    #[ets(display = "Time for extra long keypress", union)]
    pub button2_extra_long_time: TimeDurationUnion,

    // ========================================================================
    // Union Parameters - Panic/Slap Values
    // ========================================================================
    /// Panic value 0
    #[ets(display = "Panic value 0", union)]
    pub panic_value_00: ButtonValueUnion,

    /// Panic value 3
    #[ets(display = "Panic value 3", union)]
    pub panic_value_03: ButtonValueUnion,

    /// Panic time duration
    #[ets(display = "Panic time duration", union)]
    pub panic_time_duration_union: TimeDurationUnion,

    // ========================================================================
    // Union Parameters - Logic Channels
    // ========================================================================
    /// Logic 1 send condition union
    #[ets(display = "", union, hidden)]
    pub logic1_send_condition_union: SendConditionUnion,

    /// Logic 1 value to send union
    #[ets(display = "Logic 1 value", union)]
    pub logic1_value_union: LogicValueUnion,

    /// Logic 2 send condition union
    #[ets(display = "", union, hidden)]
    pub logic2_send_condition_union: SendConditionUnion,

    /// Logic 2 value to send union
    #[ets(display = "Logic 2 value", union)]
    pub logic2_value_union: LogicValueUnion,

    /// Logic 3 send condition union
    #[ets(display = "", union, hidden)]
    pub logic3_send_condition_union: SendConditionUnion,

    /// Logic 3 value to send union
    #[ets(display = "Logic 3 value", union)]
    pub logic3_value_union: LogicValueUnion,

    /// Logic 4 send condition union
    #[ets(display = "", union, hidden)]
    pub logic4_send_condition_union: SendConditionUnion,

    /// Logic 4 value to send union
    #[ets(display = "Logic 4 value", union)]
    pub logic4_value_union: LogicValueUnion,

    // ========================================================================
    // Hidden/Internal Parameters (MDT bookkeeping for ETS)
    // ========================================================================
    /// Button 1 value type (hidden - stores current value mode code for ETS)
    /// This is P-27 in MDT's structure
    #[ets(display = "", hidden)]
    pub button1_value_type: u8,

    /// Button 1 subtype (hidden - stores current subtype code for ETS)
    /// This is P-15 in MDT's structure
    #[ets(display = "", hidden)]
    pub button1_subtype: u8,

    /// Button 2 value type (hidden - stores current value mode code for ETS)
    #[ets(display = "", hidden)]
    pub button2_value_type: u8,

    /// Button 2 subtype (hidden - stores current subtype code for ETS)
    #[ets(display = "", hidden)]
    pub button2_subtype: u8,

    // ========================================================================
    // Dummy/Hidden Parameters (for enabling conditional object display)
    // ========================================================================
    /// Dummy enable parameter (hidden - MDT internal feature for showing all placeholder objects)
    /// When set to 1, all dummy/placeholder ComObjects become visible in ETS.
    #[ets(display = "", hidden, ets_enum)]
    pub dummy_enable: GEboolEnableDisable,
}

// Default and ConstDefault are auto-generated by #[derive(EtsParams)]
// based on #[ets(default = X)] attributes on fields and ConstDefault impls
// for ets_enum and union fields.

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
            ip_address: Ipv4Addr::new(192, 168, 1, 201),
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

impl zweidraehte_platform::NetworkConfig for MockIpPlatform {
    type Error = core::convert::Infallible;

    fn apply_ip_config(&self, _config: &zweidraehte_platform::IpConfig) -> Result<(), Self::Error> {
        Ok(()) // No-op — OS manages networking on Linux.
    }
}

// ============================================================================
// Stack Definition
// ============================================================================

const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();

/// Unified state type.
pub type MdtState = IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MdtParams, MockIpPlatform>;

#[derive(Debug, Clone, Copy)]
pub struct MdtStack;

impl SystemBIpDeviceDef for MdtStack {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const INTERFACE_NAME: &'static str = INTERFACE_NAME;

    type P = MdtParams;
    type CO = comm_objs::MdtComObjects;
    type Transport = zweidraehte_platform::LinuxIpTransport;
    type Platform = MockIpPlatform;
    type State = MdtState;
}

impl StackDefinition for MdtStack {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = MdtParams;
    type CO = comm_objs::MdtComObjects;
    type LLB = KnxNetIpBuilder<zweidraehte_platform::LinuxIpTransport, KnxIpDeviceUdp, 2>;
    type State = MdtState;
    type Mem = SystemBMemoryMap;
    type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<
        'a, MdtState, &'a IpExtensionState<MockIpPlatform>,
    >;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_system_b_objects::<Self, _, _>(state, &Self::memory_layout(), state.extension_state())
    }

    type LayerBuilder = InsecureIpDeviceBuilder;
}

// ============================================================================
// ETS Page Layout
// ============================================================================

impl EtsPageLayout for MdtStack {
    fn page_layout() -> PageStructure {
        ets_pages! {
            device {
                // General settings block (matches MDT PB-1 "pGeneral")
                block "pGeneral" => "General settings" {
                    obj presence
                    // Hidden dummy enable parameter (MDT internal feature)
                    param dummy_enable
                    // When dummy_enable = Active, show all dummy objects (MDT has 57 ComObjectRefRefs here)
                    when @dummy_enable {
                        [GEboolEnableDisable::Active] => {
                            // Dummy objects at various indices
                            obj dummy_5
                            obj dummy_6
                            obj dummy_7
                            obj dummy_8
                            obj dummy_15
                            obj dummy_16
                            obj dummy_17
                            obj dummy_18
                            obj dummy_25
                            obj dummy_26
                            obj dummy_27
                            obj dummy_28
                            obj dummy_44
                            obj dummy_45
                            obj dummy_46
                            obj dummy_47
                            obj dummy_48
                            obj dummy_80
                            obj dummy_81
                            obj dummy_82
                            obj dummy_83
                            obj dummy_84
                            obj dummy_85
                            obj dummy_86
                            obj dummy_87
                            obj dummy_35
                            obj dummy_36
                            obj dummy_37
                            obj dummy_38
                            obj dummy_20
                            obj dummy_21
                            obj dummy_22
                            obj dummy_23
                            obj dummy_24
                            obj dummy_29
                            obj dummy_30
                            obj dummy_31
                            obj dummy_32
                            obj dummy_33
                            obj dummy_34
                            obj dummy_39
                            obj dummy_62
                            obj dummy_63
                            obj dummy_64
                            obj dummy_65
                            obj dummy_66
                            obj dummy_67
                            obj dummy_68
                            obj dummy_69
                            obj dummy_70
                            obj dummy_73
                            obj dummy_74
                            obj dummy_75
                            obj dummy_76
                            obj dummy_78
                            obj dummy_79
                            obj dummy_71
                        }
                    }
                    param startup_timeout
                    param mode_cyclic
                    // Mode object is shown when cyclic mode is enabled (default=true), hidden when NotActive
                    when @mode_cyclic {
                        _ => { obj mode }
                        [CyclicSendInterval::NotActive] => { }
                    }
                    param value_read_on_init
                }

                // Push button functions - MDT includes a choose inside this block for eingang_type
                block "pButtons" => "Push button functions" {
                    param eingang_type
                    param eingang_type_patsch
                    sep " "
                    param debounce_time
                    param long_action_time
                    // MDT has additional hidden params inside this block based on eingang_type
                    // These are dummy/hidden params for internal use, not visible "Time for long keypress"
                    when @eingang_type {
                        // Two-button mode: show LED params, subtype, etc.
                        [ButtonsType::TwoButton] => {
                            param button1_led_color
                            param button1_led_brightness
                            param button1_subtype
                            param button1_value_type
                        }
                        // Single-button 2 functions: no additional visible params
                        [ButtonsType::SingleButton2Functions] => { }
                        // Single-button 1 function: no additional visible params
                        [ButtonsType::SingleButton1Function] => { }
                    }
                }

                // Button blocks based on eingang_type - MDT order: PB1 (2,3), PB2 (2), PB1/2 (1)
                // All three blocks in a single choose to match MDT's structure
                when @eingang_type {
                    // Single-button modes (2, 3) - PB1 block comes first in MDT
                    [ButtonsType::SingleButton2Functions, ButtonsType::SingleButton1Function] => {
                        block "pButton_0" => "    PB1: {{button1_description:Push button 1}}" {
                            param button1_description
                            param button1_function
                            // Mode 0 = switch: nested choose on switch_type (subfunction)
                            when @button1_function {
                                [ButtonFunction::Switch] => {
                                    param button1_switch_type
                                    when @button1_switch_type {
                                        // switch_type 0 = switch (simple) - MDT pattern: direct object output
                                        // In MDT, switch/switch has only "Value pushed button" visible
                                        // The "Value released button" (UP-109) has Access="None" and is hidden
                                        [SwitchSubfunction::Switch] => {
                                            obj_fixed_variant button1_main with [button1_value_type, button1_subtype] => button1_value_00::Switch @ 0 text "Value pushed button"
                                            sep "Innovative group control"
                                            param button1_group_function
                                            when @button1_group_function {
                                                // When P-28=NotActive (no group): UP-109 is hidden (sets internal value)
                                                [GEboolEnableDisable::NotActive] => { }
                                                [GEboolEnableDisable::Active] => {
                                                    // MDT outputs O-2 directly in switch mode (fixed to Switch type)
                                                    objs_by_ref_name ["button1_status_toggle_switch"] with []
                                                    // UP-109 hidden here too (Access="None")
                                                    param button1_group_send_condition
                                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                    when @button1_group_send_condition {
                                                        [GEboolEnableDisable::Active] => {
                                                            obj_direct button1_extra_long with []
                                                            union_variant button1_extra_long_time::ExtraLongKeypressTime
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // switch_type 1 = toggle (with 2 objects) - MDT pattern: no visible Value param
                                        // Toggle mode just toggles ON/OFF based on current status, no value config needed
                                        // Objects are output directly without choose block (fixed to Switch type)
                                        [SwitchSubfunction::Toggle] => {
                                            objs_by_ref_name ["button1_main_switch", "button1_secondary_switch"] with []
                                            // MDT shows hidden params P-26, P-15, P-27 here - we skip visible value params
                                            sep "Innovative group control"
                                            param button1_group_function
                                            when @button1_group_function {
                                                [GEboolEnableDisable::NotActive] => { }
                                                [GEboolEnableDisable::Active] => {
                                                    objs_by_ref_name ["button1_status_toggle_switch"] with []
                                                    param button1_group_send_condition
                                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                    when @button1_group_send_condition {
                                                        [GEboolEnableDisable::Active] => {
                                                            obj_direct button1_extra_long with []
                                                            union_variant button1_extra_long_time::ExtraLongKeypressTime
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // switch_type 2 = send status - MDT pattern: direct object output (fixed to Switch type)
                                        // Shows: O-0 (Send status), Value pushed, Value released, Delay for released button
                                        [SwitchSubfunction::SendStatus] => {
                                            objs_by_ref_name ["button1_main_switch"] with []
                                            param button1_value_pushed
                                            param button1_value_released
                                            param button1_delay_state
                                            when @button1_delay_state {
                                                [GEboolEnableDisable::Active] => {
                                                    union_variant button1_time_duration::DelayTime
                                                }
                                            }
                                        }
                                    }
                                }
                                // Mode 4 = send values
                                [ButtonFunction::SendValues] => {
                                    param button1_value_function
                                    when @button1_value_function {
                                        // value_function 0 = send values
                                        // MDT structure: P-15 (hidden), P-35 (visible), choose P-35 with obj+P-27+UP-xxx
                                        // P-15 is OM_InputUsage_subType_0 (hidden/Access=None)
                                        // P-35 is DPTButton1Bit_0 (Datapoint type)
                                        // P-27 is OM_InputUsage_valueType00_0 (hidden/Access=None)
                                        // value_function 0 = send values
                                        // MDT structure: P-15 (hidden subtype), P-35 (Datapoint type), choose P-35, P-37 (special function)
                                        [ButtonValueFunction::SendValues] => {
                                            param button1_subtype
                                            param button1_object_type
                                            // Choose on object_type (DPT): each when has obj + hidden value_type + value param
                                            obj_with_value button1_main by button1_object_type => button1_value_00 with [button1_value_type] sub_select {
                                                9 => button1_colour_control [(1, button1_main_rgb, Rgb), (2, button1_main_hsv, Hsv)]
                                            }
                                            // P-37 (Special function): switches between "Innovative group control" and "Additional object"
                                            param button1_special_function
                                            when @button1_special_function {
                                                // Special function 0 = Innovative group control
                                                [SpecialFunction::InnovativeGroupControl] => {
                                                    sep "Innovative group control"
                                                    param button1_group_function
                                                    when @button1_group_function {
                                                        // group_function NotActive: just hidden value param
                                                        [GEboolEnableDisable::NotActive] => { }
                                                        // group_function Active: show status toggle object and timing
                                                        [GEboolEnableDisable::Active] => {
                                                            // O-2 (status toggle) depends on object_type for DPT - uses same DPT as main
                                                            obj_with_value button1_status_toggle by button1_object_type => button1_value_01 with [button1_value_type] sub_select {
                                                                9 => button1_colour_control [(1, button1_status_toggle_rgb, Rgb), (2, button1_status_toggle_hsv, Hsv)]
                                                            }
                                                            param button1_group_send_condition
                                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                            when @button1_group_send_condition {
                                                                // NotActive: hidden extra long value
                                                                [GEboolEnableDisable::NotActive] => { }
                                                                // Active: show extra long object and timing
                                                                [GEboolEnableDisable::Active] => {
                                                                    // O-4 (extra long) also depends on object_type
                                                                    obj_with_value button1_extra_long by button1_object_type => button1_extra_long_value with [button1_value_type] sub_select {
                                                                        9 => button1_colour_control [(1, button1_main_rgb, Rgb), (2, button1_main_hsv, Hsv)]
                                                                    }
                                                                    union_variant button1_extra_long_time::ExtraLongKeypressTime
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Special function 1 = Additional object
                                                // MDT: UP-123 (hidden), P-39 (DPT type), choose P-39 with O-2 + UP-109 + value
                                                [SpecialFunction::AdditionalObject] => {
                                                    param button1_additional_object_type
                                                    // O-2 (status toggle) with DPT based on additional_object_type
                                                    // Each DPT value selects a different named ref
                                                    when @button1_additional_object_type {
                                                        [ObjectType::Switch] => {
                                                            objs_by_ref_name ["button1_additional_obj_switch"] with []
                                                            union_variant button1_value_01::Switch text "    Value"
                                                        }
                                                        [ObjectType::Bit2] => {
                                                            objs_by_ref_name ["button1_additional_obj_bit2"] with []
                                                            union_variant button1_value_01::ForcibleControl text "    Value"
                                                        }
                                                        [ObjectType::Percent] => {
                                                            objs_by_ref_name ["button1_additional_obj_percent"] with []
                                                            union_variant button1_value_01::Percent text "    Value"
                                                        }
                                                        [ObjectType::Decimal] => {
                                                            objs_by_ref_name ["button1_additional_obj_decimal"] with []
                                                            union_variant button1_value_01::Decimal text "    Value"
                                                        }
                                                        [ObjectType::Scene] => {
                                                            objs_by_ref_name ["button1_additional_obj_scene"] with []
                                                            union_variant button1_value_01::Scene text "    Value"
                                                        }
                                                        [ObjectType::ColourTemp] => {
                                                            objs_by_ref_name ["button1_additional_obj_colour_temp"] with []
                                                            union_variant button1_value_01::ColourTemp text "    Value"
                                                        }
                                                        [ObjectType::Temperature] => {
                                                            objs_by_ref_name ["button1_additional_obj_temp"] with []
                                                            union_variant button1_value_01::Temperature text "    Value"
                                                        }
                                                        [ObjectType::Brightness] => {
                                                            objs_by_ref_name ["button1_additional_obj_lux"] with []
                                                            union_variant button1_value_01::Brightness text "    Value"
                                                        }
                                                        [ObjectType::Rgb] => {
                                                            param button1_additional_colour_control
                                                            when @button1_additional_colour_control {
                                                                [ColourControl::Rgb] => {
                                                                    objs_by_ref_name ["button1_additional_obj_rgb"] with []
                                                                    union_variant button1_value_01::Rgb text "    Value"
                                                                }
                                                                [ColourControl::Hsv] => {
                                                                    objs_by_ref_name ["button1_additional_obj_hsv"] with []
                                                                    union_variant button1_value_01::Hsv text "    Value"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // value_function 1 = send values by state
                                        // MDT: P-15 (hidden), P-41 (DPT type), choose P-41 with obj + pushed + released + delay
                                        // NOTE: DPT type P-41 uses DPTType (no 1Bit Switch value 10), not DPTType1Bit
                                        // For each DPT: O-0 (comm obj), UP-134/etc (pushed), UP-114/etc (released), P-26 (delay)
                                        [ButtonValueFunction::SendValuesByState] => {
                                            param button1_subtype
                                            param button1_object_type_no_switch
                                            // Choose on object_type_no_switch (DPT): each when has obj + pushed value + released value + delay
                                            when @button1_object_type_no_switch {
                                                // DPT Bit2 = 2Bit Forcible control
                                                [ObjectType::Bit2] => {
                                                    objs_by_ref_name ["button1_main_bit2"] with []
                                                    union_variant button1_value_01::ForcibleControl text "Value pushed button"
                                                    union_variant button1_value_00::ForcibleControl text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT Percent = 1Byte Percent (0...100%)
                                                [ObjectType::Percent] => {
                                                    objs_by_ref_name ["button1_main_percent"] with []
                                                    union_variant button1_value_01::Percent text "Value pushed button"
                                                    union_variant button1_value_00::Percent text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT Decimal = 1Byte Decimal factor (0...255)
                                                [ObjectType::Decimal] => {
                                                    objs_by_ref_name ["button1_main_decimal"] with []
                                                    union_variant button1_value_01::Decimal text "Value pushed button"
                                                    union_variant button1_value_00::Decimal text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT Scene = 1Byte Scene number
                                                [ObjectType::Scene] => {
                                                    objs_by_ref_name ["button1_main_scene"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_01::Scene text "Value pushed button"
                                                    union_variant button1_value_00::Scene text "Value released button"
                                                }
                                                // DPT ColourTemp = 2Byte Colour Temperature (Kelvin)
                                                [ObjectType::ColourTemp] => {
                                                    objs_by_ref_name ["button1_main_colour_temp"] with []
                                                    union_variant button1_value_01::ColourTemp text "Value pushed button"
                                                    union_variant button1_value_00::ColourTemp text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT Temperature = 2Byte Temperature (°C)
                                                [ObjectType::Temperature] => {
                                                    objs_by_ref_name ["button1_main_temp"] with []
                                                    union_variant button1_value_01::Temperature text "Value pushed button"
                                                    union_variant button1_value_00::Temperature text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT Brightness = 2Byte Brightness (Lux)
                                                [ObjectType::Brightness] => {
                                                    objs_by_ref_name ["button1_main_lux"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_01::Brightness text "Value pushed button"
                                                    union_variant button1_value_00::Brightness text "Value released button"
                                                }
                                                // DPT Rgb = 3Byte RGB/HSV
                                                [ObjectType::Rgb] => {
                                                    param button1_delay_state
                                                    param button1_colour_control
                                                    when @button1_colour_control {
                                                        // RGB mode
                                                        [ColourControl::Rgb] => {
                                                            objs_by_ref_name ["button1_main_rgb"] with []
                                                            union_variant button1_value_01::Rgb text "    Value pushed button"
                                                            union_variant button1_value_00::Rgb text "    Value released button"
                                                        }
                                                        // HSV mode
                                                        [ColourControl::Hsv] => {
                                                            objs_by_ref_name ["button1_main_hsv"] with []
                                                            union_variant button1_value_01::Hsv text "    Value pushed button"
                                                            union_variant button1_value_00::Hsv text "    Value released button"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // value_function 2 = toggle values/scenes (up to 4 values)
                                        // MDT: P-41 (DPT without Switch), UP-156 (value count 2/3/4), choose P-41
                                        // Each DPT: obj + delay + value00 + value01 + conditional value02 (when >=3) + value03 (when 4)
                                        [LogicType::SendValueWhenPressed] => {
                                            param button1_object_type_no_switch
                                            union_variant button1_sub_type_h::ValueCount text "Number of values"
                                            when @button1_object_type_no_switch {
                                                // Forcible control
                                                [ObjectType::Bit2] => {
                                                    objs_by_ref_name ["button1_main_bit2"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_00::ForcibleControl text "    1. Toggle value"
                                                    union_variant button1_value_01::ForcibleControl text "    2. Toggle value"
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button1_value_02::ForcibleControl text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button1_value_03::ForcibleControl text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Percent
                                                [ObjectType::Percent] => {
                                                    objs_by_ref_name ["button1_main_percent", "button1_secondary_percent"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_00::Percent text "    1. Toggle value"
                                                    union_variant button1_value_01::Percent text "    2. Toggle value"
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button1_value_02::Percent text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button1_value_03::Percent text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Decimal
                                                [ObjectType::Decimal] => {
                                                    objs_by_ref_name ["button1_main_decimal", "button1_secondary_decimal"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_00::Decimal text "    1. Toggle value"
                                                    union_variant button1_value_01::Decimal text "    2. Toggle value"
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button1_value_02::Decimal text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button1_value_03::Decimal text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Scene
                                                [ObjectType::Scene] => {
                                                    objs_by_ref_name ["button1_main_scene"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_00::Scene text "    1. Toggle Scene number"
                                                    union_variant button1_value_01::Scene text "    2. Toggle Scene number"
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button1_value_02::Scene text "    3. Toggle Scene number"
                                                        }
                                                    }
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button1_value_03::Scene text "    4. Toggle Scene number"
                                                        }
                                                    }
                                                }
                                                // ColourTemp (6)
                                                [6] => {
                                                    objs_by_ref_name ["button1_main_colour_temp"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_00::ColourTemp text "    1. Toggle value"
                                                    union_variant button1_value_01::ColourTemp text "    2. Toggle value"
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button1_value_02::ColourTemp text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button1_value_03::ColourTemp text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Temperature (7)
                                                [7] => {
                                                    objs_by_ref_name ["button1_main_temp"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_00::Temperature text "    1. Toggle value"
                                                    union_variant button1_value_01::Temperature text "    2. Toggle value"
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button1_value_02::Temperature text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button1_value_03::Temperature text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Brightness (8)
                                                [8] => {
                                                    objs_by_ref_name ["button1_main_lux"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_00::Brightness text "    1. Toggle value"
                                                    union_variant button1_value_01::Brightness text "    2. Toggle value"
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button1_value_02::Brightness text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button1_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button1_value_03::Brightness text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // RGB/HSV (9)
                                                [ObjectType::Rgb] => {
                                                    param button1_delay_state
                                                    param button1_colour_control
                                                    when @button1_colour_control {
                                                        [ColourControl::Rgb] => {
                                                            objs_by_ref_name ["button1_main_rgb"] with []
                                                            union_variant button1_value_00::Rgb text "    1. Toggle value"
                                                            union_variant button1_value_01::Rgb text "    2. Toggle value"
                                                            choose_on_union_variant button1_sub_type_h::ValueCount {
                                                                [2, 3] => {
                                                                    union_variant button1_value_02::Rgb text "    3. Toggle value"
                                                                }
                                                            }
                                                            choose_on_union_variant button1_sub_type_h::ValueCount {
                                                                [3] => {
                                                                    union_variant button1_value_03::Rgb text "    4. Toggle value"
                                                                }
                                                            }
                                                        }
                                                        [ColourControl::Hsv] => {
                                                            objs_by_ref_name ["button1_main_hsv"] with []
                                                            union_variant button1_value_00::Hsv text "    1. Toggle value"
                                                            union_variant button1_value_01::Hsv text "    2. Toggle value"
                                                            choose_on_union_variant button1_sub_type_h::ValueCount {
                                                                [2, 3] => {
                                                                    union_variant button1_value_02::Hsv text "    3. Toggle value"
                                                                }
                                                            }
                                                            choose_on_union_variant button1_sub_type_h::ValueCount {
                                                                [3] => {
                                                                    union_variant button1_value_03::Hsv text "    4. Toggle value"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // value_function 3 = Multi-tip function (send values after number of operations)
                                        // MDT: P-42 (output_objects), UP-143 (tip count 2/3), choose P-42
                                        // Common object: P-15 (hidden), P-35 (DPT with Switch), choose P-35
                                        // Different objects: For each tip, separate DPT and obj
                                        [3] => {
                                            param button1_tip_output_objects
                                            union_variant button1_sub_type_h::TipOperations text "Number of tip-operations"
                                            when @button1_tip_output_objects {
                                                // Common object/DPT
                                                [TipOutputObjects::CommonObject] => {
                                                    param button1_subtype
                                                    param button1_object_type
                                                    when @button1_object_type {
                                                        // Switch
                                                        [ObjectType::Switch] => {
                                                            objs_by_ref_name ["button1_main_switch"] with []
                                                            union_variant button1_value_00::Switch text "    Value tip once"
                                                            union_variant button1_value_01::Switch text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [LogicType::SendValueWhenPressed] => {
                                                                    union_variant button1_value_02::Switch text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Forcible control
                                                        [ObjectType::Bit2] => {
                                                            objs_by_ref_name ["button1_main_bit2"] with []
                                                            union_variant button1_value_00::ForcibleControl text "    Value tip once"
                                                            union_variant button1_value_01::ForcibleControl text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [LogicType::SendValueWhenPressed] => {
                                                                    union_variant button1_value_02::ForcibleControl text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Percent
                                                        [ObjectType::Percent] => {
                                                            objs_by_ref_name ["button1_main_percent"] with []
                                                            union_variant button1_value_00::Percent text "    Value tip once"
                                                            union_variant button1_value_01::Percent text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [LogicType::SendValueWhenPressed] => {
                                                                    union_variant button1_value_02::Percent text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Decimal
                                                        [ObjectType::Decimal] => {
                                                            objs_by_ref_name ["button1_main_decimal"] with []
                                                            union_variant button1_value_00::Decimal text "    Value tip once"
                                                            union_variant button1_value_01::Decimal text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [LogicType::SendValueWhenPressed] => {
                                                                    union_variant button1_value_02::Decimal text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Scene
                                                        [ObjectType::Scene] => {
                                                            objs_by_ref_name ["button1_main_scene"] with []
                                                            union_variant button1_value_00::Scene text "    Scene number tip once"
                                                            union_variant button1_value_01::Scene text "    Scene number tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [LogicType::SendValueWhenPressed] => {
                                                                    union_variant button1_value_02::Scene text "    Scene number tip 3 times"
                                                                }
                                                            }
                                                        }
                                                        // ColourTemp
                                                        [ObjectType::ColourTemp] => {
                                                            objs_by_ref_name ["button1_main_colour_temp"] with []
                                                            union_variant button1_value_00::ColourTemp text "    Value tip once"
                                                            union_variant button1_value_01::ColourTemp text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [LogicType::SendValueWhenPressed] => {
                                                                    union_variant button1_value_02::ColourTemp text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Temperature
                                                        [ObjectType::Temperature] => {
                                                            objs_by_ref_name ["button1_main_temp"] with []
                                                            union_variant button1_value_00::Temperature text "    Value tip once"
                                                            union_variant button1_value_01::Temperature text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [LogicType::SendValueWhenPressed] => {
                                                                    union_variant button1_value_02::Temperature text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Brightness
                                                        [ObjectType::Brightness] => {
                                                            objs_by_ref_name ["button1_main_lux"] with []
                                                            union_variant button1_value_00::Brightness text "    Value tip once"
                                                            union_variant button1_value_01::Brightness text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [LogicType::SendValueWhenPressed] => {
                                                                    union_variant button1_value_02::Brightness text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // RGB/HSV
                                                        [ObjectType::Rgb] => {
                                                            param button1_colour_control
                                                            when @button1_colour_control {
                                                                [ColourControl::Rgb] => {
                                                                    objs_by_ref_name ["button1_main_rgb"] with []
                                                                    union_variant button1_value_00::Rgb text "    RGB-Value tip once"
                                                                    union_variant button1_value_01::Rgb text "    RGB-Value tip twice"
                                                                    choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                        [LogicType::SendValueWhenPressed] => {
                                                                            union_variant button1_value_02::Rgb text "    RGB-Value tip triple"
                                                                        }
                                                                    }
                                                                }
                                                                [ColourControl::Hsv] => {
                                                                    objs_by_ref_name ["button1_main_hsv"] with []
                                                                    union_variant button1_value_00::Hsv text "    HSV-Value tip once"
                                                                    union_variant button1_value_01::Hsv text "    HSV-Value tip twice"
                                                                    choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                        [LogicType::SendValueWhenPressed] => {
                                                                            union_variant button1_value_02::Hsv text "    HSV-Value tip triple"
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Different objects/DPT - each tip has its own DPT selector (MDT pattern)
                                                // Each tip gets its own button1_object_type / button1_tip2_object_type / button1_tip3_object_type
                                                [TipOutputObjects::DifferentObjects] => {
                                                    // Tip 1 - uses button1_object_type
                                                    param button1_subtype
                                                    param button1_object_type
                                                    when @button1_object_type {
                                                        [ObjectType::Switch] => { objs_by_ref_name ["button1_tip_switch"] with [] union_variant button1_value_00::Switch text "    Value tip once" }
                                                        [ObjectType::Bit2] => { objs_by_ref_name ["button1_tip_bit2"] with [] union_variant button1_value_00::ForcibleControl text "    Value tip once" }
                                                        [ObjectType::Percent] => { objs_by_ref_name ["button1_tip_percent"] with [] union_variant button1_value_00::Percent text "    Value tip once" }
                                                        [ObjectType::Decimal] => { objs_by_ref_name ["button1_tip_decimal"] with [] union_variant button1_value_00::Decimal text "    Value tip once" }
                                                        [ObjectType::Scene] => { objs_by_ref_name ["button1_tip_scene"] with [] union_variant button1_value_00::Scene text "    Scene number tip once" }
                                                        [ObjectType::ColourTemp] => { objs_by_ref_name ["button1_tip_colour_temp"] with [] union_variant button1_value_00::ColourTemp text "    Value tip once" }
                                                        [ObjectType::Temperature] => { objs_by_ref_name ["button1_tip_temp"] with [] union_variant button1_value_00::Temperature text "    Value tip once" }
                                                        [ObjectType::Brightness] => { objs_by_ref_name ["button1_tip_lux"] with [] union_variant button1_value_00::Brightness text "    Value tip once" }
                                                        [ObjectType::Rgb] => {
                                                            param button1_colour_control
                                                            when @button1_colour_control {
                                                                [ColourControl::Rgb] => { objs_by_ref_name ["button1_tip_rgb"] with [] union_variant button1_value_00::Rgb text "    RGB-Value tip once" }
                                                                [ColourControl::Hsv] => { objs_by_ref_name ["button1_tip_hsv"] with [] union_variant button1_value_00::Hsv text "    HSV-Value tip once" }
                                                            }
                                                        }
                                                    }
                                                    // Tip 2 - uses button1_tip2_object_type (separate DPT selector)
                                                    param button1_tip2_object_type
                                                    when @button1_tip2_object_type {
                                                        [ObjectType::Switch] => { objs_by_ref_name ["button1_2x_tip_switch"] with [] union_variant button1_value_01::Switch text "    Value tip twice" }
                                                        [ObjectType::Bit2] => { objs_by_ref_name ["button1_2x_tip_bit2"] with [] union_variant button1_value_01::ForcibleControl text "    Value tip twice" }
                                                        [ObjectType::Percent] => { objs_by_ref_name ["button1_2x_tip_percent"] with [] union_variant button1_value_01::Percent text "    Value tip twice" }
                                                        [ObjectType::Decimal] => { objs_by_ref_name ["button1_2x_tip_decimal"] with [] union_variant button1_value_01::Decimal text "    Value tip twice" }
                                                        [ObjectType::Scene] => { objs_by_ref_name ["button1_2x_tip_scene"] with [] union_variant button1_value_01::Scene text "    Scene number tip twice" }
                                                        [ObjectType::ColourTemp] => { objs_by_ref_name ["button1_2x_tip_colour_temp"] with [] union_variant button1_value_01::ColourTemp text "    Value tip twice" }
                                                        [ObjectType::Temperature] => { objs_by_ref_name ["button1_2x_tip_temp"] with [] union_variant button1_value_01::Temperature text "    Value tip twice" }
                                                        [ObjectType::Brightness] => { objs_by_ref_name ["button1_2x_tip_lux"] with [] union_variant button1_value_01::Brightness text "    Value tip twice" }
                                                        [ObjectType::Rgb] => {
                                                            param button1_tip2_colour_control
                                                            when @button1_tip2_colour_control {
                                                                [ColourControl::Rgb] => { objs_by_ref_name ["button1_2x_tip_rgb"] with [] union_variant button1_value_01::Rgb text "    RGB-Value tip twice" }
                                                                [ColourControl::Hsv] => { objs_by_ref_name ["button1_2x_tip_hsv"] with [] union_variant button1_value_01::Hsv text "    HSV-Value tip twice" }
                                                            }
                                                        }
                                                    }
                                                    // Tip 3 - only shown when 3 tips selected, uses button1_tip3_object_type
                                                    choose_on_union_variant button1_sub_type_h::TipOperations {
                                                        [LogicType::SendValueWhenPressed] => {
                                                            param button1_tip3_object_type
                                                            when @button1_tip3_object_type {
                                                                [ObjectType::Switch] => { objs_by_ref_name ["button1_3x_tip_switch"] with [] union_variant button1_value_02::Switch text "    Value tip triple" }
                                                                [ObjectType::Bit2] => { objs_by_ref_name ["button1_3x_tip_bit2"] with [] union_variant button1_value_02::ForcibleControl text "    Value tip triple" }
                                                                [ObjectType::Percent] => { objs_by_ref_name ["button1_3x_tip_percent"] with [] union_variant button1_value_02::Percent text "    Value tip triple" }
                                                                [ObjectType::Decimal] => { objs_by_ref_name ["button1_3x_tip_decimal"] with [] union_variant button1_value_02::Decimal text "    Value tip triple" }
                                                                [ObjectType::Scene] => { objs_by_ref_name ["button1_3x_tip_scene"] with [] union_variant button1_value_02::Scene text "    Scene number tip 3 times" }
                                                                [ObjectType::ColourTemp] => { objs_by_ref_name ["button1_3x_tip_colour_temp"] with [] union_variant button1_value_02::ColourTemp text "    Value tip triple" }
                                                                [ObjectType::Temperature] => { objs_by_ref_name ["button1_3x_tip_temp"] with [] union_variant button1_value_02::Temperature text "    Value tip triple" }
                                                                [ObjectType::Brightness] => { objs_by_ref_name ["button1_3x_tip_lux"] with [] union_variant button1_value_02::Brightness text "    Value tip triple" }
                                                                [ObjectType::Rgb] => {
                                                                    param button1_tip3_colour_control
                                                                    when @button1_tip3_colour_control {
                                                                        [ColourControl::Rgb] => { objs_by_ref_name ["button1_3x_tip_rgb"] with [] union_variant button1_value_02::Rgb text "    RGB-Value tip triple" }
                                                                        [ColourControl::Hsv] => { objs_by_ref_name ["button1_3x_tip_hsv"] with [] union_variant button1_value_02::Hsv text "    HSV-Value tip triple" }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                // Mode 7 = switch/send values short/long (with 2 objects)
                                // MDT: P-47 (hidden), P-13 (LED hidden), P-48 (short action), choose P-48,
                                //      separator " ", P-50 (long behavior), choose P-50, P-51 (long action), choose P-51
                                //      After long_action choose: when [0 1 2 3] show UP-110 (time)
                                // Note: For switch OFF/ON/toggle, value params are HIDDEN (Access="None")
                                //       For send values, DPT default is 2 (Percent)
                                [7] => {
                                    param button1_main_type_h
                                    // P-13 (LED color) is hidden in MDT - we output it but it should be Access="None"
                                    param button1_short_action
                                    when @button1_short_action {
                                        // short_action 0 = switch OFF: O-0, P-27 (hidden), UP-116 hidden with Value=0
                                        [ShortAction::SwitchOff] => {
                                            objs_by_ref_name ["button1_main_switch_off"] with []
                                            // P-27 and UP-116 are both hidden - no visible value selector
                                        }
                                        // short_action 1 = switch ON: O-0, P-27 (hidden), UP-116 hidden with Value=1
                                        [ShortAction::SwitchOn] => {
                                            objs_by_ref_name ["button1_main_switch_on"] with []
                                            // P-27 and UP-116 are both hidden - no visible value selector
                                        }
                                        // short_action 2 = toggle: O-0, O-1, P-27 (hidden) - no value params at all
                                        [LogicType::SendValueWhenPressed] => {
                                            objs_by_ref_name ["button1_main_toggle", "button1_secondary_toggle"] with []
                                            // No value selector for toggle
                                        }
                                        // short_action 3 = send values: P-49 (DPT type, default=2=Percent), then choose on DPT with obj+value
                                        [3] => {
                                            param button1_short_dpt_type
                                            when @button1_short_dpt_type {
                                                [ObjectType::Bit2] => {
                                                    objs_by_ref_name ["button1_main_bit2"] with []
                                                    union_variant button1_value_00::ForcibleControl text "    Value"
                                                }
                                                [ObjectType::Percent] => {
                                                    objs_by_ref_name ["button1_main_percent"] with []
                                                    union_variant button1_value_00::Percent text "    Value"
                                                }
                                                [ObjectType::Decimal] => {
                                                    objs_by_ref_name ["button1_main_decimal"] with []
                                                    union_variant button1_value_00::Decimal text "    Value"
                                                }
                                                [ObjectType::Scene] => {
                                                    objs_by_ref_name ["button1_main_scene"] with []
                                                    union_variant button1_value_00::Scene text "    Scene number"
                                                }
                                                [ObjectType::ColourTemp] => {
                                                    objs_by_ref_name ["button1_main_colour_temp"] with []
                                                    union_variant button1_value_00::ColourTemp text "    Value"
                                                }
                                                [ObjectType::Temperature] => {
                                                    objs_by_ref_name ["button1_main_temp"] with []
                                                    union_variant button1_value_00::Temperature text "    Value"
                                                }
                                                [ObjectType::Brightness] => {
                                                    objs_by_ref_name ["button1_main_lux"] with []
                                                    union_variant button1_value_00::Brightness text "    Value"
                                                }
                                                [ObjectType::Rgb] => {
                                                    param button1_colour_control
                                                    when @button1_colour_control {
                                                        [ColourControl::Rgb] => {
                                                            objs_by_ref_name ["button1_main_rgb"] with []
                                                            union_variant button1_value_00::Rgb text "    RGB-Value"
                                                        }
                                                        [ColourControl::Hsv] => {
                                                            objs_by_ref_name ["button1_main_hsv"] with []
                                                            union_variant button1_value_00::Hsv text "    HSV-Value"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // short_action 255 = not active: P-27 only (hidden)
                                        [255] => {
                                            // No visible params
                                        }
                                    }
                                    sep " "
                                    param button1_long_behavior
                                    when @button1_long_behavior {
                                        // 0 = do not send short button: show time (P-15)
                                        [0] => {
                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                        }
                                        // 1 = send short button: show time (P-15)
                                        [1] => {
                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                        }
                                    }
                                    param button1_long_action
                                    when @button1_long_action {
                                        // long_action 0 = switch OFF: O-2, UP-109 (hidden), UP-127 hidden with Value=0
                                        [LongAction::SwitchOff] => {
                                            objs_by_ref_name ["button1_long_switch_off"] with []
                                            // UP-109 and UP-127 are hidden - no visible value selector
                                        }
                                        // long_action 1 = switch ON: O-2, UP-109 (hidden), UP-127 hidden with Value=1
                                        [LongAction::SwitchOn] => {
                                            objs_by_ref_name ["button1_long_switch_on"] with []
                                            // UP-109 and UP-127 are hidden - no visible value selector
                                        }
                                        // long_action 2 = toggle: O-2, O-3, UP-109 (hidden) - no value params
                                        [LogicType::SendValueWhenPressed] => {
                                            objs_by_ref_name ["button1_long_toggle", "button1_long_status_toggle"] with []
                                            // No value selector for toggle
                                        }
                                        // long_action 3 = send values: P-52 (DPT type, default=2=Percent), then choose on DPT with obj+value
                                        [3] => {
                                            param button1_long_dpt_type
                                            when @button1_long_dpt_type {
                                                [ObjectType::Bit2] => {
                                                    objs_by_ref_name ["button1_long_bit2"] with []
                                                    union_variant button1_value_03::ForcibleControl text "    Value"
                                                }
                                                [ObjectType::Percent] => {
                                                    objs_by_ref_name ["button1_long_percent"] with []
                                                    union_variant button1_value_03::Percent text "    Value"
                                                }
                                                [ObjectType::Decimal] => {
                                                    objs_by_ref_name ["button1_long_decimal"] with []
                                                    union_variant button1_value_03::Decimal text "    Value"
                                                }
                                                [ObjectType::Scene] => {
                                                    objs_by_ref_name ["button1_long_scene"] with []
                                                    union_variant button1_value_03::Scene text "    Scene number"
                                                }
                                                [ObjectType::ColourTemp] => {
                                                    objs_by_ref_name ["button1_long_colour_temp"] with []
                                                    union_variant button1_value_03::ColourTemp text "    Value"
                                                }
                                                [ObjectType::Temperature] => {
                                                    objs_by_ref_name ["button1_long_temp"] with []
                                                    union_variant button1_value_03::Temperature text "    Value"
                                                }
                                                [ObjectType::Brightness] => {
                                                    objs_by_ref_name ["button1_long_lux"] with []
                                                    union_variant button1_value_03::Brightness text "    Value"
                                                }
                                                [ObjectType::Rgb] => {
                                                    param button1_long_colour_control
                                                    when @button1_long_colour_control {
                                                        [ColourControl::Rgb] => {
                                                            objs_by_ref_name ["button1_long_rgb"] with []
                                                            union_variant button1_value_03::Rgb text "    RGB-Value"
                                                        }
                                                        [ColourControl::Hsv] => {
                                                            objs_by_ref_name ["button1_long_hsv"] with []
                                                            union_variant button1_value_03::Hsv text "    HSV-Value"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // long_action 255 = not active - no visible params
                                        [255] => {
                                            // No visible params
                                        }
                                    }
                                    // Time shown after long_action choose when long_action in [0,1,2,3]
                                    when @button1_long_action {
                                        [LongAction::SwitchOff, LongAction::SwitchOn, LongAction::Toggle, LongAction::SendValues] => {
                                            union_variant button1_extra_long_time::ExtraLongKeypressTime text "Time for keypress"
                                        }
                                    }
                                }
                                // Mode 2 = blinds/shutter - MDT outputs objects directly (fixed type)
                                // Uses named refs to select the blinds DPT refs
                                [LogicType::SendValueWhenPressed] => {
                                    objs_by_ref_name ["button1_main_blinds", "button1_secondary_blinds", "button1_status_toggle_blinds"] with []
                                    param button1_operation_function
                                    when @button1_operation_function {
                                        [BlindsOperationFunction::LongMoveShortStop] => {
                                            // long=move / short=stop mode
                                            sep "Innovative group control"
                                            param button1_group_extra_long
                                        }
                                        [BlindsOperationFunction::ShortMoveLongStop] => {
                                            // short=move / long=stop mode - no group control
                                        }
                                    }
                                    // Time for long keypress - shown for both operation function modes
                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                    // Extra long objects only when group control is enabled
                                    when @button1_group_extra_long {
                                        [GEboolEnableDisable::Active] => {
                                            objs_direct [button1_status_display, button1_extra_long] with []
                                            union_variant button1_extra_long_time::ExtraLongKeypressTime text "Time for extra long keypress"
                                        }
                                    }
                                }
                                // Mode 1 = dimming - MDT outputs objects directly (fixed type)
                                // Uses named refs to select the dimming DPT refs
                                [ButtonFunction::Dimming] => {
                                    objs_by_ref_name ["button1_main_dimming", "button1_secondary_dimming", "button1_status_toggle_dimming"] with []
                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                }
                                // Mode 3 = scene - MDT: P-53 (Save scene), comm object, UP-117 (Scene number 1-64)
                                // Simple scene mode with save/no-save option
                                [3] => {
                                    param button1_scene_save_enable
                                    when @button1_scene_save_enable {
                                        // No save - use DPT 17.001 (Scene Number)
                                        [0] => {
                                            objs_by_ref_name ["button1_status_toggle_scene_no_save"] with []
                                        }
                                        // Save - use DPT 18.001 (Scene Control) + time for long keypress
                                        [1] => {
                                            objs_by_ref_name ["button1_status_toggle_scene_save"] with []
                                            union_variant button1_time_duration::LongKeypressTime text "    Time for long keypress"
                                        }
                                    }
                                    union_variant button1_value_00::Scene text "Scene number"
                                }
                            }
                            // Blocking object section - shown when default true (all modes except 255)
                            when @button1_function {
                                [ButtonFunction::Switch, ButtonFunction::Dimming, ButtonFunction::BlindsShutter, ButtonFunction::Scene, ButtonFunction::SendValues, ButtonFunction::SwitchSendValuesShortLong] => {
                                    sep " "
                                    param button1_blocking_enable
                                    when @button1_blocking_enable { [GEboolEnableDisable::Active] => { obj button1_blocking } }
                                }
                            }
                        }
                    }
                    // Single-button mode with 2 functions (eingang_type = 2) - PB2 block comes second in MDT
                    [LogicType::SendValueWhenPressed] => {
                        block "pButton_1" => "    PB2: {{button2_description:Push button 2}}" {
                            param button2_description
                            param button2_function
                            // Mode 0 = switch: nested choose on switch_type (subfunction)
                            when @button2_function {
                                [ButtonFunction::Switch] => {
                                    param button2_switch_type
                                    when @button2_switch_type {
                                        // switch_type 0 = switch (simple) - MDT pattern: direct object output
                                        // In MDT, switch/switch has only "Value pushed button" visible
                                        // The "Value released button" (UP-109) has Access="None" and is hidden
                                        [SwitchSubfunction::Switch] => {
                                            obj_fixed_variant button2_main with [button2_value_type, button2_subtype] => button2_value_00::Switch @ 0 text "Value pushed button"
                                            sep "Innovative group control"
                                            param button2_group_function
                                            when @button2_group_function {
                                                // When P-28=NotActive (no group): UP-109 is hidden (sets internal value)
                                                [GEboolEnableDisable::NotActive] => { }
                                                [GEboolEnableDisable::Active] => {
                                                    // MDT outputs O-12 directly in switch mode (fixed to Switch type)
                                                    objs_by_ref_name ["button2_status_toggle_switch"] with []
                                                    // UP-109 hidden here too (Access="None")
                                                    param button2_group_send_condition
                                                    union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                                    when @button2_group_send_condition {
                                                        [GEboolEnableDisable::Active] => {
                                                            obj_direct button2_extra_long with []
                                                            union_variant button2_extra_long_time::ExtraLongKeypressTime
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // switch_type 1 = toggle (with 2 objects) - MDT pattern: no visible Value param
                                        // Toggle mode just toggles ON/OFF based on current status, no value config needed
                                        // Objects are output directly without choose block (fixed to Switch type)
                                        [SwitchSubfunction::Toggle] => {
                                            objs_by_ref_name ["button2_main_switch", "button2_secondary_switch"] with []
                                            // MDT shows hidden params P-60, P-15, P-61 here - we skip visible value params
                                            sep "Innovative group control"
                                            param button2_group_function
                                            when @button2_group_function {
                                                [GEboolEnableDisable::NotActive] => { }
                                                [GEboolEnableDisable::Active] => {
                                                    objs_by_ref_name ["button2_status_toggle_switch"] with []
                                                    param button2_group_send_condition
                                                    union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                                    when @button2_group_send_condition {
                                                        [GEboolEnableDisable::Active] => {
                                                            obj_direct button2_extra_long with []
                                                            union_variant button2_extra_long_time::ExtraLongKeypressTime
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // switch_type 2 = send status - MDT pattern: direct object output (fixed to Switch type)
                                        // Shows: O-10 (Send status), Value pushed, Value released, Delay for released button
                                        [SwitchSubfunction::SendStatus] => {
                                            objs_by_ref_name ["button2_main_switch"] with []
                                            param button2_value_pushed
                                            param button2_value_released
                                            param button2_delay_state
                                            when @button2_delay_state {
                                                [GEboolEnableDisable::Active] => {
                                                    union_variant button2_time_duration::DelayTime
                                                }
                                            }
                                        }
                                    }
                                }
                                // Mode 4 = send values
                                [ButtonFunction::SendValues] => {
                                    param button2_value_function
                                    when @button2_value_function {
                                        // value_function 0 = send values
                                        // MDT structure: P-55 (hidden subtype), P-79 (Datapoint type), choose P-79, P-81 (special function)
                                        [ButtonValueFunction::SendValues] => {
                                            param button2_subtype
                                            param button2_object_type
                                            // Choose on object_type (DPT): each when has obj + hidden value_type + value param
                                            obj_with_value button2_main by button2_object_type => button2_value_00 with [button2_value_type] sub_select {
                                                9 => button2_colour_control [(1, button2_main_rgb, Rgb), (2, button2_main_hsv, Hsv)]
                                            }
                                            // P-81 (Special function): switches between "Innovative group control" and "Additional object"
                                            param button2_special_function
                                            when @button2_special_function {
                                                // Special function 0 = Innovative group control
                                                [SpecialFunction::InnovativeGroupControl] => {
                                                    sep "Innovative group control"
                                                    param button2_group_function
                                                    when @button2_group_function {
                                                        // group_function NotActive: just hidden value param
                                                        [GEboolEnableDisable::NotActive] => { }
                                                        // group_function Active: show status toggle object and timing
                                                        [GEboolEnableDisable::Active] => {
                                                            // O-12 (status toggle) depends on object_type for DPT - uses same DPT as main
                                                            obj_with_value button2_status_toggle by button2_object_type => button2_value_01 with [button2_value_type] sub_select {
                                                                9 => button2_colour_control [(1, button2_status_toggle_rgb, Rgb), (2, button2_status_toggle_hsv, Hsv)]
                                                            }
                                                            param button2_group_send_condition
                                                            union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                                            when @button2_group_send_condition {
                                                                // NotActive: hidden extra long value
                                                                [GEboolEnableDisable::NotActive] => { }
                                                                // Active: show extra long object and timing
                                                                [GEboolEnableDisable::Active] => {
                                                                    // O-14 (extra long) also depends on object_type
                                                                    obj_with_value button2_extra_long by button2_object_type => button2_extra_long_value with [button2_value_type] sub_select {
                                                                        9 => button2_colour_control [(1, button2_main_rgb, Rgb), (2, button2_main_hsv, Hsv)]
                                                                    }
                                                                    union_variant button2_extra_long_time::ExtraLongKeypressTime
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Special function 1 = Additional object
                                                // MDT: UP-189 (hidden), P-73 (DPT type), choose P-73 with O-12 + UP-175 + value
                                                [SpecialFunction::AdditionalObject] => {
                                                    param button2_additional_object_type
                                                    // O-12 (status toggle) with DPT based on additional_object_type
                                                    when @button2_additional_object_type {
                                                        [ObjectType::Switch] => {
                                                            objs_by_ref_name ["button2_additional_obj_switch"] with []
                                                            union_variant button2_value_01::Switch text "    Value"
                                                        }
                                                        [ObjectType::Bit2] => {
                                                            objs_by_ref_name ["button2_additional_obj_bit2"] with []
                                                            union_variant button2_value_01::ForcibleControl text "    Value"
                                                        }
                                                        [ObjectType::Percent] => {
                                                            objs_by_ref_name ["button2_additional_obj_percent"] with []
                                                            union_variant button2_value_01::Percent text "    Value"
                                                        }
                                                        [ObjectType::Decimal] => {
                                                            objs_by_ref_name ["button2_additional_obj_decimal"] with []
                                                            union_variant button2_value_01::Decimal text "    Value"
                                                        }
                                                        [ObjectType::Scene] => {
                                                            objs_by_ref_name ["button2_additional_obj_scene"] with []
                                                            union_variant button2_value_01::Scene text "    Value"
                                                        }
                                                        [ObjectType::ColourTemp] => {
                                                            objs_by_ref_name ["button2_additional_obj_colour_temp"] with []
                                                            union_variant button2_value_01::ColourTemp text "    Value"
                                                        }
                                                        [ObjectType::Temperature] => {
                                                            objs_by_ref_name ["button2_additional_obj_temp"] with []
                                                            union_variant button2_value_01::Temperature text "    Value"
                                                        }
                                                        [ObjectType::Brightness] => {
                                                            objs_by_ref_name ["button2_additional_obj_lux"] with []
                                                            union_variant button2_value_01::Brightness text "    Value"
                                                        }
                                                        [ObjectType::Rgb] => {
                                                            param button2_additional_colour_control
                                                            when @button2_additional_colour_control {
                                                                [ColourControl::Rgb] => {
                                                                    objs_by_ref_name ["button2_additional_obj_rgb"] with []
                                                                    union_variant button2_value_01::Rgb text "    Value"
                                                                }
                                                                [ColourControl::Hsv] => {
                                                                    objs_by_ref_name ["button2_additional_obj_hsv"] with []
                                                                    union_variant button2_value_01::Hsv text "    Value"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // value_function 1 = send values by state
                                        // MDT: P-55 (hidden), P-74 (DPT type), choose P-74 with obj + pushed + released + delay
                                        // NOTE: DPT type P-74 uses DPTType (no 1Bit Switch value 10), not DPTType1Bit
                                        // For each DPT: O-10 (comm obj), UP-192/etc (pushed), UP-172/etc (released), P-60 (delay)
                                        [ButtonValueFunction::SendValuesByState] => {
                                            param button2_subtype
                                            param button2_object_type_no_switch
                                            // Choose on object_type_no_switch (DPT): each when has obj + pushed value + released value + delay
                                            when @button2_object_type_no_switch {
                                                // DPT Bit2 = 2Bit Forcible control
                                                [ObjectType::Bit2] => {
                                                    objs_by_ref_name ["button2_main_bit2"] with []
                                                    union_variant button2_value_01::ForcibleControl text "Value pushed button"
                                                    union_variant button2_value_00::ForcibleControl text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT Percent = 1Byte Percent (0...100%)
                                                [ObjectType::Percent] => {
                                                    objs_by_ref_name ["button2_main_percent"] with []
                                                    union_variant button2_value_01::Percent text "Value pushed button"
                                                    union_variant button2_value_00::Percent text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT Decimal = 1Byte Decimal factor (0...255)
                                                [ObjectType::Decimal] => {
                                                    objs_by_ref_name ["button2_main_decimal"] with []
                                                    union_variant button2_value_01::Decimal text "Value pushed button"
                                                    union_variant button2_value_00::Decimal text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT Scene = 1Byte Scene number
                                                [ObjectType::Scene] => {
                                                    objs_by_ref_name ["button2_main_scene"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_01::Scene text "Value pushed button"
                                                    union_variant button2_value_00::Scene text "Value released button"
                                                }
                                                // DPT ColourTemp = 2Byte Colour Temperature (Kelvin)
                                                [ObjectType::ColourTemp] => {
                                                    objs_by_ref_name ["button2_main_colour_temp"] with []
                                                    union_variant button2_value_01::ColourTemp text "Value pushed button"
                                                    union_variant button2_value_00::ColourTemp text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT Temperature = 2Byte Temperature (°C)
                                                [ObjectType::Temperature] => {
                                                    objs_by_ref_name ["button2_main_temp"] with []
                                                    union_variant button2_value_01::Temperature text "Value pushed button"
                                                    union_variant button2_value_00::Temperature text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT Brightness = 2Byte Brightness (Lux)
                                                [ObjectType::Brightness] => {
                                                    objs_by_ref_name ["button2_main_lux"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_01::Brightness text "Value pushed button"
                                                    union_variant button2_value_00::Brightness text "Value released button"
                                                }
                                                // DPT Rgb = 3Byte RGB/HSV
                                                [ObjectType::Rgb] => {
                                                    param button2_delay_state
                                                    param button2_colour_control
                                                    when @button2_colour_control {
                                                        // RGB mode
                                                        [ColourControl::Rgb] => {
                                                            objs_by_ref_name ["button2_main_rgb"] with []
                                                            union_variant button2_value_01::Rgb text "    Value pushed button"
                                                            union_variant button2_value_00::Rgb text "    Value released button"
                                                        }
                                                        // HSV mode
                                                        [ColourControl::Hsv] => {
                                                            objs_by_ref_name ["button2_main_hsv"] with []
                                                            union_variant button2_value_01::Hsv text "    Value pushed button"
                                                            union_variant button2_value_00::Hsv text "    Value released button"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // value_function 2 = toggle values/scenes (up to 4 values)
                                        // MDT: P-74 (DPT without Switch), UP-213 (value count 2/3/4), choose P-74
                                        // Each DPT: obj + delay + value00 + value01 + conditional value02 (when >=3) + value03 (when 4)
                                        [LogicType::SendValueWhenPressed] => {
                                            param button2_object_type_no_switch
                                            union_variant button2_sub_type_h::ValueCount text "Number of values"
                                            when @button2_object_type_no_switch {
                                                // Forcible control
                                                [ObjectType::Bit2] => {
                                                    objs_by_ref_name ["button2_main_bit2"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_00::ForcibleControl text "    1. Toggle value"
                                                    union_variant button2_value_01::ForcibleControl text "    2. Toggle value"
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button2_value_02::ForcibleControl text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button2_value_03::ForcibleControl text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Percent
                                                [ObjectType::Percent] => {
                                                    objs_by_ref_name ["button2_main_percent", "button2_secondary_percent"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_00::Percent text "    1. Toggle value"
                                                    union_variant button2_value_01::Percent text "    2. Toggle value"
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button2_value_02::Percent text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button2_value_03::Percent text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Decimal
                                                [ObjectType::Decimal] => {
                                                    objs_by_ref_name ["button2_main_decimal", "button2_secondary_decimal"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_00::Decimal text "    1. Toggle value"
                                                    union_variant button2_value_01::Decimal text "    2. Toggle value"
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button2_value_02::Decimal text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button2_value_03::Decimal text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Scene
                                                [ObjectType::Scene] => {
                                                    objs_by_ref_name ["button2_main_scene"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_00::Scene text "    1. Toggle Scene number"
                                                    union_variant button2_value_01::Scene text "    2. Toggle Scene number"
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button2_value_02::Scene text "    3. Toggle Scene number"
                                                        }
                                                    }
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button2_value_03::Scene text "    4. Toggle Scene number"
                                                        }
                                                    }
                                                }
                                                // ColourTemp
                                                [ObjectType::ColourTemp] => {
                                                    objs_by_ref_name ["button2_main_colour_temp"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_00::ColourTemp text "    1. Toggle value"
                                                    union_variant button2_value_01::ColourTemp text "    2. Toggle value"
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button2_value_02::ColourTemp text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button2_value_03::ColourTemp text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Temperature
                                                [ObjectType::Temperature] => {
                                                    objs_by_ref_name ["button2_main_temp"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_00::Temperature text "    1. Toggle value"
                                                    union_variant button2_value_01::Temperature text "    2. Toggle value"
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button2_value_02::Temperature text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button2_value_03::Temperature text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // Brightness
                                                [ObjectType::Brightness] => {
                                                    objs_by_ref_name ["button2_main_lux"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_00::Brightness text "    1. Toggle value"
                                                    union_variant button2_value_01::Brightness text "    2. Toggle value"
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [2, 3] => {
                                                            union_variant button2_value_02::Brightness text "    3. Toggle value"
                                                        }
                                                    }
                                                    choose_on_union_variant button2_sub_type_h::ValueCount {
                                                        [3] => {
                                                            union_variant button2_value_03::Brightness text "    4. Toggle value"
                                                        }
                                                    }
                                                }
                                                // RGB/HSV
                                                [ObjectType::Rgb] => {
                                                    param button2_delay_state
                                                    param button2_colour_control
                                                    when @button2_colour_control {
                                                        [ColourControl::Rgb] => {
                                                            objs_by_ref_name ["button2_main_rgb"] with []
                                                            union_variant button2_value_00::Rgb text "    1. Toggle value"
                                                            union_variant button2_value_01::Rgb text "    2. Toggle value"
                                                            choose_on_union_variant button2_sub_type_h::ValueCount {
                                                                [2, 3] => {
                                                                    union_variant button2_value_02::Rgb text "    3. Toggle value"
                                                                }
                                                            }
                                                            choose_on_union_variant button2_sub_type_h::ValueCount {
                                                                [3] => {
                                                                    union_variant button2_value_03::Rgb text "    4. Toggle value"
                                                                }
                                                            }
                                                        }
                                                        [ColourControl::Hsv] => {
                                                            objs_by_ref_name ["button2_main_hsv"] with []
                                                            union_variant button2_value_00::Hsv text "    1. Toggle value"
                                                            union_variant button2_value_01::Hsv text "    2. Toggle value"
                                                            choose_on_union_variant button2_sub_type_h::ValueCount {
                                                                [2, 3] => {
                                                                    union_variant button2_value_02::Hsv text "    3. Toggle value"
                                                                }
                                                            }
                                                            choose_on_union_variant button2_sub_type_h::ValueCount {
                                                                [3] => {
                                                                    union_variant button2_value_03::Hsv text "    4. Toggle value"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // value_function 3 = Multi-tip function (send values after number of operations)
                                        // MDT: P-75 (output_objects), UP-201 (tip count 2/3), choose P-75
                                        // Common object: P-55 (hidden), P-79 (DPT with Switch), choose P-79
                                        // Different objects: For each tip, separate DPT and obj
                                        [3] => {
                                            param button2_tip_output_objects
                                            union_variant button2_sub_type_h::TipOperations text "Number of tip-operations"
                                            when @button2_tip_output_objects {
                                                // Common object/DPT
                                                [TipOutputObjects::CommonObject] => {
                                                    param button2_subtype
                                                    param button2_object_type
                                                    when @button2_object_type {
                                                        // Switch
                                                        [ObjectType::Switch] => {
                                                            objs_by_ref_name ["button2_main_switch"] with []
                                                            union_variant button2_value_00::Switch text "    Value tip once"
                                                            union_variant button2_value_01::Switch text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Switch text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Forcible control
                                                        [ObjectType::Bit2] => {
                                                            objs_by_ref_name ["button2_main_bit2"] with []
                                                            union_variant button2_value_00::ForcibleControl text "    Value tip once"
                                                            union_variant button2_value_01::ForcibleControl text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::ForcibleControl text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Percent
                                                        [ObjectType::Percent] => {
                                                            objs_by_ref_name ["button2_main_percent"] with []
                                                            union_variant button2_value_00::Percent text "    Value tip once"
                                                            union_variant button2_value_01::Percent text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Percent text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Decimal
                                                        [ObjectType::Decimal] => {
                                                            objs_by_ref_name ["button2_main_decimal"] with []
                                                            union_variant button2_value_00::Decimal text "    Value tip once"
                                                            union_variant button2_value_01::Decimal text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Decimal text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Scene
                                                        [ObjectType::Scene] => {
                                                            objs_by_ref_name ["button2_main_scene"] with []
                                                            union_variant button2_value_00::Scene text "    Scene number tip once"
                                                            union_variant button2_value_01::Scene text "    Scene number tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Scene text "    Scene number tip 3 times"
                                                                }
                                                            }
                                                        }
                                                        // ColourTemp
                                                        [ObjectType::ColourTemp] => {
                                                            objs_by_ref_name ["button2_main_colour_temp"] with []
                                                            union_variant button2_value_00::ColourTemp text "    Value tip once"
                                                            union_variant button2_value_01::ColourTemp text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::ColourTemp text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Temperature
                                                        [ObjectType::Temperature] => {
                                                            objs_by_ref_name ["button2_main_temp"] with []
                                                            union_variant button2_value_00::Temperature text "    Value tip once"
                                                            union_variant button2_value_01::Temperature text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Temperature text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Brightness
                                                        [ObjectType::Brightness] => {
                                                            objs_by_ref_name ["button2_main_lux"] with []
                                                            union_variant button2_value_00::Brightness text "    Value tip once"
                                                            union_variant button2_value_01::Brightness text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Brightness text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // RGB/HSV
                                                        [ObjectType::Rgb] => {
                                                            param button2_colour_control
                                                            when @button2_colour_control {
                                                                [ColourControl::Rgb] => {
                                                                    objs_by_ref_name ["button2_main_rgb"] with []
                                                                    union_variant button2_value_00::Rgb text "    RGB-Value tip once"
                                                                    union_variant button2_value_01::Rgb text "    RGB-Value tip twice"
                                                                    choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                        [2] => {
                                                                            union_variant button2_value_02::Rgb text "    RGB-Value tip triple"
                                                                        }
                                                                    }
                                                                }
                                                                [ColourControl::Hsv] => {
                                                                    objs_by_ref_name ["button2_main_hsv"] with []
                                                                    union_variant button2_value_00::Hsv text "    HSV-Value tip once"
                                                                    union_variant button2_value_01::Hsv text "    HSV-Value tip twice"
                                                                    choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                        [2] => {
                                                                            union_variant button2_value_02::Hsv text "    HSV-Value tip triple"
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Different objects/DPT - each tip has its own DPT selector (MDT pattern)
                                                // Each tip gets its own button2_object_type / button2_tip2_object_type / button2_tip3_object_type
                                                [TipOutputObjects::DifferentObjects] => {
                                                    // Tip 1 - uses button2_object_type
                                                    param button2_subtype
                                                    param button2_object_type
                                                    when @button2_object_type {
                                                        [ObjectType::Switch] => { objs_by_ref_name ["button2_tip_switch"] with [] union_variant button2_value_00::Switch text "    Value tip once" }
                                                        [ObjectType::Bit2] => { objs_by_ref_name ["button2_tip_bit2"] with [] union_variant button2_value_00::ForcibleControl text "    Value tip once" }
                                                        [ObjectType::Percent] => { objs_by_ref_name ["button2_tip_percent"] with [] union_variant button2_value_00::Percent text "    Value tip once" }
                                                        [ObjectType::Decimal] => { objs_by_ref_name ["button2_tip_decimal"] with [] union_variant button2_value_00::Decimal text "    Value tip once" }
                                                        [ObjectType::Scene] => { objs_by_ref_name ["button2_tip_scene"] with [] union_variant button2_value_00::Scene text "    Scene number tip once" }
                                                        [ObjectType::ColourTemp] => { objs_by_ref_name ["button2_tip_colour_temp"] with [] union_variant button2_value_00::ColourTemp text "    Value tip once" }
                                                        [ObjectType::Temperature] => { objs_by_ref_name ["button2_tip_temp"] with [] union_variant button2_value_00::Temperature text "    Value tip once" }
                                                        [ObjectType::Brightness] => { objs_by_ref_name ["button2_tip_lux"] with [] union_variant button2_value_00::Brightness text "    Value tip once" }
                                                        [ObjectType::Rgb] => {
                                                            param button2_colour_control
                                                            when @button2_colour_control {
                                                                [ColourControl::Rgb] => { objs_by_ref_name ["button2_tip_rgb"] with [] union_variant button2_value_00::Rgb text "    RGB-Value tip once" }
                                                                [ColourControl::Hsv] => { objs_by_ref_name ["button2_tip_hsv"] with [] union_variant button2_value_00::Hsv text "    HSV-Value tip once" }
                                                            }
                                                        }
                                                    }
                                                    // Tip 2 - uses button2_tip2_object_type (separate DPT selector)
                                                    param button2_tip2_object_type
                                                    when @button2_tip2_object_type {
                                                        [ObjectType::Switch] => { objs_by_ref_name ["button2_2x_tip_switch"] with [] union_variant button2_value_01::Switch text "    Value tip twice" }
                                                        [ObjectType::Bit2] => { objs_by_ref_name ["button2_2x_tip_bit2"] with [] union_variant button2_value_01::ForcibleControl text "    Value tip twice" }
                                                        [ObjectType::Percent] => { objs_by_ref_name ["button2_2x_tip_percent"] with [] union_variant button2_value_01::Percent text "    Value tip twice" }
                                                        [ObjectType::Decimal] => { objs_by_ref_name ["button2_2x_tip_decimal"] with [] union_variant button2_value_01::Decimal text "    Value tip twice" }
                                                        [ObjectType::Scene] => { objs_by_ref_name ["button2_2x_tip_scene"] with [] union_variant button2_value_01::Scene text "    Scene number tip twice" }
                                                        [ObjectType::ColourTemp] => { objs_by_ref_name ["button2_2x_tip_colour_temp"] with [] union_variant button2_value_01::ColourTemp text "    Value tip twice" }
                                                        [ObjectType::Temperature] => { objs_by_ref_name ["button2_2x_tip_temp"] with [] union_variant button2_value_01::Temperature text "    Value tip twice" }
                                                        [ObjectType::Brightness] => { objs_by_ref_name ["button2_2x_tip_lux"] with [] union_variant button2_value_01::Brightness text "    Value tip twice" }
                                                        [ObjectType::Rgb] => {
                                                            param button2_tip2_colour_control
                                                            when @button2_tip2_colour_control {
                                                                [ColourControl::Rgb] => { objs_by_ref_name ["button2_2x_tip_rgb"] with [] union_variant button2_value_01::Rgb text "    RGB-Value tip twice" }
                                                                [ColourControl::Hsv] => { objs_by_ref_name ["button2_2x_tip_hsv"] with [] union_variant button2_value_01::Hsv text "    HSV-Value tip twice" }
                                                            }
                                                        }
                                                    }
                                                    // Tip 3 - only shown when 3 tips selected, uses button2_tip3_object_type
                                                    choose_on_union_variant button2_sub_type_h::TipOperations {
                                                        [2] => {
                                                            param button2_tip3_object_type
                                                            when @button2_tip3_object_type {
                                                                [ObjectType::Switch] => { objs_by_ref_name ["button2_3x_tip_switch"] with [] union_variant button2_value_02::Switch text "    Value tip triple" }
                                                                [ObjectType::Bit2] => { objs_by_ref_name ["button2_3x_tip_bit2"] with [] union_variant button2_value_02::ForcibleControl text "    Value tip triple" }
                                                                [ObjectType::Percent] => { objs_by_ref_name ["button2_3x_tip_percent"] with [] union_variant button2_value_02::Percent text "    Value tip triple" }
                                                                [ObjectType::Decimal] => { objs_by_ref_name ["button2_3x_tip_decimal"] with [] union_variant button2_value_02::Decimal text "    Value tip triple" }
                                                                [ObjectType::Scene] => { objs_by_ref_name ["button2_3x_tip_scene"] with [] union_variant button2_value_02::Scene text "    Scene number tip 3 times" }
                                                                [ObjectType::ColourTemp] => { objs_by_ref_name ["button2_3x_tip_colour_temp"] with [] union_variant button2_value_02::ColourTemp text "    Value tip triple" }
                                                                [ObjectType::Temperature] => { objs_by_ref_name ["button2_3x_tip_temp"] with [] union_variant button2_value_02::Temperature text "    Value tip triple" }
                                                                [ObjectType::Brightness] => { objs_by_ref_name ["button2_3x_tip_lux"] with [] union_variant button2_value_02::Brightness text "    Value tip triple" }
                                                                [ObjectType::Rgb] => {
                                                                    param button2_tip3_colour_control
                                                                    when @button2_tip3_colour_control {
                                                                        [ColourControl::Rgb] => { objs_by_ref_name ["button2_3x_tip_rgb"] with [] union_variant button2_value_02::Rgb text "    RGB-Value tip triple" }
                                                                        [ColourControl::Hsv] => { objs_by_ref_name ["button2_3x_tip_hsv"] with [] union_variant button2_value_02::Hsv text "    HSV-Value tip triple" }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                // Mode 7 = switch/send values short/long (with 2 objects)
                                // MDT: P-81 (hidden), P-57 (LED hidden), P-82 (short action), choose P-82,
                                //      separator " ", P-84 (long behavior), choose P-84, P-85 (long action), choose P-85
                                //      After long_action choose: when [0 1 2 3] show UP-176 (time)
                                [7] => {
                                    param button2_main_type_h
                                    // P-57 (LED color) is hidden in MDT - Access="None"
                                    param button2_short_action
                                    when @button2_short_action {
                                        // short_action 0 = switch OFF: O-10, hidden value preset to 0
                                        [ShortAction::SwitchOff] => {
                                            objs_by_ref_name ["button2_main_switch_off"] with []
                                            // No visible value selector - MDT uses Access="None"
                                        }
                                        // short_action 1 = switch ON: O-10, hidden value preset to 1
                                        [ShortAction::SwitchOn] => {
                                            objs_by_ref_name ["button2_main_switch_on"] with []
                                            // No visible value selector - MDT uses Access="None"
                                        }
                                        // short_action 2 = toggle: O-10, O-11, no value params
                                        [2] => {
                                            objs_by_ref_name ["button2_main_toggle", "button2_secondary_toggle"] with []
                                            // No value selector for toggle
                                        }
                                        // short_action 3 = send values: P-83 (DPT type), then choose on DPT with obj+value
                                        [3] => {
                                            param button2_short_dpt_type
                                            when @button2_short_dpt_type {
                                                [ObjectType::Bit2] => {
                                                    objs_by_ref_name ["button2_main_bit2"] with []
                                                    union_variant button2_value_00::ForcibleControl text "    Value"
                                                }
                                                [ObjectType::Percent] => {
                                                    objs_by_ref_name ["button2_main_percent"] with []
                                                    union_variant button2_value_00::Percent text "    Value"
                                                }
                                                [ObjectType::Decimal] => {
                                                    objs_by_ref_name ["button2_main_decimal"] with []
                                                    union_variant button2_value_00::Decimal text "    Value"
                                                }
                                                [ObjectType::Scene] => {
                                                    objs_by_ref_name ["button2_main_scene"] with []
                                                    union_variant button2_value_00::Scene text "    Scene number"
                                                }
                                                [ObjectType::ColourTemp] => {
                                                    objs_by_ref_name ["button2_main_colour_temp"] with []
                                                    union_variant button2_value_00::ColourTemp text "    Value"
                                                }
                                                [ObjectType::Temperature] => {
                                                    objs_by_ref_name ["button2_main_temp"] with []
                                                    union_variant button2_value_00::Temperature text "    Value"
                                                }
                                                [ObjectType::Brightness] => {
                                                    objs_by_ref_name ["button2_main_lux"] with []
                                                    union_variant button2_value_00::Brightness text "    Value"
                                                }
                                                [ObjectType::Rgb] => {
                                                    param button2_colour_control
                                                    when @button2_colour_control {
                                                        [ColourControl::Rgb] => {
                                                            objs_by_ref_name ["button2_main_rgb"] with []
                                                            union_variant button2_value_00::Rgb text "    RGB-Value"
                                                        }
                                                        [ColourControl::Hsv] => {
                                                            objs_by_ref_name ["button2_main_hsv"] with []
                                                            union_variant button2_value_00::Hsv text "    HSV-Value"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // short_action 255 = not active: hidden only
                                        [255] => {
                                            // No visible params
                                        }
                                    }
                                    sep " "
                                    param button2_long_behavior
                                    when @button2_long_behavior {
                                        // 0 = do not send short button: show time (P-55)
                                        [0] => {
                                            union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                        }
                                        // 1 = send short button: show time (P-55)
                                        [1] => {
                                            union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                        }
                                    }
                                    param button2_long_action
                                    when @button2_long_action {
                                        // long_action 0 = switch OFF: O-12, hidden value preset to 0
                                        [LongAction::SwitchOff] => {
                                            objs_by_ref_name ["button2_long_switch_off"] with []
                                            // No visible value selector - MDT uses Access="None"
                                        }
                                        // long_action 1 = switch ON: O-12, hidden value preset to 1
                                        [LongAction::SwitchOn] => {
                                            objs_by_ref_name ["button2_long_switch_on"] with []
                                            // No visible value selector - MDT uses Access="None"
                                        }
                                        // long_action 2 = toggle: O-12, O-13, no value params
                                        [2] => {
                                            objs_by_ref_name ["button2_long_toggle", "button2_long_status_toggle"] with []
                                            // No value selector for toggle
                                        }
                                        // long_action 3 = send values: P-86 (DPT type), then choose on DPT with obj+value
                                        [3] => {
                                            param button2_long_dpt_type
                                            when @button2_long_dpt_type {
                                                [1] => {
                                                    objs_by_ref_name ["button2_long_bit2"] with []
                                                    union_variant button2_value_03::ForcibleControl text "    Value"
                                                }
                                                [2] => {
                                                    objs_by_ref_name ["button2_long_percent"] with []
                                                    union_variant button2_value_03::Percent text "    Value"
                                                }
                                                [3] => {
                                                    objs_by_ref_name ["button2_long_decimal"] with []
                                                    union_variant button2_value_03::Decimal text "    Value"
                                                }
                                                [4] => {
                                                    objs_by_ref_name ["button2_long_scene"] with []
                                                    union_variant button2_value_03::Scene text "    Scene number"
                                                }
                                                [6] => {
                                                    objs_by_ref_name ["button2_long_colour_temp"] with []
                                                    union_variant button2_value_03::ColourTemp text "    Value"
                                                }
                                                [7] => {
                                                    objs_by_ref_name ["button2_long_temp"] with []
                                                    union_variant button2_value_03::Temperature text "    Value"
                                                }
                                                [8] => {
                                                    objs_by_ref_name ["button2_long_lux"] with []
                                                    union_variant button2_value_03::Brightness text "    Value"
                                                }
                                                [ObjectType::Rgb] => {
                                                    param button2_long_colour_control
                                                    when @button2_long_colour_control {
                                                        [ColourControl::Rgb] => {
                                                            objs_by_ref_name ["button2_long_rgb"] with []
                                                            union_variant button2_value_03::Rgb text "    RGB-Value"
                                                        }
                                                        [2] => {
                                                            objs_by_ref_name ["button2_long_hsv"] with []
                                                            union_variant button2_value_03::Hsv text "    HSV-Value"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // long_action 255 = not active: hidden only
                                        [255] => {
                                            // No visible params
                                        }
                                    }
                                    // Time shown after long_action choose when long_action in [0,1,2,3]
                                    when @button2_long_action {
                                        [LongAction::SwitchOff, LongAction::SwitchOn, LongAction::Toggle, LongAction::SendValues] => {
                                            union_variant button2_extra_long_time::ExtraLongKeypressTime text "Time for keypress"
                                        }
                                    }
                                }
                                // Mode 3 = scene - MDT: P-87 (Save scene), comm object, UP-175 (Scene number 1-64)
                                // Simple scene mode with save/no-save option
                                [3] => {
                                    param button2_scene_save_enable
                                    when @button2_scene_save_enable {
                                        // No save - use DPT 17.001 (Scene Number)
                                        [0] => {
                                            objs_by_ref_name ["button2_status_toggle_scene_no_save"] with []
                                        }
                                        // Save - use DPT 18.001 (Scene Control) + time for long keypress
                                        [1] => {
                                            objs_by_ref_name ["button2_status_toggle_scene_save"] with []
                                            union_variant button2_time_duration::LongKeypressTime text "    Time for long keypress"
                                        }
                                    }
                                    union_variant button2_value_00::Scene text "Scene number"
                                }
                                // Mode 2 = blinds/shutter - MDT outputs objects directly (fixed type)
                                // Uses named refs to select the blinds DPT refs
                                [2] => {
                                    objs_by_ref_name ["button2_main_blinds", "button2_secondary_blinds", "button2_status_toggle_blinds"] with []
                                    param button2_operation_function
                                    when @button2_operation_function {
                                        [BlindsOperationFunction::LongMoveShortStop] => {
                                            // long=move / short=stop mode
                                            sep "Innovative group control"
                                            param button2_group_extra_long
                                        }
                                        [BlindsOperationFunction::ShortMoveLongStop] => {
                                            // short=move / long=stop mode - no group control
                                        }
                                    }
                                    // Time for long keypress - shown for both operation function modes
                                    union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                    // Extra long objects only when group control is enabled
                                    when @button2_group_extra_long {
                                        [GEboolEnableDisable::Active] => {
                                            objs_direct [button2_status_display, button2_extra_long] with []
                                            union_variant button2_extra_long_time::ExtraLongKeypressTime text "Time for extra long keypress"
                                        }
                                    }
                                }
                                // Mode 1 = dimming - MDT outputs objects directly (fixed type)
                                // Uses named refs to select the dimming DPT refs
                                [ButtonFunction::Dimming] => {
                                    objs_by_ref_name ["button2_main_dimming", "button2_secondary_dimming", "button2_status_toggle_dimming"] with []
                                    union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                }
                            }
                            // Blocking object section - shown when default true (all modes except 255)
                            when @button2_function {
                                [ButtonFunction::Switch, ButtonFunction::Dimming, ButtonFunction::BlindsShutter, ButtonFunction::Scene, ButtonFunction::SendValues, ButtonFunction::SwitchSendValuesShortLong] => {
                                    sep " "
                                    param button2_blocking_enable
                                    when @button2_blocking_enable { [GEboolEnableDisable::Active] => { obj button2_blocking } }
                                }
                            }
                        }
                    }
                    // Two-button mode (eingang_type = 1) - PB1/2 block comes third in MDT
                    [ButtonsType::TwoButton] => {
                        block "pButtonGroupt_0" => "    PB1/2: {{button1_description:Push buttons 1/2}}" {
                            param button1_description
                            param two_button_function
                            when @two_button_function {
                                // Mode 0 = switch: MDT pattern - O-0, hidden params, P-92, group control
                                [TwoButtonFunction::Switch] => {
                                    obj_direct button1_main with []
                                    // Hidden params P-13,14,15,16 (main_type/sub_type) - we use hidden params
                                    // P-92 button_assignment: ON/OFF or OFF/ON
                                    param button_assignment
                                    // P-27/P-43 values based on button_assignment - hidden
                                    sep "Innovative group control"
                                    param button1_group_function
                                    when @button1_group_function {
                                        [GEboolEnableDisable::Active] => {
                                            obj_direct button1_status_toggle with []
                                            // P-93 Group long sends
                                            param group_long_send_cond
                                            // Time params based on P-92 and P-93 - hidden
                                            // P-29 Group send condition for extra long
                                            param button1_group_send_condition
                                            when @button1_group_send_condition {
                                                [GEboolEnableDisable::Active] => {
                                                    obj_direct button1_extra_long with []
                                                    // P-94 Group extra long sends
                                                    param group_extra_long_send_cond
                                                }
                                            }
                                            // UP-110 Time for long keypress
                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                            when @button1_group_send_condition {
                                                [GEboolEnableDisable::Active] => {
                                                    // UP-155 Time for extra long keypress
                                                    union_variant button1_extra_long_time::ExtraLongKeypressTime
                                                }
                                            }
                                        }
                                    }
                                }
                                // Mode 3 = send values: MDT pattern - P-95 subfunction, then DPT-based objects
                                [TwoButtonFunction::SendValues] => {
                                    param two_button_value_function
                                    when @two_button_value_function {
                                        // send values mode (P-95=1)
                                        [TwoButtonValueFunction::SendValues] => {
                                            // Hidden params, P-39 (DPT type), choose P-39 for objects
                                            param button1_object_type
                                            obj_with_value button1_main by button1_object_type => button1_value_00 with [button1_value_type] sub_select {
                                                9 => button1_colour_control [(1, button1_main_rgb, Rgb), (2, button1_main_hsv, Hsv)]
                                            }
                                            // P-37 Special function
                                            param button1_special_function
                                            when @button1_special_function {
                                                // Innovative group control
                                                [0] => {
                                                    sep "Innovative group control"
                                                    param button1_group_function
                                                    when @button1_group_function {
                                                        [GEboolEnableDisable::Active] => {
                                                            // Object based on DPT
                                                            obj_with_value button1_status_toggle by button1_object_type => button1_value_01 with [button1_value_type] sub_select {
                                                                9 => button1_colour_control [(1, button1_status_toggle_rgb, Rgb), (2, button1_status_toggle_hsv, Hsv)]
                                                            }
                                                            param group_send_option
                                                            param button1_group_send_condition
                                                            when @button1_group_send_condition {
                                                                [GEboolEnableDisable::Active] => {
                                                                    obj_with_value button1_extra_long by button1_object_type => button1_extra_long_value with [button1_value_type] sub_select {
                                                                        9 => button1_colour_control [(1, button1_main_rgb, Rgb), (2, button1_main_hsv, Hsv)]
                                                                    }
                                                                    // group_send_option shown again with "Group extra long sends" text
                                                                    // MDT uses P-96 with Text override in ParameterRef
                                                                    param group_extra_long_send_cond
                                                                }
                                                            }
                                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                            when @button1_group_send_condition {
                                                                [GEboolEnableDisable::Active] => {
                                                                    union_variant button1_extra_long_time::ExtraLongKeypressTime
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Additional object
                                                [SpecialFunction::AdditionalObject] => {
                                                    param button1_additional_object_type
                                                    when @button1_additional_object_type {
                                                        [ObjectType::Switch] => {
                                                            objs_by_ref_name ["button1_additional_obj_switch"] with []
                                                            union_variant button1_value_01::Switch text "    Value"
                                                        }
                                                        [ObjectType::Bit2] => {
                                                            objs_by_ref_name ["button1_additional_obj_bit2"] with []
                                                            union_variant button1_value_01::ForcibleControl text "    Value"
                                                        }
                                                        [2] => {
                                                            objs_by_ref_name ["button1_additional_obj_percent"] with []
                                                            union_variant button1_value_01::Percent text "    Value"
                                                        }
                                                        [3] => {
                                                            objs_by_ref_name ["button1_additional_obj_decimal"] with []
                                                            union_variant button1_value_01::Decimal text "    Value"
                                                        }
                                                        [4] => {
                                                            objs_by_ref_name ["button1_additional_obj_scene"] with []
                                                            union_variant button1_value_01::Scene text "    Value"
                                                        }
                                                        [6] => {
                                                            objs_by_ref_name ["button1_additional_obj_colour_temp"] with []
                                                            union_variant button1_value_01::ColourTemp text "    Value"
                                                        }
                                                        [7] => {
                                                            objs_by_ref_name ["button1_additional_obj_temperature"] with []
                                                            union_variant button1_value_01::Temperature text "    Value"
                                                        }
                                                        [8] => {
                                                            objs_by_ref_name ["button1_additional_obj_brightness"] with []
                                                            union_variant button1_value_01::Brightness text "    Value"
                                                        }
                                                        [ObjectType::Rgb] => {
                                                            param button1_colour_control
                                                            when @button1_colour_control {
                                                                [ColourControl::Rgb] => {
                                                                    objs_by_ref_name ["button1_additional_obj_rgb"] with []
                                                                    union_variant button1_value_01::Rgb text "    Value"
                                                                }
                                                                [ColourControl::Hsv] => {
                                                                    objs_by_ref_name ["button1_additional_obj_hsv"] with []
                                                                    union_variant button1_value_01::Hsv text "    Value"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // toggle values mode (P-95=2)
                                        [2] => {
                                            param config_toggle_value
                                            param button1_object_type
                                            // Multi-value toggle objects
                                            obj_with_value button1_main by button1_object_type => button1_value_00 with [button1_value_type] sub_select {
                                                9 => button1_colour_control [(1, button1_main_rgb, Rgb), (2, button1_main_hsv, Hsv)]
                                            }
                                        }
                                        // shift value mode (P-95=3)
                                        [3] => {
                                            param config_shift_value
                                            param button1_object_type
                                            obj_with_value button1_main by button1_object_type => button1_value_00 with [button1_value_type] sub_select {
                                                9 => button1_colour_control [(1, button1_main_rgb, Rgb), (2, button1_main_hsv, Hsv)]
                                            }
                                        }
                                    }
                                }
                                // Mode 2 = blinds/shutter
                                [TwoButtonFunction::BlindsShutter] => {
                                    param config_shutter
                                    objs_by_ref_name ["button1_main_blinds", "button1_secondary_blinds"] with []
                                    param button1_operation_function
                                    when @button1_operation_function {
                                        [BlindsOperationFunction::LongMoveShortStop] => {
                                            // short=step / long=move mode - with group control
                                            sep "Innovative group control"
                                            param button1_group_function
                                            when @button1_group_function {
                                                [BlindsOperationFunction::ShortMoveLongStop] => {
                                                    objs_by_ref_name ["button1_status_display_blinds", "button1_extra_long_blinds"] with []
                                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                    union_variant button1_extra_long_time::ExtraLongKeypressTime text "Time for extra long keypress"
                                                }
                                            }
                                        }
                                        [BlindsOperationFunction::ShortMoveLongStop] => {
                                            // short=move / long=stop mode - no group control
                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                        }
                                    }
                                }
                                // Mode 1 = dimming
                                [TwoButtonFunction::Dimming] => {
                                    param config_dimmer
                                    objs_by_ref_name ["button1_main_dimming", "button1_secondary_dimming", "button1_status_toggle_dimming"] with []
                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                }
                                // Mode 5 = switch/send values short/long (with 2 objects)
                                [TwoButtonFunction::SwitchSendValues] => {
                                    // Short: switch
                                    param button_assignment
                                    obj_direct button1_main with []
                                    // Long: send values
                                    // button1_object_type shown as "Datapoint type" for long
                                    param button1_object_type
                                    obj_with_value button1_secondary by button1_object_type => button1_value_01 with [button1_value_type] sub_select {
                                        9 => button1_colour_control [(1, button1_secondary_rgb, Rgb), (2, button1_secondary_hsv, Hsv)]
                                    }
                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                }
                            }
                            sep " "
                            param button1_blocking_enable
                            when @button1_blocking_enable { [GEboolEnableDisable::Active] => { obj_direct button1_blocking with [] } }
                        }
                    }
                }

                // Slap button - only shown when slap function is enabled
                when @eingang_type_patsch {
                    [GEboolEnableDisable::Active] => {
                        block "PatchButtton" => "    Slap / Cleaning function" {
                            param slap_cleaning_mode
                            when @slap_cleaning_mode {
                                [SlapCleaningMode::CleaningNotActive] => { param slap_led_colour }
                                [SlapCleaningMode::CleaningLongSlapShort] => { param slap_led_colour sep "Cleaning time config" }
                                [SlapCleaningMode::CleaningShortSlapLong] => { param slap_led_colour sep "Extended cleaning" }
                            }
                            sep "Short keypress"
                            param slap_short_dpt_type
                            param slap_short_object_type
                            obj slap_short_main
                            selector panic_value_00
                            when @slap_short_object_type { [1, 2, 3] => { obj slap_short_status } }
                            sep "Long keypress"
                            param slap_long_dpt_type
                            param slap_long_object_type
                            obj slap_long_main
                            selector panic_value_03
                            when @slap_long_object_type { [1, 2, 3] => { obj slap_long_status selector panic_time_duration_union } }
                            sep " "
                            param slap_blocking_enable
                            when @slap_blocking_enable { [GEboolEnableDisable::Active] => { obj slap_blocking } }
                        }
                    }
                }
            }

            // Logic channel - MDT structure: GlobalLogic with all configs inline, then separate input blocks
            channel "logic" => "Logic" (3) {
                // GlobalLogic block - contains all 4 logic settings with inline output configuration
                block "GlobalLogic" => "Logic basic setting" {
                    // Logic 1 settings
                    param logic1_type
                    when @logic1_type {
                        // Active modes (And/Or/SendValue) - show description params
                        [LogicType::Or, LogicType::And, LogicType::SendValueWhenPressed] => {
                            param logic1_description
                            param logic1_add_description
                        }
                        // And/Or modes - show object type and output config
                        [LogicType::Or, LogicType::And] => {
                            param logic1_output_type
                            when @logic1_output_type {
                                // Switch (1)
                                [LogicOutputType::Switch] => {
                                    obj logic1_output
                                    union_variant logic1_send_condition_union::Condition
                                    param logic1_invert_output
                                }
                                // Scene (2)
                                [LogicOutputType::Scene] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::Scene text "    Scene number"
                                }
                                // Value (3)
                                [LogicOutputType::Value] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::ByteValue text "    1Byte Value"
                                }
                                // Forcible control (4)
                                [LogicOutputType::ForcibleControl] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                        // Send value mode - different structure
                        [LogicType::SendValueWhenPressed] => {
                            param logic1_output_type
                            when @logic1_output_type {
                                [LogicOutputType::Switch] => {
                                    obj logic1_output
                                    union_variant logic1_send_condition_union::Condition
                                    param logic1_invert_output
                                }
                                [LogicOutputType::Scene] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::Scene text "    Scene number"
                                }
                                [LogicOutputType::Value] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::ByteValue text "    1Byte Value"
                                }
                                [LogicOutputType::ForcibleControl] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                    }

                    // Logic 2 settings
                    param logic2_type
                    when @logic2_type {
                        [LogicType::Or, LogicType::And, LogicType::SendValueWhenPressed] => {
                            param logic2_description
                            param logic2_add_description
                        }
                        [LogicType::Or, LogicType::And] => {
                            param logic2_output_type
                            when @logic2_output_type {
                                [LogicOutputType::Switch] => {
                                    obj logic2_output
                                    union_variant logic2_send_condition_union::Condition
                                    param logic2_invert_output
                                }
                                [LogicOutputType::Scene] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::Scene text "    Scene number"
                                }
                                [LogicOutputType::Value] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::ByteValue text "    1Byte Value"
                                }
                                [LogicOutputType::ForcibleControl] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                        [LogicType::SendValueWhenPressed] => {
                            param logic2_output_type
                            when @logic2_output_type {
                                [LogicOutputType::Switch] => {
                                    obj logic2_output
                                    union_variant logic2_send_condition_union::Condition
                                    param logic2_invert_output
                                }
                                [LogicOutputType::Scene] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::Scene text "    Scene number"
                                }
                                [LogicOutputType::Value] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::ByteValue text "    1Byte Value"
                                }
                                [LogicOutputType::ForcibleControl] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                    }

                    // Logic 3 settings
                    param logic3_type
                    when @logic3_type {
                        [LogicType::Or, LogicType::And, LogicType::SendValueWhenPressed] => {
                            param logic3_description
                            param logic3_add_description
                        }
                        [LogicType::Or, LogicType::And] => {
                            param logic3_output_type
                            when @logic3_output_type {
                                [LogicOutputType::Switch] => {
                                    obj logic3_output
                                    union_variant logic3_send_condition_union::Condition
                                    param logic3_invert_output
                                }
                                [LogicOutputType::Scene] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::Scene text "    Scene number"
                                }
                                [LogicOutputType::Value] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::ByteValue text "    1Byte Value"
                                }
                                [LogicOutputType::ForcibleControl] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                        [LogicType::SendValueWhenPressed] => {
                            param logic3_output_type
                            when @logic3_output_type {
                                [LogicOutputType::Switch] => {
                                    obj logic3_output
                                    union_variant logic3_send_condition_union::Condition
                                    param logic3_invert_output
                                }
                                [LogicOutputType::Scene] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::Scene text "    Scene number"
                                }
                                [LogicOutputType::Value] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::ByteValue text "    1Byte Value"
                                }
                                [LogicOutputType::ForcibleControl] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                    }

                    // Logic 4 settings
                    param logic4_type
                    when @logic4_type {
                        [LogicType::Or, LogicType::And, LogicType::SendValueWhenPressed] => {
                            param logic4_description
                            param logic4_add_description
                        }
                        [LogicType::Or, LogicType::And] => {
                            param logic4_output_type
                            when @logic4_output_type {
                                [LogicOutputType::Switch] => {
                                    obj logic4_output
                                    union_variant logic4_send_condition_union::Condition
                                    param logic4_invert_output
                                }
                                [LogicOutputType::Scene] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::Scene text "    Scene number"
                                }
                                [LogicOutputType::Value] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::ByteValue text "    1Byte Value"
                                }
                                [LogicOutputType::ForcibleControl] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                        [LogicType::SendValueWhenPressed] => {
                            param logic4_output_type
                            when @logic4_output_type {
                                [LogicOutputType::Switch] => {
                                    obj logic4_output
                                    union_variant logic4_send_condition_union::Condition
                                    param logic4_invert_output
                                }
                                [LogicOutputType::Scene] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::Scene text "    Scene number"
                                }
                                [LogicOutputType::Value] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::ByteValue text "    1Byte Value"
                                }
                                [LogicOutputType::ForcibleControl] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                    }

                    // Behaviour on bus power return
                    param logic_read_on_init
                }

                // Logic 1 input configuration block (for And/Or modes)
                when @logic1_type {
                    [LogicType::Or, LogicType::And] => {
                        block "Logic_1" => "    Logic 1 {{logic1_description:}}" {
                            param logic1_ext_input_a
                            when @logic1_ext_input_a {
                                [ExtInputLogicType::NormallyActivePrealloc0, ExtInputLogicType::InvertedActivePrealloc0, ExtInputLogicType::NormallyActivePrealloc1, ExtInputLogicType::InvertedActivePrealloc1] => { obj logic1_input_a }
                            }
                            param logic1_ext_input_b
                            when @logic1_ext_input_b {
                                [ExtInputLogicType::NormallyActivePrealloc0, ExtInputLogicType::InvertedActivePrealloc0, ExtInputLogicType::NormallyActivePrealloc1, ExtInputLogicType::InvertedActivePrealloc1] => { obj logic1_input_b }
                            }
                            param logic1_button_choose_0
                            when @logic1_button_choose_0 {
                                [LogicButton::Button1] => { param logic1_int_button1 }
                                [LogicButton::Button2] => { param logic1_int_button2 }
                            }
                            param logic1_button_choose_1
                            when @logic1_button_choose_1 {
                                [LogicButton::Button1] => { param logic1_int_button1 }
                                [LogicButton::Button2] => { param logic1_int_button2 }
                            }
                        }
                    }
                    [LogicType::SendValueWhenPressed] => {
                        block "Logic_1" => "    Logic 1 {{logic1_description:}}" {
                            param logic1_button_choose_0
                            when @logic1_button_choose_0 {
                                [LogicButton::Button1] => { param logic1_int_button1 }
                                [LogicButton::Button2] => { param logic1_int_button2 }
                            }
                        }
                    }
                }

                // Logic 2 input configuration block
                when @logic2_type {
                    [LogicType::Or, LogicType::And] => {
                        block "Logic_2" => "    Logic 2 {{logic2_description:}}" {
                            param logic2_ext_input_a
                            when @logic2_ext_input_a {
                                [ExtInputLogicType::NormallyActivePrealloc0, ExtInputLogicType::InvertedActivePrealloc0, ExtInputLogicType::NormallyActivePrealloc1, ExtInputLogicType::InvertedActivePrealloc1] => { obj logic2_input_a }
                            }
                            param logic2_ext_input_b
                            when @logic2_ext_input_b {
                                [ExtInputLogicType::NormallyActivePrealloc0, ExtInputLogicType::InvertedActivePrealloc0, ExtInputLogicType::NormallyActivePrealloc1, ExtInputLogicType::InvertedActivePrealloc1] => { obj logic2_input_b }
                            }
                            param logic2_button_choose_0
                            when @logic2_button_choose_0 {
                                [LogicButton::Button1] => { param logic2_int_button1 }
                                [LogicButton::Button2] => { param logic2_int_button2 }
                            }
                            param logic2_button_choose_1
                            when @logic2_button_choose_1 {
                                [LogicButton::Button1] => { param logic2_int_button1 }
                                [LogicButton::Button2] => { param logic2_int_button2 }
                            }
                        }
                    }
                    [LogicType::SendValueWhenPressed] => {
                        block "Logic_2" => "    Logic 2 {{logic2_description:}}" {
                            param logic2_button_choose_0
                            when @logic2_button_choose_0 {
                                [LogicButton::Button1] => { param logic2_int_button1 }
                                [LogicButton::Button2] => { param logic2_int_button2 }
                            }
                        }
                    }
                }

                // Logic 3 input configuration block
                when @logic3_type {
                    [LogicType::Or, LogicType::And] => {
                        block "Logic_3" => "    Logic 3 {{logic3_description:}}" {
                            param logic3_ext_input_a
                            when @logic3_ext_input_a {
                                [ExtInputLogicType::NormallyActivePrealloc0, ExtInputLogicType::InvertedActivePrealloc0, ExtInputLogicType::NormallyActivePrealloc1, ExtInputLogicType::InvertedActivePrealloc1] => { obj logic3_input_a }
                            }
                            param logic3_ext_input_b
                            when @logic3_ext_input_b {
                                [ExtInputLogicType::NormallyActivePrealloc0, ExtInputLogicType::InvertedActivePrealloc0, ExtInputLogicType::NormallyActivePrealloc1, ExtInputLogicType::InvertedActivePrealloc1] => { obj logic3_input_b }
                            }
                            param logic3_button_choose_0
                            when @logic3_button_choose_0 {
                                [LogicButton::Button1] => { param logic3_int_button1 }
                                [LogicButton::Button2] => { param logic3_int_button2 }
                            }
                            param logic3_button_choose_1
                            when @logic3_button_choose_1 {
                                [LogicButton::Button1] => { param logic3_int_button1 }
                                [LogicButton::Button2] => { param logic3_int_button2 }
                            }
                        }
                    }
                    [LogicType::SendValueWhenPressed] => {
                        block "Logic_3" => "    Logic 3 {{logic3_description:}}" {
                            param logic3_button_choose_0
                            when @logic3_button_choose_0 {
                                [LogicButton::Button1] => { param logic3_int_button1 }
                                [LogicButton::Button2] => { param logic3_int_button2 }
                            }
                        }
                    }
                }

                // Logic 4 input configuration block
                when @logic4_type {
                    [LogicType::Or, LogicType::And] => {
                        block "Logic_4" => "    Logic 4 {{logic4_description:}}" {
                            param logic4_ext_input_a
                            when @logic4_ext_input_a {
                                [ExtInputLogicType::NormallyActivePrealloc0, ExtInputLogicType::InvertedActivePrealloc0, ExtInputLogicType::NormallyActivePrealloc1, ExtInputLogicType::InvertedActivePrealloc1] => { obj logic4_input_a }
                            }
                            param logic4_ext_input_b
                            when @logic4_ext_input_b {
                                [ExtInputLogicType::NormallyActivePrealloc0, ExtInputLogicType::InvertedActivePrealloc0, ExtInputLogicType::NormallyActivePrealloc1, ExtInputLogicType::InvertedActivePrealloc1] => { obj logic4_input_b }
                            }
                            param logic4_button_choose_0
                            when @logic4_button_choose_0 {
                                [LogicButton::Button1] => { param logic4_int_button1 }
                                [LogicButton::Button2] => { param logic4_int_button2 }
                            }
                            param logic4_button_choose_1
                            when @logic4_button_choose_1 {
                                [LogicButton::Button1] => { param logic4_int_button1 }
                                [LogicButton::Button2] => { param logic4_int_button2 }
                            }
                        }
                    }
                    [LogicType::SendValueWhenPressed] => {
                        block "Logic_4" => "    Logic 4 {{logic4_description:}}" {
                            param logic4_button_choose_0
                            when @logic4_button_choose_0 {
                                [LogicButton::Button1] => { param logic4_int_button1 }
                                [LogicButton::Button2] => { param logic4_int_button2 }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Tests: Device-side union parameter access patterns
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that union sizes remain correct after removing _pad fields.
    /// The _Reserved variant anchors the data area to the expected size.
    #[test]
    fn test_union_sizes() {
        // ButtonValueUnion: 1 byte discriminant + 1 byte alignment + 4 bytes data = 6
        // (u16 fields require 2-byte alignment, padding the discriminant)
        assert_eq!(core::mem::size_of::<ButtonValueUnion>(), 6);
        // ExtraLongValueUnion: 1 byte discriminant + 1 byte alignment + 2 bytes data = 4
        assert_eq!(core::mem::size_of::<ExtraLongValueUnion>(), 4);
        // TimeDurationUnion: 1 byte discriminant + 1 byte alignment + 2 bytes data = 4
        assert_eq!(core::mem::size_of::<TimeDurationUnion>(), 4);
    }

    /// Demonstrates the basic pattern: match directly on a ButtonValueUnion
    /// field using `{ value, .. }` to skip padding fields.
    #[test]
    fn test_button_value_union_pattern_matching() {
        let mut params = MdtParams::default();

        // Default variant is Switch (discriminant 0)
        match params.button1_value_00 {
            ButtonValueUnion::Switch { value, .. } => {
                assert_eq!(value, GedptSwitch::Off);
            }
            _ => panic!("Expected Switch variant as default"),
        }

        // Set to Percent variant with 25%
        params.button1_value_00 = ButtonValueUnion::Percent { value: Select0to100Percent::P25 };
        match params.button1_value_00 {
            ButtonValueUnion::Percent { value, .. } => {
                assert_eq!(value as u8, 64); // 25% maps to byte value 64
            }
            _ => panic!("Expected Percent variant"),
        }

        // Set to ColourTemp variant
        params.button1_value_00 = ButtonValueUnion::ColourTemp { value: 2700 };
        match params.button1_value_00 {
            ButtonValueUnion::ColourTemp { value, .. } => {
                assert_eq!(value, 2700);
            }
            _ => panic!("Expected ColourTemp variant"),
        }

        // Set to RGB variant
        params.button1_value_00 = ButtonValueUnion::Rgb { value: [255, 128, 0] };
        match params.button1_value_00 {
            ButtonValueUnion::Rgb { value, .. } => {
                assert_eq!(value, [255, 128, 0]);
            }
            _ => panic!("Expected Rgb variant"),
        }
    }

    /// Demonstrates handling a button press: read the configured value from
    /// the union and write the appropriate DPT to a comm object storage buffer.
    #[test]
    fn test_button_press_writes_to_comm_object() {
        let mut params = MdtParams::default();

        // Configure button 1 for Percent mode with value 50%
        params.button1_object_type = ObjectType::Percent;
        params.button1_value_00 = ButtonValueUnion::Percent { value: Select0to100Percent::P50 };

        // Simulate a comm object storage buffer (4 bytes for multi-DPT)
        let mut co_buffer = [0u8; 4];

        // Device code: match on the union to determine what to send
        match params.button1_value_00 {
            ButtonValueUnion::Switch { value, .. } => {
                co_buffer[0] = value as u8;
            }
            ButtonValueUnion::ForcibleControl { value, .. } => {
                co_buffer[0] = value as u8;
            }
            ButtonValueUnion::Percent { value, .. } => {
                co_buffer[0] = value as u8;
            }
            ButtonValueUnion::Decimal { value, .. } => {
                co_buffer[0] = value;
            }
            ButtonValueUnion::Scene { value, .. } => {
                co_buffer[0] = value as u8;
            }
            ButtonValueUnion::ColourTemp { value, .. } => {
                co_buffer[..2].copy_from_slice(&value.to_be_bytes());
            }
            ButtonValueUnion::Temperature { value, .. } => {
                co_buffer[..2].copy_from_slice(&value.to_be_bytes());
            }
            ButtonValueUnion::Brightness { value, .. } => {
                co_buffer[..2].copy_from_slice(&value.to_be_bytes());
            }
            ButtonValueUnion::Rgb { value, .. } => {
                co_buffer[..3].copy_from_slice(&value);
            }
            ButtonValueUnion::Switch1Bit { value, .. } => {
                co_buffer[0] = value as u8;
            }
            ButtonValueUnion::Hsv { value, .. } => {
                co_buffer[..3].copy_from_slice(&value);
            }
            ButtonValueUnion::_Reserved(_) => unreachable!(),
        }

        // 50% maps to byte value 127 (round(50 * 2.55))
        assert_eq!(co_buffer[0], 127);
    }

    /// Demonstrates using the selector enum for control flow decisions
    /// independent of the union value.
    #[test]
    fn test_selector_enum_for_mode_dispatch() {
        let mut params = MdtParams::default();
        params.button1_object_type = ObjectType::ColourTemp;

        // Use the selector to determine comm object size/encoding
        let dpt_size = match params.button1_object_type {
            ObjectType::Switch => 1,
            ObjectType::Bit2 => 1,
            ObjectType::Percent => 1,
            ObjectType::Decimal => 1,
            ObjectType::Scene => 1,
            ObjectType::ColourTemp => 2,
            ObjectType::Temperature => 2,
            ObjectType::Brightness => 2,
            ObjectType::Rgb => 3,
        };

        assert_eq!(dpt_size, 2);
    }

    /// Demonstrates toggle mode: cycling through multiple union values
    /// that all share the same active variant type.
    #[test]
    fn test_toggle_mode_with_multiple_values() {
        let mut params = MdtParams::default();
        params.button1_object_type = ObjectType::Percent;

        // Configure 3 toggle values (all Percent variant)
        params.button1_value_00 = ButtonValueUnion::Percent { value: Select0to100Percent::P0 };
        params.button1_value_01 = ButtonValueUnion::Percent { value: Select0to100Percent::P50 };
        params.button1_value_02 = ButtonValueUnion::Percent { value: Select0to100Percent::P100 };

        // Simulate toggle cycling
        let values = [&params.button1_value_00, &params.button1_value_01, &params.button1_value_02];

        let mut collected = Vec::new();
        for val in &values {
            match val {
                ButtonValueUnion::Percent { value, .. } => {
                    collected.push(*value as u8);
                }
                _ => panic!("All values should be Percent variant"),
            }
        }

        // 0% -> 0, 50% -> 127, 100% -> 255
        assert_eq!(collected, vec![0, 127, 255]);
    }

    /// Demonstrates time duration union access for keypress timing.
    #[test]
    fn test_time_duration_union_access() {
        let mut params = MdtParams::default();

        // Default is LongKeypressTime with Ms400 (the #[default] variant)
        match params.button1_time_duration {
            TimeDurationUnion::LongKeypressTime { value, .. } => {
                assert_eq!(value, TimeForLongKeypress::Ms400);
            }
            _ => panic!("Expected LongKeypressTime default variant"),
        }

        // Reconfigure to 1.0s long keypress time
        params.button1_time_duration = TimeDurationUnion::LongKeypressTime { value: TimeForLongKeypress::S1 };
        match params.button1_time_duration {
            TimeDurationUnion::LongKeypressTime { value, .. } => {
                assert_eq!(value, TimeForLongKeypress::S1);
                assert_eq!(value as u16, 33768);
            }
            _ => panic!("Expected LongKeypressTime variant"),
        }
    }

    /// Demonstrates exhaustive matching — the compiler ensures all variants
    /// are handled, providing compile-time safety.
    #[test]
    fn test_exhaustive_matching_all_button_value_variants() {
        let variants = [
            ButtonValueUnion::Switch { value: GedptSwitch::On },
            ButtonValueUnion::ForcibleControl { value: Zwangsfuehrung::PriorityOn },
            ButtonValueUnion::Percent { value: Select0to100Percent::P50 },
            ButtonValueUnion::Decimal { value: 42 },
            ButtonValueUnion::Scene { value: SceneValue::Scene1 },
            ButtonValueUnion::ColourTemp { value: 4000 },
            ButtonValueUnion::Temperature { value: 0x0C1A },
            ButtonValueUnion::Brightness { value: 0x1F00 },
            ButtonValueUnion::Rgb { value: [255, 0, 128] },
            ButtonValueUnion::Switch1Bit { value: GedptSwitch::Off },
            ButtonValueUnion::Hsv { value: [180, 255, 200] },
        ];

        for variant in &variants {
            // Exhaustive match — compiler error if a variant is missing
            let description = match variant {
                ButtonValueUnion::Switch { value, .. } => {
                    format!("Switch: {:?}", value)
                }
                ButtonValueUnion::ForcibleControl { value, .. } => {
                    format!("ForcibleControl: {:?}", value)
                }
                ButtonValueUnion::Percent { value, .. } => {
                    format!("Percent: {}", *value as u8)
                }
                ButtonValueUnion::Decimal { value, .. } => {
                    format!("Decimal: {}", value)
                }
                ButtonValueUnion::Scene { value, .. } => {
                    format!("Scene: {:?}", value)
                }
                ButtonValueUnion::ColourTemp { value, .. } => {
                    format!("ColourTemp: {}K", value)
                }
                ButtonValueUnion::Temperature { value, .. } => {
                    format!("Temperature: raw={:#06X}", value)
                }
                ButtonValueUnion::Brightness { value, .. } => {
                    format!("Brightness: raw={:#06X}", value)
                }
                ButtonValueUnion::Rgb { value, .. } => {
                    format!("RGB: #{:02X}{:02X}{:02X}", value[0], value[1], value[2])
                }
                ButtonValueUnion::Switch1Bit { value, .. } => {
                    format!("Switch1Bit: {:?}", value)
                }
                ButtonValueUnion::Hsv { value, .. } => {
                    format!("HSV: H={} S={} V={}", value[0], value[1], value[2])
                }
                ButtonValueUnion::_Reserved(_) => unreachable!(),
            };
            assert!(!description.is_empty());
        }
    }
}

// ============================================================================
// Translations
// ============================================================================

// German translations for MDT Push Button Lite device.
//
// This demonstrates the `ets_translations!` macro for defining translations
// separately from the enum/param definitions to keep code clean.
zweidraehte_device::ets_translations! {
    pub MDT_TRANSLATIONS_DE;

    "de-DE" {
        // GEboolEnableDisable translations
        GEboolEnableDisable::NotActive => "nicht aktiv",
        GEboolEnableDisable::Active => "aktiv",

        // YesNo translations
        YesNo::No => "nein",
        YesNo::Yes => "ja",

        // NoYes translations (slightly different variant names)
        NoYes::No => "Nein",
        NoYes::Yes => "Ja",

        // GedptSwitch translations
        GedptSwitch::Off => "AUS",
        GedptSwitch::On => "EIN",

        // ButtonFunction translations
        ButtonFunction::NotActive => "nicht aktiv",
        ButtonFunction::Switch => "Schalten",
        ButtonFunction::Dimming => "Dimmen",
        ButtonFunction::BlindsShutter => "Jalousie",

        // SwitchSubfunction translations
        SwitchSubfunction::Switch => "Schalten",
        SwitchSubfunction::Toggle => "Umschalten",

        // ReactionTime translations
        ReactionTime::Fast => "schnell",
        ReactionTime::Medium => "mittel",
        ReactionTime::Slow => "langsam",
    }
}
