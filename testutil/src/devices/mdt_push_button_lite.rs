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

use crate::mtxml_gen::ets_pages;
use crate::mtxml_gen::page_layout::{EtsPageLayout, PageStructure};
use zweidraehte::dpt::*;
use zweidraehte::ets::{EtsComObjects, EtsEnum, EtsParams, EtsUnion, ets_range_enum};
use zweidraehte::objects::comm::ComObject;
use zweidraehte::{
    IpPlatform, StackDefinition,
    bcus::system_b::{
        IpSystemBDeviceState, KnxIpDevice, KnxIpInterfaceObjects, MemoryLayout, SystemBDevice, SystemBMemoryMap,
        create_knxip_objects,
    },
    layers::linklayers::knxip::KnxNetIpBuilder,
};

use crate::storage::JsonStorage;

// ============================================================================
// Device Descriptor
// ============================================================================

/// Device descriptor - matches MDT Push Button Lite 55 1-fold Basic.
/// ApplicationNumber: 155 (0x009B)
/// ApplicationVersion: 20 (0x14)
/// MaskVersion: MV-0705 (System B TP BCU)
pub const DEVICE_DESCRIPTOR: zweidraehte::ets::DeviceDescriptor = zweidraehte::ets::DeviceDescriptor {
    mask_version: 0x0705,    // MV-0705 System B TP BCU
    manufacturer_id: 0x0083, // MDT
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    application_id: 0x009B,    // ApplicationNumber: 155
    application_version: 0x14, // ApplicationVersion: 20
    max_address_table_entries: 255,
    max_association_table_entries: 255,
    max_com_objects: 88, // 87 objects + 1 for header
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

/// ModeCyclic1min4h - Cyclic send interval
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ModeCyclic1min4h {
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

/// ValueRead - Status request on bus power return
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ValueRead {
    #[default]
    #[ets(display = "no request")]
    NoRequest = 0,
    #[ets(display = "request")]
    Request = 1,
}

/// EingangType - Button mode selector
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum EingangType {
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "two-button function")]
    TwoButton = 1,
    #[default]
    #[ets(display = "single-button function (2 functions, top/bottom)")]
    SingleButton2Func = 2,
    #[ets(display = "single-button function (1 function, top/bottom together)")]
    SingleButton1Func = 3,
}


/// DebounceTime - Reaction time on keypress
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum DebounceTime {
    #[default]
    #[ets(display = "fast")]
    Fast = 80,
    #[ets(display = "medium")]
    Medium = 100,
    #[ets(display = "slow")]
    Slow = 150,
}


/// ButtonSwitchType - Switch subfunction type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum ButtonSwitchType {
    #[ets(display = "switch")]
    Switch = 0,
    #[default]
    #[ets(display = "toggle")]
    Toggle = 1,
    #[ets(display = "send status")]
    SendStatus = 2,
}


/// TwoButtonFunction - Function selector for two-button mode (P-91)
/// Maps to MDT's EingangFunctionGroup parameter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
#[ets(type_name = "EingangFunctionGroup")]
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


/// SwitchType - Button assignment for two-button switch mode (P-92)
/// Maps to MDT's SwitchType parameter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
#[ets(type_name = "SwitchType")]
pub enum SwitchType {
    #[default]
    #[ets(display = "ON/OFF")]
    OnOff = 0,
    #[ets(display = "OFF/ON")]
    OffOn = 1,
}


/// GroupLongSendCondition - Group long sends option for two-button mode (P-93, P-94)
/// Maps to MDT's GroupLongSendCondition parameter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
#[ets(type_name = "GroupLongSendCondition")]
pub enum GroupLongSendCondition {
    #[default]
    #[ets(display = "send ON/OFF")]
    SendOnOff = 0,
    #[ets(display = "send OFF/ON")]
    SendOffOn = 1,
    #[ets(display = "send toggle")]
    SendToggle = 2,
}


/// ButtonGroupValueType - Subfunction for two-button send values mode (P-95)
/// Maps to MDT's ButtonGrouptValueType parameter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
#[ets(type_name = "ButtonGrouptValueType")]
pub enum ButtonGroupValueType {
    #[default]
    #[ets(display = "send values")]
    SendValues = 1,
    #[ets(display = "toggle values/scenes (up to 4 values)")]
    ToggleValues = 2,
    #[ets(display = "shift value")]
    ShiftValue = 3,
}


/// GroupSend - Group long sends options for two-button mode (P-96)
/// Maps to MDT's GroupSend parameter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
#[ets(type_name = "GroupSend")]
pub enum GroupSend {
    #[default]
    #[ets(display = "value for upper and lower button")]
    ValueBothButtons = 0,
    #[ets(display = "value for upper button")]
    ValueUpperButton = 1,
    #[ets(display = "value for lower button")]
    ValueLowerButton = 2,
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

/// EnableDisable1Byte - 8-bit enable/disable
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum EnableDisable1Byte {
    #[default]
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "active")]
    Active = 1,
}


/// ButtonValueType - Send value mode selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum ButtonValueType {
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


/// DPTType1Bit - DPT type selection for 1-bit compatible outputs
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum DPTType1Bit {
    #[ets(display = "2Bit DPT 2.001 Forcible control")]
    ForcibleControl = 1,
    #[default]
    #[ets(display = "1Byte DPT 5.001 Percent (0...100%)")]
    Percent = 2,
    #[ets(display = "1Byte DPT 5.005 Decimal factor (0...255)")]
    DecimalFactor = 3,
    #[ets(display = "1Byte DPT 17.001 Scene number")]
    SceneNumber = 4,
    #[ets(display = "2Byte DPT 7.600 Colour Temperature (Kelvin)")]
    ColourTemperature = 6,
    #[ets(display = "2Byte DPT 9.001 Temperature (°C)")]
    Temperature = 7,
    #[ets(display = "2Byte DPT 9.004 Brightness (Lux)")]
    Brightness = 8,
    #[ets(display = "3Byte DPT 232.600 RGB value 3x(0...255)")]
    RgbValue = 9,
    #[ets(display = "1Bit DPT 1.001 Switch")]
    Switch = 10,
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


/// ButtonFunction - Main button function selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum ButtonFunction {
    #[default]
    #[ets(display = "switch")]
    Switch = 0,
    #[ets(display = "dimming")]
    Dimming = 1,
    #[ets(display = "blinds/shutter")]
    Blinds = 2,
    #[ets(display = "scene")]
    Scene = 3,
    #[ets(display = "send values")]
    SendValues = 4,
    #[ets(display = "switch/send values short/long (with 2 objects)")]
    SwitchSendValues = 7,
    #[ets(display = "not active")]
    NotActive = 255,
}


/// SpecialFunction - Innovative group control options
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum SpecialFunction {
    #[default]
    #[ets(display = "innovative group control")]
    InnovativeGroupControl = 0,
    #[ets(display = "additional object")]
    AdditionalObject = 1,
}


/// ModeRGBHSV - RGB vs HSV color mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ModeRGBHSV {
    #[default]
    #[ets(display = "RGB")]
    Rgb = 1,
    #[ets(display = "HSV")]
    Hsv = 2,
}


/// LogicType - Logic function type
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum LogicType {
    #[ets(display = "Or")]
    Or = 0,
    #[ets(display = "And")]
    And = 1,
    #[ets(display = "send value when button is pressed")]
    SendValueOnPress = 2,
    #[default]
    #[ets(display = "not active")]
    NotActive = 255,
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


/// SendCondition - Logic send condition
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum SendCondition {
    #[default]
    #[ets(display = "not automatic")]
    NotAutomatic = 0,
    #[ets(display = "at input telegram")]
    AtInputTelegram = 1,
    #[ets(display = "at change output")]
    AtChangeOutput = 2,
    #[ets(display = "at change output (send only 0)")]
    AtChangeOutputSendOnly0 = 5,
    #[ets(display = "at change output (send only 1)")]
    AtChangeOutputSendOnly1 = 6,
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


/// IntInputLogicType - Internal logic input from buttons
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum IntInputLogicType {
    #[default]
    #[ets(display = "pressed = ON")]
    PressedOn = 1,
    #[ets(display = "pressed = OFF")]
    PressedOff = 2,
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


/// JaNein - Yes/No selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum JaNein {
    #[default]
    #[ets(display = "no")]
    No = 0,
    #[ets(display = "yes")]
    Yes = 1,
}


/// Cleaning - Slap/Cleaning function mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum Cleaning {
    #[default]
    #[ets(display = "cleaning not active, slap active")]
    SlapOnly = 0,
    #[ets(display = "cleaning = long button, slap = short button")]
    CleaningLongSlapShort = 1,
    #[ets(display = "cleaning = short button, slap = long button")]
    CleaningShortSlapLong = 2,
}


/// LEDRGBColorPatch - LED color for slap indication
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum LEDRGBColorPatch {
    #[ets(display = "off")]
    Off = 0,
    #[ets(display = "red")]
    Red = 1,
    #[ets(display = "green")]
    Green = 2,
    #[ets(display = "yellow")]
    Yellow = 3,
    #[ets(display = "blue")]
    Blue = 4,
    #[ets(display = "pink")]
    Pink = 5,
    #[ets(display = "cyan")]
    Cyan = 6,
    #[default]
    #[ets(display = "white")]
    White = 16,
    #[ets(display = "no signal slap function over LEDs")]
    NoSignal = 31,
}


/// DimmType - Dimmer direction configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum DimmType {
    #[default]
    #[ets(display = "brighter / darker")]
    BrighterDarker = 0,
    #[ets(display = "darker / brighter")]
    DarkerBrighter = 1,
}


/// ConfigChan - Blind channel direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum ConfigChan {
    #[default]
    #[ets(display = "Up/Down")]
    UpDown = 0,
    #[ets(display = "Down/Up")]
    DownUp = 1,
}


/// ShortLongInverse - Blind operation function (1-bit)
/// MDT: PT-Short.2FLong.5FInverse, SizeInBit="1"
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[ets(size = "1 Bit")]
#[repr(u8)]
pub enum ShortLongInverse {
    #[default]
    #[ets(display = "long=move / short=stop/slats Open/Close")]
    LongMoveShortStop = 0,
    #[ets(display = "short=move / long=stop/slats Open/Close")]
    ShortMoveLongStop = 1,
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

/// OnOff - Simple ON/OFF toggle
/// Used for various boolean-like parameters (5 occurrences)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum OnOff {
    #[default]
    #[ets(display = "OFF")]
    Off = 0,
    #[ets(display = "ON")]
    On = 1,
}

/// AndOr - Logic gate type selector
/// Used for logic channel configuration (4 occurrences)
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum AndOr {
    #[default]
    #[ets(display = "Or")]
    Or = 0,
    #[ets(display = "And")]
    And = 1,
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
        #[ets(display = "Number of tip-operations", enum_variants("2" => 1, "3" => 2), default = 1)]
        count: u8,
    } = 0,

    /// Number of values for toggle values/scenes mode (2, 3, or 4 values)
    /// MDT: ValueCount enum - Value=1 means "2 values", Value=2 means "3 values", Value=3 means "4 values"
    #[ets(display = "Value count")]
    ValueCount {
        #[ets(display = "Number of values", enum_variants("2" => 1, "3" => 2, "4" => 3), default = 1)]
        count: u8,
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
        #[ets(skip)]
        _pad: [u8; 3],
    } = 0,

    /// Forcible control (2-bit priority) - matches ObjectType::Bit2 = 1 (button_object_type "2Bit")
    #[ets(display = "Forcible control")]
    ForcibleControl {
        #[ets(display = "Value", ets_enum)]
        value: Zwangsfuehrung,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 1,

    /// Percent value (0-100%) - matches ObjectType::Percent = 2 (button_object_type "1Byte Char")
    /// Default value is 63 (25%) for button1_value_00 "Value tip once"
    #[ets(display = "Percent")]
    Percent {
        #[ets(display = "Value", ets_enum, default = 63)]
        value: Select0to100Percent,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 2,

    /// Decimal factor (0-255) - matches ObjectType::Decimal = 3 (button_object_type "1Byte SignedChar")
    /// Default value is 60 for "Value tip once"
    #[ets(display = "Decimal")]
    Decimal {
        #[ets(display = "Value", default = 60)]
        value: u8,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 3,

    /// Scene number (1-64) - matches ObjectType::Scene = 4 (button_object_type "2Byte KNX_Float")
    #[ets(display = "Scene")]
    Scene {
        #[ets(display = "Scene number", ets_enum)]
        value: SceneValue,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 4,

    /// Colour Temperature (2Byte) - matches ObjectType = 6 (DPT 7.600)
    #[ets(display = "Colour Temperature")]
    ColourTemp {
        #[ets(display = "Value", suffix = "Kelvin", default = 2700)]
        value: u16,
        #[ets(skip)]
        _pad: [u8; 2],
    } = 6,

    /// Temperature °C (2Byte Float) - matches ObjectType = 7 (DPT 9.001)
    /// Note: Default is 15°C (encoded as DPT 9 float value)
    #[ets(display = "Temperature")]
    Temperature {
        #[ets(display = "Value", suffix = "°C", default = 0)]
        value: u16,
        #[ets(skip)]
        _pad: [u8; 2],
    } = 7,

    /// Brightness Lux (2Byte Float) - matches ObjectType = 8 (DPT 9.004)
    /// Note: Default is 1000 Lux (encoded as DPT 9 float value)
    #[ets(display = "Brightness")]
    Brightness {
        #[ets(display = "Value", suffix = "Lux", default = 0)]
        value: u16,
        #[ets(skip)]
        _pad: [u8; 2],
    } = 8,

    /// RGB colour value (3 bytes) - matches ObjectType = 9 (DPT 232.600)
    /// ETS displays this as a single color picker with "#RRGGBB" format
    #[ets(display = "RGB")]
    Rgb {
        #[ets(display = "    RGB-Value", text_pattern = "^#[0-9a-fA-F]{6}$(?# TypeColor:RGB)")]
        value: [u8; 3],
        #[ets(skip)]
        _pad: u8,
    } = 9,

    /// Switch (1Bit) - matches ObjectType = 10 (DPT 1.001) - only in DPTType1Bit
    /// Note: This is value 10 in the enum because MDT uses 10 for Switch in DPTType1Bit
    #[ets(display = "Switch 1Bit")]
    Switch1Bit {
        #[ets(display = "Value", ets_enum)]
        value: GedptSwitch,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 10,

    /// HSV colour value (3 bytes) - ObjectType sub-selection via ModeRGB/HSV param
    /// ETS displays this as a single color picker with "#HHSSVV" format
    /// Note: HSV is NOT a direct ObjectType value - it's selected via P-36 ModeRGB/HSV
    #[ets(display = "HSV")]
    Hsv {
        #[ets(display = "    HSV value", text_pattern = "^#[0-9a-fA-F]{6}$(?# TypeColor:HSV)")]
        value: [u8; 3],
        #[ets(skip)]
        _pad: u8,
    } = 11,
}

/// Long Button Action Union (8-bit) - Action type for long keypress
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum LongButtonActionUnion {
    /// No long action (dummy/hidden)
    #[ets(default_variant, display = "None")]
    None {
        #[ets(skip)]
        _dummy: u8,
    } = 0,

    /// Toggle between 2 values
    #[ets(display = "2 values")]
    TwoValues {
        #[ets(display = "Action with long keypress", enum_variants("toggle value 1/2" => 0, "toggle value 2/1" => 1, "send value 1" => 2, "send value 2" => 3, "no action" => 4))]
        action: u8,
    } = 1,

    /// Toggle between 3 values
    #[ets(display = "3 values")]
    ThreeValues {
        #[ets(display = "Action with long keypress", enum_variants("toggle value 1/2/3" => 0, "toggle value 3/2/1" => 1, "send value 1" => 2, "send value 2" => 3, "send value 3" => 4, "no action" => 5))]
        action: u8,
    } = 2,

    /// Toggle between 4 values
    #[ets(display = "4 values")]
    FourValues {
        #[ets(display = "Action with long keypress", enum_variants("toggle value 1/2/3/4" => 0, "toggle value 4/3/2/1" => 1, "send value 1" => 2, "send value 2" => 3, "send value 3" => 4, "send value 4" => 5, "no action" => 6))]
        action: u8,
    } = 3,

    /// Scene toggle with 2 values (includes save option)
    #[ets(display = "2 scenes")]
    TwoScenes {
        #[ets(display = "Action with long keypress", enum_variants("toggle scene 1/2" => 0, "toggle scene 2/1" => 1, "call scene 1" => 2, "call scene 2" => 3, "no action" => 4, "save scene" => 5))]
        action: u8,
    } = 4,

    /// Scene toggle with 3 values (includes save option)
    #[ets(display = "3 scenes")]
    ThreeScenes {
        #[ets(display = "Action with long keypress", enum_variants("toggle scene 1/2/3" => 0, "toggle scene 3/2/1" => 1, "call scene 1" => 2, "call scene 2" => 3, "call scene 3" => 4, "no action" => 5, "save scene" => 6))]
        action: u8,
    } = 5,

    /// Scene toggle with 4 values (includes save option)
    #[ets(display = "4 scenes")]
    FourScenes {
        #[ets(display = "Action with long keypress", enum_variants("toggle scene 1/2/3/4" => 0, "toggle scene 4/3/2/1" => 1, "call scene 1" => 2, "call scene 2" => 3, "call scene 3" => 4, "call scene 4" => 5, "no action" => 6, "save scene" => 7))]
        action: u8,
    } = 6,
}

/// Time Duration Union (16-bit) - Various time values
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum TimeDurationUnion {
    /// Time for long keypress (with "basic setting" option) - TimeforLongSwitchGroup0-30s
    #[ets(default_variant, display = "Long keypress time")]
    LongKeypressTime {
        #[ets(display = "Time for long keypress", enum_variants(
            "basic setting" => 0,
            "0,1 s" => 32868,
            "0,2 s" => 32968,
            "0,3 s" => 33068,
            "0,4 s" => 33168,
            "0,5 s" => 33268,
            "0,6 s" => 33368,
            "0,7 s" => 33468,
            "0,8 s" => 33568,
            "0,9 s" => 33668,
            "1,0 s" => 33768,
            "1,5 s" => 34268,
            "2,0 s" => 34768,
            "2,5 s" => 35268,
            "3,0 s" => 35768,
            "3,5 s" => 36268,
            "4,0 s" => 36768,
            "4,5 s" => 37268,
            "5,5 s" => 38268,
            "6,5 s" => 39268,
            "7,5 s" => 40268,
            "8,5 s" => 41268,
            "9,5 s" => 42268,
            "12,0 s" => 12,
            "15,0 s" => 15,
            "20,0 s" => 20,
            "25,0 s" => 25,
            "30,0 s" => 30
        ))]
        value: u16,
    } = 0,

    /// Delay time (1s to 60min) - DelayTime1s-60min
    #[ets(display = "Delay time")]
    DelayTime {
        #[ets(display = "Time delay", default = 1, enum_variants(
            "1 s" => 1,
            "2 s" => 2,
            "3 s" => 3,
            "4 s" => 4,
            "5 s" => 5,
            "10 s" => 10,
            "15 s" => 15,
            "20 s" => 20,
            "25 s" => 25,
            "30 s" => 30,
            "35 s" => 35,
            "40 s" => 40,
            "45 s" => 45,
            "60 s" => 60,
            "2 min" => 120,
            "3 min" => 180,
            "4 min" => 240,
            "5 min" => 300,
            "6 min" => 360,
            "7 min" => 420,
            "8 min" => 480,
            "9 min" => 540,
            "10 min" => 600,
            "15 min" => 900,
            "20 min" => 1200,
            "25 min" => 1500,
            "30 min" => 1800,
            "35 min" => 2100,
            "40 min" => 2400,
            "45 min" => 2700,
            "60 min" => 3600
        ))]
        delay_time: u16,
    } = 1,

    /// Scene toggle delay (0-10s) - DelayTime0-10s
    #[ets(display = "Scene toggle delay")]
    SceneToggleDelay {
        #[ets(display = "Time delay between scene toggling", enum_variants(
            "0 s" => 0,
            "0,5 s" => 5,
            "1 s" => 10,
            "2 s" => 20,
            "3 s" => 30,
            "4 s" => 40,
            "5 s" => 50,
            "6 s" => 60,
            "7 s" => 70,
            "8 s" => 80,
            "9 s" => 90,
            "10 s" => 100
        ))]
        value: u16,
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
        #[ets(display = "Time for extra long keypress", default = 34768, enum_variants(
            "0,1 s" => 32868,
            "0,2 s" => 32968,
            "0,3 s" => 33068,
            "0,4 s" => 33168,
            "0,5 s" => 33268,
            "0,6 s" => 33368,
            "0,7 s" => 33468,
            "0,8 s" => 33568,
            "0,9 s" => 33668,
            "1,0 s" => 33768,
            "1,5 s" => 34268,
            "2,0 s" => 34768,
            "2,5 s" => 35268,
            "3,0 s" => 35768,
            "3,5 s" => 36268,
            "4,0 s" => 36768,
            "4,5 s" => 37268,
            "5,5 s" => 38268,
            "6,5 s" => 39268,
            "7,5 s" => 40268,
            "8,5 s" => 41268,
            "9,5 s" => 42268,
            "12,0 s" => 12,
            "15,0 s" => 15,
            "20,0 s" => 20,
            "25,0 s" => 25,
            "30,0 s" => 30
        ))]
        extra_long_time: u16,
    } = 5,
}

/// Extra Long Values Union (16-bit) - Values for extra long keypress
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum ExtraLongValueUnion {
    /// Switch value
    #[ets(default_variant, display = "Switch")]
    Switch {
        #[ets(display = "Value", enum_variants("OFF" => 0, "ON" => 1))]
        value: u8,
        #[ets(skip)]
        _pad: u8,
    } = 0,

    /// Forcible control value
    #[ets(display = "Forcible control")]
    ForcibleControl {
        #[ets(display = "Value", enum_variants("00 - no priority, OFF" => 0, "01 - no priority, ON" => 1, "10 - priority, OFF" => 2, "11 - priority, ON" => 3))]
        value: u8,
        #[ets(skip)]
        _pad: u8,
    } = 1,

    /// Percent value
    #[ets(display = "Percent")]
    Percent {
        #[ets(display = "Value")]
        value: u8,
        #[ets(skip)]
        _pad: u8,
    } = 2,

    /// Scene number
    #[ets(display = "Scene")]
    Scene {
        #[ets(display = "Scene number")]
        value: u8,
        #[ets(skip)]
        _pad: u8,
    } = 3,

    /// Colour temperature
    #[ets(display = "Colour temperature")]
    ColourTemp {
        #[ets(display = "Value")]
        value: u16,
    } = 4,
}

/// Send Condition Union (8-bit) - Condition for sending logic output
/// Used for logic channel configuration - determines when output is sent
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum SendConditionUnion {
    /// Standard send condition with enum selection
    #[ets(default_variant, display = "Send condition")]
    Condition {
        #[ets(display = "    Sending condition", enum_variants(
            "not automatic" => 0,
            "at input telegram" => 1,
            "at change output" => 2,
            "at change output (send only 0)" => 5,
            "at change output (send only 1)" => 6
        ), default = 2)]
        value: u8,
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
        #[ets(display = "    Value", enum_variants("No" => 0, "Yes" => 1))]
        value: u8,
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
        #[ets(display = "    Forcible control", enum_variants(
            "00 - no priority, OFF" => 0,
            "01 - no priority, ON" => 1,
            "10 - priority, OFF" => 2,
            "11 - priority, ON" => 3
        ))]
        value: u8,
    } = 3,
}

// ============================================================================
// Communication Objects
// ============================================================================

pub mod comm_objs {
    use super::*;
    // Import the ObjectType enum for selector values
    use super::ObjectType;
    #[allow(unused_imports)]
    use zweidraehte::objects::comm::{ComObjectIndex, ComObjectInfo, ComObjectInfoMut, ComObjectStorage, ComObjects};

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
    pub struct MdtComObjects {
        // ====================================================================
        // Status Objects
        // ====================================================================
        /// Presence - Button activation output
        /// MDT: C=1, T=1, R=0, W=0, U=0, ROI=0
        #[ets(index = 72, name = "Presence", display = "Button activation", function = "Output", flags = 0x47)]
        pub presence: ComObject<DPT_Switch>,

        /// Mode - Operation status (cyclic)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(index = 77, name = "Mode", display = "Operation", function = "Output", flags = 0x4F)]
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
            flags = 0x47,
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
            flags = 0x47,
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
            flags = 0x57,
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
            flags = 0x17,
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
            flags = 0x47,
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
        #[ets(index = 9, name = "Eingang 0", display = "Push button 1", function = "Blocking Object", flags = 0xD7)]
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
            flags = 0x47,
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
            flags = 0x47,
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
            flags = 0x17,
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
            flags = 0x17,
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
            flags = 0x47,
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
        #[ets(index = 19, name = "Eingang 1", display = "Push button 2", function = "Blocking Object", flags = 0xD7)]
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
            flags = 0x47,
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
            flags = 0x17,
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
            flags = 0x47,
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
            flags = 0x17,
            object_size = "2 Bytes",
            selector_param = "slap_long_object_type"
        )]
        // MDT has only 2 refs for O-43, both DPT_Switch with flag overrides
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Status for toggle", transmit = true, update = true)]
        #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, function = "Status for toggle", transmit = true, update = true)]
        pub slap_long_status: ComObject<ComObjectStorage<4>>,

        /// Slap button - Blocking object
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 49, name = "Eingang Patsch", display = "Slap-button", function = "Blocking Object", flags = 0xD7)]
        pub slap_blocking: ComObject<DPT_Enable>,

        // ====================================================================
        // Logic Objects (indices 50-61)
        // ====================================================================
        /// Logic 1 Input A
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 50, name = "Eingangslogik 1 A", display = "Logic", function = "Input 1 A", flags = 0xD7)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 1 {{logic1_description:}}", function = "Input 1 A")]
        pub logic1_input_a: ComObject<DPT_Switch>,

        /// Logic 1 Input B
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 51, name = "Eingangslogik 1 B", display = "Logic", function = "Input 1 B", flags = 0xD7)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 1 {{logic1_description:}}", function = "Input 1 B")]
        pub logic1_input_b: ComObject<DPT_Switch>,

        /// Logic 1 Output (multi-DPT based on LogicObjectType)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(
            index = 52,
            name = "Ausgangslogik 1",
            display = "Logic",
            function = "Output 1",
            flags = 0x4F,
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
        #[ets(index = 53, name = "Eingangslogik 2 A", display = "Logic", function = "Input 2 A", flags = 0xD7)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 2 {{logic2_description:}}", function = "Input 2 A")]
        pub logic2_input_a: ComObject<DPT_Switch>,

        /// Logic 2 Input B
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 54, name = "Eingangslogik 2 B", display = "Logic", function = "Input 2 B", flags = 0xD7)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 2 {{logic2_description:}}", function = "Input 2 B")]
        pub logic2_input_b: ComObject<DPT_Switch>,

        /// Logic 2 Output (multi-DPT based on LogicObjectType)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(
            index = 55,
            name = "Ausgangslogik 2",
            display = "Logic",
            function = "Output 2",
            flags = 0x4F,
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
        #[ets(index = 56, name = "Eingangslogik 3 A", display = "Logic", function = "Input 3 A", flags = 0xD7)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 3 {{logic3_description:}}", function = "Input 3 A")]
        pub logic3_input_a: ComObject<DPT_Switch>,

        /// Logic 3 Input B
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 57, name = "Eingangslogik 3 B", display = "Logic", function = "Input 3 B", flags = 0xD7)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 3 {{logic3_description:}}", function = "Input 3 B")]
        pub logic3_input_b: ComObject<DPT_Switch>,

        /// Logic 3 Output (multi-DPT based on LogicObjectType)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(
            index = 58,
            name = "Ausgangslogik 3",
            display = "Logic",
            function = "Output 3",
            flags = 0x4F,
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
        #[ets(index = 59, name = "Eingangslogik 4 A", display = "Logic", function = "Input 4 A", flags = 0xD7)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 4 {{logic4_description:}}", function = "Input 4 A")]
        pub logic4_input_a: ComObject<DPT_Switch>,

        /// Logic 4 Input B
        /// MDT: C=1, T=1, R=0, W=1, U=1, ROI=0
        #[ets(index = 60, name = "Eingangslogik 4 B", display = "Logic", function = "Input 4 B", flags = 0xD7)]
        #[ets_ref(dpt = DPT_Switch, text = "Logic 4 {{logic4_description:}}", function = "Input 4 B")]
        pub logic4_input_b: ComObject<DPT_Switch>,

        /// Logic 4 Output (multi-DPT based on LogicObjectType)
        /// MDT: C=1, T=1, R=1, W=0, U=0, ROI=0
        #[ets(
            index = 61,
            name = "Ausgangslogik 4",
            display = "Logic",
            function = "Output 4",
            flags = 0x4F,
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
        #[ets(index = 5, name = "Obj5", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_5: ComObject<DPT_Switch>,
        #[ets(index = 6, name = "Obj6", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_6: ComObject<DPT_Switch>,
        #[ets(index = 7, name = "Obj7", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_7: ComObject<DPT_Switch>,
        #[ets(index = 8, name = "Obj8", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_8: ComObject<DPT_Switch>,

        // Button 2 dummies (15-18)
        #[ets(index = 15, name = "Obj15", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_15: ComObject<DPT_Switch>,
        #[ets(index = 16, name = "Obj16", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_16: ComObject<DPT_Switch>,
        #[ets(index = 17, name = "Obj17", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_17: ComObject<DPT_Switch>,
        #[ets(index = 18, name = "Obj18", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_18: ComObject<DPT_Switch>,

        // Button group 3 dummies (20-28) - 4-byte objects for future extension
        #[ets(index = 20, name = "Obj20", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_20: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 21, name = "Obj21", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_21: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 22, name = "Obj22", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_22: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 23, name = "Obj23", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_23: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 24, name = "Obj24", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_24: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 25, name = "Obj25", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_25: ComObject<DPT_Switch>,
        #[ets(index = 26, name = "Obj26", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_26: ComObject<DPT_Switch>,
        #[ets(index = 27, name = "Obj27", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_27: ComObject<DPT_Switch>,
        #[ets(index = 28, name = "Obj28", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_28: ComObject<DPT_Switch>,

        // Button group 4 dummies (29-39)
        #[ets(index = 29, name = "Obj29", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_29: ComObject<DPT_Switch>,
        #[ets(index = 30, name = "Obj30", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_30: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 31, name = "Obj31", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_31: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 32, name = "Obj32", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_32: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 33, name = "Obj33", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_33: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 34, name = "Obj34", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_34: ComObject<DPT_Value_4_Ucount>,
        #[ets(index = 35, name = "Obj35", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_35: ComObject<DPT_Switch>,
        #[ets(index = 36, name = "Obj36", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_36: ComObject<DPT_Switch>,
        #[ets(index = 37, name = "Obj37", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_37: ComObject<DPT_Switch>,
        #[ets(index = 38, name = "Obj38", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_38: ComObject<DPT_Switch>,
        #[ets(index = 39, name = "Obj39", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_39: ComObject<DPT_Switch>,

        // Slap button dummies (44-48)
        #[ets(index = 44, name = "Obj44", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_44: ComObject<DPT_Switch>,
        #[ets(index = 45, name = "Obj45", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_45: ComObject<DPT_Switch>,
        #[ets(index = 46, name = "Obj46", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_46: ComObject<DPT_Switch>,
        #[ets(index = 47, name = "Obj47", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_47: ComObject<DPT_Switch>,
        #[ets(index = 48, name = "Obj48", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_48: ComObject<DPT_Switch>,

        // Logic dummies (62-70)
        #[ets(index = 62, name = "Obj62", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_62: ComObject<DPT_Value_1_Ucount>,
        #[ets(index = 63, name = "Obj63", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_63: ComObject<DPT_Value_1_Ucount>,
        #[ets(index = 64, name = "Obj64", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_64: ComObject<DPT_Value_1_Ucount>,
        #[ets(index = 65, name = "Obj65", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_65: ComObject<DPT_Value_1_Ucount>,
        #[ets(index = 66, name = "Obj66", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_66: ComObject<DPT_Switch>,
        #[ets(index = 67, name = "Obj67", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_67: ComObject<DPT_Switch>,
        #[ets(index = 68, name = "Obj68", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_68: ComObject<DPT_Switch>,
        #[ets(index = 69, name = "Obj69", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_69: ComObject<DPT_Switch>,
        #[ets(index = 70, name = "Obj70", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_70: ComObject<DPT_Switch>,
        #[ets(index = 71, name = "Obj71", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_71: ComObject<DPT_Switch>,

        // Status area dummies (73-76)
        #[ets(index = 73, name = "Obj73", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_73: ComObject<DPT_PropDataType>,
        #[ets(index = 74, name = "Obj74", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_74: ComObject<DPT_PropDataType>,
        #[ets(index = 75, name = "Obj75", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_75: ComObject<DPT_Switch>,
        #[ets(index = 76, name = "Obj76", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_76: ComObject<DPT_Switch>,

        // Reserved area dummies (78-87)
        #[ets(index = 78, name = "Obj78", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_78: ComObject<DPT_Switch>,
        #[ets(index = 79, name = "Obj79", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_79: ComObject<DPT_PropDataType>,
        #[ets(index = 80, name = "Obj80", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_80: ComObject<DPT_Switch>,
        #[ets(index = 81, name = "Obj81", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_81: ComObject<DPT_Switch>,
        #[ets(index = 82, name = "Obj82", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_82: ComObject<DPT_Switch>,
        #[ets(index = 83, name = "Obj83", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_83: ComObject<DPT_Switch>,
        #[ets(index = 84, name = "Obj84", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_84: ComObject<DPT_Switch>,
        #[ets(index = 85, name = "Obj85", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_85: ComObject<DPT_Switch>,
        #[ets(index = 86, name = "Obj86", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_86: ComObject<DPT_Switch>,
        #[ets(index = 87, name = "Obj87", display = "Dummy", function = "", flags = 0x03)]
        pub dummy_87: ComObject<DPT_Value_1_Ucount>,
    }
}

// ============================================================================
// Application Parameters
// ============================================================================

/// Application parameters for the MDT Push Button Lite device.
#[derive(Debug, Clone, Copy, EtsParams, Serialize, Deserialize)]
#[ets(derive_defaults)]
#[repr(C)]
pub struct MdtParams {
    /// Startup time in seconds (2-240), default 2s
    #[ets(display = "Startup time", suffix = "s", default = 2)]
    pub startup_timeout: u16,

    /// Debounce time (80=fast, 100=medium, 150=slow), default: fast (80)
    #[ets(display = "Reaction time on keypress", default = 80, enum_variants("fast" => 80, "medium" => 100, "slow" => 150))]
    pub debounce_time: u16,

    /// Time for long keypress (encoded value), default: 0.4s (33168)
    #[ets(display = "Time for long keypress (Basic setting)", default = 33168, enum_variants("0,1 s" => 32868, "0,2 s" => 32968, "0,3 s" => 33068, "0,4 s" => 33168, "0,5 s" => 33268, "0,6 s" => 33368, "0,7 s" => 33468, "0,8 s" => 33568, "0,9 s" => 33668, "1,0 s" => 33768, "1,5 s" => 34268, "2,0 s" => 34768, "2,5 s" => 35268, "3,0 s" => 35768, "3,5 s" => 36268, "4,0 s" => 36768, "4,5 s" => 37268, "5,5 s" => 38268, "6,5 s" => 39268, "7,5 s" => 40268, "8,5 s" => 41268, "9,5 s" => 42268, "12,0 s" => 12, "15,0 s" => 15, "20,0 s" => 20, "25,0 s" => 25, "30,0 s" => 30))]
    pub long_action_time: u16,

    /// Cyclic send mode for operation status, default: not active (0)
    #[ets(display = "Send 'Operation' cyclically", default = 0, enum_variants("not active" => 0, "1 min" => 1, "2 min" => 2, "5 min" => 5, "10 min" => 10, "20 min" => 20, "30 min" => 30, "1 h" => 60, "2 h" => 120, "4 h" => 240))]
    pub mode_cyclic: u8,

    /// Status for toggle after bus power return, default: request (1)
    #[ets(display = "Status for toggle after bus power return", default = 1, enum_variants("no request" => 0, "request" => 1))]
    pub value_read_on_init: u8,

    /// Button 1/2 function type, default: single-button function 2 functions (2)
    #[ets(display = "Buttons 1/2 (top/bottom)", default = 2, enum_variants("not active" => 0, "two-button function" => 1, "single-button function (2 functions, top/bottom)" => 2, "single-button function (1 function, top/bottom together)" => 3))]
    pub eingang_type: u8,

    /// Slap/Cleaning function enable (hidden in 1-fold Basic - hardware doesn't support it)
    #[ets(display = "Slap / Cleaning function", hidden, ets_enum)]
    pub eingang_type_patsch: GEboolEnableDisable,

    /// Button 1 main function (matching MDT ButtonFunction type values)
    #[ets(display = "Single-button function", enum_variants("not active" => 255, "switch" => 0, "dimming" => 1, "blinds/shutter" => 2, "scene" => 3, "send values" => 4, "switch/send values short/long (with 2 objects)" => 7))]
    pub button1_function: u16,

    /// Button 1 switch subfunction (default: toggle)
    #[ets(display = "Subfunction", default = 1, enum_variants("switch" => 0, "toggle" => 1, "send status" => 2))]
    pub button1_switch_type: u16,

    /// Button 1 blocking object enable
    #[ets(display = "Blocking Object", ets_enum)]
    pub button1_blocking_enable: GEboolEnableDisable,

    /// Button 1 object type selector (for ComObjectRef DPT selection)
    /// Values match MDT's DPTType1Bit: 10=Switch, 1=Bit2, 2=Percent, 3=Decimal, 4=Scene, 6=ColourTemp, 7=Temperature, 8=Brightness, 9=RGB
    /// Default: 2 (Percent) to match MDT P-35
    #[ets(display = "Datapoint type", default = 2, enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button1_object_type: u8,

    /// Button 2 main function (matching MDT ButtonFunction type values)
    #[ets(display = "Single-button function", enum_variants("not active" => 255, "switch" => 0, "dimming" => 1, "blinds/shutter" => 2, "scene" => 3, "send values" => 4, "switch/send values short/long (with 2 objects)" => 7))]
    pub button2_function: u16,

    /// Button 2 switch subfunction (default: toggle)
    #[ets(display = "Subfunction", default = 1, enum_variants("switch" => 0, "toggle" => 1, "send status" => 2))]
    pub button2_switch_type: u16,

    /// Button 2 blocking object enable
    #[ets(display = "Blocking Object", ets_enum)]
    pub button2_blocking_enable: GEboolEnableDisable,

    /// Button 2 object type selector (for ComObjectRef DPT selection)
    /// Values match MDT's DPTType1Bit: 10=Switch, 1=Bit2, 2=Percent, 3=Decimal, 4=Scene, 6=ColourTemp, 7=Temperature, 8=Brightness, 9=RGB
    /// Default: 2 (Percent) to match MDT P-69
    #[ets(display = "Datapoint type", default = 2, enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button2_object_type: u8,

    /// Slap button object type selector (for ComObjectRef DPT selection)
    #[ets(display = "Object type", enum_variants("1Bit" => 0, "2Bit" => 1, "1Byte Char" => 2, "1Byte SignedChar" => 3, "2Byte KNX_Float" => 4, "2Byte Short" => 5, "3Byte RGB" => 6, "3Byte HSV" => 7, "4Byte SignedLong" => 8, "4Byte Long Float" => 9, "1Byte Scene" => 10))]
    pub slap_object_type: u8,

    /// Logic 1 type
    #[ets(display = "Setting Logic 1", enum_variants("not active" => 255, "And" => 1, "Or" => 0, "send value when button is pressed" => 2))]
    pub logic1_type: u8,

    /// Logic 2 type
    #[ets(display = "Setting Logic 2", enum_variants("not active" => 255, "And" => 1, "Or" => 0, "send value when button is pressed" => 2))]
    pub logic2_type: u8,

    /// Logic 3 type
    #[ets(display = "Setting Logic 3", enum_variants("not active" => 255, "And" => 1, "Or" => 0, "send value when button is pressed" => 2))]
    pub logic3_type: u8,

    /// Logic 4 type
    #[ets(display = "Setting Logic 4", enum_variants("not active" => 255, "And" => 1, "Or" => 0, "send value when button is pressed" => 2))]
    pub logic4_type: u8,

    /// Logic 1 output object type
    #[ets(display = "    Object type 1", enum_variants("switch" => 1, "scene" => 2, "value" => 3, "forcible control 2Bit" => 4), default = 1)]
    pub logic1_output_type: u8,

    /// Logic 2 output object type
    #[ets(display = "    Object type 2", enum_variants("switch" => 1, "scene" => 2, "value" => 3, "forcible control 2Bit" => 4), default = 1)]
    pub logic2_output_type: u8,

    /// Logic 3 output object type
    #[ets(display = "    Object type 3", enum_variants("switch" => 1, "scene" => 2, "value" => 3, "forcible control 2Bit" => 4), default = 1)]
    pub logic3_output_type: u8,

    /// Logic 4 output object type
    #[ets(display = "    Object type 4", enum_variants("switch" => 1, "scene" => 2, "value" => 3, "forcible control 2Bit" => 4), default = 1)]
    pub logic4_output_type: u8,

    /// Slap short object type (for status ref selection)
    #[ets(display = "Object type", enum_variants("1Bit" => 0, "2Bit" => 1, "1Byte Char" => 2, "1Byte SignedChar" => 3, "2Byte KNX_Float" => 4, "2Byte Short" => 5, "3Byte RGB" => 6, "3Byte HSV" => 7, "4Byte SignedLong" => 8, "4Byte Long Float" => 9, "1Byte Scene" => 10))]
    pub slap_short_object_type: u8,

    /// Slap long object type (for status ref selection)
    #[ets(display = "Object type", enum_variants("1Bit" => 0, "2Bit" => 1, "1Byte Char" => 2, "1Byte SignedChar" => 3, "2Byte KNX_Float" => 4, "2Byte Short" => 5, "3Byte RGB" => 6, "3Byte HSV" => 7, "4Byte SignedLong" => 8, "4Byte Long Float" => 9, "1Byte Scene" => 10))]
    pub slap_long_object_type: u8,

    // ========================================================================
    // Button 1 Value Parameters
    // ========================================================================
    /// Button 1 value mode (for send value function)
    #[ets(display = "Value mode", enum_variants("send values" => 0, "send values by state" => 1, "toggle values/scenes (up to 4 values)" => 2, "Multi-tip function (send values after number of operations)" => 3))]
    pub button1_value_mode: u16,

    /// Button 1 DPT type for values
    #[ets(display = "Object type", enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button1_dpt_type: u8,

    /// Button 1 value for released button (switch mode)
    #[ets(display = "Value released button", ets_enum)]
    pub button1_value_released: OnOff,

    /// Button 1 value for pushed button (switch mode)
    #[ets(display = "Value pushed button", ets_enum)]
    pub button1_value_pushed: OnOff,

    /// Button 1 percent value
    #[ets(display = "Percent value")]
    pub button1_percent_value: u8,

    /// Button 1 scene number (1-64)
    #[ets(display = "Scene number")]
    pub button1_scene_number: u8,

    /// Button 1 colour temperature (Kelvin)
    #[ets(display = "Colour temperature")]
    pub button1_colour_temp: u16,

    /// Button 1 group long keypress enable
    #[ets(display = "Group long keypress", ets_enum)]
    pub button1_group_long_enable: GEboolEnableDisable,

    /// Button 1 time for long keypress
    #[ets(display = "Time for long keypress")]
    pub button1_long_time: u16,

    /// Button 1 dimming direction
    #[ets(display = "Dimming direction", enum_variants("brighter / darker" => 0, "darker / brighter" => 1))]
    pub button1_dimm_direction: u16,

    /// Button 1 blinds direction
    #[ets(display = "Blinds direction", enum_variants("Up/Down" => 0, "Down/Up" => 1))]
    pub button1_blinds_direction: u16,

    /// Button 1 blinds function mode
    #[ets(display = "Blinds function", enum_variants("long=Up/Down / short=stop/slats Open/Close" => 0, "short=Up/Down / long=stop/slats Open/Close" => 1, "short=Up/Down/Stop (MDT Single Object Control)" => 2, "short=Up/Down/Stop / long=central object (MDT Single Object Control)" => 3))]
    pub button1_blinds_function: u8,

    /// Button 1 scene save enable (P-53 equivalent)
    /// MDT: SaveScene_0
    #[ets(display = "Save scene", enum_variants("no save" => 0, "save" => 1))]
    pub button1_scene_save_enable: u8,

    // ========================================================================
    // Button 2 Value Parameters
    // ========================================================================
    /// Button 2 value mode (for send value function)
    #[ets(display = "Value mode", enum_variants("send values" => 0, "send values by state" => 1, "toggle values/scenes (up to 4 values)" => 2, "Multi-tip function (send values after number of operations)" => 3))]
    pub button2_value_mode: u16,

    /// Button 2 DPT type for values
    #[ets(display = "Object type", enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button2_dpt_type: u8,

    /// Button 2 value for released button (switch mode)
    #[ets(display = "Value released button", ets_enum)]
    pub button2_value_released: OnOff,

    /// Button 2 value for pushed button (switch mode)
    #[ets(display = "Value pushed button", ets_enum)]
    pub button2_value_pushed: OnOff,

    /// Button 2 percent value
    #[ets(display = "Percent value")]
    pub button2_percent_value: u8,

    /// Button 2 scene number (1-64)
    #[ets(display = "Scene number")]
    pub button2_scene_number: u8,

    /// Button 2 colour temperature (Kelvin)
    #[ets(display = "Colour temperature")]
    pub button2_colour_temp: u16,

    /// Button 2 group long keypress enable
    #[ets(display = "Group long keypress", ets_enum)]
    pub button2_group_long_enable: GEboolEnableDisable,

    /// Button 2 time for long keypress
    #[ets(display = "Time for long keypress")]
    pub button2_long_time: u16,

    /// Button 2 dimming direction
    #[ets(display = "Dimming direction", enum_variants("brighter / darker" => 0, "darker / brighter" => 1))]
    pub button2_dimm_direction: u16,

    /// Button 2 blinds direction
    #[ets(display = "Blinds direction", enum_variants("Up/Down" => 0, "Down/Up" => 1))]
    pub button2_blinds_direction: u16,

    /// Button 2 blinds function mode
    #[ets(display = "Blinds function", enum_variants("long=Up/Down / short=stop/slats Open/Close" => 0, "short=Up/Down / long=stop/slats Open/Close" => 1, "short=Up/Down/Stop (MDT Single Object Control)" => 2, "short=Up/Down/Stop / long=central object (MDT Single Object Control)" => 3))]
    pub button2_blinds_function: u8,

    /// Button 2 scene save enable (P-87 equivalent)
    /// MDT: SaveScene_1
    #[ets(display = "Save scene", enum_variants("no save" => 0, "save" => 1))]
    pub button2_scene_save_enable: u8,

    // ========================================================================
    // Slap Button Parameters
    // ========================================================================
    /// Slap cleaning mode
    #[ets(display = "Cleaning function", enum_variants("cleaning not active, slap active" => 0, "cleaning = long button, slap = short button" => 1, "cleaning = short button, slap = long button" => 2))]
    pub slap_cleaning_mode: u8,

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
    /// Logic 1 send condition
    #[ets(display = "Send condition", enum_variants("not automatic" => 0, "at input telegram" => 1, "at change output" => 2, "at change output (send only 0)" => 5, "at change output (send only 1)" => 6))]
    pub logic1_send_condition: u8,

    /// Logic 1 external input A type
    #[ets(display = "Logic object 1 A (external)", ets_enum)]
    pub logic1_ext_input_a: ExtInputLogicType,

    /// Logic 1 external input B type
    #[ets(display = "Logic object 1 B (external)", ets_enum)]
    pub logic1_ext_input_b: ExtInputLogicType,

    /// Logic 1 internal input button
    #[ets(display = "Internal input (button)", ets_enum)]
    pub logic1_int_button: LogicButton,

    /// Logic 1 output value ON
    #[ets(display = "Output value ON")]
    pub logic1_output_on: u8,

    /// Logic 1 output value OFF
    #[ets(display = "Output value OFF")]
    pub logic1_output_off: u8,

    /// Logic 2 send condition
    #[ets(display = "Send condition", enum_variants("not automatic" => 0, "at input telegram" => 1, "at change output" => 2, "at change output (send only 0)" => 5, "at change output (send only 1)" => 6))]
    pub logic2_send_condition: u8,

    /// Logic 2 external input A type
    #[ets(display = "Logic object 2 A (external)", ets_enum)]
    pub logic2_ext_input_a: ExtInputLogicType,

    /// Logic 2 external input B type
    #[ets(display = "Logic object 2 B (external)", ets_enum)]
    pub logic2_ext_input_b: ExtInputLogicType,

    /// Logic 2 internal input button
    #[ets(display = "Internal input (button)", ets_enum)]
    pub logic2_int_button: LogicButton,

    /// Logic 2 output value ON
    #[ets(display = "Output value ON")]
    pub logic2_output_on: u8,

    /// Logic 2 output value OFF
    #[ets(display = "Output value OFF")]
    pub logic2_output_off: u8,

    /// Logic 3 send condition
    #[ets(display = "Send condition", enum_variants("not automatic" => 0, "at input telegram" => 1, "at change output" => 2, "at change output (send only 0)" => 5, "at change output (send only 1)" => 6))]
    pub logic3_send_condition: u8,

    /// Logic 3 external input A type
    #[ets(display = "Logic object 3 A (external)", ets_enum)]
    pub logic3_ext_input_a: ExtInputLogicType,

    /// Logic 3 external input B type
    #[ets(display = "Logic object 3 B (external)", ets_enum)]
    pub logic3_ext_input_b: ExtInputLogicType,

    /// Logic 3 internal input button
    #[ets(display = "Internal input (button)", ets_enum)]
    pub logic3_int_button: LogicButton,

    /// Logic 3 output value ON
    #[ets(display = "Output value ON")]
    pub logic3_output_on: u8,

    /// Logic 3 output value OFF
    #[ets(display = "Output value OFF")]
    pub logic3_output_off: u8,

    /// Logic 4 send condition
    #[ets(display = "Send condition", enum_variants("not automatic" => 0, "at input telegram" => 1, "at change output" => 2, "at change output (send only 0)" => 5, "at change output (send only 1)" => 6))]
    pub logic4_send_condition: u8,

    /// Logic 4 external input A type
    #[ets(display = "Logic object 4 A (external)", ets_enum)]
    pub logic4_ext_input_a: ExtInputLogicType,

    /// Logic 4 external input B type
    #[ets(display = "Logic object 4 B (external)", ets_enum)]
    pub logic4_ext_input_b: ExtInputLogicType,

    /// Logic 4 internal input button
    #[ets(display = "Internal input (button)", ets_enum)]
    pub logic4_int_button: LogicButton,

    /// Logic 4 output value ON
    #[ets(display = "Output value ON")]
    pub logic4_output_on: u8,

    /// Logic 4 output value OFF
    #[ets(display = "Output value OFF")]
    pub logic4_output_off: u8,

    // ========================================================================
    // Button 1 Extended Parameters
    // ========================================================================
    /// Button 1 description text
    #[ets(display = "Description of buttons/objects", string)]
    pub button1_description: [u8; 30],

    /// Button 1 short action (P-48 equivalent)
    /// MDT: ButtonShort_0, ValueShort type
    #[ets(display = "Action short keypress", enum_variants("switch OFF" => 0, "switch ON" => 1, "toggle" => 2, "send values" => 3, "not active" => 255))]
    pub button1_short_action: u8,

    /// Button 1 long behavior (P-50 equivalent)
    /// MDT: NumberTelergamLong_0, NumberTelgram type
    #[ets(display = "Behavior on long keypress", enum_variants("do not send short button" => 0, "send short button" => 1))]
    pub button1_long_behavior: u8,

    /// Button 1 long action (P-51 equivalent)
    /// MDT: ButtonLong_0, ValueLong type
    #[ets(display = "Action long keypress", enum_variants("switch OFF" => 0, "switch ON" => 1, "toggle" => 2, "send values" => 3, "not active" => 255))]
    pub button1_long_action: u8,

    /// Button 1 short value function
    #[ets(display = "Subfunction", enum_variants("send values" => 0, "send values by state" => 1, "toggle values/scenes" => 2, "multi-tip" => 3))]
    pub button1_short_value_func: u8,

    /// Button 1 long value function
    #[ets(display = "Subfunction", enum_variants("send values" => 0, "send values by state" => 1, "toggle values/scenes" => 2, "multi-tip" => 3))]
    pub button1_long_value_func: u8,

    /// Button 1 behavior on long keypress
    #[ets(display = "Behavior on long keypress", enum_variants("send 1 telegram" => 0, "send 2 telegrams" => 1, "send 3 telegrams" => 2))]
    pub button1_long_telegram_count: u8,

    /// Button 1 tip long active (3rd function)
    #[ets(display = "3. function (long keypress)", ets_enum)]
    pub button1_tip_long_active: GEboolEnableDisable,

    /// Button 1 long keypress enable
    #[ets(display = "Long keypress", ets_enum)]
    pub button1_long_enable: GEboolEnableDisable,

    /// Button 1 switching type
    #[ets(display = "Switching type", enum_variants("send when pressed" => 0, "send when released" => 1, "send when pressed and released" => 2))]
    pub button1_switch_mode: u8,

    /// Button 1 repeat switch
    #[ets(display = "Repeat switch on long keypress", ets_enum)]
    pub button1_repeat_switch: GEboolEnableDisable,

    /// Button 1 delay for released button
    #[ets(display = "Delay for released button", ets_enum)]
    pub button1_delay_state: GEboolEnableDisable,

    /// Button 1 group extra long keypress enable
    #[ets(display = "Group extra long keypress", ets_enum)]
    pub button1_group_extra_long_enable: GEboolEnableDisable,

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
    #[ets(display = "Special function", enum_variants("Innovative group control" => 0, "Additional object" => 1))]
    pub button1_special_function: u8,

    /// Button 1 additional object DPT type (P-39 equivalent)
    /// MDT: DPTButtonGrouptSendValue_0 - DPT type for the additional object
    /// Uses same enum values as button1_object_type for comm object ref selection
    #[ets(display = "Datapoint type (2. object)", default = 2, enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button1_additional_object_type: u8,

    /// Button 1 additional object RGB/HSV colour control (P-40 equivalent)
    /// MDT: ModeRGB_HSV_Long_0
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_additional_colour_control: ColourControl,

    /// Button 1 dimmer style
    #[ets(display = "Dimmer style", enum_variants("short/long" => 0, "long/short" => 1))]
    pub button1_dimmer_style: u8,

    /// Button 1 blinds operation function (P-54 equivalent)
    /// MDT: ShutterShortLongInv_0, 1-bit
    #[ets(display = "Operation function", enum_variants("long=move / short=stop/slats Open/Close" => 0, "short=move / long=stop/slats Open/Close" => 1))]
    pub button1_operation_function: u8,

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
    #[ets(display = "Subfunction", enum_variants("send values" => 0, "send values by state" => 1, "toggle values/scenes (up to 4 values)" => 2, "Multi-tip function (send values after number of operations)" => 3))]
    pub button1_value_function: u8,

    /// Button 1 DPT type for "send values by state" mode (P-41 equivalent)
    /// MDT: DPTButton_0, DPTType (no Switch option - only for mode 1)
    #[ets(display = "Datapoint type", default = 2, enum_variants("2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button1_object_type_no_switch: u8,

    /// Button 1 tip output objects (P-42 equivalent)
    /// MDT: TipOutputObjects_0 - selects common vs different objects/DPT for toggle mode
    #[ets(display = "Output objects", enum_variants("common object /DPT" => 0, "different objects / DPT" => 1))]
    pub button1_tip_output_objects: u8,

    /// Button 1 DPT type for tip 2 in "different objects" mode
    /// Separate selector for the second tip object
    #[ets(display = "Datapoint type", default = 2, enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button1_tip2_object_type: u8,

    /// Button 1 colour control for tip 2
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_tip2_colour_control: ColourControl,

    /// Button 1 DPT type for tip 3 in "different objects" mode
    /// Separate selector for the third tip object
    #[ets(display = "Datapoint type", default = 2, enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button1_tip3_object_type: u8,

    /// Button 1 colour control for tip 3
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_tip3_colour_control: ColourControl,

    /// Button 1 main type H (P-47 equivalent) - hidden dummy param for Mode 7
    /// MDT: OM_inputUsage_mainTypeH_0, dummy8u, Access="None"
    #[ets(display = "", hidden)]
    pub button1_main_type_h: u8,

    /// Button 1 short DPT type (P-49 equivalent) for Mode 7 short action
    /// MDT: Button_Value_short_0, DPTType (no Switch option)
    #[ets(display = "    Datapoint type", default = 2, enum_variants("2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button1_short_dpt_type: u8,

    /// Button 1 long DPT type (P-52 equivalent) for Mode 7 long action
    /// MDT: Button_Value_long_0, DPTType (no Switch option)
    #[ets(display = "    Datapoint type", default = 2, enum_variants("2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button1_long_dpt_type: u8,

    /// Button 1 long colour control (P-40 equivalent) for Mode 7 long RGB/HSV
    /// MDT: ModeRGB_HSV_Long_0
    #[ets(display = "    Colour control", ets_enum)]
    pub button1_long_colour_control: ColourControl,

    /// Button 1 long time special
    #[ets(display = "Time for long keypress")]
    pub button1_long_time_special: u16,

    // ========================================================================
    // Button 2 Extended Parameters
    // ========================================================================
    /// Button 2 description text
    #[ets(display = "Description of buttons/objects", string)]
    pub button2_description: [u8; 30],

    /// Button 2 short action (P-48 equivalent for button 2)
    /// MDT: ButtonShort_1, ValueShort type
    #[ets(display = "Action short keypress", enum_variants("switch OFF" => 0, "switch ON" => 1, "toggle" => 2, "send values" => 3, "not active" => 255))]
    pub button2_short_action: u8,

    /// Button 2 long behavior (P-50 equivalent for button 2)
    /// MDT: NumberTelergamLong_1, NumberTelgram type
    #[ets(display = "Behavior on long keypress", enum_variants("do not send short button" => 0, "send short button" => 1))]
    pub button2_long_behavior: u8,

    /// Button 2 long action (P-51 equivalent for button 2)
    /// MDT: ButtonLong_1, ValueLong type
    #[ets(display = "Action long keypress", enum_variants("switch OFF" => 0, "switch ON" => 1, "toggle" => 2, "send values" => 3, "not active" => 255))]
    pub button2_long_action: u8,

    /// Button 2 short value function
    #[ets(display = "Subfunction", enum_variants("send values" => 0, "send values by state" => 1, "toggle values/scenes" => 2, "multi-tip" => 3))]
    pub button2_short_value_func: u8,

    /// Button 2 long value function
    #[ets(display = "Subfunction", enum_variants("send values" => 0, "send values by state" => 1, "toggle values/scenes" => 2, "multi-tip" => 3))]
    pub button2_long_value_func: u8,

    /// Button 2 behavior on long keypress
    #[ets(display = "Behavior on long keypress", enum_variants("send 1 telegram" => 0, "send 2 telegrams" => 1, "send 3 telegrams" => 2))]
    pub button2_long_telegram_count: u8,

    /// Button 2 tip long active (3rd function)
    #[ets(display = "3. function (long keypress)", ets_enum)]
    pub button2_tip_long_active: GEboolEnableDisable,

    /// Button 2 long keypress enable
    #[ets(display = "Long keypress", ets_enum)]
    pub button2_long_enable: GEboolEnableDisable,

    /// Button 2 switching type
    #[ets(display = "Switching type", enum_variants("send when pressed" => 0, "send when released" => 1, "send when pressed and released" => 2))]
    pub button2_switch_mode: u8,

    /// Button 2 delay for released button
    #[ets(display = "Delay for released button", ets_enum)]
    pub button2_delay_state: GEboolEnableDisable,

    /// Button 2 group extra long keypress enable
    #[ets(display = "Group extra long keypress", ets_enum)]
    pub button2_group_extra_long_enable: GEboolEnableDisable,

    /// Button 2 LED color
    #[ets(display = "LED colour", enum_variants("off" => 0, "green" => 1, "red" => 2, "orange" => 3, "blue" => 4, "white" => 5, "pink" => 6))]
    pub button2_led_color: u8,

    /// Button 2 LED brightness
    #[ets(display = "LED brightness", enum_variants("off" => 0, "10%" => 1, "20%" => 2, "30%" => 3, "40%" => 4, "50%" => 5, "60%" => 6, "70%" => 7, "80%" => 8, "90%" => 9, "100%" => 10))]
    pub button2_led_brightness: u8,

    /// Button 2 group function (Group long keypress in MDT)
    #[ets(display = "Group long keypress", ets_enum)]
    pub button2_group_function: GEboolEnableDisable,

    /// Button 2 group send condition (Group extra long keypress in MDT)
    #[ets(display = "Group extra long keypress", ets_enum)]
    pub button2_group_send_condition: GEboolEnableDisable,

    /// Button 2 special function (P-81 equivalent)
    /// MDT: GroupSpecialFunction_1 - switches between "Innovative group control" and "Additional object"
    #[ets(display = "Special function", enum_variants("Innovative group control" => 0, "Additional object" => 1))]
    pub button2_special_function: u8,

    /// Button 2 additional object DPT type (P-73 equivalent)
    /// MDT: DPTButtonGrouptSendValue_1 - DPT type for the additional object
    /// Uses same enum values as button2_object_type for comm object ref selection
    #[ets(display = "Datapoint type (2. object)", default = 2, enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button2_additional_object_type: u8,

    /// Button 2 additional object RGB/HSV colour control (P-74 equivalent)
    /// MDT: ModeRGB_HSV_Long_1
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_additional_colour_control: ColourControl,

    /// Button 2 dimmer style
    #[ets(display = "Dimmer style", enum_variants("short/long" => 0, "long/short" => 1))]
    pub button2_dimmer_style: u8,

    /// Button 2 blinds operation function (P-88 equivalent)
    /// MDT: ShutterShortLongInv_1, 1-bit
    #[ets(display = "Operation function", enum_variants("long=move / short=stop/slats Open/Close" => 0, "short=move / long=stop/slats Open/Close" => 1))]
    pub button2_operation_function: u8,

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
    #[ets(display = "Subfunction", enum_variants("send values" => 0, "send values by state" => 1, "toggle values/scenes (up to 4 values)" => 2, "Multi-tip function (send values after number of operations)" => 3))]
    pub button2_value_function: u8,

    /// Button 2 DPT type for "send values by state" mode (P-74 equivalent)
    /// MDT: DPTButton_1, DPTType (no Switch option - only for mode 1)
    #[ets(display = "Datapoint type", default = 2, enum_variants("2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button2_object_type_no_switch: u8,

    /// Button 2 tip output objects (P-75 equivalent)
    /// MDT: TipOutputObjects_1 - selects common vs different objects/DPT for toggle mode
    #[ets(display = "Output objects", enum_variants("common object /DPT" => 0, "different objects / DPT" => 1))]
    pub button2_tip_output_objects: u8,

    /// Button 2 DPT type for tip 2 in "different objects" mode
    /// Separate selector for the second tip object
    #[ets(display = "Datapoint type", default = 2, enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button2_tip2_object_type: u8,

    /// Button 2 colour control for tip 2
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_tip2_colour_control: ColourControl,

    /// Button 2 DPT type for tip 3 in "different objects" mode
    /// Separate selector for the third tip object
    #[ets(display = "Datapoint type", default = 2, enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button2_tip3_object_type: u8,

    /// Button 2 colour control for tip 3
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_tip3_colour_control: ColourControl,

    /// Button 2 main type H (P-81 equivalent) - hidden dummy param for Mode 7
    /// MDT: OM_inputUsage_mainTypeH_1, dummy8u, Access="None"
    #[ets(display = "", hidden)]
    pub button2_main_type_h: u8,

    /// Button 2 short DPT type (P-83 equivalent) for Mode 7 short action
    /// MDT: Button_Value_short_1, DPTType (no Switch option)
    #[ets(display = "    Datapoint type", default = 2, enum_variants("2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button2_short_dpt_type: u8,

    /// Button 2 long DPT type (P-86 equivalent) for Mode 7 long action
    /// MDT: Button_Value_long_1, DPTType (no Switch option)
    #[ets(display = "    Datapoint type", default = 2, enum_variants("2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent (0...100%)" => 2, "1Byte DPT 5.005 Decimal factor (0...255)" => 3, "1Byte DPT 17.001 Scene number" => 4, "2Byte DPT 7.600 Colour Temperature (Kelvin)" => 6, "2Byte DPT 9.001 Temperature (°C)" => 7, "2Byte DPT 9.004 Brightness (Lux)" => 8, "3Byte DPT 232.600 RGB value 3x(0...255)" => 9))]
    pub button2_long_dpt_type: u8,

    /// Button 2 long colour control (P-74 equivalent) for Mode 7 long RGB/HSV
    /// MDT: ModeRGB_HSV_Long_1
    #[ets(display = "    Colour control", ets_enum)]
    pub button2_long_colour_control: ColourControl,

    // ========================================================================
    // Two-Button Mode Parameters
    // ========================================================================
    /// Two-button function selector (P-91 equivalent)
    /// MDT: EnableGrupMain_0, EingangFunctionGroup type
    #[ets(display = "Two-button function", type_name = "EingangFunctionGroup", enum_variants("switch" => 0, "dimming" => 1, "blinds/shutter" => 2, "send values" => 3, "switch/send values short/long (with 2 objects)" => 5))]
    pub two_button_function: u16,

    /// Button assignment for two-button switch mode (P-92 equivalent)
    /// MDT: ConfigSwitch_0, SwitchType type
    #[ets(display = "Button assignment (1/2)", type_name = "SwitchType", enum_variants("ON/OFF" => 0, "OFF/ON" => 1))]
    pub button_assignment: u16,

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
    #[ets(display = "Subfunction", type_name = "ButtonGrouptValueType", default = 1, enum_variants("send values" => 1, "toggle values/scenes (up to 4 values)" => 2, "shift value" => 3))]
    pub two_button_value_function: u8,

    /// Group send option (P-96 equivalent)
    /// MDT: GroupSend_0, GroupSend type
    #[ets(display = "    Group long sends", type_name = "GroupSend", enum_variants("value for upper and lower button" => 0, "value for upper button" => 1, "value for lower button" => 2))]
    pub group_send_option: u8,

    /// Two-button switch configuration
    #[ets(display = "Switch configuration", enum_variants("brighter/darker" => 0, "darker/brighter" => 1))]
    pub config_switch: u8,

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

    /// Button mapping for two-button mode
    #[ets(display = "Button mapping")]
    pub button_mapping: u8,

    /// Main type for button 0 (two-button mode)
    #[ets(display = "Main type button 0")]
    pub main_type_0: u8,

    /// Main type for button 1 (two-button mode)
    #[ets(display = "Main type button 1")]
    pub main_type_1: u8,

    /// Sub type for button 0 (two-button mode)
    #[ets(display = "Sub type button 0")]
    pub sub_type_0: u8,

    /// Sub type for button 1 (two-button mode)
    #[ets(display = "Sub type button 1")]
    pub sub_type_1: u8,

    // ========================================================================
    // Group Functions Parameters
    // ========================================================================
    /// Group main enable
    #[ets(display = "Enable group function", ets_enum)]
    pub group_main_enable: GEboolEnableDisable,

    /// Group switch long
    #[ets(display = "Group switch on long keypress", ets_enum)]
    pub group_switch_long: GEboolEnableDisable,

    /// Group switch extra long
    #[ets(display = "Group switch on extra long keypress", ets_enum)]
    pub group_switch_extra_long: GEboolEnableDisable,

    /// Button short group action
    #[ets(display = "Short group action")]
    pub button_short_groupt: u8,

    /// Button long group action
    #[ets(display = "Long group action")]
    pub button_long_groupt: u8,

    /// Group long condition
    #[ets(display = "Condition for long group", enum_variants("always" => 0, "on button 1" => 1, "on button 2" => 2))]
    pub cond_long_groupt: u8,

    /// Group value function
    #[ets(display = "Group value function", enum_variants("send values" => 0, "toggle values" => 1))]
    pub button_groupt_value_func: u8,

    /// Group DPT type
    #[ets(display = "Group datapoint type", enum_variants("1Bit" => 0, "2Bit" => 1, "1Byte" => 2))]
    pub dpt_button_groupt: u8,

    /// Group send value DPT type (button 0)
    #[ets(display = "Datapoint type", enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent" => 2))]
    pub dpt_button_groupt_send_value_0: u8,

    /// Group send value DPT type (button 1)
    #[ets(display = "Datapoint type (2. object)", enum_variants("1Bit DPT 1.001 Switch" => 10, "2Bit DPT 2.001 Forcible control" => 1, "1Byte DPT 5.001 Percent" => 2))]
    pub dpt_button_groupt_send_value_1: u8,

    /// Group special function (button 0)
    #[ets(display = "Special function", enum_variants("innovative group control" => 0, "additional object" => 1))]
    pub group_special_func_0: u8,

    /// Group special function (button 1)
    #[ets(display = "Special function", enum_variants("innovative group control" => 0, "additional object" => 1))]
    pub group_special_func_1: u8,

    /// Blocking object for group
    #[ets(display = "Blocking object", ets_enum)]
    pub block_object_groupt: GEboolEnableDisable,

    // ========================================================================
    // Panic/Slap Extended Parameters
    // ========================================================================
    /// Panic block switch
    #[ets(display = "Block switch during panic", ets_enum)]
    pub block_switch_panic: GEboolEnableDisable,

    /// Panic value/control mode
    #[ets(display = "Panic value/control", enum_variants("value" => 0, "control" => 1))]
    pub value_control_panic: u8,

    /// Panic short function
    #[ets(display = "Short function during panic", enum_variants("switch" => 0, "send value" => 1))]
    pub button_func_short_panic: u8,

    /// Panic long function
    #[ets(display = "Long function during panic", enum_variants("switch" => 0, "send value" => 1))]
    pub button_func_long_panic: u8,

    /// Panic RGB/HSV mode
    #[ets(display = "Colour control", ets_enum)]
    pub mode_rgb_hsv_panic: ColourControl,

    /// Panic long RGB/HSV mode
    #[ets(display = "Colour control (long)", ets_enum)]
    pub mode_rgb_hsv_lang_panic: ColourControl,

    /// Panic time duration
    #[ets(display = "Panic time duration")]
    pub time_duration_panic: u16,

    // ========================================================================
    // Logic Extended Parameters
    // ========================================================================
    /// Logic read on init
    #[ets(display = "Read logic on init", enum_variants("no request" => 0, "request" => 1))]
    pub logic_read: u8,

    /// Logic delay time
    #[ets(display = "Logic delay time")]
    pub logic_delay_time: u16,

    /// Logic 1 operation type
    #[ets(display = "Logic operation", ets_enum)]
    pub logic1_operation: AndOr,

    /// Logic 2 operation type
    #[ets(display = "Logic operation", ets_enum)]
    pub logic2_operation: AndOr,

    /// Logic 3 operation type
    #[ets(display = "Logic operation", ets_enum)]
    pub logic3_operation: AndOr,

    /// Logic 4 operation type
    #[ets(display = "Logic operation", ets_enum)]
    pub logic4_operation: AndOr,

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

    /// Logic output object type (Or 0)
    #[ets(display = "Output object type", enum_variants("switch" => 1, "scene" => 2, "value" => 3, "forcible control" => 4))]
    pub logic_objecttype_or_0: u8,

    /// Logic output object type (Or 1)
    #[ets(display = "Output object type", enum_variants("switch" => 1, "scene" => 2, "value" => 3, "forcible control" => 4))]
    pub logic_objecttype_or_1: u8,

    /// Logic output object type (And 2)
    #[ets(display = "Output object type", enum_variants("switch" => 1, "scene" => 2, "value" => 3, "forcible control" => 4))]
    pub logic_objecttype_and_2: u8,

    /// Logic output object type (And 3)
    #[ets(display = "Output object type", enum_variants("switch" => 1, "scene" => 2, "value" => 3, "forcible control" => 4))]
    pub logic_objecttype_and_3: u8,

    // ========================================================================
    // Blocking Object Parameters
    // ========================================================================
    /// Block object enable (button 0)
    #[ets(display = "Blocking Object", ets_enum)]
    pub block_object_0: GEboolEnableDisable,

    /// Block object enable (button 1)
    #[ets(display = "Blocking Object", ets_enum)]
    pub block_object_1: GEboolEnableDisable,

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

    /// Button 1 long action type (upper button)
    #[ets(display = "Long action type (upper)", union)]
    pub button1_long_action_type_upper: LongButtonActionUnion,

    /// Button 1 long action type (main)
    #[ets(display = "Long action type", union)]
    pub button1_long_action_type: LongButtonActionUnion,

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

    /// Button 2 long action type (upper button)
    #[ets(display = "Long action type (upper)", union)]
    pub button2_long_action_type_upper: LongButtonActionUnion,

    /// Button 2 long action type (main)
    #[ets(display = "Long action type", union)]
    pub button2_long_action_type: LongButtonActionUnion,

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
    /// Panic sub-type configuration
    #[ets(display = "Panic sub type", union)]
    pub panic_sub_type: LongButtonActionUnion,

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

    /// Slap button value type (hidden)
    #[ets(display = "", hidden)]
    pub slap_value_type: u8,

    /// Slap button subtype (hidden)
    #[ets(display = "", hidden)]
    pub slap_subtype: u8,

    // ========================================================================
    // Dummy/Hidden Parameters (for enabling conditional object display)
    // ========================================================================
    /// Dummy enable parameter (hidden - MDT internal feature for showing all placeholder objects)
    /// When set to 1, all dummy/placeholder ComObjects become visible in ETS.
    #[ets(display = "", hidden, ets_enum)]
    pub dummy_enable: GEboolEnableDisable,
}

// Default and ConstDefault are auto-generated by #[ets(derive_defaults)]
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

// ============================================================================
// Stack Definition
// ============================================================================

/// Table sizes computed from DeviceDescriptor
pub const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
pub const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
pub const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();
pub const APP_DATA_SIZE: usize = core::mem::size_of::<MdtParams>();

/// Unified state type
pub type MdtState = IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MdtParams, MdtStack>;

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
pub struct MdtStack;

impl SystemBDevice for MdtStack {
    type Storage = JsonStorage;
}

impl KnxIpDevice for MdtStack {
    const INTERFACE_NAME: &'static str = INTERFACE_NAME;
    type Platform = MockIpPlatform;
}

impl StackDefinition for MdtStack {
    const DEVICE: &'static zweidraehte::ets::DeviceDescriptor = &DEVICE_DESCRIPTOR;

    type P = MdtParams;
    type CO = comm_objs::MdtComObjects;
    type LLB = KnxNetIpBuilder<2, 2>;
    type State = MdtState;
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
        create_knxip_objects::<MdtStack, _>(state, &MEMORY_LAYOUT)
    }
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
                    // When dummy_enable = 1, show all dummy objects (MDT has 57 ComObjectRefRefs here)
                    when @dummy_enable {
                        [1] => {
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
                    // Mode object is shown when cyclic mode is enabled (default=true), hidden when 0
                    when @mode_cyclic {
                        _ => { obj mode }
                        [0] => { }
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
                        [1] => {
                            param button1_led_color
                            param button1_led_brightness
                            param button1_subtype
                            param button1_value_type
                        }
                        // Single-button 2 functions: no additional visible params
                        [2] => { }
                        // Single-button 1 function: no additional visible params
                        [3] => { }
                    }
                }

                // Button blocks based on eingang_type - MDT order: PB1 (2,3), PB2 (2), PB1/2 (1)
                // All three blocks in a single choose to match MDT's structure
                when @eingang_type {
                    // Single-button modes (2, 3) - PB1 block comes first in MDT
                    [2, 3] => {
                        block "pButton_0" => "    PB1: {{button1_description:Push button 1}}" {
                            param button1_description
                            param button1_function
                            // Mode 0 = switch: nested choose on switch_type (subfunction)
                            when @button1_function {
                                [0] => {
                                    param button1_switch_type
                                    when @button1_switch_type {
                                        // switch_type 0 = switch (simple) - MDT pattern: direct object output
                                        // In MDT, switch/switch has only "Value pushed button" visible
                                        // The "Value released button" (UP-109) has Access="None" and is hidden
                                        [0] => {
                                            obj_fixed_variant button1_main with [button1_value_type, button1_subtype] => button1_value_00::Switch @ 0 text "Value pushed button"
                                            sep "Innovative group control"
                                            param button1_group_function
                                            when @button1_group_function {
                                                // When P-28=0 (no group): UP-109 is hidden (sets internal value)
                                                [0] => { }
                                                [1] => {
                                                    // MDT outputs O-2 directly in switch mode (fixed to Switch type)
                                                    objs_by_ref_name ["button1_status_toggle_switch"] with []
                                                    // UP-109 hidden here too (Access="None")
                                                    param button1_group_send_condition
                                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                    when @button1_group_send_condition {
                                                        [1] => {
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
                                        [1] => {
                                            objs_by_ref_name ["button1_main_switch", "button1_secondary_switch"] with []
                                            // MDT shows hidden params P-26, P-15, P-27 here - we skip visible value params
                                            sep "Innovative group control"
                                            param button1_group_function
                                            when @button1_group_function {
                                                [0] => { }
                                                [1] => {
                                                    objs_by_ref_name ["button1_status_toggle_switch"] with []
                                                    param button1_group_send_condition
                                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                    when @button1_group_send_condition {
                                                        [1] => {
                                                            obj_direct button1_extra_long with []
                                                            union_variant button1_extra_long_time::ExtraLongKeypressTime
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // switch_type 2 = send status - MDT pattern: direct object output (fixed to Switch type)
                                        // Shows: O-0 (Send status), Value pushed, Value released, Delay for released button
                                        [2] => {
                                            objs_by_ref_name ["button1_main_switch"] with []
                                            param button1_value_pushed
                                            param button1_value_released
                                            param button1_delay_state
                                            when @button1_delay_state {
                                                [1] => {
                                                    union_variant button1_time_duration::DelayTime
                                                }
                                            }
                                        }
                                    }
                                }
                                // Mode 4 = send values
                                [4] => {
                                    param button1_value_function
                                    when @button1_value_function {
                                        // value_function 0 = send values
                                        // MDT structure: P-15 (hidden), P-35 (visible), choose P-35 with obj+P-27+UP-xxx
                                        // P-15 is OM_InputUsage_subType_0 (hidden/Access=None)
                                        // P-35 is DPTButton1Bit_0 (Datapoint type)
                                        // P-27 is OM_InputUsage_valueType00_0 (hidden/Access=None)
                                        // value_function 0 = send values
                                        // MDT structure: P-15 (hidden subtype), P-35 (Datapoint type), choose P-35, P-37 (special function)
                                        [0] => {
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
                                                [0] => {
                                                    sep "Innovative group control"
                                                    param button1_group_function
                                                    when @button1_group_function {
                                                        // group_function 0 = not active: just hidden value param
                                                        [0] => { }
                                                        // group_function 1 = active: show status toggle object and timing
                                                        [1] => {
                                                            // O-2 (status toggle) depends on object_type for DPT - uses same DPT as main
                                                            obj_with_value button1_status_toggle by button1_object_type => button1_value_01 with [button1_value_type] sub_select {
                                                                9 => button1_colour_control [(1, button1_status_toggle_rgb, Rgb), (2, button1_status_toggle_hsv, Hsv)]
                                                            }
                                                            param button1_group_send_condition
                                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                            when @button1_group_send_condition {
                                                                // 0 = not active: hidden extra long value
                                                                [0] => { }
                                                                // 1 = active: show extra long object and timing
                                                                [1] => {
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
                                                [1] => {
                                                    param button1_additional_object_type
                                                    // O-2 (status toggle) with DPT based on additional_object_type
                                                    // Each DPT value selects a different named ref
                                                    when @button1_additional_object_type {
                                                        [10] => {
                                                            objs_by_ref_name ["button1_additional_obj_switch"] with []
                                                            union_variant button1_value_01::Switch text "    Value"
                                                        }
                                                        [1] => {
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
                                                            objs_by_ref_name ["button1_additional_obj_temp"] with []
                                                            union_variant button1_value_01::Temperature text "    Value"
                                                        }
                                                        [8] => {
                                                            objs_by_ref_name ["button1_additional_obj_lux"] with []
                                                            union_variant button1_value_01::Brightness text "    Value"
                                                        }
                                                        [9] => {
                                                            param button1_additional_colour_control
                                                            when @button1_additional_colour_control {
                                                                [1] => {
                                                                    objs_by_ref_name ["button1_additional_obj_rgb"] with []
                                                                    union_variant button1_value_01::Rgb text "    Value"
                                                                }
                                                                [2] => {
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
                                        [1] => {
                                            param button1_subtype
                                            param button1_object_type_no_switch
                                            // Choose on object_type_no_switch (DPT): each when has obj + pushed value + released value + delay
                                            when @button1_object_type_no_switch {
                                                // DPT 1 = 2Bit Forcible control
                                                [1] => {
                                                    objs_by_ref_name ["button1_main_bit2"] with []
                                                    union_variant button1_value_01::ForcibleControl text "Value pushed button"
                                                    union_variant button1_value_00::ForcibleControl text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT 2 = 1Byte Percent (0...100%)
                                                [2] => {
                                                    objs_by_ref_name ["button1_main_percent"] with []
                                                    union_variant button1_value_01::Percent text "Value pushed button"
                                                    union_variant button1_value_00::Percent text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT 3 = 1Byte Decimal factor (0...255)
                                                [3] => {
                                                    objs_by_ref_name ["button1_main_decimal"] with []
                                                    union_variant button1_value_01::Decimal text "Value pushed button"
                                                    union_variant button1_value_00::Decimal text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT 4 = 1Byte Scene number
                                                [4] => {
                                                    objs_by_ref_name ["button1_main_scene"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_01::Scene text "Value pushed button"
                                                    union_variant button1_value_00::Scene text "Value released button"
                                                }
                                                // DPT 6 = 2Byte Colour Temperature (Kelvin)
                                                [6] => {
                                                    objs_by_ref_name ["button1_main_colour_temp"] with []
                                                    union_variant button1_value_01::ColourTemp text "Value pushed button"
                                                    union_variant button1_value_00::ColourTemp text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT 7 = 2Byte Temperature (°C)
                                                [7] => {
                                                    objs_by_ref_name ["button1_main_temp"] with []
                                                    union_variant button1_value_01::Temperature text "Value pushed button"
                                                    union_variant button1_value_00::Temperature text "Value released button"
                                                    param button1_delay_state
                                                }
                                                // DPT 8 = 2Byte Brightness (Lux)
                                                [8] => {
                                                    objs_by_ref_name ["button1_main_lux"] with []
                                                    param button1_delay_state
                                                    union_variant button1_value_01::Brightness text "Value pushed button"
                                                    union_variant button1_value_00::Brightness text "Value released button"
                                                }
                                                // DPT 9 = 3Byte RGB/HSV
                                                [9] => {
                                                    param button1_delay_state
                                                    param button1_colour_control
                                                    when @button1_colour_control {
                                                        // RGB mode
                                                        [1] => {
                                                            objs_by_ref_name ["button1_main_rgb"] with []
                                                            union_variant button1_value_01::Rgb text "    Value pushed button"
                                                            union_variant button1_value_00::Rgb text "    Value released button"
                                                        }
                                                        // HSV mode
                                                        [2] => {
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
                                        [2] => {
                                            param button1_object_type_no_switch
                                            union_variant button1_sub_type_h::ValueCount text "Number of values"
                                            when @button1_object_type_no_switch {
                                                // Forcible control (1)
                                                [1] => {
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
                                                // Percent (2)
                                                [2] => {
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
                                                // Decimal (3)
                                                [3] => {
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
                                                // Scene (4)
                                                [4] => {
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
                                                [9] => {
                                                    param button1_delay_state
                                                    param button1_colour_control
                                                    when @button1_colour_control {
                                                        [1] => {
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
                                                        [2] => {
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
                                                [0] => {
                                                    param button1_subtype
                                                    param button1_object_type
                                                    when @button1_object_type {
                                                        // Switch (10)
                                                        [10] => {
                                                            objs_by_ref_name ["button1_main_switch"] with []
                                                            union_variant button1_value_00::Switch text "    Value tip once"
                                                            union_variant button1_value_01::Switch text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button1_value_02::Switch text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Forcible control (1)
                                                        [1] => {
                                                            objs_by_ref_name ["button1_main_bit2"] with []
                                                            union_variant button1_value_00::ForcibleControl text "    Value tip once"
                                                            union_variant button1_value_01::ForcibleControl text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button1_value_02::ForcibleControl text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Percent (2)
                                                        [2] => {
                                                            objs_by_ref_name ["button1_main_percent"] with []
                                                            union_variant button1_value_00::Percent text "    Value tip once"
                                                            union_variant button1_value_01::Percent text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button1_value_02::Percent text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Decimal (3)
                                                        [3] => {
                                                            objs_by_ref_name ["button1_main_decimal"] with []
                                                            union_variant button1_value_00::Decimal text "    Value tip once"
                                                            union_variant button1_value_01::Decimal text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button1_value_02::Decimal text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Scene (4)
                                                        [4] => {
                                                            objs_by_ref_name ["button1_main_scene"] with []
                                                            union_variant button1_value_00::Scene text "    Scene number tip once"
                                                            union_variant button1_value_01::Scene text "    Scene number tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button1_value_02::Scene text "    Scene number tip 3 times"
                                                                }
                                                            }
                                                        }
                                                        // ColourTemp (6)
                                                        [6] => {
                                                            objs_by_ref_name ["button1_main_colour_temp"] with []
                                                            union_variant button1_value_00::ColourTemp text "    Value tip once"
                                                            union_variant button1_value_01::ColourTemp text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button1_value_02::ColourTemp text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Temperature (7)
                                                        [7] => {
                                                            objs_by_ref_name ["button1_main_temp"] with []
                                                            union_variant button1_value_00::Temperature text "    Value tip once"
                                                            union_variant button1_value_01::Temperature text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button1_value_02::Temperature text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Brightness (8)
                                                        [8] => {
                                                            objs_by_ref_name ["button1_main_lux"] with []
                                                            union_variant button1_value_00::Brightness text "    Value tip once"
                                                            union_variant button1_value_01::Brightness text "    Value tip twice"
                                                            choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button1_value_02::Brightness text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // RGB/HSV (9)
                                                        [9] => {
                                                            param button1_colour_control
                                                            when @button1_colour_control {
                                                                [1] => {
                                                                    objs_by_ref_name ["button1_main_rgb"] with []
                                                                    union_variant button1_value_00::Rgb text "    RGB-Value tip once"
                                                                    union_variant button1_value_01::Rgb text "    RGB-Value tip twice"
                                                                    choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                        [2] => {
                                                                            union_variant button1_value_02::Rgb text "    RGB-Value tip triple"
                                                                        }
                                                                    }
                                                                }
                                                                [2] => {
                                                                    objs_by_ref_name ["button1_main_hsv"] with []
                                                                    union_variant button1_value_00::Hsv text "    HSV-Value tip once"
                                                                    union_variant button1_value_01::Hsv text "    HSV-Value tip twice"
                                                                    choose_on_union_variant button1_sub_type_h::TipOperations {
                                                                        [2] => {
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
                                                [1] => {
                                                    // Tip 1 - uses button1_object_type
                                                    param button1_subtype
                                                    param button1_object_type
                                                    when @button1_object_type {
                                                        [10] => { objs_by_ref_name ["button1_tip_switch"] with [] union_variant button1_value_00::Switch text "    Value tip once" }
                                                        [1] => { objs_by_ref_name ["button1_tip_bit2"] with [] union_variant button1_value_00::ForcibleControl text "    Value tip once" }
                                                        [2] => { objs_by_ref_name ["button1_tip_percent"] with [] union_variant button1_value_00::Percent text "    Value tip once" }
                                                        [3] => { objs_by_ref_name ["button1_tip_decimal"] with [] union_variant button1_value_00::Decimal text "    Value tip once" }
                                                        [4] => { objs_by_ref_name ["button1_tip_scene"] with [] union_variant button1_value_00::Scene text "    Scene number tip once" }
                                                        [6] => { objs_by_ref_name ["button1_tip_colour_temp"] with [] union_variant button1_value_00::ColourTemp text "    Value tip once" }
                                                        [7] => { objs_by_ref_name ["button1_tip_temp"] with [] union_variant button1_value_00::Temperature text "    Value tip once" }
                                                        [8] => { objs_by_ref_name ["button1_tip_lux"] with [] union_variant button1_value_00::Brightness text "    Value tip once" }
                                                        [9] => {
                                                            param button1_colour_control
                                                            when @button1_colour_control {
                                                                [1] => { objs_by_ref_name ["button1_tip_rgb"] with [] union_variant button1_value_00::Rgb text "    RGB-Value tip once" }
                                                                [2] => { objs_by_ref_name ["button1_tip_hsv"] with [] union_variant button1_value_00::Hsv text "    HSV-Value tip once" }
                                                            }
                                                        }
                                                    }
                                                    // Tip 2 - uses button1_tip2_object_type (separate DPT selector)
                                                    param button1_tip2_object_type
                                                    when @button1_tip2_object_type {
                                                        [10] => { objs_by_ref_name ["button1_2x_tip_switch"] with [] union_variant button1_value_01::Switch text "    Value tip twice" }
                                                        [1] => { objs_by_ref_name ["button1_2x_tip_bit2"] with [] union_variant button1_value_01::ForcibleControl text "    Value tip twice" }
                                                        [2] => { objs_by_ref_name ["button1_2x_tip_percent"] with [] union_variant button1_value_01::Percent text "    Value tip twice" }
                                                        [3] => { objs_by_ref_name ["button1_2x_tip_decimal"] with [] union_variant button1_value_01::Decimal text "    Value tip twice" }
                                                        [4] => { objs_by_ref_name ["button1_2x_tip_scene"] with [] union_variant button1_value_01::Scene text "    Scene number tip twice" }
                                                        [6] => { objs_by_ref_name ["button1_2x_tip_colour_temp"] with [] union_variant button1_value_01::ColourTemp text "    Value tip twice" }
                                                        [7] => { objs_by_ref_name ["button1_2x_tip_temp"] with [] union_variant button1_value_01::Temperature text "    Value tip twice" }
                                                        [8] => { objs_by_ref_name ["button1_2x_tip_lux"] with [] union_variant button1_value_01::Brightness text "    Value tip twice" }
                                                        [9] => {
                                                            param button1_tip2_colour_control
                                                            when @button1_tip2_colour_control {
                                                                [1] => { objs_by_ref_name ["button1_2x_tip_rgb"] with [] union_variant button1_value_01::Rgb text "    RGB-Value tip twice" }
                                                                [2] => { objs_by_ref_name ["button1_2x_tip_hsv"] with [] union_variant button1_value_01::Hsv text "    HSV-Value tip twice" }
                                                            }
                                                        }
                                                    }
                                                    // Tip 3 - only shown when 3 tips selected, uses button1_tip3_object_type
                                                    choose_on_union_variant button1_sub_type_h::TipOperations {
                                                        [2] => {
                                                            param button1_tip3_object_type
                                                            when @button1_tip3_object_type {
                                                                [10] => { objs_by_ref_name ["button1_3x_tip_switch"] with [] union_variant button1_value_02::Switch text "    Value tip triple" }
                                                                [1] => { objs_by_ref_name ["button1_3x_tip_bit2"] with [] union_variant button1_value_02::ForcibleControl text "    Value tip triple" }
                                                                [2] => { objs_by_ref_name ["button1_3x_tip_percent"] with [] union_variant button1_value_02::Percent text "    Value tip triple" }
                                                                [3] => { objs_by_ref_name ["button1_3x_tip_decimal"] with [] union_variant button1_value_02::Decimal text "    Value tip triple" }
                                                                [4] => { objs_by_ref_name ["button1_3x_tip_scene"] with [] union_variant button1_value_02::Scene text "    Scene number tip 3 times" }
                                                                [6] => { objs_by_ref_name ["button1_3x_tip_colour_temp"] with [] union_variant button1_value_02::ColourTemp text "    Value tip triple" }
                                                                [7] => { objs_by_ref_name ["button1_3x_tip_temp"] with [] union_variant button1_value_02::Temperature text "    Value tip triple" }
                                                                [8] => { objs_by_ref_name ["button1_3x_tip_lux"] with [] union_variant button1_value_02::Brightness text "    Value tip triple" }
                                                                [9] => {
                                                                    param button1_tip3_colour_control
                                                                    when @button1_tip3_colour_control {
                                                                        [1] => { objs_by_ref_name ["button1_3x_tip_rgb"] with [] union_variant button1_value_02::Rgb text "    RGB-Value tip triple" }
                                                                        [2] => { objs_by_ref_name ["button1_3x_tip_hsv"] with [] union_variant button1_value_02::Hsv text "    HSV-Value tip triple" }
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
                                        [0] => {
                                            objs_by_ref_name ["button1_main_switch_off"] with []
                                            // P-27 and UP-116 are both hidden - no visible value selector
                                        }
                                        // short_action 1 = switch ON: O-0, P-27 (hidden), UP-116 hidden with Value=1
                                        [1] => {
                                            objs_by_ref_name ["button1_main_switch_on"] with []
                                            // P-27 and UP-116 are both hidden - no visible value selector
                                        }
                                        // short_action 2 = toggle: O-0, O-1, P-27 (hidden) - no value params at all
                                        [2] => {
                                            objs_by_ref_name ["button1_main_toggle", "button1_secondary_toggle"] with []
                                            // No value selector for toggle
                                        }
                                        // short_action 3 = send values: P-49 (DPT type, default=2=Percent), then choose on DPT with obj+value
                                        [3] => {
                                            param button1_short_dpt_type
                                            when @button1_short_dpt_type {
                                                [1] => {
                                                    objs_by_ref_name ["button1_main_bit2"] with []
                                                    union_variant button1_value_00::ForcibleControl text "    Value"
                                                }
                                                [2] => {
                                                    objs_by_ref_name ["button1_main_percent"] with []
                                                    union_variant button1_value_00::Percent text "    Value"
                                                }
                                                [3] => {
                                                    objs_by_ref_name ["button1_main_decimal"] with []
                                                    union_variant button1_value_00::Decimal text "    Value"
                                                }
                                                [4] => {
                                                    objs_by_ref_name ["button1_main_scene"] with []
                                                    union_variant button1_value_00::Scene text "    Scene number"
                                                }
                                                [6] => {
                                                    objs_by_ref_name ["button1_main_colour_temp"] with []
                                                    union_variant button1_value_00::ColourTemp text "    Value"
                                                }
                                                [7] => {
                                                    objs_by_ref_name ["button1_main_temp"] with []
                                                    union_variant button1_value_00::Temperature text "    Value"
                                                }
                                                [8] => {
                                                    objs_by_ref_name ["button1_main_lux"] with []
                                                    union_variant button1_value_00::Brightness text "    Value"
                                                }
                                                [9] => {
                                                    param button1_colour_control
                                                    when @button1_colour_control {
                                                        [1] => {
                                                            objs_by_ref_name ["button1_main_rgb"] with []
                                                            union_variant button1_value_00::Rgb text "    RGB-Value"
                                                        }
                                                        [2] => {
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
                                        [0] => {
                                            objs_by_ref_name ["button1_long_switch_off"] with []
                                            // UP-109 and UP-127 are hidden - no visible value selector
                                        }
                                        // long_action 1 = switch ON: O-2, UP-109 (hidden), UP-127 hidden with Value=1
                                        [1] => {
                                            objs_by_ref_name ["button1_long_switch_on"] with []
                                            // UP-109 and UP-127 are hidden - no visible value selector
                                        }
                                        // long_action 2 = toggle: O-2, O-3, UP-109 (hidden) - no value params
                                        [2] => {
                                            objs_by_ref_name ["button1_long_toggle", "button1_long_status_toggle"] with []
                                            // No value selector for toggle
                                        }
                                        // long_action 3 = send values: P-52 (DPT type, default=2=Percent), then choose on DPT with obj+value
                                        [3] => {
                                            param button1_long_dpt_type
                                            when @button1_long_dpt_type {
                                                [1] => {
                                                    objs_by_ref_name ["button1_long_bit2"] with []
                                                    union_variant button1_value_03::ForcibleControl text "    Value"
                                                }
                                                [2] => {
                                                    objs_by_ref_name ["button1_long_percent"] with []
                                                    union_variant button1_value_03::Percent text "    Value"
                                                }
                                                [3] => {
                                                    objs_by_ref_name ["button1_long_decimal"] with []
                                                    union_variant button1_value_03::Decimal text "    Value"
                                                }
                                                [4] => {
                                                    objs_by_ref_name ["button1_long_scene"] with []
                                                    union_variant button1_value_03::Scene text "    Scene number"
                                                }
                                                [6] => {
                                                    objs_by_ref_name ["button1_long_colour_temp"] with []
                                                    union_variant button1_value_03::ColourTemp text "    Value"
                                                }
                                                [7] => {
                                                    objs_by_ref_name ["button1_long_temp"] with []
                                                    union_variant button1_value_03::Temperature text "    Value"
                                                }
                                                [8] => {
                                                    objs_by_ref_name ["button1_long_lux"] with []
                                                    union_variant button1_value_03::Brightness text "    Value"
                                                }
                                                [9] => {
                                                    param button1_long_colour_control
                                                    when @button1_long_colour_control {
                                                        [1] => {
                                                            objs_by_ref_name ["button1_long_rgb"] with []
                                                            union_variant button1_value_03::Rgb text "    RGB-Value"
                                                        }
                                                        [2] => {
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
                                        [0, 1, 2, 3] => {
                                            union_variant button1_extra_long_time::ExtraLongKeypressTime text "Time for keypress"
                                        }
                                    }
                                }
                                // Mode 2 = blinds/shutter - MDT outputs objects directly (fixed type)
                                // Uses named refs to select the blinds DPT refs
                                [2] => {
                                    objs_by_ref_name ["button1_main_blinds", "button1_secondary_blinds", "button1_status_toggle_blinds"] with []
                                    param button1_operation_function
                                    when @button1_operation_function {
                                        [0] => {
                                            // long=move / short=stop mode
                                            sep "Innovative group control"
                                            param button1_group_extra_long
                                        }
                                        [1] => {
                                            // short=move / long=stop mode - no group control
                                        }
                                    }
                                    // Time for long keypress - shown for both operation function modes
                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                    // Extra long objects only when group control is enabled
                                    when @button1_group_extra_long {
                                        [1] => {
                                            objs_direct [button1_status_display, button1_extra_long] with []
                                            union_variant button1_extra_long_time::ExtraLongKeypressTime text "Time for extra long keypress"
                                        }
                                    }
                                }
                                // Mode 1 = dimming - MDT outputs objects directly (fixed type)
                                // Uses named refs to select the dimming DPT refs
                                [1] => {
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
                                [0, 1, 2, 3, 4, 7] => {
                                    sep " "
                                    param button1_blocking_enable
                                    when @button1_blocking_enable { [1] => { obj button1_blocking } }
                                }
                            }
                        }
                    }
                    // Single-button mode with 2 functions (eingang_type = 2) - PB2 block comes second in MDT
                    [2] => {
                        block "pButton_1" => "    PB2: {{button2_description:Push button 2}}" {
                            param button2_description
                            param button2_function
                            // Mode 0 = switch: nested choose on switch_type (subfunction)
                            when @button2_function {
                                [0] => {
                                    param button2_switch_type
                                    when @button2_switch_type {
                                        // switch_type 0 = switch (simple) - MDT pattern: direct object output
                                        // In MDT, switch/switch has only "Value pushed button" visible
                                        // The "Value released button" (UP-109) has Access="None" and is hidden
                                        [0] => {
                                            obj_fixed_variant button2_main with [button2_value_type, button2_subtype] => button2_value_00::Switch @ 0 text "Value pushed button"
                                            sep "Innovative group control"
                                            param button2_group_function
                                            when @button2_group_function {
                                                // When P-28=0 (no group): UP-109 is hidden (sets internal value)
                                                [0] => { }
                                                [1] => {
                                                    // MDT outputs O-12 directly in switch mode (fixed to Switch type)
                                                    objs_by_ref_name ["button2_status_toggle_switch"] with []
                                                    // UP-109 hidden here too (Access="None")
                                                    param button2_group_send_condition
                                                    union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                                    when @button2_group_send_condition {
                                                        [1] => {
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
                                        [1] => {
                                            objs_by_ref_name ["button2_main_switch", "button2_secondary_switch"] with []
                                            // MDT shows hidden params P-60, P-15, P-61 here - we skip visible value params
                                            sep "Innovative group control"
                                            param button2_group_function
                                            when @button2_group_function {
                                                [0] => { }
                                                [1] => {
                                                    objs_by_ref_name ["button2_status_toggle_switch"] with []
                                                    param button2_group_send_condition
                                                    union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                                    when @button2_group_send_condition {
                                                        [1] => {
                                                            obj_direct button2_extra_long with []
                                                            union_variant button2_extra_long_time::ExtraLongKeypressTime
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // switch_type 2 = send status - MDT pattern: direct object output (fixed to Switch type)
                                        // Shows: O-10 (Send status), Value pushed, Value released, Delay for released button
                                        [2] => {
                                            objs_by_ref_name ["button2_main_switch"] with []
                                            param button2_value_pushed
                                            param button2_value_released
                                            param button2_delay_state
                                            when @button2_delay_state {
                                                [1] => {
                                                    union_variant button2_time_duration::DelayTime
                                                }
                                            }
                                        }
                                    }
                                }
                                // Mode 4 = send values
                                [4] => {
                                    param button2_value_function
                                    when @button2_value_function {
                                        // value_function 0 = send values
                                        // MDT structure: P-55 (hidden subtype), P-79 (Datapoint type), choose P-79, P-81 (special function)
                                        [0] => {
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
                                                [0] => {
                                                    sep "Innovative group control"
                                                    param button2_group_function
                                                    when @button2_group_function {
                                                        // group_function 0 = not active: just hidden value param
                                                        [0] => { }
                                                        // group_function 1 = active: show status toggle object and timing
                                                        [1] => {
                                                            // O-12 (status toggle) depends on object_type for DPT - uses same DPT as main
                                                            obj_with_value button2_status_toggle by button2_object_type => button2_value_01 with [button2_value_type] sub_select {
                                                                9 => button2_colour_control [(1, button2_status_toggle_rgb, Rgb), (2, button2_status_toggle_hsv, Hsv)]
                                                            }
                                                            param button2_group_send_condition
                                                            union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                                            when @button2_group_send_condition {
                                                                // 0 = not active: hidden extra long value
                                                                [0] => { }
                                                                // 1 = active: show extra long object and timing
                                                                [1] => {
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
                                                [1] => {
                                                    param button2_additional_object_type
                                                    // O-12 (status toggle) with DPT based on additional_object_type
                                                    when @button2_additional_object_type {
                                                        [10] => {
                                                            objs_by_ref_name ["button2_additional_obj_switch"] with []
                                                            union_variant button2_value_01::Switch text "    Value"
                                                        }
                                                        [1] => {
                                                            objs_by_ref_name ["button2_additional_obj_bit2"] with []
                                                            union_variant button2_value_01::ForcibleControl text "    Value"
                                                        }
                                                        [2] => {
                                                            objs_by_ref_name ["button2_additional_obj_percent"] with []
                                                            union_variant button2_value_01::Percent text "    Value"
                                                        }
                                                        [3] => {
                                                            objs_by_ref_name ["button2_additional_obj_decimal"] with []
                                                            union_variant button2_value_01::Decimal text "    Value"
                                                        }
                                                        [4] => {
                                                            objs_by_ref_name ["button2_additional_obj_scene"] with []
                                                            union_variant button2_value_01::Scene text "    Value"
                                                        }
                                                        [6] => {
                                                            objs_by_ref_name ["button2_additional_obj_colour_temp"] with []
                                                            union_variant button2_value_01::ColourTemp text "    Value"
                                                        }
                                                        [7] => {
                                                            objs_by_ref_name ["button2_additional_obj_temp"] with []
                                                            union_variant button2_value_01::Temperature text "    Value"
                                                        }
                                                        [8] => {
                                                            objs_by_ref_name ["button2_additional_obj_lux"] with []
                                                            union_variant button2_value_01::Brightness text "    Value"
                                                        }
                                                        [9] => {
                                                            param button2_additional_colour_control
                                                            when @button2_additional_colour_control {
                                                                [1] => {
                                                                    objs_by_ref_name ["button2_additional_obj_rgb"] with []
                                                                    union_variant button2_value_01::Rgb text "    Value"
                                                                }
                                                                [2] => {
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
                                        [1] => {
                                            param button2_subtype
                                            param button2_object_type_no_switch
                                            // Choose on object_type_no_switch (DPT): each when has obj + pushed value + released value + delay
                                            when @button2_object_type_no_switch {
                                                // DPT 1 = 2Bit Forcible control
                                                [1] => {
                                                    objs_by_ref_name ["button2_main_bit2"] with []
                                                    union_variant button2_value_01::ForcibleControl text "Value pushed button"
                                                    union_variant button2_value_00::ForcibleControl text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT 2 = 1Byte Percent (0...100%)
                                                [2] => {
                                                    objs_by_ref_name ["button2_main_percent"] with []
                                                    union_variant button2_value_01::Percent text "Value pushed button"
                                                    union_variant button2_value_00::Percent text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT 3 = 1Byte Decimal factor (0...255)
                                                [3] => {
                                                    objs_by_ref_name ["button2_main_decimal"] with []
                                                    union_variant button2_value_01::Decimal text "Value pushed button"
                                                    union_variant button2_value_00::Decimal text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT 4 = 1Byte Scene number
                                                [4] => {
                                                    objs_by_ref_name ["button2_main_scene"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_01::Scene text "Value pushed button"
                                                    union_variant button2_value_00::Scene text "Value released button"
                                                }
                                                // DPT 6 = 2Byte Colour Temperature (Kelvin)
                                                [6] => {
                                                    objs_by_ref_name ["button2_main_colour_temp"] with []
                                                    union_variant button2_value_01::ColourTemp text "Value pushed button"
                                                    union_variant button2_value_00::ColourTemp text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT 7 = 2Byte Temperature (°C)
                                                [7] => {
                                                    objs_by_ref_name ["button2_main_temp"] with []
                                                    union_variant button2_value_01::Temperature text "Value pushed button"
                                                    union_variant button2_value_00::Temperature text "Value released button"
                                                    param button2_delay_state
                                                }
                                                // DPT 8 = 2Byte Brightness (Lux)
                                                [8] => {
                                                    objs_by_ref_name ["button2_main_lux"] with []
                                                    param button2_delay_state
                                                    union_variant button2_value_01::Brightness text "Value pushed button"
                                                    union_variant button2_value_00::Brightness text "Value released button"
                                                }
                                                // DPT 9 = 3Byte RGB/HSV
                                                [9] => {
                                                    param button2_delay_state
                                                    param button2_colour_control
                                                    when @button2_colour_control {
                                                        // RGB mode
                                                        [1] => {
                                                            objs_by_ref_name ["button2_main_rgb"] with []
                                                            union_variant button2_value_01::Rgb text "    Value pushed button"
                                                            union_variant button2_value_00::Rgb text "    Value released button"
                                                        }
                                                        // HSV mode
                                                        [2] => {
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
                                        [2] => {
                                            param button2_object_type_no_switch
                                            union_variant button2_sub_type_h::ValueCount text "Number of values"
                                            when @button2_object_type_no_switch {
                                                // Forcible control (1)
                                                [1] => {
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
                                                // Percent (2)
                                                [2] => {
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
                                                // Decimal (3)
                                                [3] => {
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
                                                // Scene (4)
                                                [4] => {
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
                                                // ColourTemp (6)
                                                [6] => {
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
                                                // Temperature (7)
                                                [7] => {
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
                                                // Brightness (8)
                                                [8] => {
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
                                                // RGB/HSV (9)
                                                [9] => {
                                                    param button2_delay_state
                                                    param button2_colour_control
                                                    when @button2_colour_control {
                                                        [1] => {
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
                                                        [2] => {
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
                                                [0] => {
                                                    param button2_subtype
                                                    param button2_object_type
                                                    when @button2_object_type {
                                                        // Switch (10)
                                                        [10] => {
                                                            objs_by_ref_name ["button2_main_switch"] with []
                                                            union_variant button2_value_00::Switch text "    Value tip once"
                                                            union_variant button2_value_01::Switch text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Switch text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Forcible control (1)
                                                        [1] => {
                                                            objs_by_ref_name ["button2_main_bit2"] with []
                                                            union_variant button2_value_00::ForcibleControl text "    Value tip once"
                                                            union_variant button2_value_01::ForcibleControl text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::ForcibleControl text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Percent (2)
                                                        [2] => {
                                                            objs_by_ref_name ["button2_main_percent"] with []
                                                            union_variant button2_value_00::Percent text "    Value tip once"
                                                            union_variant button2_value_01::Percent text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Percent text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Decimal (3)
                                                        [3] => {
                                                            objs_by_ref_name ["button2_main_decimal"] with []
                                                            union_variant button2_value_00::Decimal text "    Value tip once"
                                                            union_variant button2_value_01::Decimal text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Decimal text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Scene (4)
                                                        [4] => {
                                                            objs_by_ref_name ["button2_main_scene"] with []
                                                            union_variant button2_value_00::Scene text "    Scene number tip once"
                                                            union_variant button2_value_01::Scene text "    Scene number tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Scene text "    Scene number tip 3 times"
                                                                }
                                                            }
                                                        }
                                                        // ColourTemp (6)
                                                        [6] => {
                                                            objs_by_ref_name ["button2_main_colour_temp"] with []
                                                            union_variant button2_value_00::ColourTemp text "    Value tip once"
                                                            union_variant button2_value_01::ColourTemp text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::ColourTemp text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Temperature (7)
                                                        [7] => {
                                                            objs_by_ref_name ["button2_main_temp"] with []
                                                            union_variant button2_value_00::Temperature text "    Value tip once"
                                                            union_variant button2_value_01::Temperature text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Temperature text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // Brightness (8)
                                                        [8] => {
                                                            objs_by_ref_name ["button2_main_lux"] with []
                                                            union_variant button2_value_00::Brightness text "    Value tip once"
                                                            union_variant button2_value_01::Brightness text "    Value tip twice"
                                                            choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                [2] => {
                                                                    union_variant button2_value_02::Brightness text "    Value tip triple"
                                                                }
                                                            }
                                                        }
                                                        // RGB/HSV (9)
                                                        [9] => {
                                                            param button2_colour_control
                                                            when @button2_colour_control {
                                                                [1] => {
                                                                    objs_by_ref_name ["button2_main_rgb"] with []
                                                                    union_variant button2_value_00::Rgb text "    RGB-Value tip once"
                                                                    union_variant button2_value_01::Rgb text "    RGB-Value tip twice"
                                                                    choose_on_union_variant button2_sub_type_h::TipOperations {
                                                                        [2] => {
                                                                            union_variant button2_value_02::Rgb text "    RGB-Value tip triple"
                                                                        }
                                                                    }
                                                                }
                                                                [2] => {
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
                                                [1] => {
                                                    // Tip 1 - uses button2_object_type
                                                    param button2_subtype
                                                    param button2_object_type
                                                    when @button2_object_type {
                                                        [10] => { objs_by_ref_name ["button2_tip_switch"] with [] union_variant button2_value_00::Switch text "    Value tip once" }
                                                        [1] => { objs_by_ref_name ["button2_tip_bit2"] with [] union_variant button2_value_00::ForcibleControl text "    Value tip once" }
                                                        [2] => { objs_by_ref_name ["button2_tip_percent"] with [] union_variant button2_value_00::Percent text "    Value tip once" }
                                                        [3] => { objs_by_ref_name ["button2_tip_decimal"] with [] union_variant button2_value_00::Decimal text "    Value tip once" }
                                                        [4] => { objs_by_ref_name ["button2_tip_scene"] with [] union_variant button2_value_00::Scene text "    Scene number tip once" }
                                                        [6] => { objs_by_ref_name ["button2_tip_colour_temp"] with [] union_variant button2_value_00::ColourTemp text "    Value tip once" }
                                                        [7] => { objs_by_ref_name ["button2_tip_temp"] with [] union_variant button2_value_00::Temperature text "    Value tip once" }
                                                        [8] => { objs_by_ref_name ["button2_tip_lux"] with [] union_variant button2_value_00::Brightness text "    Value tip once" }
                                                        [9] => {
                                                            param button2_colour_control
                                                            when @button2_colour_control {
                                                                [1] => { objs_by_ref_name ["button2_tip_rgb"] with [] union_variant button2_value_00::Rgb text "    RGB-Value tip once" }
                                                                [2] => { objs_by_ref_name ["button2_tip_hsv"] with [] union_variant button2_value_00::Hsv text "    HSV-Value tip once" }
                                                            }
                                                        }
                                                    }
                                                    // Tip 2 - uses button2_tip2_object_type (separate DPT selector)
                                                    param button2_tip2_object_type
                                                    when @button2_tip2_object_type {
                                                        [10] => { objs_by_ref_name ["button2_2x_tip_switch"] with [] union_variant button2_value_01::Switch text "    Value tip twice" }
                                                        [1] => { objs_by_ref_name ["button2_2x_tip_bit2"] with [] union_variant button2_value_01::ForcibleControl text "    Value tip twice" }
                                                        [2] => { objs_by_ref_name ["button2_2x_tip_percent"] with [] union_variant button2_value_01::Percent text "    Value tip twice" }
                                                        [3] => { objs_by_ref_name ["button2_2x_tip_decimal"] with [] union_variant button2_value_01::Decimal text "    Value tip twice" }
                                                        [4] => { objs_by_ref_name ["button2_2x_tip_scene"] with [] union_variant button2_value_01::Scene text "    Scene number tip twice" }
                                                        [6] => { objs_by_ref_name ["button2_2x_tip_colour_temp"] with [] union_variant button2_value_01::ColourTemp text "    Value tip twice" }
                                                        [7] => { objs_by_ref_name ["button2_2x_tip_temp"] with [] union_variant button2_value_01::Temperature text "    Value tip twice" }
                                                        [8] => { objs_by_ref_name ["button2_2x_tip_lux"] with [] union_variant button2_value_01::Brightness text "    Value tip twice" }
                                                        [9] => {
                                                            param button2_tip2_colour_control
                                                            when @button2_tip2_colour_control {
                                                                [1] => { objs_by_ref_name ["button2_2x_tip_rgb"] with [] union_variant button2_value_01::Rgb text "    RGB-Value tip twice" }
                                                                [2] => { objs_by_ref_name ["button2_2x_tip_hsv"] with [] union_variant button2_value_01::Hsv text "    HSV-Value tip twice" }
                                                            }
                                                        }
                                                    }
                                                    // Tip 3 - only shown when 3 tips selected, uses button2_tip3_object_type
                                                    choose_on_union_variant button2_sub_type_h::TipOperations {
                                                        [2] => {
                                                            param button2_tip3_object_type
                                                            when @button2_tip3_object_type {
                                                                [10] => { objs_by_ref_name ["button2_3x_tip_switch"] with [] union_variant button2_value_02::Switch text "    Value tip triple" }
                                                                [1] => { objs_by_ref_name ["button2_3x_tip_bit2"] with [] union_variant button2_value_02::ForcibleControl text "    Value tip triple" }
                                                                [2] => { objs_by_ref_name ["button2_3x_tip_percent"] with [] union_variant button2_value_02::Percent text "    Value tip triple" }
                                                                [3] => { objs_by_ref_name ["button2_3x_tip_decimal"] with [] union_variant button2_value_02::Decimal text "    Value tip triple" }
                                                                [4] => { objs_by_ref_name ["button2_3x_tip_scene"] with [] union_variant button2_value_02::Scene text "    Scene number tip 3 times" }
                                                                [6] => { objs_by_ref_name ["button2_3x_tip_colour_temp"] with [] union_variant button2_value_02::ColourTemp text "    Value tip triple" }
                                                                [7] => { objs_by_ref_name ["button2_3x_tip_temp"] with [] union_variant button2_value_02::Temperature text "    Value tip triple" }
                                                                [8] => { objs_by_ref_name ["button2_3x_tip_lux"] with [] union_variant button2_value_02::Brightness text "    Value tip triple" }
                                                                [9] => {
                                                                    param button2_tip3_colour_control
                                                                    when @button2_tip3_colour_control {
                                                                        [1] => { objs_by_ref_name ["button2_3x_tip_rgb"] with [] union_variant button2_value_02::Rgb text "    RGB-Value tip triple" }
                                                                        [2] => { objs_by_ref_name ["button2_3x_tip_hsv"] with [] union_variant button2_value_02::Hsv text "    HSV-Value tip triple" }
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
                                        [0] => {
                                            objs_by_ref_name ["button2_main_switch_off"] with []
                                            // No visible value selector - MDT uses Access="None"
                                        }
                                        // short_action 1 = switch ON: O-10, hidden value preset to 1
                                        [1] => {
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
                                                [1] => {
                                                    objs_by_ref_name ["button2_main_bit2"] with []
                                                    union_variant button2_value_00::ForcibleControl text "    Value"
                                                }
                                                [2] => {
                                                    objs_by_ref_name ["button2_main_percent"] with []
                                                    union_variant button2_value_00::Percent text "    Value"
                                                }
                                                [3] => {
                                                    objs_by_ref_name ["button2_main_decimal"] with []
                                                    union_variant button2_value_00::Decimal text "    Value"
                                                }
                                                [4] => {
                                                    objs_by_ref_name ["button2_main_scene"] with []
                                                    union_variant button2_value_00::Scene text "    Scene number"
                                                }
                                                [6] => {
                                                    objs_by_ref_name ["button2_main_colour_temp"] with []
                                                    union_variant button2_value_00::ColourTemp text "    Value"
                                                }
                                                [7] => {
                                                    objs_by_ref_name ["button2_main_temp"] with []
                                                    union_variant button2_value_00::Temperature text "    Value"
                                                }
                                                [8] => {
                                                    objs_by_ref_name ["button2_main_lux"] with []
                                                    union_variant button2_value_00::Brightness text "    Value"
                                                }
                                                [9] => {
                                                    param button2_colour_control
                                                    when @button2_colour_control {
                                                        [1] => {
                                                            objs_by_ref_name ["button2_main_rgb"] with []
                                                            union_variant button2_value_00::Rgb text "    RGB-Value"
                                                        }
                                                        [2] => {
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
                                        [0] => {
                                            objs_by_ref_name ["button2_long_switch_off"] with []
                                            // No visible value selector - MDT uses Access="None"
                                        }
                                        // long_action 1 = switch ON: O-12, hidden value preset to 1
                                        [1] => {
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
                                                [9] => {
                                                    param button2_long_colour_control
                                                    when @button2_long_colour_control {
                                                        [1] => {
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
                                        [0, 1, 2, 3] => {
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
                                        [0] => {
                                            // long=move / short=stop mode
                                            sep "Innovative group control"
                                            param button2_group_extra_long
                                        }
                                        [1] => {
                                            // short=move / long=stop mode - no group control
                                        }
                                    }
                                    // Time for long keypress - shown for both operation function modes
                                    union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                    // Extra long objects only when group control is enabled
                                    when @button2_group_extra_long {
                                        [1] => {
                                            objs_direct [button2_status_display, button2_extra_long] with []
                                            union_variant button2_extra_long_time::ExtraLongKeypressTime text "Time for extra long keypress"
                                        }
                                    }
                                }
                                // Mode 1 = dimming - MDT outputs objects directly (fixed type)
                                // Uses named refs to select the dimming DPT refs
                                [1] => {
                                    objs_by_ref_name ["button2_main_dimming", "button2_secondary_dimming", "button2_status_toggle_dimming"] with []
                                    union_variant button2_time_duration::LongKeypressTime text "Time for long keypress"
                                }
                            }
                            // Blocking object section - shown when default true (all modes except 255)
                            when @button2_function {
                                [0, 1, 2, 3, 4, 7] => {
                                    sep " "
                                    param button2_blocking_enable
                                    when @button2_blocking_enable { [1] => { obj button2_blocking } }
                                }
                            }
                        }
                    }
                    // Two-button mode (eingang_type = 1) - PB1/2 block comes third in MDT
                    [1] => {
                        block "pButtonGroupt_0" => "    PB1/2: {{button1_description:Push buttons 1/2}}" {
                            param button1_description
                            param two_button_function
                            when @two_button_function {
                                // Mode 0 = switch: MDT pattern - O-0, hidden params, P-92, group control
                                [0] => {
                                    obj_direct button1_main with []
                                    // Hidden params P-13,14,15,16 (main_type/sub_type) - we use hidden params
                                    // P-92 button_assignment: ON/OFF or OFF/ON
                                    param button_assignment
                                    // P-27/P-43 values based on button_assignment - hidden
                                    sep "Innovative group control"
                                    param button1_group_function
                                    when @button1_group_function {
                                        [1] => {
                                            obj_direct button1_status_toggle with []
                                            // P-93 Group long sends
                                            param group_long_send_cond
                                            // Time params based on P-92 and P-93 - hidden
                                            // P-29 Group send condition for extra long
                                            param button1_group_send_condition
                                            when @button1_group_send_condition {
                                                [1] => {
                                                    obj_direct button1_extra_long with []
                                                    // P-94 Group extra long sends
                                                    param group_extra_long_send_cond
                                                }
                                            }
                                            // UP-110 Time for long keypress
                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                            when @button1_group_send_condition {
                                                [1] => {
                                                    // UP-155 Time for extra long keypress
                                                    union_variant button1_extra_long_time::ExtraLongKeypressTime
                                                }
                                            }
                                        }
                                    }
                                }
                                // Mode 3 = send values: MDT pattern - P-95 subfunction, then DPT-based objects
                                [3] => {
                                    param two_button_value_function
                                    when @two_button_value_function {
                                        // send values mode (P-95=1)
                                        [1] => {
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
                                                        [1] => {
                                                            // Object based on DPT
                                                            obj_with_value button1_status_toggle by button1_object_type => button1_value_01 with [button1_value_type] sub_select {
                                                                9 => button1_colour_control [(1, button1_status_toggle_rgb, Rgb), (2, button1_status_toggle_hsv, Hsv)]
                                                            }
                                                            param group_send_option
                                                            param button1_group_send_condition
                                                            when @button1_group_send_condition {
                                                                [1] => {
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
                                                                [1] => {
                                                                    union_variant button1_extra_long_time::ExtraLongKeypressTime
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Additional object
                                                [1] => {
                                                    param button1_additional_object_type
                                                    when @button1_additional_object_type {
                                                        [10] => {
                                                            objs_by_ref_name ["button1_additional_obj_switch"] with []
                                                            union_variant button1_value_01::Switch text "    Value"
                                                        }
                                                        [1] => {
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
                                                        [9] => {
                                                            param button1_colour_control
                                                            when @button1_colour_control {
                                                                [1] => {
                                                                    objs_by_ref_name ["button1_additional_obj_rgb"] with []
                                                                    union_variant button1_value_01::Rgb text "    Value"
                                                                }
                                                                [2] => {
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
                                [2] => {
                                    param config_shutter
                                    objs_by_ref_name ["button1_main_blinds", "button1_secondary_blinds"] with []
                                    param button1_operation_function
                                    when @button1_operation_function {
                                        [0] => {
                                            // short=step / long=move mode - with group control
                                            sep "Innovative group control"
                                            param button1_group_function
                                            when @button1_group_function {
                                                [1] => {
                                                    objs_by_ref_name ["button1_status_display_blinds", "button1_extra_long_blinds"] with []
                                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                                    union_variant button1_extra_long_time::ExtraLongKeypressTime text "Time for extra long keypress"
                                                }
                                            }
                                        }
                                        [1] => {
                                            // short=move / long=stop mode - no group control
                                            union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                        }
                                    }
                                }
                                // Mode 1 = dimming
                                [1] => {
                                    param config_dimmer
                                    objs_by_ref_name ["button1_main_dimming", "button1_secondary_dimming", "button1_status_toggle_dimming"] with []
                                    union_variant button1_time_duration::LongKeypressTime text "Time for long keypress"
                                }
                                // Mode 5 = switch/send values short/long (with 2 objects)
                                [5] => {
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
                            when @button1_blocking_enable { [1] => { obj_direct button1_blocking with [] } }
                        }
                    }
                }

                // Slap button - only shown when slap function is enabled
                when @eingang_type_patsch {
                    [1] => {
                        block "PatchButtton" => "    Slap / Cleaning function" {
                            param slap_cleaning_mode
                            when @slap_cleaning_mode {
                                [0] => { param slap_led_colour }
                                [1] => { param slap_led_colour sep "Cleaning time config" }
                                [2] => { param slap_led_colour sep "Extended cleaning" }
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
                            when @slap_blocking_enable { [1] => { obj slap_blocking } }
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
                        [0, 1, 2] => {
                            param logic1_description
                            param logic1_add_description
                        }
                        // And/Or modes - show object type and output config
                        [0, 1] => {
                            param logic1_output_type
                            when @logic1_output_type {
                                // Switch (1)
                                [1] => {
                                    obj logic1_output
                                    union_variant logic1_send_condition_union::Condition
                                    param logic1_invert_output
                                }
                                // Scene (2)
                                [2] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::Scene text "    Scene number"
                                }
                                // Value (3)
                                [3] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::ByteValue text "    1Byte Value"
                                }
                                // Forcible control (4)
                                [4] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                        // Send value mode - different structure
                        [2] => {
                            param logic1_output_type
                            when @logic1_output_type {
                                [1] => {
                                    obj logic1_output
                                    union_variant logic1_send_condition_union::Condition
                                    param logic1_invert_output
                                }
                                [2] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::Scene text "    Scene number"
                                }
                                [3] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::ByteValue text "    1Byte Value"
                                }
                                [4] => {
                                    obj logic1_output
                                    union_variant logic1_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                    }

                    // Logic 2 settings
                    param logic2_type
                    when @logic2_type {
                        [0, 1, 2] => {
                            param logic2_description
                            param logic2_add_description
                        }
                        [0, 1] => {
                            param logic2_output_type
                            when @logic2_output_type {
                                [1] => {
                                    obj logic2_output
                                    union_variant logic2_send_condition_union::Condition
                                    param logic2_invert_output
                                }
                                [2] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::Scene text "    Scene number"
                                }
                                [3] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::ByteValue text "    1Byte Value"
                                }
                                [4] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                        [2] => {
                            param logic2_output_type
                            when @logic2_output_type {
                                [1] => {
                                    obj logic2_output
                                    union_variant logic2_send_condition_union::Condition
                                    param logic2_invert_output
                                }
                                [2] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::Scene text "    Scene number"
                                }
                                [3] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::ByteValue text "    1Byte Value"
                                }
                                [4] => {
                                    obj logic2_output
                                    union_variant logic2_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                    }

                    // Logic 3 settings
                    param logic3_type
                    when @logic3_type {
                        [0, 1, 2] => {
                            param logic3_description
                            param logic3_add_description
                        }
                        [0, 1] => {
                            param logic3_output_type
                            when @logic3_output_type {
                                [1] => {
                                    obj logic3_output
                                    union_variant logic3_send_condition_union::Condition
                                    param logic3_invert_output
                                }
                                [2] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::Scene text "    Scene number"
                                }
                                [3] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::ByteValue text "    1Byte Value"
                                }
                                [4] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                        [2] => {
                            param logic3_output_type
                            when @logic3_output_type {
                                [1] => {
                                    obj logic3_output
                                    union_variant logic3_send_condition_union::Condition
                                    param logic3_invert_output
                                }
                                [2] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::Scene text "    Scene number"
                                }
                                [3] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::ByteValue text "    1Byte Value"
                                }
                                [4] => {
                                    obj logic3_output
                                    union_variant logic3_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                    }

                    // Logic 4 settings
                    param logic4_type
                    when @logic4_type {
                        [0, 1, 2] => {
                            param logic4_description
                            param logic4_add_description
                        }
                        [0, 1] => {
                            param logic4_output_type
                            when @logic4_output_type {
                                [1] => {
                                    obj logic4_output
                                    union_variant logic4_send_condition_union::Condition
                                    param logic4_invert_output
                                }
                                [2] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::Scene text "    Scene number"
                                }
                                [3] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::ByteValue text "    1Byte Value"
                                }
                                [4] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::ForcibleControl text "    Forcible control"
                                }
                            }
                        }
                        [2] => {
                            param logic4_output_type
                            when @logic4_output_type {
                                [1] => {
                                    obj logic4_output
                                    union_variant logic4_send_condition_union::Condition
                                    param logic4_invert_output
                                }
                                [2] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::Scene text "    Scene number"
                                }
                                [3] => {
                                    obj logic4_output
                                    union_variant logic4_value_union::ByteValue text "    1Byte Value"
                                }
                                [4] => {
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
                    [0, 1] => {
                        block "Logic_1" => "    Logic 1 {{logic1_description:}}" {
                            param logic1_ext_input_a
                            when @logic1_ext_input_a {
                                [1, 2, 129, 130] => { obj logic1_input_a }
                            }
                            param logic1_ext_input_b
                            when @logic1_ext_input_b {
                                [1, 2, 129, 130] => { obj logic1_input_b }
                            }
                            param logic1_button_choose_0
                            when @logic1_button_choose_0 {
                                [1] => { param logic1_int_button1 }
                                [2] => { param logic1_int_button2 }
                            }
                            param logic1_button_choose_1
                            when @logic1_button_choose_1 {
                                [1] => { param logic1_int_button1 }
                                [2] => { param logic1_int_button2 }
                            }
                        }
                    }
                    [2] => {
                        block "Logic_1" => "    Logic 1 {{logic1_description:}}" {
                            param logic1_button_choose_0
                            when @logic1_button_choose_0 {
                                [1] => { param logic1_int_button1 }
                                [2] => { param logic1_int_button2 }
                            }
                        }
                    }
                }

                // Logic 2 input configuration block
                when @logic2_type {
                    [0, 1] => {
                        block "Logic_2" => "    Logic 2 {{logic2_description:}}" {
                            param logic2_ext_input_a
                            when @logic2_ext_input_a {
                                [1, 2, 129, 130] => { obj logic2_input_a }
                            }
                            param logic2_ext_input_b
                            when @logic2_ext_input_b {
                                [1, 2, 129, 130] => { obj logic2_input_b }
                            }
                            param logic2_button_choose_0
                            when @logic2_button_choose_0 {
                                [1] => { param logic2_int_button1 }
                                [2] => { param logic2_int_button2 }
                            }
                            param logic2_button_choose_1
                            when @logic2_button_choose_1 {
                                [1] => { param logic2_int_button1 }
                                [2] => { param logic2_int_button2 }
                            }
                        }
                    }
                    [2] => {
                        block "Logic_2" => "    Logic 2 {{logic2_description:}}" {
                            param logic2_button_choose_0
                            when @logic2_button_choose_0 {
                                [1] => { param logic2_int_button1 }
                                [2] => { param logic2_int_button2 }
                            }
                        }
                    }
                }

                // Logic 3 input configuration block
                when @logic3_type {
                    [0, 1] => {
                        block "Logic_3" => "    Logic 3 {{logic3_description:}}" {
                            param logic3_ext_input_a
                            when @logic3_ext_input_a {
                                [1, 2, 129, 130] => { obj logic3_input_a }
                            }
                            param logic3_ext_input_b
                            when @logic3_ext_input_b {
                                [1, 2, 129, 130] => { obj logic3_input_b }
                            }
                            param logic3_button_choose_0
                            when @logic3_button_choose_0 {
                                [1] => { param logic3_int_button1 }
                                [2] => { param logic3_int_button2 }
                            }
                            param logic3_button_choose_1
                            when @logic3_button_choose_1 {
                                [1] => { param logic3_int_button1 }
                                [2] => { param logic3_int_button2 }
                            }
                        }
                    }
                    [2] => {
                        block "Logic_3" => "    Logic 3 {{logic3_description:}}" {
                            param logic3_button_choose_0
                            when @logic3_button_choose_0 {
                                [1] => { param logic3_int_button1 }
                                [2] => { param logic3_int_button2 }
                            }
                        }
                    }
                }

                // Logic 4 input configuration block
                when @logic4_type {
                    [0, 1] => {
                        block "Logic_4" => "    Logic 4 {{logic4_description:}}" {
                            param logic4_ext_input_a
                            when @logic4_ext_input_a {
                                [1, 2, 129, 130] => { obj logic4_input_a }
                            }
                            param logic4_ext_input_b
                            when @logic4_ext_input_b {
                                [1, 2, 129, 130] => { obj logic4_input_b }
                            }
                            param logic4_button_choose_0
                            when @logic4_button_choose_0 {
                                [1] => { param logic4_int_button1 }
                                [2] => { param logic4_int_button2 }
                            }
                            param logic4_button_choose_1
                            when @logic4_button_choose_1 {
                                [1] => { param logic4_int_button1 }
                                [2] => { param logic4_int_button2 }
                            }
                        }
                    }
                    [2] => {
                        block "Logic_4" => "    Logic 4 {{logic4_description:}}" {
                            param logic4_button_choose_0
                            when @logic4_button_choose_0 {
                                [1] => { param logic4_int_button1 }
                                [2] => { param logic4_int_button2 }
                            }
                        }
                    }
                }
            }
        }
    }
}
