//! Parameter definitions for the 2-button light switch.
//!
//! The device supports two operating modes selected by [`ButtonsMode`]:
//!
//! - **1-function**: Both physical buttons act as one unit (rocker pair).
//!   Top = one direction, bottom = opposite. Only `button1_config` is
//!   user-visible; direction is controlled by [`RockerDirection`].
//! - **2-function**: Each button is independently configurable with its
//!   own function mode and comm objects.
//!
//! Each button/pair supports four function modes via [`ButtonConfig`]:
//! - Switch: on/off control (toggle needs status feedback)
//! - Dimmer: short press toggles, long press dims relatively
//! - Blind: short press steps, long press moves up/down
//! - Scene: short press recalls, long press stores

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};

use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_ets_model::{EtsEnum, ets_params, ets_range_enum, ets_union};

// ============================================================================
// Simple Enums
// ============================================================================

/// Debounce time for button inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, KnownLayout, Immutable, IntoBytes)]
#[repr(u8)]
pub enum DebounceTime {
    #[ets(display = "20 ms")]
    Ms20 = 0,
    #[ets(display = "50 ms")]
    Ms50 = 1,
    #[ets(display = "80 ms")]
    Ms80 = 2,
    #[ets(display = "100 ms")]
    Ms100 = 3,
    #[ets(display = "150 ms")]
    Ms150 = 4,
}

impl ConstDefault for DebounceTime {
    const DEFAULT: Self = Self::Ms50;
}

impl DebounceTime {
    pub const fn as_ms(self) -> u32 {
        match self {
            Self::Ms20 => 20,
            Self::Ms50 => 50,
            Self::Ms80 => 80,
            Self::Ms100 => 100,
            Self::Ms150 => 150,
        }
    }

    #[cfg(feature = "full")]
    pub const fn as_duration(self) -> embassy_time::Duration {
        embassy_time::Duration::from_millis(self.as_ms() as u64)
    }
}

/// Threshold for distinguishing short from long button presses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, KnownLayout, Immutable, IntoBytes)]
#[repr(u8)]
pub enum LongPressTime {
    #[ets(display = "300 ms")]
    Ms300 = 0,
    #[ets(display = "500 ms")]
    Ms500 = 1,
    #[ets(display = "800 ms")]
    Ms800 = 2,
    #[ets(display = "1000 ms")]
    Ms1000 = 3,
    #[ets(display = "1500 ms")]
    Ms1500 = 4,
}

impl ConstDefault for LongPressTime {
    const DEFAULT: Self = Self::Ms500;
}

impl LongPressTime {
    pub const fn as_ms(self) -> u32 {
        match self {
            Self::Ms300 => 300,
            Self::Ms500 => 500,
            Self::Ms800 => 800,
            Self::Ms1000 => 1000,
            Self::Ms1500 => 1500,
        }
    }

    #[cfg(feature = "full")]
    pub const fn as_duration(self) -> embassy_time::Duration {
        embassy_time::Duration::from_millis(self.as_ms() as u64)
    }
}

/// 1-function (rocker pair) or 2-function (independent buttons) mode.
///
/// In 1-function mode, both physical buttons act as one unit:
/// top = ON/brighter/up, bottom = OFF/darker/down (or inverted via
/// [`RockerDirection`]).
///
/// In 2-function mode, each button has its own independent function
/// configuration and comm objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, KnownLayout, Immutable, IntoBytes)]
#[repr(u8)]
pub enum ButtonsMode {
    #[ets(display = "1-function")]
    OneFunction = 0,
    #[ets(display = "2-function")]
    TwoFunction = 1,
}

impl ConstDefault for ButtonsMode {
    const DEFAULT: Self = Self::TwoFunction;
}

/// Direction assignment for 1-function (rocker) mode.
///
/// Controls which physical button maps to which logical direction.
/// Only visible in the ETS UI when `buttons_mode` is `OneFunction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, KnownLayout, Immutable, IntoBytes)]
#[repr(u8)]
pub enum RockerDirection {
    #[ets(display = "Top = ON / Up / Brighter")]
    Normal = 0,
    #[ets(display = "Top = OFF / Down / Darker")]
    Inverted = 1,
}

impl ConstDefault for RockerDirection {
    const DEFAULT: Self = Self::Normal;
}

/// What pressing a button does in Switch mode (2-function only).
///
/// In 1-function Switch mode, the action is always fixed on/off based
/// on which physical button is pressed, so this parameter is hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize, KnownLayout, Immutable, IntoBytes)]
#[repr(u8)]
pub enum SwitchAction {
    /// Invert the last known state (requires status feedback object)
    #[ets(display = "Toggle")]
    Toggle = 0,
    /// Always send ON
    #[ets(display = "On")]
    On = 1,
    /// Always send OFF
    #[ets(display = "Off")]
    Off = 2,
}

impl ConstDefault for SwitchAction {
    const DEFAULT: Self = Self::Toggle;
}

// Scene number selection (1–64).
// Stored as 0–63 internally, matching DPT 17.001 wire format.
// Displayed as "1" through "64" in the ETS dropdown.
ets_range_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, KnownLayout, Immutable, IntoBytes)]
    #[ets(type_name = "SceneNumber")]
    pub enum SceneNumber {
        range 0..64 => "Scene{}";
        default = 0;
    }
}

// ============================================================================
// Button Configuration Union
// ============================================================================

/// Per-button function mode.
///
/// The discriminant selects the operating mode and controls which
/// communication objects and parameters are visible in ETS.
///
/// - **Switch**: on/off control. In 2-function mode, the `action`
///   parameter selects between toggle (needs status feedback), fixed
///   on, or fixed off. In 1-function mode, `action` is hidden —
///   direction is always fixed via [`RockerDirection`].
/// - **Dimmer**: short press toggles on/off (needs status feedback),
///   long press sends relative dimming commands.
/// - **Blind**: short press sends step/stop, long press sends move
///   up/down.
/// - **Scene**: short press recalls a scene, long press stores it.
///   Scene number is configurable.
#[ets_union]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ButtonConfig {
    /// Switch on/off
    #[ets(default_variant, display = "Switch")]
    Switch {
        /// What pressing this button does (2-function mode only)
        #[ets(display = "Switch action", ets_enum)]
        action: SwitchAction,
    } = 0,

    /// Dimming control
    #[ets(display = "Dimmer")]
    Dimmer = 1,

    /// Blind/shutter control
    #[ets(display = "Blind")]
    Blind = 2,

    /// Scene recall/store
    #[ets(display = "Scene")]
    Scene {
        /// Scene number (1–64, stored as 0–63 for DPT 17.001)
        #[ets(display = "Scene number", ets_enum)]
        scene_number: SceneNumber,
    } = 3,
}

// ============================================================================
// Virtual Parameters (ETS-only, not in device memory)
// ============================================================================

// Object description text fields for each button. These are editable in ETS
// and appear in the comm object tree via `{{param:default}}` text templates.
// They have no device memory footprint.
zweidraehte_ets_model::ets_virtual_params! {
    pub LIGHT_SWITCH_VIRTUAL_PARAMS {
        btn1_description: String(30) => "Object description",
        btn2_description: String(30) => "Object description",
    }
}

// ============================================================================
// Application Parameters
// ============================================================================

/// Application parameters for the 2-button light switch.
///
/// The `buttons_mode` parameter selects between 1-function (rocker pair)
/// and 2-function (independent buttons) operation.
///
/// In 1-function mode, `button1_config` drives both buttons' behavior
/// and `button2_config` is hidden in ETS (but still occupies memory
/// since `#[repr(C)]` requires fixed layout). The `rocker_direction`
/// parameter controls which physical button maps to which direction.
///
/// In 2-function mode, each button has its own independent `ButtonConfig`.
/// The `rocker_direction` parameter is hidden.
#[ets_params]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LightSwitchParams {
    /// Button input debounce time (applies to both buttons)
    #[ets(display = "Debounce time", ets_enum)]
    pub debounce_time: DebounceTime,

    /// Long press detection threshold (applies to both buttons)
    #[ets(display = "Long press time", ets_enum)]
    pub long_press_time: LongPressTime,

    /// 1-function (rocker pair) or 2-function (independent) mode
    #[ets(display = "Button mode", ets_enum)]
    pub buttons_mode: ButtonsMode,

    /// Direction assignment for 1-function mode (hidden in 2-function)
    #[ets(display = "Rocker direction", ets_enum)]
    pub rocker_direction: RockerDirection,

    /// Button 1 function mode and mode-specific parameters.
    /// In 1-function mode, this drives the function for both buttons.
    #[ets(union, display = "Function")]
    pub button1_config: ButtonConfig,

    /// Button 2 function mode and mode-specific parameters.
    /// Hidden in 1-function mode.
    #[ets(union, display = "Function")]
    pub button2_config: ButtonConfig,
}

/// The factory-default parameter bytes, exactly as they sit in device
/// memory — the image a product database ships as segment data and a
/// BCU-era device bakes into its boot EEPROM.
///
/// The transmute is sound because `#[ets_params]` guarantees a padding
/// free `#[repr(C)]` layout (the same guarantee the System B memory
/// map relies on when it lets ETS overwrite the struct byte by byte).
pub const DEFAULT_PARAM_BYTES: [u8; core::mem::size_of::<LightSwitchParams>()] =
    unsafe { core::mem::transmute(<LightSwitchParams as ConstDefault>::DEFAULT) };

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the concrete wire layout of [`LightSwitchParams`]. The
    /// product databases, the System B memory map and the micro
    /// devices' EEPROM images all carry these bytes — if this test
    /// fails, a macro or struct change silently re-laid the parameter
    /// memory and every downloaded device would misread its
    /// configuration.
    #[test]
    fn default_param_bytes_layout_is_pinned() {
        assert_eq!(DEFAULT_PARAM_BYTES, [
            DebounceTime::Ms50 as u8,
            LongPressTime::Ms500 as u8,
            ButtonsMode::TwoFunction as u8,
            RockerDirection::Normal as u8,
            0, // button1_config: Switch discriminant
            SwitchAction::Toggle as u8,
            0, // button2_config: Switch discriminant
            SwitchAction::Toggle as u8,
        ]);
    }
}
