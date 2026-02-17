//! Parameter definitions for the 2-button light switch.
//!
//! Each button is independently configurable for one of four modes:
//! - Switch: simple on/off toggle
//! - Dimmer: toggle + relative dimming via long press
//! - Blind: move up/down + step/stop
//! - Scene: recall/store scenes

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};

use zweidraehte::prelude::*;

// ============================================================================
// Simple Enums
// ============================================================================

/// Debounce time for button inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize)]
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

/// Threshold for distinguishing short from long button presses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize)]
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

/// Switch mode: what a short button press does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize)]
#[repr(u8)]
pub enum SwitchOperation {
    #[ets(display = "Toggle")]
    Toggle = 0,
    #[ets(display = "On")]
    On = 1,
    #[ets(display = "Off")]
    Off = 2,
}

impl ConstDefault for SwitchOperation {
    const DEFAULT: Self = Self::Toggle;
}

/// Switch mode: what a long button press does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Serialize, Deserialize)]
#[repr(u8)]
pub enum SwitchLongPress {
    #[ets(display = "None")]
    None = 0,
    #[ets(display = "Toggle")]
    Toggle = 1,
    #[ets(display = "On")]
    On = 2,
    #[ets(display = "Off")]
    Off = 3,
}

impl ConstDefault for SwitchLongPress {
    const DEFAULT: Self = Self::None;
}

// ============================================================================
// Button Configuration Union
// ============================================================================

/// Per-button function mode.
///
/// The discriminant selects the operating mode and controls which
/// communication objects and parameters are visible in ETS.
///
/// - **Switch**: simple on/off with configurable short and long press actions
/// - **Dimmer**: short press toggles, long press dims (no extra params — direction alternates)
/// - **Blind**: short press steps, long press moves (no extra params)
/// - **Scene**: short press recalls, long press stores (scene number configurable)
#[derive(Debug, Clone, Copy, EtsUnion, Serialize, Deserialize)]
#[repr(C, u8)]
pub enum ButtonConfig {
    /// Switch on/off
    #[ets(display = "Switch")]
    Switch {
        /// Short press action
        #[ets(display = "Short press", ets_enum)]
        operation: SwitchOperation,
        /// Long press action
        #[ets(display = "Long press", ets_enum)]
        long_press: SwitchLongPress,
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
        /// Scene number (1-64)
        #[ets(display = "Scene number")]
        scene_number: u8,
    } = 3,
}

impl ConstDefault for ButtonConfig {
    const DEFAULT: Self = ButtonConfig::Switch {
        operation: SwitchOperation::DEFAULT,
        long_press: SwitchLongPress::DEFAULT,
    };
}

// ============================================================================
// Application Parameters
// ============================================================================

/// Application parameters for the 2-button light switch.
///
/// Global settings (debounce, long press threshold) apply to both buttons.
/// Each button has an independent function mode selected via the `ButtonConfig`
/// union — the discriminant controls both the ETS parameter visibility and
/// which communication objects are active.
#[derive(Debug, Clone, Copy, EtsParams, Serialize, Deserialize)]
#[repr(C)]
pub struct LightSwitchParams {
    /// Button input debounce time (applies to both buttons)
    #[ets(display = "Debounce time", ets_enum)]
    pub debounce_time: DebounceTime,

    /// Long press detection threshold (applies to both buttons)
    #[ets(display = "Long press time", ets_enum)]
    pub long_press_time: LongPressTime,

    /// Button 1 function mode and mode-specific parameters
    #[ets(union, display = "Button 1 function")]
    pub button1_config: ButtonConfig,

    /// Button 2 function mode and mode-specific parameters
    #[ets(union, display = "Button 2 function")]
    pub button2_config: ButtonConfig,
}
