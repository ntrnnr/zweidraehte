//! Communication objects for the 2-button light switch.
//!
//! Each button has two comm objects:
//! - **Primary**: always present, DPT varies by mode (Switch/UpDown/SceneControl)
//! - **Secondary**: only for Dimmer and Blind modes (Control_Dimming/Step)
//!
//! The `selector_param` on each object points to the auto-generated
//! `buttonN_config_selector` discriminant parameter from the `ButtonConfig`
//! union, so ETS shows/hides comm objects and selects the right DPT
//! based on the chosen function mode.

use super::params::ButtonConfigDiscriminant;
use zweidraehte::dpt::*;
use zweidraehte::objects::comm::{ComObject, ComObjectStorage};
use zweidraehte::prelude::*;

/// Communication objects for the 2-button light switch.
#[derive(EtsComObjects)]
pub struct LightSwitchComObjects {
    // ====================================================================
    // Button 1
    // ====================================================================

    /// Button 1 primary output — DPT selected by function mode.
    ///
    /// - Switch: sends DPT_Switch on/off
    /// - Dimmer: sends DPT_Switch toggle on short press
    /// - Blind: sends DPT_UpDown move on long press
    /// - Scene: sends DPT_SceneControl recall/store
    #[ets(
        index = 1,
        display = "Button 1 output",
        function = "Primary output",
        flags = C | W | T,
        selector_param = "button1_config_selector"
    )]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Switch, function = "Switch on/off")]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Dimmer, function = "Switch toggle")]
    #[ets_ref(dpt = DPT_UpDown, when = ButtonConfigDiscriminant::Blind, function = "Move up/down")]
    #[ets_ref(dpt = DPT_SceneControl, when = ButtonConfigDiscriminant::Scene, function = "Scene control")]
    pub btn1_primary: ComObject<ComObjectStorage<1>>,

    /// Button 1 secondary output — only active in Dimmer and Blind modes.
    ///
    /// - Dimmer: sends DPT_Control_Dimming on long press
    /// - Blind: sends DPT_Step step/stop on short press
    #[ets(
        index = 2,
        display = "Button 1 dimming/step",
        function = "Secondary output",
        flags = C | W | T,
        selector_param = "button1_config_selector"
    )]
    #[ets_ref(dpt = DPT_Control_Dimming, when = ButtonConfigDiscriminant::Dimmer, function = "Dimming control")]
    #[ets_ref(dpt = DPT_Step, when = ButtonConfigDiscriminant::Blind, function = "Step/stop")]
    pub btn1_secondary: ComObject<ComObjectStorage<1>>,

    // ====================================================================
    // Button 2
    // ====================================================================

    /// Button 2 primary output — same pattern as button 1.
    #[ets(
        index = 3,
        display = "Button 2 output",
        function = "Primary output",
        flags = C | W | T,
        selector_param = "button2_config_selector"
    )]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Switch, function = "Switch on/off")]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Dimmer, function = "Switch toggle")]
    #[ets_ref(dpt = DPT_UpDown, when = ButtonConfigDiscriminant::Blind, function = "Move up/down")]
    #[ets_ref(dpt = DPT_SceneControl, when = ButtonConfigDiscriminant::Scene, function = "Scene control")]
    pub btn2_primary: ComObject<ComObjectStorage<1>>,

    /// Button 2 secondary output — only active in Dimmer and Blind modes.
    #[ets(
        index = 4,
        display = "Button 2 dimming/step",
        function = "Secondary output",
        flags = C | W | T,
        selector_param = "button2_config_selector"
    )]
    #[ets_ref(dpt = DPT_Control_Dimming, when = ButtonConfigDiscriminant::Dimmer, function = "Dimming control")]
    #[ets_ref(dpt = DPT_Step, when = ButtonConfigDiscriminant::Blind, function = "Step/stop")]
    pub btn2_secondary: ComObject<ComObjectStorage<1>>,
}
