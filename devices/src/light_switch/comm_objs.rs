//! Communication objects for the 2-button light switch.
//!
//! 6 base objects (3 per button):
//!
//! - **Primary**: always present, DPT varies by mode (Switch/UpDown/SceneControl)
//! - **Secondary**: only for Dimmer and Blind modes (Control_Dimming/Step)
//! - **Status**: feedback input for Switch (Toggle) and Dimmer modes.
//!   Receives current actuator state from the bus so the device knows
//!   what to invert when toggling.
//!
//! The `selector_param` on each object points to the auto-generated
//! `buttonN_config_selector` discriminant parameter from the `ButtonConfig`
//! union, so ETS shows/hides comm objects and selects the right DPT
//! based on the chosen function mode.
//!
//! Visibility of button 2's objects in 1-function vs 2-function mode is
//! controlled by the page layout, not by the comm object selectors.
//!
//! Each comm object ref uses a `text` template referencing the virtual
//! description parameter (e.g., `{{btn1_description:Button 1}}`).
//! ETS resolves this to the user-entered description text, or falls
//! back to the default if the user hasn't changed it.

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
    /// - Switch: sends DPT_Switch on/off or toggle
    /// - Dimmer: sends DPT_Switch toggle on short press
    /// - Blind: sends DPT_UpDown move on long press
    /// - Scene: sends DPT_SceneControl recall/store
    #[ets(
        index = 1,
        display = "Button 1 switching",
        function = "Primary output",
        flags = C | T,
        selector_param = "button1_config_selector"
    )]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Switch, text = "Button 1 {{btn1_description:}} switching", function = "Switch on/off")]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Dimmer, text = "Button 1 {{btn1_description:}} switching", function = "Switch toggle")]
    #[ets_ref(dpt = DPT_UpDown, when = ButtonConfigDiscriminant::Blind, text = "Button 1 {{btn1_description:}} move", function = "Move up/down")]
    #[ets_ref(dpt = DPT_SceneControl, when = ButtonConfigDiscriminant::Scene, text = "Button 1 {{btn1_description:}} scene", function = "Scene control")]
    pub btn1_primary: ComObject<ComObjectStorage<1>>,

    /// Button 1 status feedback — receives current actuator state.
    ///
    /// Active in Switch and Dimmer modes. The device uses this to
    /// determine what to send when toggling (invert last known state).
    /// Write + Update flags: the device receives status from the bus.
    #[ets(
        index = 2,
        display = "Button 1 status",
        function = "Status feedback",
        flags = C | W | T | U | ROI,
        selector_param = "button1_config_selector"
    )]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Switch, text = "Button 1 {{btn1_description:}} status", function = "Switch status")]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Dimmer, text = "Button 1 {{btn1_description:}} status", function = "Dimmer status")]
    pub btn1_status: ComObject<ComObjectStorage<1>>,

    /// Button 1 secondary output — only active in Dimmer and Blind modes.
    ///
    /// - Dimmer: sends DPT_Control_Dimming on long press
    /// - Blind: sends DPT_Step step/stop on short press
    #[ets(
        index = 3,
        display = "Button 1 dimming/step",
        function = "Secondary output",
        flags = C | T,
        selector_param = "button1_config_selector"
    )]
    #[ets_ref(dpt = DPT_Control_Dimming, when = ButtonConfigDiscriminant::Dimmer, text = "Button 1 {{btn1_description:}} dimming", function = "Dimming control")]
    #[ets_ref(dpt = DPT_Step, when = ButtonConfigDiscriminant::Blind, text = "Button 1 {{btn1_description:}} step", function = "Step/stop")]
    pub btn1_secondary: ComObject<ComObjectStorage<1>>,

    // ====================================================================
    // Button 2
    // ====================================================================
    /// Button 2 primary output — same pattern as button 1.
    #[ets(
        index = 4,
        display = "Button 2 switching",
        function = "Primary output",
        flags = C | T,
        selector_param = "button2_config_selector"
    )]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Switch, text = "Button 2 {{btn2_description:}} switching", function = "Switch on/off")]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Dimmer, text = "Button 2 {{btn2_description:}} switching", function = "Switch toggle")]
    #[ets_ref(dpt = DPT_UpDown, when = ButtonConfigDiscriminant::Blind, text = "Button 2 {{btn2_description:}} move", function = "Move up/down")]
    #[ets_ref(dpt = DPT_SceneControl, when = ButtonConfigDiscriminant::Scene, text = "Button 2 {{btn2_description:}} scene", function = "Scene control")]
    pub btn2_primary: ComObject<ComObjectStorage<1>>,

    /// Button 2 status feedback — receives current actuator state.
    #[ets(
        index = 5,
        display = "Button 2 status",
        function = "Status feedback",
        flags = C | W | T | U | ROI,
        selector_param = "button2_config_selector"
    )]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Switch, text = "Button 2 {{btn2_description:}} status", function = "Switch status")]
    #[ets_ref(dpt = DPT_Switch, when = ButtonConfigDiscriminant::Dimmer, text = "Button 2 {{btn2_description:}} status", function = "Dimmer status")]
    pub btn2_status: ComObject<ComObjectStorage<1>>,

    /// Button 2 secondary output — only active in Dimmer and Blind modes.
    #[ets(
        index = 6,
        display = "Button 2 dimming/step",
        function = "Secondary output",
        flags = C | T,
        selector_param = "button2_config_selector"
    )]
    #[ets_ref(dpt = DPT_Control_Dimming, when = ButtonConfigDiscriminant::Dimmer, text = "Button 2 {{btn2_description:}} dimming", function = "Dimming control")]
    #[ets_ref(dpt = DPT_Step, when = ButtonConfigDiscriminant::Blind, text = "Button 2 {{btn2_description:}} step", function = "Step/stop")]
    pub btn2_secondary: ComObject<ComObjectStorage<1>>,
}
