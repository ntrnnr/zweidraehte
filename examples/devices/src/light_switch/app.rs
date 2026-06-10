//! Application logic for the 2-button light switch.
//!
//! Handles button press events and dispatches KNX messages based on the
//! ETS-configured parameters. This module is platform-agnostic — it works
//! with any [`StackDefinition`] whose communication objects are
//! [`LightSwitchComObjects`].
//!
//! The only platform coupling is the [`WaitForRelease`] trait, which
//! the caller implements for their specific button hardware.
//!
//! # Usage
//!
//! ```rust,ignore
//! use devices::light_switch::app::*;
//!
//! // In your embassy task:
//! let event = btn.wait_for_press(debounce, Some(long_press)).await;
//! let mut waiter = ReleaseWaiter { btn: &mut btn, debounce };
//! handle_button_press(&knx, &params, event, ButtonId::Btn1, &mut waiter, &mut dim_up).await;
//! ```

pub use zweidraehte_util::input::{ButtonEvent, WaitForRelease};

use super::comm_objs::{Index, LightSwitchComObjects};
use super::params::{ButtonConfig, ButtonsMode, LightSwitchParams, RockerDirection, SwitchAction};
use zweidraehte_device::prelude::*;
use zweidraehte_proto::dpt::*;

// ============================================================================
// Types
// ============================================================================

/// Which physical button was pressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonId {
    Btn1,
    Btn2,
}

// ============================================================================
// Button Resolution
// ============================================================================

/// Resolve which [`ButtonConfig`] and comm object indices to use.
///
/// Takes into account the buttons_mode (1-function vs 2-function) and
/// rocker direction settings.
///
/// Returns `(config, primary_obj, status_obj, secondary_obj, is_on_direction)`.
/// `is_on_direction` is `Some(true)` for the ON/up/brighter side of
/// a rocker pair, `Some(false)` for the OFF/down/darker side, or
/// `None` in 2-function mode where direction is per-config.
pub fn resolve_button(
    params: &LightSwitchParams,
    button: ButtonId,
) -> (&ButtonConfig, Index, Index, Index, Option<bool>) {
    match params.buttons_mode {
        ButtonsMode::OneFunction => {
            // Both physical buttons share button1_config. The rocker
            // direction determines which button is "on" vs "off".
            let is_top = matches!(button, ButtonId::Btn1);
            let is_on = match params.rocker_direction {
                RockerDirection::Normal => is_top,
                RockerDirection::Inverted => !is_top,
            };
            (&params.button1_config, Index::Btn1Primary, Index::Btn1Status, Index::Btn1Secondary, Some(is_on))
        }
        ButtonsMode::TwoFunction => {
            // Each button is independent with its own config and objects.
            match button {
                ButtonId::Btn1 => {
                    (&params.button1_config, Index::Btn1Primary, Index::Btn1Status, Index::Btn1Secondary, None)
                }
                ButtonId::Btn2 => {
                    (&params.button2_config, Index::Btn2Primary, Index::Btn2Status, Index::Btn2Secondary, None)
                }
            }
        }
    }
}

/// Read the current status object value as a bool (for toggle logic).
pub fn read_status<D>(knx: &Stack<'_, D>, status_obj: Index) -> bool
where
    D: StackDefinition<CO = LightSwitchComObjects>,
{
    let objs = knx.objects().borrow();
    let val = objs.value(status_obj.index());
    val.and_then(|v| v.first().copied()).is_some_and(|b| b & 1 != 0)
}

/// Optimistically update the local status object to match what we sent.
///
/// Without this, `read_status` returns the stale value until the actuator
/// sends a status telegram back. That means consecutive toggles after
/// boot (when status starts at 0) all read the same value and the button
/// appears stuck. This local write is overridden whenever a real status
/// telegram arrives from the bus.
fn write_local_status<D>(knx: &Stack<'_, D>, status_obj: Index, value: bool)
where
    D: StackDefinition<CO = LightSwitchComObjects>,
{
    let mut objs = knx.objects().borrow_mut();
    if let Some(b) = objs.value_mut(status_obj.index()).and_then(|buf| buf.first_mut()) {
        *b = value as u8;
    }
}

// ============================================================================
// Main Dispatcher
// ============================================================================

/// Process a button press event and publish to KNX comm objects.
///
/// Reads the button configuration from `params`, resolves the correct
/// comm objects, and delegates to the mode-specific handler.
///
/// `dim_up` tracks alternating dimmer direction between consecutive
/// long presses in 2-function mode — pass a persistent `&mut bool`
/// per physical button.
pub async fn handle_button_press<D, R>(
    knx: &Stack<'_, D>,
    params: &LightSwitchParams,
    event: ButtonEvent,
    button: ButtonId,
    release: &mut R,
    dim_up: &mut bool,
) where
    D: StackDefinition<CO = LightSwitchComObjects>,
    R: WaitForRelease,
{
    let (config, primary, status, secondary, rocker_on) = resolve_button(params, button);

    match config {
        ButtonConfig::Switch { action } => {
            handle_switch(knx, event, *action, primary, status, rocker_on).await;
        }
        ButtonConfig::Dimmer => {
            handle_dimmer(knx, event, primary, status, secondary, rocker_on, release, dim_up).await;
        }
        ButtonConfig::Blind => {
            handle_blind(knx, event, primary, secondary, rocker_on, release).await;
        }
        ButtonConfig::Scene { scene_number } => {
            handle_scene(knx, event, primary, *scene_number as u8).await;
        }
    }
}

// ============================================================================
// Per-Mode Handlers
// ============================================================================

/// Switch mode: short press sends on/off on the primary object.
///
/// In 1-function (rocker) mode, `rocker_on` determines direction
/// regardless of the SwitchAction setting. In 2-function mode,
/// the action parameter selects toggle/on/off behavior.
pub async fn handle_switch<D>(
    knx: &Stack<'_, D>,
    event: ButtonEvent,
    action: SwitchAction,
    primary: Index,
    status: Index,
    rocker_on: Option<bool>,
) where
    D: StackDefinition<CO = LightSwitchComObjects>,
{
    // Long press has no effect in switch mode.
    if event == ButtonEvent::LongPress {
        return;
    }

    let value = match rocker_on {
        // 1-function rocker: direction is fixed by physical position.
        Some(on) => on,
        // 2-function: use the configured action.
        None => match action {
            SwitchAction::Toggle => !read_status(knx, status),
            SwitchAction::On => true,
            SwitchAction::Off => false,
        },
    };

    let dpt = DPT_Switch::from(value);
    let _ = knx.update_object(primary, dpt).await;
    write_local_status(knx, status, value);
}

/// Dimmer mode:
/// - Short press: toggle on/off via primary object.
/// - Long press start: begin relative dimming via secondary object.
/// - Long press release: send dimming stop via secondary object.
///
/// Alternates dimming direction between consecutive long presses
/// in 2-function mode. In rocker mode, direction is fixed.
pub async fn handle_dimmer<D, R>(
    knx: &Stack<'_, D>,
    event: ButtonEvent,
    primary: Index,
    status: Index,
    secondary: Index,
    rocker_on: Option<bool>,
    release: &mut R,
    dim_up: &mut bool,
) where
    D: StackDefinition<CO = LightSwitchComObjects>,
    R: WaitForRelease,
{
    match event {
        ButtonEvent::ShortPress => {
            // Toggle on/off.
            let current = read_status(knx, status);
            let value = match rocker_on {
                Some(on) => on,
                None => !current,
            };
            let dpt = DPT_Switch::from(value);
            let _ = knx.update_object(primary, dpt).await;
            write_local_status(knx, status, value);

            // In 2-function mode, set the next dim direction based on
            // the switch action: if we just turned ON, the user likely
            // wants to dim DOWN next; if we turned OFF, dim UP.
            if rocker_on.is_none() {
                *dim_up = !value;
            }
        }
        ButtonEvent::LongPress => {
            // Determine dim direction: in rocker mode it's fixed,
            // in 2-function mode it alternates.
            let up = rocker_on.unwrap_or(*dim_up);

            // DPT 3.007 format: bit 3 = control (1=dim), bits 0-2 = step code.
            // Step code 1 = 100% (full range dim). Control bit + step = start dimming.
            let start_byte: u8 = if up { 0b0000_1001 } else { 0b0000_0001 };
            let dpt = DPT_Control_Dimming::new(start_byte.into());
            let _ = knx.update_object(secondary, dpt).await;

            // Wait for button release.
            release.wait_for_release().await;

            // Send stop: step code 0 = break (stop dimming).
            let stop_byte: u8 = if up { 0b0000_1000 } else { 0b0000_0000 };
            let stop_dpt = DPT_Control_Dimming::new(stop_byte.into());
            let _ = knx.update_object(secondary, stop_dpt).await;

            // Alternate direction for next long press (2-function only;
            // in rocker mode, rocker_on overrides this).
            if rocker_on.is_none() {
                *dim_up = !*dim_up;
            }
        }
    }
}

/// Blind mode:
/// - Short press: send step/stop on secondary object.
/// - Long press: send move up/down on primary object.
///
/// In 1-function mode, the rocker position determines direction.
/// In 2-function mode, short press always sends step-stop and
/// long press direction alternates (same pattern as dimmer).
pub async fn handle_blind<D, R>(
    knx: &Stack<'_, D>,
    event: ButtonEvent,
    primary: Index,
    secondary: Index,
    rocker_on: Option<bool>,
    release: &mut R,
) where
    D: StackDefinition<CO = LightSwitchComObjects>,
    R: WaitForRelease,
{
    match event {
        ButtonEvent::ShortPress => {
            // Step/stop: DPT 1.007.
            // In rocker mode we send the direction-appropriate step;
            // in 2-function mode we send a step-stop (value=0 for increase).
            let step_up = rocker_on.unwrap_or(true);
            let dpt = DPT_Step::from(!step_up); // DPT_Step: 0=increase, 1=decrease
            let _ = knx.update_object(secondary, dpt).await;
        }
        ButtonEvent::LongPress => {
            // Move up/down: DPT 1.008.
            // 0 = Up, 1 = Down.
            let go_up = rocker_on.unwrap_or(true);
            let value: u8 = if go_up { 0 } else { 1 };
            let dpt = DPT_UpDown::new(value.into());
            let _ = knx.update_object(primary, dpt).await;

            // Wait for release, then send stop (step with same direction).
            release.wait_for_release().await;
            let stop_dpt = DPT_Step::from(!go_up);
            let _ = knx.update_object(secondary, stop_dpt).await;
        }
    }
}

/// Scene mode:
/// - Short press: recall scene (activate).
/// - Long press: store scene (learn).
///
/// DPT 18.001 format: bit 7 = learn flag, bits 0-5 = scene number (0-63).
pub async fn handle_scene<D>(knx: &Stack<'_, D>, event: ButtonEvent, primary: Index, scene_number: u8)
where
    D: StackDefinition<CO = LightSwitchComObjects>,
{
    let value = match event {
        ButtonEvent::ShortPress => scene_number & 0x3F,         // Recall
        ButtonEvent::LongPress => (scene_number & 0x3F) | 0x80, // Store
    };
    let dpt = DPT_SceneControl::new(value.into());
    let _ = knx.update_object(primary, dpt).await;
}
