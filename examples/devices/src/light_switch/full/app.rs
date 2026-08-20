//! Application logic for the 2-button light switch.
//!
//! Handles classified button events and dispatches KNX messages based on the
//! ETS-configured parameters. This module is platform-agnostic — it works
//! with any [`StackDefinition`] whose communication objects are
//! [`LightSwitchComObjects`].
//!
//! # Usage
//!
//! ```rust,ignore
//! use devices::light_switch::full::*;
//!
//! // In your embassy task:
//! let event = btn.wait_for_event(debounce, Some(long_press)).await;
//! let mut state = ButtonState::new();
//! handle_button_event(&knx, &params, event, ButtonId::Btn1, &mut state).await;
//! ```

pub use zweidraehte_util::input::ButtonEvent;

use super::super::behavior::{self, Decision, ValueKind};
pub use super::super::behavior::{ButtonId, ButtonState};
use super::super::comm_objs::{Index, LightSwitchComObjects};
use super::super::params::LightSwitchParams;
use zweidraehte_device::prelude::*;
use zweidraehte_proto::dpt::*;

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

/// Translate a pure decision into the full stack's typed object API.
async fn apply_decision<D>(knx: &Stack<'_, D>, decision: Decision)
where
    D: StackDefinition<CO = LightSwitchComObjects>,
{
    if let Some(write) = decision.publish {
        match write.kind {
            ValueKind::Switch => {
                let _ = knx.update_object(write.object, DPT_Switch::from(write.value != 0)).await;
            }
            ValueKind::RelativeDimming => {
                let _ = knx.update_object(write.object, DPT_Control_Dimming::new(write.value.into())).await;
            }
            ValueKind::BlindStep => {
                let _ = knx.update_object(write.object, DPT_Step::from(write.value != 0)).await;
            }
            ValueKind::BlindMove => {
                let _ = knx.update_object(write.object, DPT_UpDown::new(write.value.into())).await;
            }
            ValueKind::Scene => {
                let _ = knx.update_object(write.object, DPT_SceneControl::new(write.value.into())).await;
            }
        }
    }

    if let Some(status) = decision.local_status {
        write_local_status(knx, status.object, status.value);
    }
}

/// Process one button event and publish to KNX comm objects.
///
/// The shared behavior reducer decides what to publish. This adapter only
/// translates that decision into the full stack's typed object API.
///
/// `state` tracks behavior across presses. Keep one instance per physical
/// button.
pub async fn handle_button_event<D>(
    knx: &Stack<'_, D>,
    params: &LightSwitchParams,
    event: ButtonEvent,
    button: ButtonId,
    state: &mut ButtonState,
) where
    D: StackDefinition<CO = LightSwitchComObjects>,
{
    let behavior = behavior::resolve_button(params, button);
    let status = behavior.objects.status;
    let current_status = if event == ButtonEvent::ShortPress { read_status(knx, status) } else { false };
    let decision = behavior::reduce(behavior, event, current_status, state);
    apply_decision(knx, decision).await;
}
