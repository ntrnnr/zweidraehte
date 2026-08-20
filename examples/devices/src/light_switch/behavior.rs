//! Pure button decisions shared by the full and micro light-switch adapters.
//!
//! This module deliberately knows neither stack. It resolves the product's
//! parameter model into semantic object writes while the adapters retain their
//! own scheduling, object storage, and transmission APIs.

use zweidraehte_util::input::ButtonEvent;

use super::comm_objs::Index;
use super::params::{ButtonConfig, ButtonsMode, LightSwitchParams, RockerDirection, SwitchAction};

/// Which physical button produced an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonId {
    Btn1,
    Btn2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ButtonObjects {
    pub primary: Index,
    pub status: Index,
    pub secondary: Index,
}

const BTN1_OBJECTS: ButtonObjects =
    ButtonObjects { primary: Index::Btn1Primary, status: Index::Btn1Status, secondary: Index::Btn1Secondary };

const BTN2_OBJECTS: ButtonObjects =
    ButtonObjects { primary: Index::Btn2Primary, status: Index::Btn2Status, secondary: Index::Btn2Secondary };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ButtonFunction {
    Switch(SwitchAction),
    Dimmer,
    Blind,
    Scene(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ButtonBehavior {
    pub function: ButtonFunction,
    pub objects: ButtonObjects,
    /// Fixed direction for a one-function rocker. `None` means the
    /// independent-button behavior decides from status/local state.
    pub rocker_on: Option<bool>,
}

/// Resolve the selected function, object triple, and rocker direction once.
pub(super) fn resolve_button(params: &LightSwitchParams, button: ButtonId) -> ButtonBehavior {
    let (config, objects, rocker_on) = match params.buttons_mode {
        ButtonsMode::OneFunction => {
            let is_top = matches!(button, ButtonId::Btn1);
            let on = match params.rocker_direction {
                RockerDirection::Normal => is_top,
                RockerDirection::Inverted => !is_top,
            };
            (&params.button1_config, BTN1_OBJECTS, Some(on))
        }
        ButtonsMode::TwoFunction => match button {
            ButtonId::Btn1 => (&params.button1_config, BTN1_OBJECTS, None),
            ButtonId::Btn2 => (&params.button2_config, BTN2_OBJECTS, None),
        },
    };

    let function = match config {
        ButtonConfig::Switch { action, .. } => ButtonFunction::Switch(*action),
        ButtonConfig::Dimmer { .. } => ButtonFunction::Dimmer,
        ButtonConfig::Blind { .. } => ButtonFunction::Blind,
        ButtonConfig::Scene { scene_number, .. } => ButtonFunction::Scene(*scene_number as u8),
    };

    ButtonBehavior { function, objects, rocker_on }
}

/// Which DPT the full adapter uses for an encoded one-octet value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ValueKind {
    Switch,
    RelativeDimming,
    BlindStep,
    BlindMove,
    Scene,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ObjectWrite {
    pub object: Index,
    pub kind: ValueKind,
    /// Complete one-octet DPT representation. Keeping this encoded in the
    /// pure layer lets micro forward it without a second value dispatch.
    pub value: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StatusUpdate {
    pub object: Index,
    pub value: bool,
}

/// Effects of one reducer call. At most one telegram and one local status
/// update are produced by any button phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Decision {
    pub publish: Option<ObjectWrite>,
    pub local_status: Option<StatusUpdate>,
}

impl Decision {
    const NONE: Self = Self { publish: None, local_status: None };

    const fn publish(object: Index, kind: ValueKind, value: u8) -> Self {
        Self { publish: Some(ObjectWrite { object, kind, value }), local_status: None }
    }

    const fn publish_and_status(object: Index, value: bool, status: Index) -> Self {
        Self {
            publish: Some(ObjectWrite { object, kind: ValueKind::Switch, value: value as u8 }),
            local_status: Some(StatusUpdate { object: status, value }),
        }
    }
}

/// Per-physical-button behavior state.
///
/// `next_dim_up` preserves the existing alternating direction policy.
pub struct ButtonState {
    next_dim_up: bool,
}

impl ButtonState {
    /// Start with upward dimming as the first long-press direction.
    pub const fn new() -> Self {
        Self { next_dim_up: true }
    }

    #[cfg_attr(not(feature = "full"), allow(dead_code))]
    pub const fn next_dim_up(&self) -> bool {
        self.next_dim_up
    }
}

impl Default for ButtonState {
    fn default() -> Self {
        Self::new()
    }
}

/// Reduce one button phase to stack-independent effects.
pub(super) fn reduce(
    behavior: ButtonBehavior,
    event: ButtonEvent,
    current_status: bool,
    state: &mut ButtonState,
) -> Decision {
    match behavior.function {
        ButtonFunction::Switch(action) => reduce_switch(behavior, event, action, current_status),
        ButtonFunction::Dimmer => reduce_dimmer(behavior, event, current_status, state),
        ButtonFunction::Blind => reduce_blind(behavior, event, state),
        ButtonFunction::Scene(number) => reduce_scene(behavior, event, number),
    }
}

fn reduce_switch(behavior: ButtonBehavior, event: ButtonEvent, action: SwitchAction, current_status: bool) -> Decision {
    if event != ButtonEvent::ShortPress {
        return Decision::NONE;
    }
    let value = behavior.rocker_on.unwrap_or(match action {
        SwitchAction::Toggle => !current_status,
        SwitchAction::On => true,
        SwitchAction::Off => false,
    });
    Decision::publish_and_status(behavior.objects.primary, value, behavior.objects.status)
}

fn reduce_dimmer(
    behavior: ButtonBehavior,
    event: ButtonEvent,
    current_status: bool,
    state: &mut ButtonState,
) -> Decision {
    match event {
        ButtonEvent::ShortPress => {
            let value = behavior.rocker_on.unwrap_or(!current_status);
            if behavior.rocker_on.is_none() {
                // Turning on makes down the useful next long-press direction;
                // turning off makes up useful.
                state.next_dim_up = !value;
            }
            Decision::publish_and_status(behavior.objects.primary, value, behavior.objects.status)
        }
        ButtonEvent::LongPressStart => {
            let increase = behavior.rocker_on.unwrap_or(state.next_dim_up);
            Decision::publish(behavior.objects.secondary, ValueKind::RelativeDimming, ((increase as u8) << 3) | 1)
        }
        ButtonEvent::LongPressRelease => {
            let increase = behavior.rocker_on.unwrap_or(state.next_dim_up);
            if behavior.rocker_on.is_none() {
                state.next_dim_up = !state.next_dim_up;
            }
            Decision::publish(behavior.objects.secondary, ValueKind::RelativeDimming, (increase as u8) << 3)
        }
    }
}

fn reduce_blind(behavior: ButtonBehavior, event: ButtonEvent, _state: &mut ButtonState) -> Decision {
    // Independent blind buttons preserve the established behavior: up for
    // every press. Unlike dimming, no blind-direction state existed to toggle.
    let down = !behavior.rocker_on.unwrap_or(true);
    match event {
        ButtonEvent::ShortPress => Decision::publish(behavior.objects.secondary, ValueKind::BlindStep, down as u8),
        ButtonEvent::LongPressStart => Decision::publish(behavior.objects.primary, ValueKind::BlindMove, down as u8),
        ButtonEvent::LongPressRelease => {
            Decision::publish(behavior.objects.secondary, ValueKind::BlindStep, down as u8)
        }
    }
}

fn reduce_scene(behavior: ButtonBehavior, event: ButtonEvent, number: u8) -> Decision {
    match event {
        ButtonEvent::ShortPress => Decision::publish(behavior.objects.primary, ValueKind::Scene, number & 0x3F),
        ButtonEvent::LongPressStart => {
            Decision::publish(behavior.objects.primary, ValueKind::Scene, (number & 0x3F) | 0x80)
        }
        // Scene store already went out at the long-press threshold.
        ButtonEvent::LongPressRelease => Decision::NONE,
    }
}

#[cfg(test)]
mod tests {
    use const_default::ConstDefault;

    use super::*;

    fn behavior(function: ButtonFunction) -> ButtonBehavior {
        ButtonBehavior { function, objects: BTN1_OBJECTS, rocker_on: None }
    }

    #[test]
    fn one_function_rocker_shares_button_one_objects_and_applies_polarity() {
        let mut params = <LightSwitchParams as ConstDefault>::DEFAULT;
        params.buttons_mode = ButtonsMode::OneFunction;
        params.rocker_direction = RockerDirection::Inverted;

        let top = resolve_button(&params, ButtonId::Btn1);
        let bottom = resolve_button(&params, ButtonId::Btn2);
        assert_eq!(top.objects, BTN1_OBJECTS);
        assert_eq!(bottom.objects, BTN1_OBJECTS);
        assert_eq!(top.rocker_on, Some(false));
        assert_eq!(bottom.rocker_on, Some(true));
    }

    #[test]
    fn switch_decision_updates_the_optimistic_status() {
        let mut state = ButtonState::new();
        let decision =
            reduce(behavior(ButtonFunction::Switch(SwitchAction::Toggle)), ButtonEvent::ShortPress, false, &mut state);

        assert_eq!(decision, Decision::publish_and_status(Index::Btn1Primary, true, Index::Btn1Status));
    }

    #[test]
    fn dimmer_brackets_one_direction_and_alternates_after_release() {
        let mut state = ButtonState::new();
        let behavior = behavior(ButtonFunction::Dimmer);

        let start = reduce(behavior, ButtonEvent::LongPressStart, false, &mut state);
        assert_eq!(start, Decision::publish(Index::Btn1Secondary, ValueKind::RelativeDimming, 0x09));
        let stop = reduce(behavior, ButtonEvent::LongPressRelease, false, &mut state);
        assert_eq!(stop, Decision::publish(Index::Btn1Secondary, ValueKind::RelativeDimming, 0x08));
        assert!(!state.next_dim_up());
    }

    #[test]
    fn dimmer_short_press_updates_status_and_next_direction() {
        let mut state = ButtonState::new();
        let decision = reduce(behavior(ButtonFunction::Dimmer), ButtonEvent::ShortPress, false, &mut state);

        assert_eq!(decision, Decision::publish_and_status(Index::Btn1Primary, true, Index::Btn1Status));
        assert!(!state.next_dim_up());
    }

    #[test]
    fn blind_long_press_moves_then_stops_in_the_same_direction() {
        let mut state = ButtonState::new();
        let behavior =
            ButtonBehavior { function: ButtonFunction::Blind, objects: BTN1_OBJECTS, rocker_on: Some(false) };

        assert_eq!(
            reduce(behavior, ButtonEvent::LongPressStart, false, &mut state),
            Decision::publish(Index::Btn1Primary, ValueKind::BlindMove, 1)
        );
        assert_eq!(
            reduce(behavior, ButtonEvent::LongPressRelease, false, &mut state),
            Decision::publish(Index::Btn1Secondary, ValueKind::BlindStep, 1)
        );
    }

    #[test]
    fn scene_store_keeps_the_existing_one_octet_coding() {
        let mut state = ButtonState::new();
        let decision = reduce(behavior(ButtonFunction::Scene(63)), ButtonEvent::LongPressStart, false, &mut state);
        assert_eq!(decision, Decision::publish(Index::Btn1Primary, ValueKind::Scene, 0xBF));
    }
}
