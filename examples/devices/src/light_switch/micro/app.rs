//! Polled light-switch application and micro-stack adapter.

use zweidraehte_microdevice::co_flags;
use zweidraehte_microdevice::device::Microdevice;
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_util::input::{ButtonEvent, PolledButton};

use super::super::behavior::{self, ButtonId, ButtonState, Decision};
use super::super::comm_objs::Index;
use super::super::params::LightSwitchParams;

// The micro stack addresses communication objects by an 8-bit ASAP. For this
// device, each generated ETS index is also its ASAP.
const fn asap(index: Index) -> u8 {
    assert!((index as u16) <= u8::MAX as u16, "communication object index must fit an ASAP");
    index as u8
}

/// Read the parameter block directly from the EEPROM image ETS writes.
///
/// An undersized image is a family-wiring error; defaults keep that error from
/// turning into an out-of-bounds read. Every field accepts all bit patterns
/// the product database can produce.
fn read_params(eeprom: &[u8], offset: usize) -> LightSwitchParams {
    match eeprom.get(offset..offset + core::mem::size_of::<LightSwitchParams>()) {
        Some(bytes) => unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const LightSwitchParams) },
        None => const_default::ConstDefault::DEFAULT,
    }
}

/// Two polled buttons and their persistent behavior state.
pub struct LightSwitchMicroApp {
    params_offset: usize,
    btn1: PolledButton,
    btn2: PolledButton,
    btn1_state: ButtonState,
    btn2_state: ButtonState,
}

impl LightSwitchMicroApp {
    pub const fn new(params_offset: usize) -> Self {
        Self {
            params_offset,
            btn1: PolledButton::new(),
            btn2: PolledButton::new(),
            btn1_state: ButtonState::new(),
            btn2_state: ButtonState::new(),
        }
    }

    /// Debounce both inputs and publish decisions from the shared behavior.
    /// Input is ignored while the downloaded application is not running.
    pub fn poll<F: MicroDeviceFamily>(
        &mut self,
        stack: &mut Microdevice<F>,
        btn1_raw: bool,
        btn2_raw: bool,
        now_ms: u32,
    ) {
        if !stack.is_running() {
            return;
        }
        let params = read_params(stack.eeprom_image(), self.params_offset);
        let debounce = params.debounce_time.as_ms();
        let long_press = params.long_press_time.as_ms();

        if let Some(event) = self.btn1.poll(btn1_raw, now_ms, debounce, long_press) {
            handle_event(stack, &params, event, ButtonId::Btn1, &mut self.btn1_state);
        }
        if let Some(event) = self.btn2.poll(btn2_raw, now_ms, debounce, long_press) {
            handle_event(stack, &params, event, ButtonId::Btn2, &mut self.btn2_state);
        }
    }

    /// Consume a bus update of button 1's status object for a local indicator.
    pub fn take_btn1_status_update<F: MicroDeviceFamily>(&mut self, stack: &mut Microdevice<F>) -> Option<bool> {
        let status = asap(Index::Btn1Status);
        if stack.object_flags(status) & co_flags::UPDATE == 0 {
            return None;
        }
        stack.clear_update_flag(status);
        Some(read_status(stack, status))
    }
}

fn handle_event<F: MicroDeviceFamily>(
    stack: &mut Microdevice<F>,
    params: &LightSwitchParams,
    event: ButtonEvent,
    button: ButtonId,
    state: &mut ButtonState,
) {
    let behavior = behavior::resolve_button(params, button);
    // Reading the one-byte RAM slot on every phase is cheaper than branching
    // here on Cortex-M0; phases that do not need status simply ignore it.
    let current_status = read_status(stack, asap(behavior.objects.status));
    let decision = behavior::reduce(behavior, event, current_status, state);
    apply_decision(stack, decision);
}

fn read_status<F: MicroDeviceFamily>(stack: &Microdevice<F>, status: u8) -> bool {
    let mut buf = [0u8; 1];
    stack.read_value(status, &mut buf);
    buf[0] & 1 != 0
}

fn send<F: MicroDeviceFamily>(stack: &mut Microdevice<F>, asap: u8, value: u8) {
    stack.write_value(asap, &[value]);
    stack.set_transmit_request(asap);
}

fn apply_decision<F: MicroDeviceFamily>(stack: &mut Microdevice<F>, decision: Decision) {
    if let Some(write) = decision.publish {
        send(stack, asap(write.object), write.value);
    }
    if let Some(status) = decision.local_status {
        stack.write_value(asap(status.object), &[status.value as u8]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::light_switch::ButtonConfig;
    use crate::light_switch::micro::definition::{BCU2_PARAMS_IMAGE_OFFSET, bcu2_definition};

    #[test]
    fn params_round_trip_through_the_bcu2_image() {
        let image = bcu2_definition().build_eeprom();
        let params = read_params(&image, BCU2_PARAMS_IMAGE_OFFSET);
        assert_eq!(params.debounce_time.as_ms(), 50);
        assert_eq!(params.long_press_time.as_ms(), 500);
        assert!(matches!(params.button1_config, ButtonConfig::Switch { .. }));
    }
}
