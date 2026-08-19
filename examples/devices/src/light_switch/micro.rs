//! The light switch on the microdevice (BCU-era) stack.
//!
//! The System B firmware gets its behavior from [`super::app`] — an
//! async module speaking the full stack's API. The BCU2 and micro
//! System 7 targets run the same *product* on `zweidraehte-microdevice`
//! instead: no executor, one polled loop, parameters read straight out
//! of the EEPROM image ETS wrote them into. This module is everything
//! those targets share, so a firmware main shrinks to board bring-up,
//! the TPUART pump, and one [`LightSwitchMicroApp::poll`] call — and so
//! the product generators and conformance fixtures use the *same*
//! descriptor tables the firmware bakes into its boot image (the
//! download engine preserves a product's group-object pointers only if
//! the product database carries them; see the client's
//! `CotM112::overlay`).
//!
//! Behavior mirrors [`super::app`] function by function; where that
//! module awaits a button release, this one gets the release as a
//! [`MicroButtonEvent::LongPressRelease`] from the polled button state
//! machine.

use zweidraehte_microdevice::co_flags;
use zweidraehte_microdevice::device::Microdevice;
use zweidraehte_microdevice::families::CoDescriptor;
use zweidraehte_microdevice::families::bcu2::Bcu2DeviceDefinition;
use zweidraehte_microdevice::families::system7::{System7CoDescriptor, System7DeviceDefinition, System7Family};
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::com_object::ComObjectFlags;

use super::LightSwitchDevice;
use super::params::{ButtonConfig, ButtonsMode, DEFAULT_PARAM_BYTES, LightSwitchParams, RockerDirection, SwitchAction};

// ============================================================================
// The canonical micro tables
// ============================================================================

/// ASAPs of one button's object triple. Same roster as
/// [`super::comm_objs::Index`]: objects 0..=2 are button 1's
/// primary/status/secondary, 3..=5 button 2's.
const BTN1_ASAPS: (u8, u8, u8) = (0, 1, 2);
const BTN2_ASAPS: (u8, u8, u8) = (3, 4, 5);

/// Config octets, from the same flag sets `LightSwitchComObjects`
/// declares: primary and secondary transmit (C|T), status is the
/// feedback sink (C|W|T|U|ROI). All at low priority (bits 1:0 = 11b).
const PRIORITY_LOW: u8 = 0x03;
const CONFIG_PRIMARY: u8 = ComObjectFlags::CE_FLAG_MASK | ComObjectFlags::TE_FLAG_MASK | PRIORITY_LOW;
const CONFIG_STATUS: u8 = ComObjectFlags::CE_FLAG_MASK
    | ComObjectFlags::WE_FLAG_MASK
    | ComObjectFlags::TE_FLAG_MASK
    | ComObjectFlags::UE_FLAG_MASK
    | ComObjectFlags::ROI_FLAG_MASK
    | PRIORITY_LOW;

/// Page-0 RAM addresses of the six object values, one byte each. The
/// widest configurable DPT is one byte (`DPT_SceneControl`), so a
/// reconfigured object can never outgrow its slot.
const DATA_BASE: u8 = 0xC6;
/// Page-0 RAM address of the first RAM-flags byte.
const RAM_FLAGS_PTR: u8 = 0xD0;

/// The RT2 group object table of the BCU2 variant — the rows the boot
/// image bakes and the mask-0020 product database ships as segment
/// defaults, so a download's `Cot2::overlay` keeps the pointers while
/// re-typing the objects per configured DPT.
pub const CO_DESCRIPTORS_BCU2: [CoDescriptor; 6] = {
    let mut t = [CoDescriptor { data_ptr: 0, config: 0, value_type: 0 }; 6];
    let mut i = 0;
    while i < 6 {
        t[i] = CoDescriptor {
            data_ptr: DATA_BASE + i as u8,
            // Status objects sit at triple position 1.
            config: if i % 3 == 1 { CONFIG_STATUS } else { CONFIG_PRIMARY },
            // 1-bit switch, the factory default configuration.
            value_type: 0x00,
        };
        i += 1;
    }
    t
};

/// The M112 group object table of the micro System 7 variant — the
/// same six rows with the family's two-byte data pointers.
pub const CO_DESCRIPTORS_S7: [System7CoDescriptor; 6] = {
    let mut t = [System7CoDescriptor { data_ptr: 0, config: 0, value_type: 0 }; 6];
    let mut i = 0;
    while i < 6 {
        t[i] = System7CoDescriptor {
            data_ptr: CO_DESCRIPTORS_BCU2[i].data_ptr as u16,
            config: CO_DESCRIPTORS_BCU2[i].config,
            value_type: CO_DESCRIPTORS_BCU2[i].value_type,
        };
        i += 1;
    }
    t
};

// ============================================================================
// The device definitions
// ============================================================================

/// Image offset (from 0100h) of the BCU2 parameter block — device
/// address 0200h, the mask-0020 product's parameter segment. Clear of
/// the RT2 table page below 0200h, so the one-byte table pointers and
/// the parameters can never collide.
pub const BCU2_PARAMS_IMAGE_OFFSET: usize = 0x100;

/// The micro System 7 family of the light switch: 1 KiB of user EEPROM
/// from 4000h, the group object table published at 4200h — the same
/// geometry the shared mask-0705 product database declares.
pub type LightSwitchS7Family = System7Family<0x400, 0x4200>;

/// Image offset (from 4000h) of the System 7 parameter block — device
/// address 4300h, the shared product's parameter segment (which is
/// also the application segment the third load state machine tracks).
pub const S7_PARAMS_IMAGE_OFFSET: usize = 0x300;

/// The BCU2 (mask 0020h) light switch, its own product entry —
/// `APPLICATION_ID_TP1_BCU2` / `HARDWARE_TYPE_TP1_BCU2`.
pub const fn bcu2_definition() -> Bcu2DeviceDefinition {
    Bcu2DeviceDefinition {
        manufacturer_id: LightSwitchDevice::MANUFACTURER_ID,
        app_manufacturer_id: LightSwitchDevice::MANUFACTURER_ID,
        device_type: LightSwitchDevice::APPLICATION_ID_TP1_BCU2,
        version: LightSwitchDevice::APPLICATION_VERSION,
        pei_type: LightSwitchDevice::PEI_TYPE,
        individual_address: IndividualAddress::new(15, 15, 255),
        max_group_addresses: LightSwitchDevice::MAX_ADDRESS_TABLE_ENTRIES as u8,
        max_associations: LightSwitchDevice::MAX_ASSOCIATION_TABLE_ENTRIES as u8,
        ram_flags_ptr: RAM_FLAGS_PTR,
        comm_objects: &CO_DESCRIPTORS_BCU2,
        group_addresses: &[],
        associations: &[],
        app_params: Some((&DEFAULT_PARAM_BYTES, BCU2_PARAMS_IMAGE_OFFSET)),
    }
}

/// The micro System 7 light switch. Identity and geometry are the
/// full-stack System 7 variant's — one mask-0705 product database
/// drives either firmware — so the `PID_HARDWARE_TYPE` a device built
/// from this must report is `HARDWARE_TYPE_TP1_SYSTEM7`.
pub const fn system7_definition() -> System7DeviceDefinition {
    System7DeviceDefinition {
        manufacturer_id: LightSwitchDevice::MANUFACTURER_ID,
        device_type: LightSwitchDevice::APPLICATION_ID_TP1_SYSTEM7,
        version: LightSwitchDevice::APPLICATION_VERSION,
        individual_address: IndividualAddress::new(15, 15, 255),
        max_group_addresses: LightSwitchDevice::MAX_ADDRESS_TABLE_ENTRIES as u8,
        max_associations: LightSwitchDevice::MAX_ASSOCIATION_TABLE_ENTRIES as u8,
        ram_flags_ptr: RAM_FLAGS_PTR as u16,
        comm_objects: &CO_DESCRIPTORS_S7,
        group_addresses: &[],
        associations: &[],
        ast_offset: 0x100,
        app_offset: S7_PARAMS_IMAGE_OFFSET,
        app_params: &DEFAULT_PARAM_BYTES,
    }
}

// ============================================================================
// Parameters out of the EEPROM image
// ============================================================================

/// Read the parameter block from the device's EEPROM image.
///
/// On these families ETS configures the device by writing the
/// parameter bytes into EEPROM (`A_Memory_Write` during the download),
/// so the image *is* the parameter storage. Reconstructing the struct
/// from those bytes carries the same trust the System B memory map
/// extends when it lets ETS overwrite its parameter struct byte by
/// byte: the product database and `#[ets_params]` agree on the layout,
/// and every field tolerates every bit pattern ETS can produce for it.
///
/// An image too short to hold the block (a family sized below the
/// product's layout — a wiring error) yields the factory defaults.
pub fn read_params(eeprom: &[u8], offset: usize) -> LightSwitchParams {
    match eeprom.get(offset..offset + core::mem::size_of::<LightSwitchParams>()) {
        Some(bytes) => unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const LightSwitchParams) },
        None => const_default::ConstDefault::DEFAULT,
    }
}

// ============================================================================
// Polled button events
// ============================================================================

/// What one poll of a [`PolledButton`] observed.
///
/// The async app distinguishes short from long presses with
/// `ButtonEvent` and then awaits the release; a polled loop cannot
/// await, so the release after a long press is its own event and the
/// dimmer/blind handlers act on the pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicroButtonEvent {
    /// Released before the long-press threshold.
    ShortPress,
    /// Held past the long-press threshold (fires once, button still
    /// down).
    LongPressStart,
    /// Released after a [`LongPressStart`](Self::LongPressStart).
    LongPressRelease,
}

/// Debounce + long-press state machine over a raw pin level.
///
/// Feed it the current level and the millisecond clock once per main
/// loop iteration; the thresholds come from the parameters so an ETS
/// download takes effect on the next press.
pub struct PolledButton {
    /// Debounced level (true = pressed).
    stable: bool,
    /// Last raw level seen, and since when.
    last_raw: bool,
    raw_since_ms: u32,
    /// When the debounced press began, for the long-press threshold.
    pressed_at_ms: u32,
    long_fired: bool,
}

impl PolledButton {
    pub const fn new() -> Self {
        Self { stable: false, last_raw: false, raw_since_ms: 0, pressed_at_ms: 0, long_fired: false }
    }

    pub fn poll(&mut self, raw: bool, now_ms: u32, debounce_ms: u32, long_press_ms: u32) -> Option<MicroButtonEvent> {
        if raw != self.last_raw {
            self.last_raw = raw;
            self.raw_since_ms = now_ms;
        }

        if raw != self.stable && now_ms.wrapping_sub(self.raw_since_ms) >= debounce_ms {
            self.stable = raw;
            if raw {
                self.pressed_at_ms = now_ms;
                self.long_fired = false;
                return None;
            }
            return Some(if self.long_fired {
                MicroButtonEvent::LongPressRelease
            } else {
                MicroButtonEvent::ShortPress
            });
        }

        if self.stable && !self.long_fired && now_ms.wrapping_sub(self.pressed_at_ms) >= long_press_ms {
            self.long_fired = true;
            return Some(MicroButtonEvent::LongPressStart);
        }

        None
    }
}

impl Default for PolledButton {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// The application
// ============================================================================

/// Which physical button an event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Btn1,
    Btn2,
}

/// The polled light-switch application: two button state machines and
/// the per-button dimmer direction memory, dispatching over the same
/// four function modes as [`super::app`].
pub struct LightSwitchMicroApp {
    /// Image offset of the parameter block for this family's layout.
    params_offset: usize,
    btn1: PolledButton,
    btn2: PolledButton,
    dim1_up: bool,
    dim2_up: bool,
}

impl LightSwitchMicroApp {
    pub const fn new(params_offset: usize) -> Self {
        Self { params_offset, btn1: PolledButton::new(), btn2: PolledButton::new(), dim1_up: true, dim2_up: true }
    }

    /// Drive the application: debounce the buttons and turn presses
    /// into group telegrams per the ETS-configured function modes.
    ///
    /// Call once per main-loop iteration with the raw (pressed = true)
    /// button levels. While the application is not running — mid
    /// download, or unloaded — button input is ignored, exactly as the
    /// full stack gates on its run state machine.
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
            let dim_up = &mut self.dim1_up;
            handle_event(stack, &params, event, Button::Btn1, dim_up);
        }
        if let Some(event) = self.btn2.poll(btn2_raw, now_ms, debounce, long_press) {
            let dim_up = &mut self.dim2_up;
            handle_event(stack, &params, event, Button::Btn2, dim_up);
        }
    }

    /// Consume a bus update of button 1's status object, for driving a
    /// local indicator (the firmware's user LED). Returns the new
    /// on/off level when a telegram arrived since the last call.
    pub fn take_btn1_status_update<F: MicroDeviceFamily>(&mut self, stack: &mut Microdevice<F>) -> Option<bool> {
        let (_, status, _) = BTN1_ASAPS;
        if stack.object_flags(status) & co_flags::UPDATE == 0 {
            return None;
        }
        stack.clear_update_flag(status);
        Some(read_status(stack, status))
    }
}

/// Resolve config and objects for a button — [`super::app`]'s
/// `resolve_button` over ASAPs instead of `Index`. In 1-function
/// (rocker) mode both buttons share `button1_config` and its objects,
/// with the physical position fixing the direction.
fn resolve_button(params: &LightSwitchParams, button: Button) -> (&ButtonConfig, (u8, u8, u8), Option<bool>) {
    match params.buttons_mode {
        ButtonsMode::OneFunction => {
            let is_top = matches!(button, Button::Btn1);
            let is_on = match params.rocker_direction {
                RockerDirection::Normal => is_top,
                RockerDirection::Inverted => !is_top,
            };
            (&params.button1_config, BTN1_ASAPS, Some(is_on))
        }
        ButtonsMode::TwoFunction => match button {
            Button::Btn1 => (&params.button1_config, BTN1_ASAPS, None),
            Button::Btn2 => (&params.button2_config, BTN2_ASAPS, None),
        },
    }
}

fn handle_event<F: MicroDeviceFamily>(
    stack: &mut Microdevice<F>,
    params: &LightSwitchParams,
    event: MicroButtonEvent,
    button: Button,
    dim_up: &mut bool,
) {
    let (config, (primary, status, secondary), rocker_on) = resolve_button(params, button);

    match config {
        ButtonConfig::Switch { action, .. } => {
            handle_switch(stack, event, *action, primary, status, rocker_on);
        }
        ButtonConfig::Dimmer { .. } => {
            handle_dimmer(stack, event, primary, status, secondary, rocker_on, dim_up);
        }
        ButtonConfig::Blind { .. } => {
            handle_blind(stack, event, primary, secondary, rocker_on);
        }
        ButtonConfig::Scene { scene_number, .. } => {
            handle_scene(stack, event, primary, *scene_number as u8);
        }
    }
}

/// Read the status object's current value as a bool (toggle logic).
fn read_status<F: MicroDeviceFamily>(stack: &Microdevice<F>, status: u8) -> bool {
    let mut buf = [0u8; 1];
    stack.read_value(status, &mut buf);
    buf[0] & 1 != 0
}

/// Send one value on an object: place the bytes in its RAM slot and
/// raise the transmit request; the stack's flag scan turns it into a
/// group write through the object's sending association.
fn send<F: MicroDeviceFamily>(stack: &mut Microdevice<F>, asap: u8, value: &[u8]) {
    stack.write_value(asap, value);
    stack.set_transmit_request(asap);
}

/// Switch mode — [`super::app::handle_switch`]: short press sends
/// on/off on the primary, long presses do nothing. The status object
/// is updated optimistically so consecutive toggles do not read a
/// stale value while the actuator's feedback is still in flight.
fn handle_switch<F: MicroDeviceFamily>(
    stack: &mut Microdevice<F>,
    event: MicroButtonEvent,
    action: SwitchAction,
    primary: u8,
    status: u8,
    rocker_on: Option<bool>,
) {
    if event != MicroButtonEvent::ShortPress {
        return;
    }
    let value = match rocker_on {
        Some(on) => on,
        None => match action {
            SwitchAction::Toggle => !read_status(stack, status),
            SwitchAction::On => true,
            SwitchAction::Off => false,
        },
    };
    send(stack, primary, &[value as u8]);
    stack.write_value(status, &[value as u8]);
}

/// Dimmer mode — [`super::app::handle_dimmer`]: short press toggles
/// via the primary; a long press brackets relative dimming on the
/// secondary (DPT 3.007: control bit + step code 1 to start, step
/// code 0 to stop), the direction alternating between long presses in
/// 2-function mode.
fn handle_dimmer<F: MicroDeviceFamily>(
    stack: &mut Microdevice<F>,
    event: MicroButtonEvent,
    primary: u8,
    status: u8,
    secondary: u8,
    rocker_on: Option<bool>,
    dim_up: &mut bool,
) {
    match event {
        MicroButtonEvent::ShortPress => {
            let value = match rocker_on {
                Some(on) => on,
                None => !read_status(stack, status),
            };
            send(stack, primary, &[value as u8]);
            stack.write_value(status, &[value as u8]);
            // Just turned ON: the user likely wants to dim DOWN next.
            if rocker_on.is_none() {
                *dim_up = !value;
            }
        }
        MicroButtonEvent::LongPressStart => {
            let up = rocker_on.unwrap_or(*dim_up);
            let start: u8 = if up { 0b0000_1001 } else { 0b0000_0001 };
            send(stack, secondary, &[start]);
        }
        MicroButtonEvent::LongPressRelease => {
            let up = rocker_on.unwrap_or(*dim_up);
            let stop: u8 = if up { 0b0000_1000 } else { 0b0000_0000 };
            send(stack, secondary, &[stop]);
            if rocker_on.is_none() {
                *dim_up = !*dim_up;
            }
        }
    }
}

/// Blind mode — [`super::app::handle_blind`]: short press steps
/// (DPT 1.007, 0 = increase), long press moves (DPT 1.008 on the
/// primary, 0 = up) with the stop step on release.
fn handle_blind<F: MicroDeviceFamily>(
    stack: &mut Microdevice<F>,
    event: MicroButtonEvent,
    primary: u8,
    secondary: u8,
    rocker_on: Option<bool>,
) {
    let up = rocker_on.unwrap_or(true);
    match event {
        MicroButtonEvent::ShortPress => {
            send(stack, secondary, &[!up as u8]);
        }
        MicroButtonEvent::LongPressStart => {
            send(stack, primary, &[if up { 0 } else { 1 }]);
        }
        MicroButtonEvent::LongPressRelease => {
            send(stack, secondary, &[!up as u8]);
        }
    }
}

/// Scene mode — [`super::app::handle_scene`]: short press recalls,
/// long press stores (DPT 18.001: bit 7 = learn).
fn handle_scene<F: MicroDeviceFamily>(stack: &mut Microdevice<F>, event: MicroButtonEvent, primary: u8, scene: u8) {
    let value = match event {
        MicroButtonEvent::ShortPress => scene & 0x3F,
        MicroButtonEvent::LongPressStart => (scene & 0x3F) | 0x80,
        // The store already went out on the long-press threshold.
        MicroButtonEvent::LongPressRelease => return,
    };
    send(stack, primary, &[value]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_state_machine_debounces_and_times() {
        let mut b = PolledButton::new();
        // Bounce shorter than the debounce time: no event.
        assert_eq!(b.poll(true, 0, 50, 500), None);
        assert_eq!(b.poll(false, 20, 50, 500), None);
        assert_eq!(b.poll(true, 30, 50, 500), None);
        // Stable press accepted after the debounce window.
        assert_eq!(b.poll(true, 85, 50, 500), None);
        // Released before the long-press threshold: short press.
        assert_eq!(b.poll(false, 200, 50, 500), None); // debouncing the release
        assert_eq!(b.poll(false, 260, 50, 500), Some(MicroButtonEvent::ShortPress));

        // Press and hold past the threshold: start, then release.
        assert_eq!(b.poll(true, 300, 50, 500), None);
        assert_eq!(b.poll(true, 360, 50, 500), None); // debounced press at 360
        assert_eq!(b.poll(true, 800, 50, 500), None);
        assert_eq!(b.poll(true, 900, 50, 500), Some(MicroButtonEvent::LongPressStart));
        assert_eq!(b.poll(true, 1000, 50, 500), None);
        assert_eq!(b.poll(false, 1100, 50, 500), None);
        assert_eq!(b.poll(false, 1160, 50, 500), Some(MicroButtonEvent::LongPressRelease));
    }

    #[test]
    fn params_round_trip_through_the_bcu2_image() {
        let def = bcu2_definition();
        let image = def.build_eeprom();
        let params = read_params(&image, BCU2_PARAMS_IMAGE_OFFSET);
        assert_eq!(params.debounce_time.as_ms(), 50);
        assert_eq!(params.long_press_time.as_ms(), 500);
        assert!(matches!(params.button1_config, ButtonConfig::Switch { .. }));
    }

    #[test]
    fn s7_image_matches_the_shared_product_geometry() {
        let def = system7_definition();
        let image = LightSwitchS7Family::build_eeprom(&def);
        // COT at 4200h: count 6, RAM flags at 00D0h, first row points
        // at 00C6h.
        assert_eq!(image[0x200], 6);
        assert_eq!(&image[0x201..0x203], &[0x00, 0xD0]);
        assert_eq!(&image[0x203..0x205], &[0x00, 0xC6]);
        // Parameters at 4300h are the factory defaults.
        assert_eq!(&image[0x300..0x300 + DEFAULT_PARAM_BYTES.len()], &DEFAULT_PARAM_BYTES);
    }
}
