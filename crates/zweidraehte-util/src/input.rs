//! Generic input event types for embedded devices.
//!
//! Platform-agnostic building blocks for button handling. The concrete
//! button driver (debouncing, edge detection) lives in platform-specific
//! crates; this module provides the shared event vocabulary.

/// One phase of a classified button press.
///
/// Every classifier emits the same stream: a short press produces
/// `ShortPress`; a long press produces `LongPressStart` followed by
/// `LongPressRelease`. How the source observes the physical input does not
/// change the meaning of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonEvent {
    /// The button was pressed and released before the long-press threshold.
    ShortPress,

    /// The button has been held past the long-press threshold and is still
    /// held down. The caller should act on the long-press start (e.g. begin
    /// dimming); the same input source later emits [`LongPressRelease`](Self::LongPressRelease).
    LongPressStart,

    /// The button was released after [`LongPressStart`](Self::LongPressStart).
    LongPressRelease,
}

/// Debounce and long-press classification over a raw button level.
///
/// Feed the current level (`true` = pressed) and a wrapping monotonic
/// millisecond clock once per main-loop iteration.
pub struct PolledButton {
    stable: bool,
    last_raw: bool,
    raw_since_ms: u32,
    pressed_at_ms: u32,
    long_fired: bool,
}

impl PolledButton {
    pub const fn new() -> Self {
        Self { stable: false, last_raw: false, raw_since_ms: 0, pressed_at_ms: 0, long_fired: false }
    }

    pub fn poll(&mut self, raw: bool, now_ms: u32, debounce_ms: u32, long_press_ms: u32) -> Option<ButtonEvent> {
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
            return Some(if self.long_fired { ButtonEvent::LongPressRelease } else { ButtonEvent::ShortPress });
        }

        if self.stable && !self.long_fired && now_ms.wrapping_sub(self.pressed_at_ms) >= long_press_ms {
            self.long_fired = true;
            return Some(ButtonEvent::LongPressStart);
        }

        None
    }
}

impl Default for PolledButton {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polled_button_debounces_and_classifies_press_duration() {
        let mut button = PolledButton::new();
        assert_eq!(button.poll(true, 0, 50, 500), None);
        assert_eq!(button.poll(false, 20, 50, 500), None);
        assert_eq!(button.poll(true, 30, 50, 500), None);
        assert_eq!(button.poll(true, 85, 50, 500), None);
        assert_eq!(button.poll(false, 200, 50, 500), None);
        assert_eq!(button.poll(false, 260, 50, 500), Some(ButtonEvent::ShortPress));

        assert_eq!(button.poll(true, 300, 50, 500), None);
        assert_eq!(button.poll(true, 360, 50, 500), None);
        assert_eq!(button.poll(true, 800, 50, 500), None);
        assert_eq!(button.poll(true, 900, 50, 500), Some(ButtonEvent::LongPressStart));
        assert_eq!(button.poll(true, 1000, 50, 500), None);
        assert_eq!(button.poll(false, 1100, 50, 500), None);
        assert_eq!(button.poll(false, 1160, 50, 500), Some(ButtonEvent::LongPressRelease));
    }
}
