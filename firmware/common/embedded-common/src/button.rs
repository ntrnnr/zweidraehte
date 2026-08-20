//! Debounced push-button driver with short/long press detection.
//!
//! Generic over any pin implementing the embedded-hal `InputPin` and
//! `Wait` traits, so it works with embassy-rp, embassy-stm32, etc.
//!
//! Assumes active-low buttons (pressed = low, released = high) with
//! an external or internal pull-up resistor.

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};
use embedded_hal::digital::InputPin;
use embedded_hal_async::digital::Wait;

pub use zweidraehte_util::input::ButtonEvent;

/// A push-button with debounce and short/long press classification.
///
/// Wraps any GPIO input pin that implements the embedded-hal digital
/// traits. Assumes active-low wiring (pressed = low).
pub struct DebouncedButton<P: InputPin + Wait> {
    pin: P,
    long_active: bool,
}

impl<P: InputPin + Wait> DebouncedButton<P> {
    pub fn new(pin: P) -> Self {
        Self { pin, long_active: false }
    }

    /// Wait for the next event in the classified button stream.
    ///
    /// 1. Waits for a falling edge (button pressed, active low).
    /// 2. Debounces by sleeping for `debounce` and re-checking that
    ///    the pin is still low. If it bounced back high, restarts.
    /// 3. If `long_press` is `Some`, races the rising edge (release)
    ///    against the long-press timeout:
    ///    - Released before timeout → [`ButtonEvent::ShortPress`]
    ///    - Timeout while still held → [`ButtonEvent::LongPressStart`]
    ///
    ///    If `long_press` is `None`, waits for release and always
    ///    returns [`ButtonEvent::ShortPress`].
    ///
    /// A short press produces one [`ButtonEvent::ShortPress`]. A long press
    /// produces [`ButtonEvent::LongPressStart`] at the threshold and
    /// [`ButtonEvent::LongPressRelease`] on the next call after release. This
    /// keeps the event contract independent of whether a caller polls a level
    /// or awaits GPIO edges.
    pub async fn wait_for_event(&mut self, debounce: Duration, long_press: Option<Duration>) -> ButtonEvent {
        if self.long_active {
            self.wait_for_debounced_release(debounce).await;
            self.long_active = false;
            return ButtonEvent::LongPressRelease;
        }

        loop {
            // Wait for button to be pressed (falling edge).
            let _ = self.pin.wait_for_falling_edge().await;

            // Debounce: let the contact settle, then verify still pressed.
            Timer::after(debounce).await;
            if self.pin.is_high().unwrap_or(true) {
                // Bounced back — not a real press, try again.
                continue;
            }

            // Button is solidly pressed. Now classify: short vs long.
            let Some(long_press) = long_press else {
                // No long-press detection — just wait for release.
                self.wait_for_debounced_release(debounce).await;
                return ButtonEvent::ShortPress;
            };

            let long_timeout = Timer::after(long_press);
            let release = self.pin.wait_for_rising_edge();

            match select(release, long_timeout).await {
                Either::First(_) => {
                    // Released before the long-press threshold.
                    self.wait_for_debounced_release(debounce).await;
                    return ButtonEvent::ShortPress;
                }
                Either::Second(_) => {
                    // Still held past the threshold.
                    self.long_active = true;
                    return ButtonEvent::LongPressStart;
                }
            }
        }
    }

    /// Wait for a stable release without assuming its edge is still pending.
    ///
    /// The application may spend time handling `LongPressStart` before it asks
    /// for the next event. Checking the level first prevents a release during
    /// that work from being lost.
    async fn wait_for_debounced_release(&mut self, debounce: Duration) {
        loop {
            if self.pin.is_low().unwrap_or(true) {
                let _ = self.pin.wait_for_rising_edge().await;
            }
            Timer::after(debounce).await;
            if self.pin.is_high().unwrap_or(false) {
                return;
            }
        }
    }
}
