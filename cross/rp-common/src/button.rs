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

pub use embedded_util::input::ButtonEvent;

/// A push-button with debounce and short/long press classification.
///
/// Wraps any GPIO input pin that implements the embedded-hal digital
/// traits. Assumes active-low wiring (pressed = low).
pub struct DebouncedButton<P: InputPin + Wait> {
    pin: P,
}

impl<P: InputPin + Wait> DebouncedButton<P> {
    pub fn new(pin: P) -> Self {
        Self { pin }
    }

    /// Wait for the next debounced button press and classify it.
    ///
    /// 1. Waits for a falling edge (button pressed, active low).
    /// 2. Debounces by sleeping for `debounce` and re-checking that
    ///    the pin is still low. If it bounced back high, restarts.
    /// 3. If `long_press` is `Some`, races the rising edge (release)
    ///    against the long-press timeout:
    ///    - Released before timeout → [`ButtonEvent::ShortPress`]
    ///    - Timeout while still held → [`ButtonEvent::LongPress`]
    ///
    ///    If `long_press` is `None`, waits for release and always
    ///    returns [`ButtonEvent::ShortPress`].
    ///
    /// After [`ButtonEvent::ShortPress`], the button has already been
    /// released. After [`ButtonEvent::LongPress`], it is still held —
    /// call [`wait_for_release`](Self::wait_for_release) when done.
    pub async fn wait_for_press(
        &mut self,
        debounce: Duration,
        long_press: Option<Duration>,
    ) -> ButtonEvent {
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
                let _ = self.pin.wait_for_rising_edge().await;
                Timer::after(debounce).await;
                return ButtonEvent::ShortPress;
            };

            let long_timeout = Timer::after(long_press);
            let release = self.pin.wait_for_rising_edge();

            match select(release, long_timeout).await {
                Either::First(_) => {
                    // Released before the long-press threshold.
                    return ButtonEvent::ShortPress;
                }
                Either::Second(_) => {
                    // Still held past the threshold.
                    return ButtonEvent::LongPress;
                }
            }
        }
    }

    /// Wait for the button to be released after a long press.
    ///
    /// Waits for a rising edge and then debounces the release. Call
    /// this after receiving [`ButtonEvent::LongPress`] and acting on
    /// the long-press start event.
    pub async fn wait_for_release(&mut self, debounce: Duration) {
        let _ = self.pin.wait_for_rising_edge().await;
        Timer::after(debounce).await;
    }
}
