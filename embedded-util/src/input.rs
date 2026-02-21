//! Generic input event types for embedded devices.
//!
//! Platform-agnostic building blocks for button handling. The concrete
//! button driver (debouncing, edge detection) lives in platform-specific
//! crates; this module provides the shared event vocabulary.

/// Result of a debounced button press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonEvent {
    /// The button was pressed and released before the long-press threshold.
    ShortPress,

    /// The button has been held past the long-press threshold and is still
    /// held down. The caller should act on the long-press start (e.g. begin
    /// dimming), then use a [`WaitForRelease`] implementation to detect
    /// when the user lets go.
    LongPress,
}

/// Wait for a button release after a long press.
///
/// Implementations capture the debounce duration and button hardware
/// at construction time. Application logic calls `wait_for_release()`
/// during dimmer and blind long-press handling to detect when the user
/// lets go, without knowing anything about the underlying GPIO driver.
///
/// # Example
///
/// ```rust,ignore
/// struct ReleaseWaiter<'a> {
///     btn: &'a mut MyButton,
///     debounce: Duration,
/// }
///
/// impl WaitForRelease for ReleaseWaiter<'_> {
///     async fn wait_for_release(&mut self) {
///         self.btn.wait_for_release(self.debounce).await;
///     }
/// }
/// ```
// All consumers are single-threaded embedded executors where Send
// bounds don't apply, so async fn in trait is fine here.
#[allow(async_fn_in_trait)]
pub trait WaitForRelease {
    /// Block until the button is released (with debouncing).
    async fn wait_for_release(&mut self);
}
