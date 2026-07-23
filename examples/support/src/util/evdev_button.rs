//! evdev-backed button emulation for host-target device shells.
//!
//! The light-switch application logic
//! ([`devices::light_switch::app::handle_button_press`]) is platform-agnostic:
//! it consumes [`ButtonEvent`]s and a [`WaitForRelease`] implementer, and every
//! firmware target feeds it from a debounced GPIO button. On a Linux host there
//! is no GPIO, so this module synthesises the same events from the keyboard via
//! **evdev** (`/dev/input/event*`), mapping physical key **1 → Button 1** and
//! **key 2 → Button 2**.
//!
//! evdev is used rather than terminal raw-mode because it exposes true KEY_DOWN
//! / KEY_UP transitions: a *tap* becomes a [`ButtonEvent::ShortPress`], a *hold*
//! past the long-press threshold becomes a [`ButtonEvent::LongPress`] (still
//! held), and [`EvdevButton::wait_for_release`] resolves on the key-up — so
//! hold-to-dim and blind-move durations are actually controllable. A terminal
//! reader has no key-release event and cannot do this.
//!
//! # Architecture
//!
//! The embassy `arch-std` executor is single-threaded and cooperative, and the
//! `evdev` crate's blocking `fetch_events()` (or its tokio `EventStream`) does
//! not fit it. So a dedicated **OS thread** does the blocking reads and forwards
//! each KEY_1 / KEY_2 edge into a per-button [`embassy_sync`] channel; the async
//! [`EvdevButton`] awaits those edges and classifies them, mirroring the
//! embedded `DebouncedButton` surface (`wait_for_press` / `wait_for_release`).
//!
//! # Permissions and capture
//!
//! Reading `/dev/input/event*` requires root or membership in the `input`
//! group; [`open_keyboard`] surfaces a clear hint on `EACCES`. The device is
//! **not** grabbed (`EVIOCGRAB`), so key presses still reach the focused window
//! — pressing `1` also types `1` wherever focus is. This is deliberate: grabbing
//! would steal all keyboard input system-wide, including the terminal running
//! the device. Run in a dedicated console if that matters.

use std::io;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver};
use embassy_time::{Duration, Timer};

use evdev::{Device, EventSummary, KeyCode};

pub use zweidraehte_util::input::{ButtonEvent, WaitForRelease};

/// Which physical button an edge belongs to. Mirrors
/// [`devices::light_switch::app::ButtonId`] but is defined here so the support
/// crate does not depend on the device definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvdevButtonId {
    Btn1,
    Btn2,
}

/// Environment variable naming the input device to read (e.g.
/// `/dev/input/event3`). When unset, [`open_keyboard`] auto-detects the first
/// device that reports the number keys.
pub const DEVICE_ENV: &str = "KNX_EVDEV";

/// Depth of each per-button edge channel. A couple of slots absorb the down/up
/// pair of a fast tap without the reader thread blocking; the async side drains
/// them promptly.
const CHANNEL_DEPTH: usize = 4;

/// One per-button edge channel: `true` = key down, `false` = key up.
type EdgeChannel = Channel<CriticalSectionRawMutex, bool, CHANNEL_DEPTH>;

/// The two per-button edge channels the reader thread publishes into and the
/// [`EvdevButton`]s consume. `'static` so the reader thread (which outlives any
/// stack frame) can hold references to them.
pub struct EvdevChannels {
    btn1: EdgeChannel,
    btn2: EdgeChannel,
}

impl EvdevChannels {
    pub const fn new() -> Self {
        Self { btn1: Channel::new(), btn2: Channel::new() }
    }

    /// The edge channel for `button`.
    fn channel(&self, button: EvdevButtonId) -> &EdgeChannel {
        match button {
            EvdevButtonId::Btn1 => &self.btn1,
            EvdevButtonId::Btn2 => &self.btn2,
        }
    }

    /// Push one raw edge (`true` = down, `false` = up) for `button`.
    ///
    /// Non-blocking (`try_send`); a full channel drops the edge, harmless for
    /// human-paced input. Public so a non-evdev edge source (the terminal
    /// fallback) can feed the same [`EvdevButton`] machinery.
    pub fn push_edge(&self, button: EvdevButtonId, down: bool) {
        let _ = self.channel(button).try_send(down);
    }

    /// Inject a synthetic **press** for `button` from a source with no real
    /// key-release (the terminal fallback).
    ///
    /// Emits a down edge, waits `hold`, then an up edge. With `hold` shorter
    /// than the app's long-press threshold this reads as a
    /// [`ButtonEvent::ShortPress`]; with `hold` longer it reads as a
    /// [`ButtonEvent::LongPress`] whose release fires when the up lands — so a
    /// terminal keypress yields a bounded, self-releasing hold. Await it from an
    /// async context (e.g. spawn it) so the down/up gap is real wall-clock time.
    pub async fn inject_press(&self, button: EvdevButtonId, hold: Duration) {
        self.push_edge(button, true);
        Timer::after(hold).await;
        self.push_edge(button, false);
    }
}

impl Default for EvdevChannels {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a terminal character to a button and whether it is a long press.
///
/// `1`/`2` are short presses on Button 1 / 2; `!`/`@` (shift-1 / shift-2) are
/// long presses. Any other character is `None`. Used by the terminal fallback
/// when evdev is unavailable — a terminal has no key-release event, so long
/// press is a distinct key rather than a hold.
pub fn terminal_key_to_button(key: char) -> Option<(EvdevButtonId, bool)> {
    match key {
        '1' => Some((EvdevButtonId::Btn1, false)),
        '2' => Some((EvdevButtonId::Btn2, false)),
        '!' => Some((EvdevButtonId::Btn1, true)),
        '@' => Some((EvdevButtonId::Btn2, true)),
        _ => None,
    }
}

// ============================================================================
// Device open + selection
// ============================================================================

/// Open the input device to read keys from.
///
/// Uses `path` if given, else `$KNX_EVDEV`, else auto-detects the first
/// `/dev/input/event*` device whose supported keys include the number row
/// (a proxy for "this is a keyboard"). Returns a clear error on permission
/// failure — reading evdev nodes needs root or `input`-group membership.
pub fn open_keyboard(path: Option<&str>) -> io::Result<Device> {
    let explicit = path.map(String::from).or_else(|| std::env::var(DEVICE_ENV).ok());

    if let Some(path) = explicit {
        return Device::open(&path).map_err(|e| annotate_permission(e, &path));
    }

    // Auto-detect: the first enumerated device that reports KEY_1 is almost
    // certainly the keyboard.
    //
    // `evdev::enumerate()` opens each `/dev/input/event*` and *silently skips*
    // any it cannot open — so on a machine where the caller lacks `input`-group
    // access, it yields nothing and we'd otherwise report a misleading "no
    // keyboard found" when the real cause is permissions. To keep the failure
    // diagnosable, we scan the raw event nodes ourselves and remember whether a
    // permission error was the reason nothing opened.
    let mut saw_permission_error = false;
    for entry in read_event_nodes() {
        match Device::open(&entry) {
            Ok(device) => {
                if device.supported_keys().is_some_and(|keys| keys.contains(KeyCode::KEY_1)) {
                    log::info!("evdev: using auto-detected keyboard {}", entry.display());
                    return Ok(device);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => saw_permission_error = true,
            Err(_) => {}
        }
    }

    if saw_permission_error {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cannot read /dev/input/event* (permission denied): add your user to the `input` \
                 group (`sudo usermod -aG input $USER`, then re-log in) or run with sudo; \
                 or point {DEVICE_ENV} at a readable device node"
            ),
        ))
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no keyboard-like /dev/input device found (set {DEVICE_ENV}=/dev/input/eventN)"),
        ))
    }
}

/// The `/dev/input/event*` device nodes, sorted, ignoring a missing directory.
///
/// We enumerate the nodes ourselves rather than via `evdev::enumerate()` so a
/// permission error on a node is visible (see [`open_keyboard`]) instead of
/// being silently swallowed.
fn read_event_nodes() -> Vec<std::path::PathBuf> {
    let mut nodes: Vec<_> = std::fs::read_dir("/dev/input")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("event")))
        .collect();
    nodes.sort();
    nodes
}

/// Attach an actionable hint to an `EACCES` when opening a device by path.
fn annotate_permission(err: io::Error, path: &str) -> io::Error {
    if err.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cannot read {path} (permission denied): add your user to the `input` group \
                 (`sudo usermod -aG input $USER`, then re-log in) or run with sudo"
            ),
        )
    } else {
        err
    }
}

// ============================================================================
// Reader thread
// ============================================================================

/// Spawn the blocking evdev reader thread, forwarding KEY_1 / KEY_2 edges into
/// `channels`.
///
/// The thread owns `device` and runs until the process exits (a device read
/// error ends it, logged). Autorepeat events (value `2`) are ignored — only the
/// initial down (`1`) and the up (`0`) drive the button state machine. Edges are
/// pushed with `try_send`, so if the async side is momentarily behind, the
/// oldest-unread policy is "drop" rather than block the reader; for human key
/// taps the channel never actually fills.
pub fn spawn_evdev_reader(mut device: Device, channels: &'static EvdevChannels) {
    std::thread::Builder::new()
        .name("evdev-reader".into())
        .spawn(move || {
            loop {
                let events = match device.fetch_events() {
                    Ok(events) => events,
                    Err(e) => {
                        log::warn!("evdev reader stopping: {e}");
                        return;
                    }
                };
                for event in events {
                    // value: 1 = press, 0 = release, 2 = autorepeat (ignored).
                    let (button, down) = match event.destructure() {
                        EventSummary::Key(_, KeyCode::KEY_1, 1) => (EvdevButtonId::Btn1, true),
                        EventSummary::Key(_, KeyCode::KEY_1, 0) => (EvdevButtonId::Btn1, false),
                        EventSummary::Key(_, KeyCode::KEY_2, 1) => (EvdevButtonId::Btn2, true),
                        EventSummary::Key(_, KeyCode::KEY_2, 0) => (EvdevButtonId::Btn2, false),
                        _ => continue,
                    };
                    channels.push_edge(button, down);
                }
            }
        })
        .expect("spawn evdev reader thread");
}

// ============================================================================
// Press classification
// ============================================================================

/// Map the outcome of the release-vs-threshold race to a [`ButtonEvent`].
///
/// `released_first` is `true` when the key came up before the long-press
/// threshold elapsed (→ [`ButtonEvent::ShortPress`]) and `false` when the
/// threshold fired first with the key still held (→ [`ButtonEvent::LongPress`]).
/// Extracted as a pure function so the mapping is testable without driving a
/// real timer.
fn classify_press(released_first: bool) -> ButtonEvent {
    if released_first { ButtonEvent::ShortPress } else { ButtonEvent::LongPress }
}

// ============================================================================
// EvdevButton
// ============================================================================

/// One emulated button, consuming edges from its per-button channel.
///
/// Presents the same surface as the embedded `DebouncedButton`
/// (`firmware/common/embedded-common`) so a Linux `app_task` mirrors the
/// firmware one: [`wait_for_press`](Self::wait_for_press) classifies the next
/// press as short/long, and [`wait_for_release`](Self::wait_for_release) awaits
/// the key-up after a long press.
pub struct EvdevButton {
    edges: Receiver<'static, CriticalSectionRawMutex, bool, CHANNEL_DEPTH>,
}

impl EvdevButton {
    /// Build the two buttons wired to `channels`. Call once, after
    /// [`spawn_evdev_reader`] with the same `channels`.
    pub fn pair(channels: &'static EvdevChannels) -> (Self, Self) {
        (Self { edges: channels.btn1.receiver() }, Self { edges: channels.btn2.receiver() })
    }

    /// Await the next key-down edge, discarding any stale key-up.
    async fn wait_for_down(&mut self) {
        loop {
            if self.edges.receive().await {
                return;
            }
        }
    }

    /// Await the next key-up edge, discarding any stale key-down.
    async fn wait_for_up(&mut self) {
        loop {
            if !self.edges.receive().await {
                return;
            }
        }
    }

    /// Wait for a press and classify it, mirroring
    /// `DebouncedButton::wait_for_press`.
    ///
    /// Returns [`ButtonEvent::ShortPress`] if the key is released before
    /// `long_press` elapses (or immediately, when `long_press` is `None`), and
    /// [`ButtonEvent::LongPress`] — with the key still held — once the threshold
    /// passes. `debounce` is honoured for parity with the GPIO driver; the
    /// kernel already debounces key events, so it is a short settle only.
    pub async fn wait_for_press(&mut self, debounce: Duration, long_press: Option<Duration>) -> ButtonEvent {
        self.wait_for_down().await;
        Timer::after(debounce).await;

        let Some(long_press) = long_press else {
            // No long-press classification: behave like a momentary press.
            self.wait_for_up().await;
            return ButtonEvent::ShortPress;
        };

        // Race the release against the long-press threshold. The pure
        // `classify_press` maps the race outcome to the event so the mapping is
        // unit-testable without a timer.
        let released_first = matches!(
            embassy_futures::select::select(self.wait_for_up(), Timer::after(long_press)).await,
            embassy_futures::select::Either::First(())
        );
        classify_press(released_first)
    }

    /// Wait for the key-up after a [`ButtonEvent::LongPress`].
    pub async fn wait_for_release(&mut self, debounce: Duration) {
        self.wait_for_up().await;
        Timer::after(debounce).await;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // The release-vs-threshold race outcome maps to the right event. The async
    // race itself needs an embassy executor + timer driver (exercised on the
    // real device); the *mapping* is pure and tested here.
    #[test]
    fn press_classification_maps_race_outcome() {
        assert_eq!(classify_press(true), ButtonEvent::ShortPress); // released first
        assert_eq!(classify_press(false), ButtonEvent::LongPress); // threshold first
    }

    // The reader routes each key's edges to its own button channel, so the two
    // buttons never see each other's edges. Uses `try_send`/`try_receive` — no
    // executor or timer needed.
    #[test]
    fn edges_demux_per_button() {
        let channels = EvdevChannels::new();

        // Btn1 down/up and Btn2 down land on disjoint channels.
        channels.btn1.try_send(true).unwrap();
        channels.btn2.try_send(true).unwrap();
        channels.btn1.try_send(false).unwrap();

        assert_eq!(channels.btn1.try_receive(), Ok(true));
        assert_eq!(channels.btn1.try_receive(), Ok(false));
        assert_eq!(channels.btn2.try_receive(), Ok(true));
        // Nothing cross-contaminated: both channels are now empty.
        assert!(channels.btn1.try_receive().is_err());
        assert!(channels.btn2.try_receive().is_err());
    }

    // The terminal fallback maps the number keys to short presses and their
    // shifted forms to long presses; everything else is ignored.
    #[test]
    fn terminal_key_mapping() {
        assert_eq!(terminal_key_to_button('1'), Some((EvdevButtonId::Btn1, false)));
        assert_eq!(terminal_key_to_button('2'), Some((EvdevButtonId::Btn2, false)));
        assert_eq!(terminal_key_to_button('!'), Some((EvdevButtonId::Btn1, true)));
        assert_eq!(terminal_key_to_button('@'), Some((EvdevButtonId::Btn2, true)));
        assert_eq!(terminal_key_to_button('p'), None);
        assert_eq!(terminal_key_to_button('3'), None);
    }
}
