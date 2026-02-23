//! Keyboard input helper for test utilities
//!
//! Provides non-blocking single-key input using termios raw mode.
//! Sets up terminal for single character input without echo, but keeps
//! signal handling (Ctrl+C still works).
//!
//! Usage:
//! ```ignore
//! loop {
//!     if let Some(key) = keyboard::poll_key() {
//!         match key {
//!             'q' => break,
//!             '1' => println!("Got 1"),
//!             _ => {}
//!         }
//!     }
//! }
//! ```

use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::sync::Mutex;

/// Original terminal settings for restoration
static ORIGINAL_TERMIOS: std::sync::OnceLock<Mutex<libc::termios>> = std::sync::OnceLock::new();

/// Initialize raw mode (called automatically on first poll)
fn init_raw_mode() {
    ORIGINAL_TERMIOS.get_or_init(|| {
        let fd = std::io::stdin().as_raw_fd();
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };

        // Get current terminal settings
        unsafe { libc::tcgetattr(fd, &mut termios) };

        let original = termios;

        // Set raw mode but keep ISIG for Ctrl+C handling
        termios.c_lflag &= !(libc::ICANON | libc::ECHO);
        termios.c_cc[libc::VMIN] = 0; // Non-blocking
        termios.c_cc[libc::VTIME] = 0; // No timeout

        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };

        // Register cleanup handler
        unsafe {
            libc::atexit(restore_terminal);
        }

        Mutex::new(original)
    });
}

/// Restore terminal to original settings
extern "C" fn restore_terminal() {
    if let Some(original) = ORIGINAL_TERMIOS.get()
        && let Ok(original) = original.lock() {
            let fd = std::io::stdin().as_raw_fd();
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &*original) };
        }
}

/// Poll for a key press (non-blocking)
///
/// Returns `Some(char)` if a key was pressed, `None` otherwise.
/// Terminal is set to raw mode on first call.
pub fn poll_key() -> Option<char> {
    init_raw_mode();

    let mut buf = [0u8; 1];
    match std::io::stdin().read(&mut buf) {
        Ok(1) => Some(buf[0] as char),
        _ => None,
    }
}
