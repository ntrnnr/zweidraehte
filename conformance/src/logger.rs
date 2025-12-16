//! Custom logger for conformance tests
//!
//! Captures log output per test run and displays it with pretty formatting.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use log::{Level, LevelFilter, Log, Metadata, Record};

/// Maximum number of log entries to keep per test
const MAX_LOG_ENTRIES: usize = 1000;

/// A single log entry
#[derive(Clone)]
pub struct LogEntry {
    pub level: Level,
    pub target: String,
    pub message: String,
    pub timestamp_ms: u64,
}

/// Storage for captured logs, keyed by test name
struct LogStorage {
    /// Current test name (if any)
    current_test: Option<String>,
    /// Logs captured during current test
    current_logs: VecDeque<LogEntry>,
    /// Whether to also print to stderr
    print_live: bool,
}

impl LogStorage {
    fn new() -> Self {
        Self { current_test: None, current_logs: VecDeque::with_capacity(MAX_LOG_ENTRIES), print_live: false }
    }
}

static STORAGE: OnceLock<Mutex<LogStorage>> = OnceLock::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static START_TIME: OnceLock<Instant> = OnceLock::new();

/// The conformance test logger
struct ConformanceLogger {
    level: LevelFilter,
}

impl Log for ConformanceLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let storage = STORAGE.get().expect("Logger not initialized");
        let mut storage = storage.lock().unwrap();

        let elapsed = START_TIME.get().map(|t| t.elapsed().as_millis() as u64).unwrap_or(0);
        let entry = LogEntry {
            level: record.level(),
            target: record.target().to_string(),
            message: format!("{}", record.args()),
            timestamp_ms: elapsed,
        };

        // Store the log entry
        if storage.current_logs.len() >= MAX_LOG_ENTRIES {
            storage.current_logs.pop_front();
        }
        storage.current_logs.push_back(entry.clone());

        // Optionally print live
        if storage.print_live {
            print_entry(&entry);
        }
    }

    fn flush(&self) {}
}

/// Format timestamp as seconds.milliseconds
fn format_timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    format!("{:3}.{:03}", secs, millis)
}

/// Print a log entry with pretty formatting (env_logger style)
fn print_entry(entry: &LogEntry) {
    let (color, level_str) = match entry.level {
        Level::Error => ("\x1b[31m", "ERROR"),
        Level::Warn => ("\x1b[33m", "WARN "),
        Level::Info => ("\x1b[32m", "INFO "),
        Level::Debug => ("\x1b[34m", "DEBUG"),
        Level::Trace => ("\x1b[35m", "TRACE"),
    };

    // Shorten target for readability
    let target = shorten_target(&entry.target);
    let ts = format_timestamp(entry.timestamp_ms);

    eprintln!("{}[{} {} {}]\x1b[0m {}", color, ts, level_str, target, entry.message);
}

/// Shorten module paths for readability
fn shorten_target(target: &str) -> String {
    // Keep last 2 parts of the module path
    let parts: Vec<&str> = target.split("::").collect();
    if parts.len() <= 2 {
        target.to_string()
    } else {
        parts[parts.len() - 2..].join("::")
    }
}

/// Initialize the conformance logger
///
/// Call this once at program start.
pub fn init(level: LevelFilter, print_live: bool) {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // Already initialized
    }

    START_TIME.set(Instant::now()).ok();

    let mut storage = LogStorage::new();
    storage.print_live = print_live;
    STORAGE.set(Mutex::new(storage)).ok();

    let logger = ConformanceLogger { level };
    log::set_boxed_logger(Box::new(logger)).ok();
    log::set_max_level(level);
}

/// Initialize with default settings (TRACE level, no live printing)
pub fn init_default() {
    init(LevelFilter::Trace, false);
}

/// Start capturing logs for a new test
pub fn start_test(name: &str) {
    let storage = STORAGE.get().expect("Logger not initialized");
    let mut storage = storage.lock().unwrap();
    storage.current_test = Some(name.to_string());
    storage.current_logs.clear();
}

/// End the current test and return captured logs
pub fn end_test() -> Vec<LogEntry> {
    let storage = STORAGE.get().expect("Logger not initialized");
    let mut storage = storage.lock().unwrap();
    storage.current_test = None;
    storage.current_logs.drain(..).collect()
}

/// Get logs captured during current test (without clearing)
pub fn get_current_logs() -> Vec<LogEntry> {
    let storage = STORAGE.get().expect("Logger not initialized");
    let storage = storage.lock().unwrap();
    storage.current_logs.iter().cloned().collect()
}

/// Clear current logs
pub fn clear_logs() {
    let storage = STORAGE.get().expect("Logger not initialized");
    let mut storage = storage.lock().unwrap();
    storage.current_logs.clear();
}

/// Set whether to print logs live to stderr
pub fn set_live_print(enabled: bool) {
    let storage = STORAGE.get().expect("Logger not initialized");
    let mut storage = storage.lock().unwrap();
    storage.print_live = enabled;
}

/// Print captured logs with a header
pub fn print_logs(logs: &[LogEntry], indent: &str) {
    if logs.is_empty() {
        return;
    }

    for entry in logs {
        let (color, level_str) = match entry.level {
            Level::Error => ("\x1b[31m", "ERROR"),
            Level::Warn => ("\x1b[33m", "WARN "),
            Level::Info => ("\x1b[32m", "INFO "),
            Level::Debug => ("\x1b[34m", "DEBUG"),
            Level::Trace => ("\x1b[35m", "TRACE"),
        };

        let target = shorten_target(&entry.target);
        let ts = format_timestamp(entry.timestamp_ms);

        eprintln!("{}{}[{} {} {}]\x1b[0m {}", indent, color, ts, level_str, target, entry.message);
    }
}

/// Print a summary of captured logs (counts per level)
pub fn print_log_summary(logs: &[LogEntry], indent: &str) {
    let mut errors = 0;
    let mut warns = 0;
    let mut infos = 0;
    let mut debugs = 0;
    let mut traces = 0;

    for entry in logs {
        match entry.level {
            Level::Error => errors += 1,
            Level::Warn => warns += 1,
            Level::Info => infos += 1,
            Level::Debug => debugs += 1,
            Level::Trace => traces += 1,
        }
    }

    eprintln!(
        "{}📊 Logs: {} total (\x1b[31m{} errors\x1b[0m, \x1b[33m{} warns\x1b[0m, \x1b[32m{} info\x1b[0m, \x1b[34m{} debug\x1b[0m, \x1b[35m{} trace\x1b[0m)",
        indent, logs.len(), errors, warns, infos, debugs, traces
    );
}

/// Filter logs by minimum level
pub fn filter_logs(logs: &[LogEntry], min_level: Level) -> Vec<LogEntry> {
    logs.iter().filter(|e| e.level <= min_level).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shorten_target() {
        assert_eq!(shorten_target("zweidraehte::layers::network"), "layers::network");
        assert_eq!(shorten_target("network"), "network");
        assert_eq!(shorten_target("a::b"), "a::b");
        assert_eq!(shorten_target("a::b::c::d"), "c::d");
    }
}
