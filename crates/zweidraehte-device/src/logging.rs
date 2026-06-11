//! Conditional logging macros.
//!
//! Re-exports `log` or `defmt` macros depending on which feature is enabled.
//! When neither is enabled, provides silent no-op macros so the crate compiles
//! without a logging backend.

// Facade completeness: every level is re-exported even when a given
// feature set happens to have no call sites for it.
#[cfg(feature = "defmt")]
#[allow(unused_imports)]
pub use defmt::{debug, error, info, trace, warn};

#[cfg(feature = "log")]
#[allow(unused_imports)]
pub use log::{debug, error, info, trace, warn};

#[cfg(not(any(feature = "log", feature = "defmt")))]
mod noop {
    // The format arguments are referenced (then discarded) so that
    // bindings used only in log statements don't trip unused-variable
    // warnings when no logging backend is enabled. The reference is
    // free at runtime; the fallback arm covers non-standard arg forms.
    macro_rules! noop_log {
        ($fmt:literal $(, $arg:expr)* $(,)?) => {{ $( let _ = &$arg; )* }};
        ($($t:tt)*) => {{}};
    }
    // Facade completeness: every level is re-exported even when a
    // given feature set happens to have no call sites for it.
    #[allow(unused_imports)]
    pub(crate) use noop_log as debug;
    #[allow(unused_imports)]
    pub(crate) use noop_log as error;
    #[allow(unused_imports)]
    pub(crate) use noop_log as info;
    #[allow(unused_imports)]
    pub(crate) use noop_log as trace;
    #[allow(unused_imports)]
    pub(crate) use noop_log as warn;
}
#[cfg(not(any(feature = "log", feature = "defmt")))]
pub(crate) use noop::*;
