//! Conditional logging macros.
//!
//! Re-exports `log` or `defmt` macros depending on which feature is enabled.
//! When neither is enabled, provides silent no-op macros so the crate compiles
//! without a logging backend.


#[cfg(feature = "defmt")]
pub use defmt::{debug, error, info, trace, warn};

#[cfg(feature = "log")]
pub use log::{debug, error, info, trace, warn};

#[cfg(not(any(feature = "log", feature = "defmt")))]
mod noop {
    macro_rules! noop_log {
        ($($t:tt)*) => {{}};
    }
    pub(crate) use noop_log as debug;
    pub(crate) use noop_log as error;
    pub(crate) use noop_log as info;
    pub(crate) use noop_log as trace;
    pub(crate) use noop_log as warn;
}
#[cfg(not(any(feature = "log", feature = "defmt")))]
pub use noop::*;
