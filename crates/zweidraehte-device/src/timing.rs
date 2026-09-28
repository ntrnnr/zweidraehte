//! Wall-clock compression for conformance runs.
//!
//! The conformance harness runs its DUTs in a fast mode that divides every
//! protocol-level wall-clock delay — Transport Layer timeouts, the S-A_Sync
//! rate limit, IP Secure session timers, the diagnostic countdown, random
//! response waits — by the `KNX_TIME_DIVISOR` environment variable, so the
//! logical ordering of a test survives while the run stays fast. Product
//! builds have no `conformance` feature and always see a divisor of 1.

/// The conformance fast-mode divisor: `KNX_TIME_DIVISOR` under the
/// `conformance` feature (1 if absent, unparseable or zero), otherwise 1.
pub(crate) fn time_divisor() -> u64 {
    #[cfg(feature = "conformance")]
    {
        extern crate std;
        std::env::var("KNX_TIME_DIVISOR").ok().and_then(|s| s.parse().ok()).filter(|&d| d > 0).unwrap_or(1)
    }
    #[cfg(not(feature = "conformance"))]
    {
        1
    }
}
