//! Host CSPRNG for secure Linux device targets.
//!
//! Secure stacks refuse to build with [`NoRng`](zweidraehte_device::NoRng)
//! (see [`require_secure_rng`](zweidraehte_device::rng::require_secure_rng)),
//! so a Data-Secure or IP-Secure device must supply a real random source: the
//! Secure Application Layer's `S-A_Sync` challenges and the IP-Secure
//! session/timer nonces draw from it. On a Linux host the OS CSPRNG
//! (`getrandom(2)`) is the right source.

use zweidraehte_device::Rng;

/// A secure [`Rng`] backed by the operating-system CSPRNG via `getrandom(2)`.
///
/// Suitable for the host-target secure device shells. Mirrors the conformance
/// harness's identically named helper.
pub struct GetrandomRng;

impl Rng for GetrandomRng {
    fn fill(buf: &mut [u8]) {
        // A `getrandom` failure on Linux means the kernel CSPRNG is
        // unavailable — unrecoverable for a secure device, so panic rather
        // than proceed with predictable key material.
        getrandom::fill(buf).expect("OS CSPRNG (getrandom) unavailable");
    }
}
