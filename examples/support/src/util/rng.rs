//! Host CSPRNG for secure Linux device targets.
//!
//! Secure stacks reject [`NoRng`](zweidraehte_device::NoRng) at compile time
//! (a `where D::Rng: SecureRng` bound), so a Data-Secure or IP-Secure device
//! must supply a real random source: the Secure Application Layer's `S-A_Sync`
//! challenges and the IP-Secure session/timer nonces draw from it. On a Linux
//! host the OS CSPRNG (`getrandom(2)`) is the right source.

use zweidraehte_device::{Rng, SecureRng};

/// A [`SecureRng`] backed by the operating-system CSPRNG via `getrandom(2)`.
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

impl SecureRng for GetrandomRng {}
