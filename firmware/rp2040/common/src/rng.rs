//! Cryptographic RNG for KNX Data Secure on RP2040.
//!
//! Output stream is **ChaCha20** (RFC 8439) driven from the
//! [`chacha20`] crate's `rng` feature — a constructive CSPRNG that
//! resists state recovery from observed output, which is what KNX
//! Data Secure session-key material needs. The seed comes from the
//! RP2040's ring oscillator (ROSC): we sample the ROSC's random bit
//! many times, fold the bits into 256 bits of seed state via a
//! SplitMix64-style avalanche per 32-bit lane, and load that into
//! ChaCha20's 256-bit key.
//!
//! This is the RP2040 analogue of `stm32-common`'s `Stm32CommonRng`.
//! The only difference is the entropy source: the STM32G0B0 has no
//! TRNG so it samples a floating ADC pin; the RP2040 exposes the ROSC
//! random bit directly via [`RoscRng`], so no spare pin is needed.
//!
//! # Seed quality caveat
//!
//! The RP2040 ROSC random bit is correlated and biased — a single bit
//! carries only a fraction of a bit of entropy. We compensate by
//! collecting [`SEED_SAMPLES`] bits (far more than 256) and folding
//! them through the avalanche mixer, the same conditioning the STM32
//! path applies to its ADC LSBs. ChaCha20 itself is secure under
//! standard assumptions; the practical concern is seed entropy, and a
//! well-filled 256-bit seed space is sufficient. We seed once at boot
//! and do not reseed at runtime — fine for a device that emits far
//! less than ChaCha20's 2⁶⁴-block limit over its lifetime.
//!
//! # Plugging into the KNX stack
//!
//! [`RpCommonRng`] is a ZST that implements
//! [`Rng`](zweidraehte_device::rng::Rng) and
//! [`SecureRng`](zweidraehte_device::rng::SecureRng) — firmware just
//! sets `type Rng = RpCommonRng;` on its `StackDefinition`. Call
//! [`seed_from_rosc`] once at boot before the secure stack runs.

use core::cell::RefCell;

use chacha20::ChaCha20Rng;
use chacha20::rand_core::{SeedableRng, TryRng};
use critical_section::Mutex;
use embassy_rp::clocks::RoscRng;

// ============================================================================
// Global CSPRNG state
// ============================================================================

/// Global ChaCha20 CSPRNG. Lazily populated by [`seed_from_rosc`] and
/// then serves every [`fill`] call.
///
/// `ChaCha20Rng` owns a 256-bit key + a 64-bit block counter; advances
/// the counter per 64-byte keystream block; never needs re-seeding
/// under the 2⁶⁴-block limit (that's 1 TiB of output per seed, way
/// beyond anything a KNX device will emit in its lifetime).
static RNG: Mutex<RefCell<Option<ChaCha20Rng>>> = Mutex::new(RefCell::new(None));

// ============================================================================
// ROSC-based seeding
// ============================================================================

/// Number of ROSC random bits collected at boot to build the seed.
///
/// The RP2040 ROSC random bit is far lower quality than a real TRNG —
/// correlated and biased — so we oversample heavily. 4096 raw bits
/// folded into a 256-bit seed gives a comfortable budget even at a
/// pessimistic fraction-of-a-bit per sample. Sampling is fast (a
/// register read each), so the boot-time cost is negligible.
const SEED_SAMPLES: usize = 4096;

/// Seed the CSPRNG from RP2040 ROSC noise.
///
/// Samples [`SEED_SAMPLES`] ROSC random bits, folds them into 256 bits
/// of seed state via a SplitMix64-style avalanche per 32-bit lane, and
/// installs the ChaCha20 generator.
///
/// Must be called once at boot before the secure stack runs.
/// Subsequent calls re-seed and are harmless; the mutex serialises
/// access so there's no ordering concern.
pub fn seed_from_rosc() {
    // SplitMix64-style avalanche per 32-bit lane. Its job is to
    // diffuse each raw 32-bit word across every output bit so that a
    // biased input stream (the ROSC bit drifting slowly) still
    // produces a well-distributed state word.
    fn mix(mut x: u32) -> u32 {
        x = (x ^ (x >> 16)).wrapping_mul(0x7feb_352d);
        x = (x ^ (x >> 15)).wrapping_mul(0x846c_a68b);
        x ^ (x >> 16)
    }

    // Collect SEED_SAMPLES ROSC bits into eight rotating u32
    // accumulators (= 256 bits of pre-avalanche seed state). Rotating
    // the target lane per sample spreads any systematic bias across
    // all lanes rather than concentrating it in one; the rotate-left
    // before XOR puts each contribution on a different bit position so
    // identical consecutive bits don't cancel.
    let mut lanes = [0u32; 8];
    for i in 0..SEED_SAMPLES {
        let bit = RoscRng::next_u8() & 1;
        let lane = i & 7;
        lanes[lane] = lanes[lane].rotate_left(1) ^ (bit as u32);
    }

    // Pass each lane through the mixer so residual bias or short-range
    // correlation doesn't survive into ChaCha20's key.
    let mut seed = [0u8; 32];
    for (i, lane) in lanes.iter().enumerate() {
        seed[i * 4..(i + 1) * 4].copy_from_slice(&mix(*lane).to_le_bytes());
    }

    let rng = ChaCha20Rng::from_seed(seed);
    critical_section::with(|cs| {
        *RNG.borrow(cs).borrow_mut() = Some(rng);
    });
}

// ============================================================================
// Output API
// ============================================================================

/// ZST that plugs into `StackDefinition::Rng` for secure firmware.
/// Routes every call through [`fill`].
pub struct RpCommonRng;

impl zweidraehte_device::rng::Rng for RpCommonRng {
    fn fill(buf: &mut [u8]) {
        fill(buf);
    }
}

impl zweidraehte_device::rng::SecureRng for RpCommonRng {}

/// Fill `buf` with cryptographically pseudo-random bytes.
///
/// Panics if [`seed_from_rosc`] has not been called yet — that's a
/// firmware wiring error, not a runtime condition to handle.
pub fn fill(buf: &mut [u8]) {
    critical_section::with(|cs| {
        let mut rng = RNG.borrow(cs).borrow_mut();
        let rng = rng.as_mut().expect("rp_common::rng not seeded — call seed_from_rosc() at boot");
        // `ChaCha20Rng::try_fill_bytes` is `Result<_, Infallible>` —
        // the `.ok()` unwrap is structural, not a correctness concern.
        rng.try_fill_bytes(buf).ok();
    });
}
