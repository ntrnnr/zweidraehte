//! Cryptographic RNG for KNX Data Secure on STM32G0B0.
//!
//! Output stream is **ChaCha20** (RFC 8439) driven from the
//! [`chacha20`] crate's `rng` feature — a constructive CSPRNG that
//! resists state recovery from observed output, which is what KNX
//! Data Secure session-key material needs. The seed comes from
//! hardware noise: ADC LSBs sampled from a floating input pin,
//! conditioned through a SplitMix64-style avalanche per 32-bit lane
//! and loaded into ChaCha20's 256-bit key.
//!
//! STM32G0B0 value-line parts have no hardware TRNG. We build one by
//! sampling the LSB of an unconnected ADC channel and folding those
//! bits into 256 bits of seed state. A floating ADC pin picks up
//! thermal noise on the sampling capacitor and ambient EMI from
//! nearby signals (TPUART at 19200 8E1, SPI2 at 4 MHz to the FRAM) —
//! each sample contributes a fraction of a bit of real entropy, and
//! [`SEED_SAMPLES`] samples gives a comfortable budget well over
//! 256 bits before folding.
//!
//! # Scope caveat
//!
//! Seed comes from the ADC once, at boot. We do not reseed during
//! runtime. If the chip runs for a very long time while an attacker
//! captures a large amount of output, the seed quality is the entire
//! story — ChaCha20 itself is secure under standard assumptions, so
//! the practical concern is seed entropy. With 256-bit seed space
//! well-filled by real noise, this is fine.
//!
//! # Plugging into the KNX stack
//!
//! [`Stm32CommonRng`] is a ZST that implements
//! [`Rng`](zweidraehte_device::rng::Rng) and
//! [`SecureRng`](zweidraehte_device::rng::SecureRng) — firmware just
//! sets `type Rng = Stm32CommonRng;` on its [`StackDefinition`]
//! (`zweidraehte_device::StackDefinition`). No state newtype needed.

use core::cell::RefCell;

use chacha20::ChaCha20Rng;
use chacha20::rand_core::{SeedableRng, TryRng};
use critical_section::Mutex;
use embassy_stm32::Peri;
use embassy_stm32::PeripheralType;
use embassy_stm32::adc::{Adc, AdcChannel, SampleTime};
use embassy_stm32::peripherals::ADC1;

// ============================================================================
// Global CSPRNG state
// ============================================================================

/// Global ChaCha20 CSPRNG. Lazily populated by [`seed_from_adc`] and
/// then serves every [`fill`] call.
///
/// `ChaCha20Rng` owns a 256-bit key + a 64-bit block counter; advances
/// the counter per 64-byte keystream block; never needs re-seeding
/// under the 2⁶⁴-block limit (that's 1 TiB of output per seed, way
/// beyond anything a KNX device will emit in its lifetime).
static RNG: Mutex<RefCell<Option<ChaCha20Rng>>> = Mutex::new(RefCell::new(None));

// ============================================================================
// ADC-based seeding
// ============================================================================

/// Number of ADC samples collected at boot to build the seed.
///
/// Each sample contributes ~0.5–1 bit of real entropy (quantisation
/// + thermal noise + ambient EMI). At ~12 µs per sample (ADC clock /
/// 160.5 cycles sample-time, 12-bit conversion) 1024 samples adds
/// ~12 ms to boot — unnoticeable. With 1024 bits of raw-LSB input
/// folded into a 256-bit seed, the seed has well over 256 bits of
/// entropy even at the pessimistic end of per-sample entropy.
const SEED_SAMPLES: usize = 1024;

/// Seed the CSPRNG from ADC noise on a floating pin.
///
/// Samples the LSB of [`SEED_SAMPLES`] ADC conversions on `pin`,
/// folds the bits into 256 bits of seed state via a SplitMix64-style
/// avalanche per 32-bit lane, and installs the ChaCha20 generator.
/// The pin must be physically unconnected (no pull-up/down, no trace
/// to any signal) so the ADC input sees only thermal noise on its
/// sampling capacitor and ambient EMI.
///
/// Must be called once at boot before the secure stack runs.
/// Subsequent calls re-seed and are harmless; there's no ordering
/// concern because the mutex serialises access.
pub fn seed_from_adc<'d, P>(adc: Peri<'d, ADC1>, mut pin: Peri<'d, P>)
where
    P: PeripheralType,
    Peri<'d, P>: AdcChannel<ADC1>,
{
    let mut adc = Adc::new(adc);

    // SplitMix64-style avalanche per 32-bit lane. Its job is to
    // diffuse each raw 32-bit word across every output bit so that a
    // biased input stream (e.g. the ADC's last-bit drifting slowly
    // with temperature) still produces a well-distributed state word.
    fn mix(mut x: u32) -> u32 {
        x = (x ^ (x >> 16)).wrapping_mul(0x7feb_352d);
        x = (x ^ (x >> 15)).wrapping_mul(0x846c_a68b);
        x ^ (x >> 16)
    }

    // Collect SEED_SAMPLES LSBs into eight rotating u32 accumulators
    // (= 256 bits of pre-avalanche seed state). Rotating the target
    // lane per-sample means a systematic bias on any single sample
    // position (e.g. if the ADC always reports an even value for the
    // first conversion after enabling) gets spread across all lanes
    // rather than concentrating in one. We rotate-left the target
    // lane before XORing so that each contribution falls on a
    // different bit position, preventing pairs of identical LSBs
    // from cancelling.
    let mut lanes = [0u32; 8];
    for i in 0..SEED_SAMPLES {
        let sample = adc.blocking_read(&mut pin, SampleTime::CYCLES160_5);
        let lane = i & 7;
        lanes[lane] = lanes[lane].rotate_left(1) ^ (sample as u32 & 1);
    }

    // Pass each lane through the mixer so any residual bias or
    // short-range correlation doesn't survive into ChaCha20's key.
    // The output is a fully-mixed 256-bit seed.
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

/// ZST that plugs into [`StackDefinition::Rng`][sd] for secure
/// firmware. Routes every call through [`fill`].
///
/// [sd]: zweidraehte_device::StackDefinition::Rng
pub struct Stm32CommonRng;

impl zweidraehte_device::rng::Rng for Stm32CommonRng {
    fn fill(buf: &mut [u8]) {
        fill(buf);
    }
}

impl zweidraehte_device::rng::SecureRng for Stm32CommonRng {}

/// Fill `buf` with cryptographically pseudo-random bytes.
///
/// Panics if [`seed_from_adc`] has not been called yet — that's a
/// firmware wiring error, not a runtime condition to handle.
pub fn fill(buf: &mut [u8]) {
    critical_section::with(|cs| {
        let mut rng = RNG.borrow(cs).borrow_mut();
        let rng = rng.as_mut().expect("stm32_common::rng not seeded — call seed_from_adc() at boot");
        // `ChaCha20Rng::try_fill_bytes` is `Result<_, Infallible>` —
        // the `.ok()` unwrap is structural, not a correctness concern.
        rng.try_fill_bytes(buf).ok();
    });
}
