//! Boot-time CSPRNG seeding without pulling in the embassy ADC driver.
//!
//! PA0 must be physically unconnected. We sample 1024 ADC LSBs and condition
//! the eight 32-bit lanes before using them as a ChaCha20 key. The generator
//! then lives in `FramStore`, beside the only micro-stack resource that asks
//! for random bytes (`S-A_Sync_Res`).

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng;
use stm32_metapac::{self as pac, ADC1, GPIOA, RCC};

const SEED_SAMPLES: usize = 1024;

pub fn seed_csprng() -> ChaCha20Rng {
    use pac::adc::vals::{Ckmode, SampleTime, Smpsel};
    use pac::gpio::vals::{Moder, Pupdr};

    GPIOA.moder().modify(|w| w.set_moder(0, Moder::ANALOG));
    GPIOA.pupdr().modify(|w| w.set_pupdr(0, Pupdr::FLOATING));
    RCC.apbenr2().modify(|w| w.set_adcen(true));

    // Use the known 16 MHz peripheral clock rather than depending on an
    // asynchronously selected ADC clock left over from reset state.
    ADC1.cfgr2().modify(|w| w.set_ckmode(Ckmode::PCLK_DIV2));
    ADC1.cr().modify(|w| w.set_advregen(true));
    for _ in 0..400 {
        cortex_m::asm::nop();
    }

    ADC1.cr().modify(|w| w.set_adcal(true));
    while ADC1.cr().read().adcal() {}

    ADC1.cfgr1().modify(|w| w.set_chselrmod(false));
    ADC1.smpr().modify(|w| {
        w.set_sample_time(0, SampleTime::CYCLES160_5);
        w.set_smpsel(0, Smpsel::SMP1);
    });
    ADC1.chselr().write(|w| w.set_chsel(0, true));
    ADC1.isr().write(|w| w.set_adrdy(true));
    ADC1.cr().modify(|w| w.set_aden(true));
    while !ADC1.isr().read().adrdy() {}

    let mut lanes = [0u32; 8];
    for i in 0..SEED_SAMPLES {
        ADC1.cr().modify(|w| w.set_adstart(true));
        while !ADC1.isr().read().eoc() {}
        let sample = ADC1.dr().read().data();
        let lane = i & 7;
        lanes[lane] = lanes[lane].rotate_left(1) ^ u32::from(sample & 1);
    }

    let mut seed = [0u8; 32];
    for (i, lane) in lanes.into_iter().enumerate() {
        seed[i * 4..i * 4 + 4].copy_from_slice(&mix(lane).to_le_bytes());
    }
    ChaCha20Rng::from_seed(seed)
}

fn mix(mut value: u32) -> u32 {
    value = (value ^ (value >> 16)).wrapping_mul(0x7feb_352d);
    value = (value ^ (value >> 15)).wrapping_mul(0x846c_a68b);
    value ^ (value >> 16)
}
