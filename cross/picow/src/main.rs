#![no_std]
#![no_main]

use cyw43_pio::PioSpi;
use defmt::*;
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{self, Pio};
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => pio::InterruptHandler<PIO0>;
});

#[embassy_executor::task]
async fn cyw43_task(
    runner: cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO0, 0, DMA_CH0>>,
) -> ! {
    runner.run().await
}

// ================================================================================
// Firmware blobs
// ================================================================================

// The CYW43439 WiFi chip requires firmware to be loaded at init time.
// These blobs come from the embassy cyw43-firmware directory, originally
// sourced from https://github.com/georgerobotics/cyw43-driver.
// Licensed under the Infineon Permissive Binary License.

// Ensure 4-byte alignment for DMA transfers.
#[repr(C, align(4))]
struct Aligned<const N: usize>([u8; N]);

static FW: Aligned<{ include_bytes!("../firmware/43439A0.bin").len() }> =
    Aligned(*include_bytes!("../firmware/43439A0.bin"));

static CLM: Aligned<{ include_bytes!("../firmware/43439A0_clm.bin").len() }> =
    Aligned(*include_bytes!("../firmware/43439A0_clm.bin"));

// ================================================================================
// Entry point
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    info!("Pico W initializing");

    // The Pico W onboard LED is controlled via the CYW43 WiFi chip
    // (not a direct GPIO), so we must initialize the WiFi driver even
    // just to blink the LED.
    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        cyw43_pio::DEFAULT_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        p.DMA_CH0,
    );

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (_net_device, mut control, runner) = cyw43::new(state, pwr, spi, &FW.0).await;

    spawner
        .spawn(cyw43_task(runner))
        .expect("cyw43_task spawnable once");

    control.init(&CLM.0).await;
    control
        .set_power_management(cyw43::PowerManagementMode::PowerSave)
        .await;

    info!("Pico W initialized, blinking LED");

    loop {
        control.gpio_set(0, true).await;
        Timer::after(Duration::from_millis(500)).await;
        control.gpio_set(0, false).await;
        Timer::after(Duration::from_millis(500)).await;
    }
}
