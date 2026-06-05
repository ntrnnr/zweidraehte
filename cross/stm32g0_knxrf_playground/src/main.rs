#![no_std]
#![no_main]

//! SX1211 KNX-RF receive playground for the STM32G0B0RE.
//!
//! Brings up the SX1211 over SPI3, arms it for **buffered-mode** KNX-RF
//! reception, then drains each frame off the FIFO over SPI, Manchester-decodes
//! it, verifies the block CRCs and dumps the decoded telegram over defmt/RTT.
//! Transmit is not wired yet (the codec for it lives in
//! `knxrf::frame::prepare_tx_buf`).
//!
//! Wiring (see also the crate README / plan):
//!   SPI3:  SCK=PC10, MISO=PC11, MOSI=PC12
//!   NSS_CONFIG=PD0, NSS_DATA=PD1  (outputs)
//!   PLL_LOCK=PD3, IRQ1=PD4, IRQ0=PD5, DATA=PD6  (inputs)
//!
//! # Why buffered mode (and the exact FIFO cadence)
//!
//! In buffered Rx the SX1211 starts pushing received bytes into the FIFO only
//! once the sync word is detected (`Fifo_fill_method = 0`). With `Fifo_thresh`
//! = 1 (see `DEFAULT_CONFIG[5] = 0xC1`), the Fifo_threshold IRQ source on the
//! IRQ_1 pin (PD4) goes high whenever the FIFO holds **≥ 2** bytes. We read
//! exactly two FIFO bytes per assertion and Manchester-decode them into one
//! source byte — the high nibble from the first byte, the low from the second.
//! Reading in committed 2-byte groups is what keeps the Manchester stream
//! byte-aligned; the earlier continuous-mode DATA/DCLK sampler could not
//! recover that alignment reliably.
//!
//! IRQ0 (PD5) carries Sync in buffered Rx and signals frame start. The DATA
//! pin (PD6) is unused in buffered mode and is pulled up per the datasheet.

use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_stm32::bind_interrupts;
use embassy_stm32::exti::{self, ExtiInput};
use embassy_stm32::gpio::{Input, Level, Output, Pull, Speed};
use embassy_stm32::spi::{Config as SpiConfig, Spi};
use embassy_stm32::time::Hertz;
use embassy_time::{Duration, Timer};
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use knxrf::crc;
use knxrf::frame;
use knxrf::manchester::decode_pair;
use knxrf::sx1211::Sx1211;
use {defmt_rtt as _, panic_probe as _};

// EXTI line 3 (PD3) lives in the EXTI2_3 vector; lines 4/5 (PD4/PD5) in
// EXTI4_15. The same `Irqs` token is handed to every `ExtiInput::new`.
bind_interrupts!(struct Irqs {
    EXTI2_3 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI2_3>;
    EXTI4_15 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI4_15>;
});

/// Wait (with a 50 ms cap) for the SX1211 PLL-lock pin to go high.
async fn wait_pll_lock(pll_lock: &mut ExtiInput<'static>) -> bool {
    matches!(
        select(pll_lock.wait_for_high(), Timer::after(Duration::from_millis(50))).await,
        Either::First(_)
    )
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_stm32::init(Default::default());
    info!("SX1211 KNX-RF playground starting");

    // SPI3 in blocking mode. The SX1211 config interface is SPI mode 0
    // (CPOL=0, CPHA=0), which is `SpiConfig::default()`.
    //
    // Clock at 1 MHz: the SX1211 datasheet rates the **Data** (FIFO) SPI
    // interface (`SCK_DATA`) at a 1 MHz maximum, even though the **Config**
    // (register) interface (`SCK_CONFIG`) allows 6 MHz. We share one bus for
    // both, so the slower of the two limits applies. Running the FIFO reads at
    // 4 MHz violated `SCK_DATA`/`T_DATA` and corrupted every byte (the first
    // chip got double-clocked, one chip lost per byte); register access happened
    // to tolerate it because of its higher limit, which is why init verified
    // cleanly while reception decoded to noise.
    let mut spi_cfg = SpiConfig::default();
    spi_cfg.frequency = Hertz(1_000_000);
    let spi = Spi::new_blocking(p.SPI3, p.PC10, p.PC12, p.PC11, spi_cfg);

    // Both chip-selects idle high.
    let nss_cfg = Output::new(p.PD0, Level::High, Speed::VeryHigh);
    let nss_data = Output::new(p.PD1, Level::High, Speed::VeryHigh);

    // The SX1211 drives these lines; no internal pull needed.
    let mut pll_lock = ExtiInput::new(p.PD3, p.EXTI3, Pull::None, Irqs);
    // IRQ_1 pin: Fifo_threshold in buffered Rx (DCLK only in continuous mode).
    let mut threshold = ExtiInput::new(p.PD4, p.EXTI4, Pull::None, Irqs);
    let mut irq0 = ExtiInput::new(p.PD5, p.EXTI5, Pull::None, Irqs); // sync detected
    // DATA is unused in buffered mode; the datasheet asks for a pull-up.
    let _data = Input::new(p.PD6, Pull::Up);

    let mut radio = Sx1211::new(spi, nss_cfg, nss_data);

    // First light: writing + verifying the default register image confirms the
    // SPI wiring and chip-select polarity.
    if let Err(e) = radio.init() {
        error!("SX1211 init failed (check SPI wiring): {}", e);
        halt().await;
    }
    if let Err(e) = radio.set_channel_ready() {
        error!("SX1211 channel setup failed: {}", e);
        halt().await;
    }
    info!("SX1211 initialised — listening on 868.300 MHz");

    let mut dumped = false;

    loop {
        // Let the synthesizer settle, then arm the receiver in buffered mode.
        if let Err(e) = radio.enter_synth() {
            warn!("enter_synth: {}", e);
            Timer::after(Duration::from_millis(100)).await;
            continue;
        }
        if !wait_pll_lock(&mut pll_lock).await {
            warn!("PLL lock timeout");
            continue;
        }
        if let Err(e) = radio.start_rx() {
            warn!("start_rx: {}", e);
            Timer::after(Duration::from_millis(100)).await;
            continue;
        }

        // One-shot dump of the live register file (in RX configuration) so we
        // can confirm the chip's actual config matches the intended values.
        if !dumped {
            let mut regs = [0u8; 0x20];
            for (r, slot) in regs.iter_mut().enumerate() {
                *slot = radio.read_reg(r as u8).unwrap_or(0xEE);
            }
            info!("REGS 0x00-0x1F: {=[u8]:02x}", &regs[..]);
            dumped = true;
        }

        // Wait for sync-word detection (IRQ0). Until sync, the FIFO stays empty
        // (Fifo_fill_method = 0), so this is also when the FIFO begins filling.
        // Re-arm if the band stays quiet.
        if let Either::Second(_) =
            select(irq0.wait_for_rising_edge(), Timer::after(Duration::from_secs(5))).await
        {
            let _ = radio.stop();
            continue;
        }
        let rssi = radio.get_rssi().unwrap_or(0);

        // Read the frame off the FIFO, two bytes (one Manchester source byte)
        // per Fifo_threshold assertion. The first source byte is the length
        // field; from it we know the exact number of remaining source bytes
        // (telegram + interspersed block CRCs). On any decode/CRC failure we
        // fall back to dumping the raw FIFO bytes for analysis.
        let mut onair = [0u8; frame::MAX_ONAIR_LEN];
        let mut raw = [0u8; frame::MAX_ONAIR_LEN * 2];

        let (h0, l0) = match read_fifo_pair(&mut radio, &mut threshold).await {
            Some((p, _)) => p,
            None => {
                let _ = radio.stop();
                continue;
            }
        };
        raw[0] = h0;
        raw[1] = l0;
        let mut nraw = 2usize;

        let mut ok = true;
        let len = match decode_pair(h0, l0) {
            Ok(b) if frame::is_valid_len(b) => b,
            _ => {
                ok = false;
                0
            }
        };

        let total = if ok { frame::rx_onair_len(len) } else { 0 };
        if ok {
            onair[0] = len;
            for slot in onair.iter_mut().take(total).skip(1) {
                let (h, l) = match read_fifo_pair(&mut radio, &mut threshold).await {
                    Some((p, _)) => p,
                    None => {
                        ok = false;
                        break;
                    }
                };
                if nraw + 1 < raw.len() {
                    raw[nraw] = h;
                    raw[nraw + 1] = l;
                    nraw += 2;
                }
                match decode_pair(h, l) {
                    Ok(b) => *slot = b,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
        }
        let _ = radio.stop();

        if ok {
            let mut out = [0u8; 96];
            match crc::verify_and_strip(&onair[..total], &mut out) {
                Ok(n) => info!(
                    "KNX-RF frame (rssi={=u8}, {=usize} bytes): {=[u8]:02x}",
                    rssi,
                    n,
                    &out[..n]
                ),
                Err(_) => warn!(
                    "block CRC fail (rssi={=u8}, len={=u8}); onair {=[u8]:02x}",
                    rssi,
                    len,
                    &onair[..total]
                ),
            }
        } else {
            warn!(
                "decode failed (rssi={=u8}); raw FIFO {=[u8]:02x}",
                rssi,
                &raw[..nraw]
            );
        }
    }
}

/// Read one Manchester source byte's worth of FIFO data in buffered mode: the
/// two on-air bytes the SX1211 buffered for it.
///
/// With `Fifo_thresh` = 1 the Fifo_threshold line (PD4 / IRQ_1) is high
/// whenever the FIFO holds ≥ 2 bytes and stays high while it does. So we check
/// the level first and only await a fresh rising edge when the FIFO has drained
/// below the threshold — otherwise, if we ever fell a pair behind, the line
/// would already be high with no further edge coming and we would deadlock.
///
/// Returns `Some((pair, did_wait))` where `did_wait` is true if we had to block
/// on a fresh threshold edge (the FIFO had drained below the threshold), or
/// `None` if no pair arrives within the timeout (a truncated frame or the end
/// of the postamble), which the caller treats as end-of-reception.
async fn read_fifo_pair<SPI, NCFG, NDATA>(
    radio: &mut Sx1211<SPI, NCFG, NDATA>,
    threshold: &mut ExtiInput<'static>,
) -> Option<((u8, u8), bool)>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    // One source byte is ~486 µs on air; 20 ms tolerates a long stall while
    // still bailing out promptly once a frame (plus its postamble) has passed.
    const PAIR_TIMEOUT: Duration = Duration::from_millis(20);

    let mut did_wait = false;
    if !threshold.is_high() {
        did_wait = true;
        if let Either::Second(_) =
            select(threshold.wait_for_rising_edge(), Timer::after(PAIR_TIMEOUT)).await
        {
            return None;
        }
    }
    let high = radio.read_fifo().ok()?;
    let low = radio.read_fifo().ok()?;
    Some(((high, low), did_wait))
}

/// Park forever after an unrecoverable init error, keeping the executor alive.
async fn halt() -> ! {
    loop {
        Timer::after(Duration::from_secs(60)).await;
    }
}
