#![no_std]
#![no_main]

//! SX1211 KNX-RF receive playground for the STM32G0B0RE.
//!
//! Brings up the SX1211 over SPI3, arms it for **buffered-mode** KNX-RF
//! reception, then drains each frame off the FIFO over SPI, Manchester-decodes
//! it, verifies the block CRCs and dumps the decoded telegram over defmt/RTT.
//! A push button on PC8 transmits a DPT 9.001 temperature telegram (starting at
//! 0 °C, +1 °C per press) using listen-before-talk, built on
//! `knxrf::frame::build_tx_buf` and the `arm_tx` / `prepare_cca` driver methods.
//!
//! Wiring (see also the crate README / plan):
//!   SPI3:  SCK=PC10, MISO=PC11, MOSI=PC12
//!   NSS_CONFIG=PD0, NSS_DATA=PD1  (outputs)
//!   PLL_LOCK=PD3, IRQ1=PD4, IRQ0=PD5, DATA=PD6  (inputs)
//!   BUTTON=PC8 (input, active-low to GND, internal pull-up)
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
use embassy_futures::select::{Either, Either3, select, select3};
use embassy_stm32::bind_interrupts;
use embassy_stm32::exti::{self, ExtiInput};
use embassy_stm32::gpio::{Input, Level, Output, Pull, Speed};
use embassy_stm32::spi::{Config as SpiConfig, Spi};
use embassy_stm32::time::Hertz;
use embassy_time::{Duration, Instant, Timer};
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use knxrf::crc;
use knxrf::frame;
use knxrf::manchester::decode_pair;
use knxrf::sx1211::regs::{LBT_EDGE_HIGH, LBT_EDGE_LOW, LBT_RSSI_THRESHOLD};
use knxrf::sx1211::{Sx1211, Sx1211Error};
use zweidraehte_proto::dpt::KnxFloat16;
use {defmt_rtt as _, panic_probe as _};

// EXTI line 3 (PD3) lives in the EXTI2_3 vector; lines 4/5 (PD4/PD5) in
// EXTI4_15. The same `Irqs` token is handed to every `ExtiInput::new`.
bind_interrupts!(struct Irqs {
    EXTI2_3 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI2_3>;
    EXTI4_15 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI4_15>;
});

// ---- Listen-before-talk / transmit tuning ---------------------------------
//
// Timings are in milliseconds; the edge-count band and RSSI threshold live in
// `knxrf::sx1211::regs`. The CCA window is kept at 1 ms so the edge thresholds
// (8..31) stay valid — they were calibrated against a ~1 ms poll cadence, and
// widening the window would require scaling the band.

/// Inter-frame gap floor before the first carrier-sense (KNX §6.6.1 `Tint`).
const LBT_INTERFRAME_BASE_MS: u64 = 14;
/// Random span added to the inter-frame gap, giving 14..27 ms.
const LBT_INTERFRAME_MOD_MS: u64 = 14;
/// Carrier-sense listen window (~1 ms poll cadence).
const LBT_WINDOW_MS: u64 = 1;
/// Back-off while another KNX frame finishes before re-sensing.
const LBT_KNX_WAIT_MS: u64 = 20;
/// Back-off on non-KNX interference before re-sensing.
const LBT_BLOCK_WAIT_MS: u64 = 15;
/// Overall LBT deadline; past it we force-transmit (watchdog).
const LBT_TIMEOUT_MS: u64 = 400;
/// Yield (~one on-air byte period) when the TX FIFO is full during the feed.
const TX_FIFO_YIELD_US: u64 = 250;
/// Maximum wait for the FIFO feed and Tx-done to complete.
const TX_DONE_TIMEOUT_MS: u64 = 500;

/// Base telegram for the button-triggered send: a KNX-RF GroupValueWrite
/// carrying a DPT 9.001 temperature. `[0]` is the length field (0x13 = 19); the
/// two bytes at [`TEMP_VALUE_OFFSET`] are the KNX 2-byte float and are
/// overwritten with the current temperature before each transmit (the `0x0CC4`
/// here, 24.4 °C, is just a placeholder).
const TEMP_TELEGRAM: [u8; 20] = [
    0x13, 0x44, 0xff, 0x02, 0x00, 0xfa, 0xb6, 0xab, 0xb2, 0x86, 0x00, 0x12, 0x01, 0x01, 0x00, 0xe3,
    0x00, 0x80, 0x0c, 0xc4,
];
/// Byte offset of the 2-byte DPT 9.001 temperature value within
/// [`TEMP_TELEGRAM`].
const TEMP_VALUE_OFFSET: usize = 18;
/// Byte offset of the KNX-RF info octet within [`TEMP_TELEGRAM`]; bits [3:1]
/// hold the LFN (Last Frame Number), which is incremented mod 8 per new frame
/// so the receiver does not suppress consecutive frames as duplicates (KNX
/// 03/02/05 §6.1.4.3).
const RF_INFO_OFFSET: usize = 15;
/// Mask of the LFN field within the RF info octet.
const RF_INFO_LFN_MASK: u8 = 0x0E;

/// Carrier-sense verdict for a single listen window.
#[derive(Clone, Copy, PartialEq, Eq, Format)]
enum ChannelStatus {
    /// No KNX-rate activity and RSSI below threshold — clear to transmit.
    Free,
    /// Edge count in the KNX Manchester band — another KNX device is sending.
    Knx,
    /// Energy above the RSSI threshold but not KNX-shaped — generic interference.
    Blocked,
}

/// Why a [`transmit`] attempt failed.
#[derive(Format)]
enum TxError<E> {
    /// A driver / SPI operation failed.
    Driver(Sx1211Error<E>),
    /// The PLL did not lock before keying up.
    PllTimeout,
    /// The FIFO feed stalled or Tx-done never arrived.
    TxTimeout,
}

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
    // DATA carries the demodulated chips in continuous mode (counted for the
    // carrier-sense window); unused in buffered RX, where the datasheet asks
    // for a pull-up.
    let data = Input::new(p.PD6, Pull::Up);

    // Push button on PC8 (EXTI8, in the EXTI4_15 group). Active-low: wired to
    // GND, held high by the internal pull-up, so a press is a falling edge.
    let mut button = ExtiInput::new(p.PC8, p.EXTI8, Pull::Up, Irqs);

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
    info!("SX1211 initialised — listening on 868.300 MHz, PC8 transmits temp");

    let mut dumped = false;
    // Working copy of the temperature telegram and the next value to send. The
    // temperature starts at 0 °C and steps up by 1 °C on each button press. The
    // LFN cycles 0..7 per frame so the coupler does not drop rapid presses as
    // duplicate retransmissions.
    let mut telegram = TEMP_TELEGRAM;
    let mut temp_c: i32 = 0;
    let mut lfn: u8 = 0;

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

        // Wait for a button press (transmit) or sync-word detection (receive),
        // re-arming after a few quiet seconds. Until sync the FIFO stays empty
        // (Fifo_fill_method = 0), so the sync edge is also when it begins
        // filling.
        match select3(
            button.wait_for_falling_edge(),
            irq0.wait_for_rising_edge(),
            Timer::after(Duration::from_secs(5)),
        )
        .await
        {
            Either3::First(_) => {
                // Button pressed: leave RX and transmit the current temperature.
                let _ = radio.stop();
                let bytes = KnxFloat16::from_f32(temp_c as f32).to_bytes();
                telegram[TEMP_VALUE_OFFSET] = bytes[0];
                telegram[TEMP_VALUE_OFFSET + 1] = bytes[1];
                // Advance the LFN (mod 8) so consecutive frames aren't dropped
                // as duplicate retransmissions.
                lfn = (lfn + 1) & 0x07;
                telegram[RF_INFO_OFFSET] =
                    (telegram[RF_INFO_OFFSET] & !RF_INFO_LFN_MASK) | (lfn << 1);
                info!("button: transmitting {=i32} C (DPT 9.001, lfn={=u8})", temp_c, lfn);
                match transmit(&mut radio, &telegram, &mut pll_lock, &mut threshold, &data).await {
                    Ok(()) => {
                        info!("TX ok ({=i32} C)", temp_c);
                        temp_c += 1;
                    }
                    Err(e) => warn!("TX failed: {}", e),
                }
                Timer::after(Duration::from_millis(50)).await; // debounce
                continue;
            }
            Either3::Third(_) => {
                // Quiet band — re-arm RX.
                let _ = radio.stop();
                continue;
            }
            // Sync detected — fall through to read and decode the frame below.
            Either3::Second(_) => {}
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

/// Measure the channel for one listen-before-talk window: continuous-mode RX
/// with the RSSI block on, count demodulated DATA transitions for
/// [`LBT_WINDOW_MS`], read RSSI, and classify: an edge count in the
/// `[LBT_EDGE_LOW, LBT_EDGE_HIGH)` band means another KNX device is
/// transmitting; otherwise the RSSI decides free vs. blocked.
async fn measure_cca<SPI, NCFG, NDATA>(
    radio: &mut Sx1211<SPI, NCFG, NDATA>,
    pll_lock: &mut ExtiInput<'static>,
    data: &Input<'static>,
) -> Result<ChannelStatus, Sx1211Error<SPI::Error>>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    radio.enter_synth()?;
    if !wait_pll_lock(pll_lock).await {
        // PLL didn't settle; report blocked so the caller backs off and retries.
        let _ = radio.stop();
        return Ok(ChannelStatus::Blocked);
    }
    radio.prepare_cca()?;

    // Count demodulated transitions with a tight sample loop — the executor is
    // blocked for the ~1 ms window while edge-counting.
    // A plain level read catches every transition without EXTI re-arm races.
    let mut edges: u32 = 0;
    let mut prev = data.is_high();
    let end = Instant::now() + Duration::from_millis(LBT_WINDOW_MS);
    while Instant::now() < end {
        let cur = data.is_high();
        if cur != prev {
            edges += 1;
            prev = cur;
        }
    }

    let rssi = radio.get_rssi()?;
    radio.stop()?;

    Ok(if (LBT_EDGE_LOW..LBT_EDGE_HIGH).contains(&edges) {
        ChannelStatus::Knx
    } else if rssi < LBT_RSSI_THRESHOLD {
        ChannelStatus::Free
    } else {
        ChannelStatus::Blocked
    })
}

/// Transmit `telegram` (`telegram[0]` is the length field) with
/// listen-before-talk: an
/// inter-frame random delay, carrier sense with KNX-aware back-off and a
/// force-transmit deadline, then key up and stream the on-air buffer through the
/// FIFO until Tx-done.
async fn transmit<SPI, NCFG, NDATA>(
    radio: &mut Sx1211<SPI, NCFG, NDATA>,
    telegram: &[u8],
    pll_lock: &mut ExtiInput<'static>,
    threshold: &mut ExtiInput<'static>,
    data: &Input<'static>,
) -> Result<(), TxError<SPI::Error>>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    // Assemble the full on-air frame once: preamble + sync + CRC-blocked
    // Manchester telegram + postamble.
    let mut tx_buf = [0u8; frame::TX_BUF_CAP];
    let tx_len = frame::build_tx_buf(telegram, &mut tx_buf);

    // Inter-frame gap with a pseudo-random component (the 32 kHz tick counter is
    // free entropy — there is no PRNG in this no_std build).
    let jitter = Instant::now().as_ticks() % LBT_INTERFRAME_MOD_MS;
    Timer::after(Duration::from_millis(LBT_INTERFRAME_BASE_MS + jitter)).await;

    // Listen-before-talk: sense until the channel is free, deferring on KNX
    // traffic and other energy; force-transmit only past the deadline.
    let deadline = Instant::now() + Duration::from_millis(LBT_TIMEOUT_MS);
    loop {
        if Instant::now() >= deadline {
            warn!("LBT: channel never free, forcing transmit");
            break;
        }
        match measure_cca(radio, pll_lock, data).await.map_err(TxError::Driver)? {
            ChannelStatus::Free => break,
            ChannelStatus::Knx => Timer::after(Duration::from_millis(LBT_KNX_WAIT_MS)).await,
            ChannelStatus::Blocked => Timer::after(Duration::from_millis(LBT_BLOCK_WAIT_MS)).await,
        }
    }

    // Restore the data-mode filters the CCA window narrowed, then settle the PLL.
    radio.set_channel_ready().map_err(TxError::Driver)?;
    radio.enter_synth().map_err(TxError::Driver)?;
    if !wait_pll_lock(pll_lock).await {
        let _ = radio.stop();
        return Err(TxError::PllTimeout);
    }

    // Key up: arming starts transmitting the prime byte, so feed without delay.
    radio.arm_tx().map_err(TxError::Driver)?;
    let feed_deadline = Instant::now() + Duration::from_millis(TX_DONE_TIMEOUT_MS);
    let mut pos = 0;
    while pos < tx_len {
        if Instant::now() >= feed_deadline {
            let _ = radio.stop();
            return Err(TxError::TxTimeout);
        }
        pos += radio.write_fifo_chunk(&tx_buf[pos..]).map_err(TxError::Driver)?;
        if pos < tx_len {
            Timer::after(Duration::from_micros(TX_FIFO_YIELD_US)).await;
        }
    }

    // Tx-done arrives on the IRQ1 pin (same pin as the RX FIFO threshold).
    let done = select(
        threshold.wait_for_rising_edge(),
        Timer::after(Duration::from_millis(TX_DONE_TIMEOUT_MS)),
    )
    .await;
    let _ = radio.stop();
    match done {
        Either::First(_) => Ok(()),
        Either::Second(_) => Err(TxError::TxTimeout),
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
