//! `Sx1211Adapter` — bridges the blocking SX1211 driver + EXTI pins to the
//! device stack's async [`RfTransceiver`] trait.
//!
//! All the radio logic is ported from `stm32g0_knxrf_playground`: buffered-mode
//! reception (drain the FIFO two on-air bytes per `Fifo_threshold` assertion,
//! Manchester-decode, verify the block CRCs) and listen-before-talk transmission
//! (inter-frame gap, carrier sense with KNX-aware back-off, then key up and feed
//! the FIFO until Tx-done). The link layer drives `receive`/`transmit`; this
//! adapter only exposes CRC-stripped telegrams (`telegram[0]` = length).
//!
//! `receive` is **cancel-safe** as the trait requires: it stops the radio at
//! entry (cleaning up after a future dropped mid-drain) and re-arms RX each call.

use defmt::warn;
use embassy_futures::select::{Either, select};
use embassy_stm32::exti::ExtiInput;
use embassy_stm32::gpio::Input;
use embassy_time::{Duration, Instant, Timer};
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use knxrf::sx1211::regs::{LBT_EDGE_HIGH, LBT_EDGE_LOW, LBT_RSSI_THRESHOLD};
use knxrf::sx1211::{Sx1211, Sx1211Error};
use knxrf::{crc, frame, manchester::decode_pair};
use zweidraehte_device::layers::linklayers::knxrf::{RfRx, RfTransceiver};

// ---- Listen-before-talk / transmit tuning (mirrors the playground) ----------
const LBT_INTERFRAME_BASE_MS: u64 = 14;
const LBT_INTERFRAME_MOD_MS: u64 = 14;
const LBT_WINDOW_MS: u64 = 1;
const LBT_KNX_WAIT_MS: u64 = 20;
const LBT_BLOCK_WAIT_MS: u64 = 15;
const LBT_TIMEOUT_MS: u64 = 400;
const TX_FIFO_YIELD_US: u64 = 250;
const TX_DONE_TIMEOUT_MS: u64 = 500;

/// Carrier-sense verdict for a single listen window.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChannelStatus {
    Free,
    Knx,
    Blocked,
}

/// Errors surfaced from the radio to the link layer. Non-generic (the link
/// layer only needs `Debug`) so it does not leak `SPI::Error`.
#[derive(Debug, Clone, Copy)]
pub enum RadioError {
    /// An SPI / driver operation failed.
    Driver,
    /// The PLL did not lock before keying up.
    PllTimeout,
    /// The FIFO feed stalled or Tx-done never arrived.
    TxTimeout,
}

/// Async [`RfTransceiver`] over an SX1211 plus its EXTI status pins.
pub struct Sx1211Adapter<SPI, NCFG, NDATA> {
    radio: Sx1211<SPI, NCFG, NDATA>,
    pll_lock: ExtiInput<'static>,
    threshold: ExtiInput<'static>,
    irq0: ExtiInput<'static>,
    data: Input<'static>,
}

impl<SPI, NCFG, NDATA> Sx1211Adapter<SPI, NCFG, NDATA> {
    /// Wrap an already-initialised radio (`init` + `set_channel_ready` done by
    /// the caller) and its status pins.
    pub fn new(
        radio: Sx1211<SPI, NCFG, NDATA>,
        pll_lock: ExtiInput<'static>,
        threshold: ExtiInput<'static>,
        irq0: ExtiInput<'static>,
        data: Input<'static>,
    ) -> Self {
        Self { radio, pll_lock, threshold, irq0, data }
    }
}

impl<SPI, NCFG, NDATA> RfTransceiver for Sx1211Adapter<SPI, NCFG, NDATA>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    type Error = RadioError;

    async fn receive(&mut self, buf: &mut [u8]) -> Result<RfRx, RadioError> {
        // Clean up after a possible mid-drain cancellation, then re-arm until a
        // frame decodes (transient PLL / CRC failures just retry).
        let _ = self.radio.stop();
        loop {
            self.radio.enter_synth().map_err(driver_err)?;
            if !wait_pll_lock(&mut self.pll_lock).await {
                Timer::after(Duration::from_millis(5)).await;
                continue;
            }
            self.radio.start_rx().map_err(driver_err)?;

            // Buffered Rx fills the FIFO only after sync (IRQ0) — the cancellation
            // point while idle.
            self.irq0.wait_for_rising_edge().await;
            let rssi = self.radio.get_rssi().unwrap_or(0);

            let result = drain_frame(&mut self.radio, &mut self.threshold, buf).await;
            let _ = self.radio.stop();
            if let Some(len) = result {
                return Ok(RfRx { len, rssi });
            }
            // Undecodable frame — re-arm.
        }
    }

    async fn transmit(&mut self, telegram: &[u8]) -> Result<(), RadioError> {
        let _ = self.radio.stop();
        transmit(&mut self.radio, telegram, &mut self.pll_lock, &mut self.threshold, &self.data).await
    }
}

fn driver_err<E>(_e: Sx1211Error<E>) -> RadioError {
    RadioError::Driver
}

/// Wait (50 ms cap) for the SX1211 PLL-lock pin to go high.
async fn wait_pll_lock(pll_lock: &mut ExtiInput<'static>) -> bool {
    matches!(select(pll_lock.wait_for_high(), Timer::after(Duration::from_millis(50))).await, Either::First(_))
}

/// Drain one frame off the FIFO and return the CRC-stripped telegram length in
/// `out`, or `None` on truncation / decode / CRC failure.
async fn drain_frame<SPI, NCFG, NDATA>(
    radio: &mut Sx1211<SPI, NCFG, NDATA>,
    threshold: &mut ExtiInput<'static>,
    out: &mut [u8],
) -> Option<usize>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    let mut onair = [0u8; frame::MAX_ONAIR_LEN];

    // First source byte = length field; it fixes the exact on-air byte count.
    let (h0, l0) = read_fifo_pair(radio, threshold).await?;
    let len = match decode_pair(h0, l0) {
        Ok(b) if frame::is_valid_len(b) => b,
        _ => return None,
    };
    let total = frame::rx_onair_len(len);
    if total > onair.len() {
        return None;
    }
    onair[0] = len;
    for slot in onair.iter_mut().take(total).skip(1) {
        let (h, l) = read_fifo_pair(radio, threshold).await?;
        *slot = decode_pair(h, l).ok()?;
    }
    crc::verify_and_strip(&onair[..total], out).ok()
}

/// Read one Manchester source byte's worth of FIFO data (two on-air bytes) in
/// buffered mode. Checks the threshold level first to avoid deadlocking if the
/// FIFO already holds ≥ 2 bytes with no fresh edge pending; bails after a 20 ms
/// stall (end of frame / postamble).
async fn read_fifo_pair<SPI, NCFG, NDATA>(
    radio: &mut Sx1211<SPI, NCFG, NDATA>,
    threshold: &mut ExtiInput<'static>,
) -> Option<(u8, u8)>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    const PAIR_TIMEOUT: Duration = Duration::from_millis(20);

    if !threshold.is_high() {
        if let Either::Second(_) = select(threshold.wait_for_rising_edge(), Timer::after(PAIR_TIMEOUT)).await {
            return None;
        }
    }
    let high = radio.read_fifo().ok()?;
    let low = radio.read_fifo().ok()?;
    Some((high, low))
}

/// One listen-before-talk window: continuous-mode RX with the RSSI block on,
/// count demodulated DATA transitions for ~1 ms, then classify.
async fn measure_cca<SPI, NCFG, NDATA>(
    radio: &mut Sx1211<SPI, NCFG, NDATA>,
    pll_lock: &mut ExtiInput<'static>,
    data: &Input<'static>,
) -> Result<ChannelStatus, RadioError>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    radio.enter_synth().map_err(driver_err)?;
    if !wait_pll_lock(pll_lock).await {
        let _ = radio.stop();
        return Ok(ChannelStatus::Blocked);
    }
    radio.prepare_cca().map_err(driver_err)?;

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

    let rssi = radio.get_rssi().map_err(driver_err)?;
    radio.stop().map_err(driver_err)?;

    Ok(if (LBT_EDGE_LOW..LBT_EDGE_HIGH).contains(&edges) {
        ChannelStatus::Knx
    } else if rssi < LBT_RSSI_THRESHOLD {
        ChannelStatus::Free
    } else {
        ChannelStatus::Blocked
    })
}

/// Transmit `telegram` (`telegram[0]` = length) with listen-before-talk, then
/// key up and stream the on-air buffer through the FIFO until Tx-done.
async fn transmit<SPI, NCFG, NDATA>(
    radio: &mut Sx1211<SPI, NCFG, NDATA>,
    telegram: &[u8],
    pll_lock: &mut ExtiInput<'static>,
    threshold: &mut ExtiInput<'static>,
    data: &Input<'static>,
) -> Result<(), RadioError>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    let mut tx_buf = [0u8; frame::TX_BUF_CAP];
    let tx_len = frame::build_tx_buf(telegram, &mut tx_buf);

    // Inter-frame gap with a pseudo-random component (the 32 kHz tick counter is
    // free entropy — there is no PRNG in this no_std build).
    let jitter = Instant::now().as_ticks() % LBT_INTERFRAME_MOD_MS;
    Timer::after(Duration::from_millis(LBT_INTERFRAME_BASE_MS + jitter)).await;

    // Carrier-sense until free, deferring on KNX traffic / energy; force past the
    // deadline.
    let deadline = Instant::now() + Duration::from_millis(LBT_TIMEOUT_MS);
    loop {
        if Instant::now() >= deadline {
            warn!("KNX-RF LBT: channel never free, forcing transmit");
            break;
        }
        match measure_cca(radio, pll_lock, data).await? {
            ChannelStatus::Free => break,
            ChannelStatus::Knx => Timer::after(Duration::from_millis(LBT_KNX_WAIT_MS)).await,
            ChannelStatus::Blocked => Timer::after(Duration::from_millis(LBT_BLOCK_WAIT_MS)).await,
        }
    }

    // Restore the data-mode filters the CCA window narrowed, then settle the PLL.
    radio.set_channel_ready().map_err(driver_err)?;
    radio.enter_synth().map_err(driver_err)?;
    if !wait_pll_lock(pll_lock).await {
        let _ = radio.stop();
        return Err(RadioError::PllTimeout);
    }

    // Key up: arming starts transmitting the prime byte, so feed without delay.
    radio.arm_tx().map_err(driver_err)?;
    let feed_deadline = Instant::now() + Duration::from_millis(TX_DONE_TIMEOUT_MS);
    let mut pos = 0;
    while pos < tx_len {
        if Instant::now() >= feed_deadline {
            let _ = radio.stop();
            return Err(RadioError::TxTimeout);
        }
        pos += radio.write_fifo_chunk(&tx_buf[pos..]).map_err(driver_err)?;
        if pos < tx_len {
            Timer::after(Duration::from_micros(TX_FIFO_YIELD_US)).await;
        }
    }

    // Tx-done arrives on IRQ1 (same pin as the RX FIFO threshold).
    let done = select(threshold.wait_for_rising_edge(), Timer::after(Duration::from_millis(TX_DONE_TIMEOUT_MS))).await;
    let _ = radio.stop();
    match done {
        Either::First(_) => Ok(()),
        Either::Second(_) => Err(RadioError::TxTimeout),
    }
}
