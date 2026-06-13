//! Busy gating for persistence: software BUSY acknowledges and the
//! chip-autonomous busy-mode rendezvous.
//!
//! TP1 demands an acknowledge ~1.7 ms after a frame ends, but a flash
//! erase/write takes tens of milliseconds — and on some platforms
//! (RP2040 with XIP disabled, single-bank STM32 flash) it stalls the
//! whole executor, so no Rust code runs at all while the storage
//! backend writes. Following the classic System-B reference behaviour,
//! the device answers addressed frames with a BUSY acknowledge for the
//! duration; the sender's link layer retries (`busy_retry_count`, PID
//! 52) until the device acknowledges normally again. Two cooperating
//! mechanisms implement this:
//!
//! 1. **Software busy flag** ([`TpUartLinkLayerBuilder::with_busy_flag`](super::TpUartLinkLayerBuilder::with_busy_flag)):
//!    a shared `AtomicBool` the storage task sets around a save. The
//!    TPUART task checks it at the ACK decision point and answers
//!    `U_BUSY_INF` instead of `U_ACK_INF`. This covers saves performed
//!    while the executor still schedules the link-layer task.
//! 2. **Chip busy mode** ([`ChipBusyRequest`]): before a save that
//!    stalls the executor, the storage task round-trips through the
//!    TPUART task to put the transceiver itself into busy mode
//!    ([`ChipType::busy_mode_commands`](super::chip::ChipType::busy_mode_commands)).
//!    The chip then answers BUSY autonomously while no code runs;
//!    afterwards a second round-trip leaves busy mode.
//!
//! The rendezvous sequence in the storage task (see `BusyGuard` in the
//! cross-target glue):
//!
//! ```text
//! flag.store(true)                          // software gate up
//! chip_busy.request(Activate).await         // chip armed, TPUART task confirmed
//! storage.save(...)                         // executor may fully stall
//! chip_busy.request(Deactivate).await       // chip back to normal
//! flag.store(false)
//! ```
//!
//! The `Activate` reply is the storage task's guarantee that the
//! command byte left for the chip *before* the stall begins.

/// Request from the storage task to the TPUART task to enter or leave
/// the transceiver's autonomous busy mode.
///
/// Sent as an [`actor::Request<ChipBusyRequest, ()>`](crate::actor::Request)
/// — the reply confirms the UART command was written. Wire the channel
/// with [`TpUartLinkLayerBuilder::with_chip_busy_channel`](super::TpUartLinkLayerBuilder::with_chip_busy_channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChipBusyRequest {
    /// Send the chip's activate-busy-mode command. The reply means the
    /// byte was handed to the UART — safe to stall the executor.
    Activate,
    /// Send the chip's reset-busy-mode command, resuming normal
    /// acknowledges.
    Deactivate,
}
