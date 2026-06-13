//! Busy gating around storage saves on TP1 devices.
//!
//! A flash erase/write takes tens of milliseconds and on our embedded
//! targets stalls the entire executor (RP2040 disables XIP; single-bank
//! STM32 flash stalls any flash fetch), so the TPUART task cannot meet
//! the ~1.7 ms TP1 acknowledge window during a save. [`BusyGate`]
//! coordinates the two protections offered by the link layer (see
//! `zweidraehte_device::layers::linklayers::tpuart::busy`):
//!
//! - the software busy flag, turning ACKs into BUSY acknowledges while
//!   the link-layer task still runs, and
//! - the chip busy-mode rendezvous, arming the transceiver's autonomous
//!   BUSY responses before the executor stalls.
//!
//! ```ignore
//! static BUSY_FLAG: AtomicBool = AtomicBool::new(false);
//!
//! let gate = BusyGate { flag: &BUSY_FLAG, chip_busy: Some(chip_busy_sender) };
//! let guard = gate.acquire().await;   // gate up, chip armed
//! save_state(state, storage);         // executor may fully stall here
//! guard.release().await;              // chip disarmed, gate down
//! ```
//!
//! `release()` is explicit (there is no async `Drop`); dropping the
//! guard without releasing leaves the device answering BUSY forever.

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::DynamicSender;
use zweidraehte_device::actor::{ActorRequest, Request};
use zweidraehte_device::layers::linklayers::tpuart::busy::ChipBusyRequest;

/// The storage task's handle on the link layer's busy protections.
pub struct BusyGate {
    /// Software busy flag shared with the TPUART link layer
    /// (`TpUartLinkLayerBuilder::with_busy_flag`).
    pub flag: &'static AtomicBool,
    /// Chip busy-mode rendezvous towards the TPUART task
    /// (`TpUartLinkLayerBuilder::with_chip_busy_channel`). `None` on
    /// devices whose saves do not stall the executor.
    pub chip_busy: Option<DynamicSender<'static, Request<ChipBusyRequest, ()>>>,
}

impl BusyGate {
    /// Raise the busy gate: set the software flag, then arm the chip's
    /// autonomous busy mode and wait for the TPUART task to confirm the
    /// command reached the UART. After this returns it is safe to stall
    /// the executor with a blocking flash operation.
    pub async fn acquire(&self) -> BusyGuard<'_> {
        self.flag.store(true, Ordering::Release);
        if let Some(sender) = self.chip_busy {
            ActorRequest::<CriticalSectionRawMutex, _, _>::request(&sender, ChipBusyRequest::Activate).await;
        }
        BusyGuard { gate: self }
    }
}

/// Raised busy gate; call [`release()`](Self::release) after the save.
#[must_use = "the gate stays up (device answers BUSY) until release() is called"]
pub struct BusyGuard<'a> {
    gate: &'a BusyGate,
}

impl BusyGuard<'_> {
    /// Lower the busy gate: disarm the chip's busy mode, then clear the
    /// software flag. Order matters — the flag drops last so every
    /// frame until full normality still gets a BUSY instead of silence.
    pub async fn release(self) {
        if let Some(sender) = self.gate.chip_busy {
            ActorRequest::<CriticalSectionRawMutex, _, _>::request(&sender, ChipBusyRequest::Deactivate).await;
        }
        self.gate.flag.store(false, Ordering::Release);
    }
}
