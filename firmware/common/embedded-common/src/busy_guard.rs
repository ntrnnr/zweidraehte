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
///
/// `Copy` (both fields are `Copy`) so the raised [`BusyGuard`] can own a copy of
/// the gate rather than borrow it — which lets `BusyGate` satisfy the storage
/// layer's [`SaveGuard`](zweidraehte_device::storage::SaveGuard) trait (whose
/// associated guard type can't name a `&self` borrow without GATs).
#[derive(Clone, Copy)]
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
    pub async fn acquire(&self) -> BusyGuard {
        self.flag.store(true, Ordering::Release);
        if let Some(sender) = self.chip_busy {
            ActorRequest::<CriticalSectionRawMutex, _, _>::request(&sender, ChipBusyRequest::Activate).await;
        }
        BusyGuard { gate: *self }
    }
}

/// Raised busy gate; call [`release()`](Self::release) after the save. Owns a
/// copy of the [`BusyGate`] (it is `Copy`), so it carries no borrow.
#[must_use = "the gate stays up (device answers BUSY) until release() is called"]
pub struct BusyGuard {
    gate: BusyGate,
}

impl BusyGuard {
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

// ----------------------------------------------------------------------------
// SaveGuard wiring — let the storage task raise this gate around each save
// ----------------------------------------------------------------------------

impl zweidraehte_device::storage::SaveGuard for BusyGate {
    type Guard = BusyGuard;
    async fn acquire(&self) -> Self::Guard {
        BusyGate::acquire(self).await
    }
}

impl zweidraehte_device::storage::SaveGuardToken for BusyGuard {
    async fn release(self) {
        BusyGuard::release(self).await
    }
}

/// Emit the busy-gate statics + constructor every TP1 device wires identically:
/// the `BUSY_FLAG` software flag, the `CHIP_BUSY` rendezvous channel, and a
/// `busy_gate()` building the [`BusyGate`] over them.
///
/// Invoke once at module level; the emitted `BUSY_FLAG` / `CHIP_BUSY` statics
/// stay nameable at the call site for the link-layer wiring:
///
/// ```ignore
/// embedded_common::tp1_busy_gate!();
/// // …
/// TpUartLinkLayerBuilder::new(tx, rx)
///     .with_busy_flag(&BUSY_FLAG)
///     .with_chip_busy_channel(CHIP_BUSY.dyn_receiver());
/// // …
/// zweidraehte_device::storage_task! {
///     device: PicoTp1LightSwitch,
///     system: embedded_common::CortexMSystem,
///     guard: busy_gate(),
/// }
/// ```
#[macro_export]
macro_rules! tp1_busy_gate {
    () => {
        static BUSY_FLAG: ::core::sync::atomic::AtomicBool = ::core::sync::atomic::AtomicBool::new(false);
        static CHIP_BUSY: ::embassy_sync::channel::Channel<
            ::embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            ::zweidraehte_device::actor::Request<
                ::zweidraehte_device::layers::linklayers::tpuart::busy::ChipBusyRequest,
                (),
            >,
            1,
        > = ::embassy_sync::channel::Channel::new();

        /// Build the [`BusyGate`](embedded_common::BusyGate) the storage task
        /// raises around each flash save: the software busy flag turns ACKs into
        /// BUSY acknowledges, and the rendezvous channel arms the transceiver's
        /// autonomous busy mode before the executor stalls.
        fn busy_gate() -> $crate::BusyGate {
            $crate::BusyGate { flag: &BUSY_FLAG, chip_busy: Some(CHIP_BUSY.dyn_sender()) }
        }
    };
}
