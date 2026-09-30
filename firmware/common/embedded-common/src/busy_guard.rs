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
//! // Gate up and chip armed around the save; the executor may fully stall
//! // inside the closure.
//! gate.guarded(|| save_state(state, storage)).await;
//! ```
//!
//! The work runs as a closure because there is no async `Drop`: taking it
//! lets the gate lower itself on the one path out, where a guard value the
//! caller had to release could be dropped and leave the device answering
//! BUSY forever.

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::DynamicSender;
use zweidraehte_device::actor::{ActorRequest, Request};
use zweidraehte_device::layers::linklayers::tpuart::busy::ChipBusyRequest;
use zweidraehte_device::storage::SaveGuard;

/// The storage task's handle on the link layer's busy protections.
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

impl SaveGuard for BusyGate {
    async fn guarded<R>(&self, work: impl FnOnce() -> R) -> R {
        // Raise: set the software flag, then arm the chip's autonomous busy
        // mode and wait for the TPUART task to confirm the command reached
        // the UART. After that it is safe to stall the executor.
        self.flag.store(true, Ordering::Release);
        if let Some(sender) = self.chip_busy {
            ActorRequest::<CriticalSectionRawMutex, _, _>::request(&sender, ChipBusyRequest::Activate).await;
        }

        let result = work();

        // Lower: disarm the chip's busy mode, then clear the software flag.
        // Order matters — the flag drops last so every frame until full
        // normality still gets a BUSY instead of silence.
        if let Some(sender) = self.chip_busy {
            ActorRequest::<CriticalSectionRawMutex, _, _>::request(&sender, ChipBusyRequest::Deactivate).await;
        }
        self.flag.store(false, Ordering::Release);

        result
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
