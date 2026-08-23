//! Bridges the zweidraehte-client library onto a conformance DUT.
//!
//! The client speaks cEMI through its [`KnxConnector`] trait; the DUT
//! child speaks the postcard IPC protocol carrying TP1-like frames
//! (no checksum). This module owns the [`ChildLifecycle`] in a pump
//! task and exposes both sides:
//!
//! - [`DutConnector`] — a `KnxConnector` the client's `KnxBus` runs
//!   on. `send_cemi` becomes an `Inject` step; every frame the DUT
//!   emits (step replies and unsolicited retransmits alike) comes
//!   back as an `L_Data.ind`. Like a real bus interface, the bridge
//!   answers each accepted `L_Data.req` with a positive `L_Data.con`
//!   echo — the client's TL state machine feeds on those.
//! - [`DutControl`] — the out-of-band levers a scenario needs that
//!   have no bus-side form: programming mode, factory reset, and the
//!   DUT-initiated group triggers.
//!
//! One pump task serializes everything: the IPC protocol is strictly
//! request/response, and a single owner is what makes the
//! "inject → captured frames" attribution reliable. Unsolicited
//! frames (DUT-side TL retransmits) are picked up whenever the pump
//! is idle for ~20 ms — far inside the client's spec-level timeouts.
//!
//! It is an ordinary tokio task: [`ChildLifecycle`] is runtime-
//! agnostic (async-io reactor, no executor coupling), so the pump and
//! the client share one runtime with no bridging thread. Embassy
//! lives in the DUT child process, where the device stack is.

use std::io;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use zweidraehte_client::connector::KnxConnector;
use zweidraehte_client::{Error as ClientError, Result as ClientResult};
use zweidraehte_proto::encoding::cemi::{CemiMessageCode, cemi_to_knx_message, knx_to_cemi_message};
use zweidraehte_proto::encoding::tp1;

use super::lifecycle::ChildLifecycle;
use crate::ipc::protocol::RunnerMessage;

// ============================================================================
// cEMI ⇄ internal ⇄ TP1 conversion
// ============================================================================

/// Internal-format KNX message → cEMI with the given message code.
/// (Same shape as the client's own `core::frames::internal_to_cemi`.)
fn internal_to_cemi(internal: &[u8], msg_code: CemiMessageCode) -> Vec<u8> {
    let mut buf = vec![0u8; internal.len() + 3];
    buf[..internal.len()].copy_from_slice(internal);
    let final_len = knx_to_cemi_message(&mut buf, 0, internal.len(), msg_code);
    buf.truncate(final_len);
    buf
}

/// A DUT-captured TP1 frame (no checksum) → cEMI `L_Data.ind`.
fn captured_to_cemi(tp1_data: &[u8]) -> Vec<u8> {
    let internal = tp1::tp1_to_knx_vec_no_checksum(tp1_data);
    internal_to_cemi(&internal, CemiMessageCode::LDataInd)
}

// ============================================================================
// Bridge plumbing
// ============================================================================

enum BridgeCmd {
    /// Inject an internal-format L_Data frame into the DUT.
    Inject {
        internal: Vec<u8>,
        done: oneshot::Sender<io::Result<()>>,
    },
    SetProgrammingMode {
        enabled: bool,
        done: oneshot::Sender<io::Result<()>>,
    },
    /// Kill → default snapshot → respawn: a factory-fresh DUT.
    FullReset {
        done: oneshot::Sender<io::Result<()>>,
    },
    /// Exercise the DUT's local master-reset implementation and reboot the
    /// persisted result. Unlike `FullReset`, this does not replace state with
    /// the conformance boot image.
    MasterReset {
        erase_code: u8,
        done: oneshot::Sender<io::Result<()>>,
    },
    /// Reboot the persisted image without replacing either configuration or
    /// sequence state, as on a power interruption.
    PowerCycle {
        done: oneshot::Sender<io::Result<()>>,
    },
    /// Make the DUT transmit a GroupValue_Write on the given ASAP.
    TriggerGroupWrite {
        asap: u16,
        done: oneshot::Sender<io::Result<()>>,
    },
    Close {
        done: oneshot::Sender<()>,
    },
}

/// The client-side half: a [`KnxConnector`] over the pump.
pub struct DutConnector {
    cmd_tx: mpsc::Sender<BridgeCmd>,
    frame_rx: mpsc::Receiver<Vec<u8>>,
}

/// The scenario-side half: out-of-band DUT control. Cloneable.
#[derive(Clone)]
pub struct DutControl {
    cmd_tx: mpsc::Sender<BridgeCmd>,
}

/// Spawn the pump around a lifecycle whose child is already running
/// (`spawn_and_wait_roi` done). Returns the connector to hand to
/// `KnxBus::with_connector` and the control handle for scenarios.
pub fn spawn(lifecycle: ChildLifecycle) -> (DutConnector, DutControl) {
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (frame_tx, frame_rx) = mpsc::channel(64);
    tokio::spawn(pump(lifecycle, cmd_rx, frame_tx));
    (DutConnector { cmd_tx: cmd_tx.clone(), frame_rx }, DutControl { cmd_tx })
}

impl DutControl {
    async fn command(&self, make: impl FnOnce(oneshot::Sender<io::Result<()>>) -> BridgeCmd) -> io::Result<()> {
        let (done, wait) = oneshot::channel();
        self.cmd_tx.send(make(done)).await.map_err(|_| io::Error::other("bridge pump gone"))?;
        wait.await.map_err(|_| io::Error::other("bridge pump gone"))?
    }

    pub async fn set_programming_mode(&self, enabled: bool) -> io::Result<()> {
        self.command(|done| BridgeCmd::SetProgrammingMode { enabled, done }).await
    }

    pub async fn full_reset(&self) -> io::Result<()> {
        self.command(|done| BridgeCmd::FullReset { done }).await
    }

    pub async fn master_reset(&self, erase_code: u8) -> io::Result<()> {
        self.command(|done| BridgeCmd::MasterReset { erase_code, done }).await
    }

    pub async fn power_cycle(&self) -> io::Result<()> {
        self.command(|done| BridgeCmd::PowerCycle { done }).await
    }

    pub async fn trigger_group_write(&self, asap: u16) -> io::Result<()> {
        self.command(|done| BridgeCmd::TriggerGroupWrite { asap, done }).await
    }
}

impl KnxConnector for DutConnector {
    async fn send_cemi(&mut self, cemi: &[u8]) -> ClientResult<()> {
        // The connectors only ever carry L_Data; anything else would
        // be a client-side regression worth failing loudly on.
        let internal = cemi_to_knx_message(cemi.to_vec());
        let (done, wait) = oneshot::channel();
        self.cmd_tx.send(BridgeCmd::Inject { internal, done }).await.map_err(|_| ClientError::WorkerGone)?;
        wait.await.map_err(|_| ClientError::WorkerGone)?.map_err(ClientError::Io)
    }

    async fn recv_cemi(&mut self) -> ClientResult<Vec<u8>> {
        self.frame_rx.recv().await.ok_or(ClientError::WorkerGone)
    }

    async fn close(&mut self) -> ClientResult<()> {
        let (done, wait) = oneshot::channel();
        if self.cmd_tx.send(BridgeCmd::Close { done }).await.is_ok() {
            let _ = wait.await;
        }
        Ok(())
    }
}

// ============================================================================
// The pump
// ============================================================================

/// How long the pump waits for a command before giving the IPC socket
/// a chance to deliver unsolicited DUT frames (TL retransmits).
const IDLE_POLL: Duration = Duration::from_millis(20);

async fn pump(mut lifecycle: ChildLifecycle, mut cmd_rx: mpsc::Receiver<BridgeCmd>, frame_tx: mpsc::Sender<Vec<u8>>) {
    loop {
        // Whatever the DUT produced so far goes to the client first —
        // frames precede any new command's effects.
        drain_frames(&mut lifecycle, &frame_tx).await;

        let command = match tokio::time::timeout(IDLE_POLL, cmd_rx.recv()).await {
            Ok(command) => command,
            Err(_elapsed) => {
                // No command: let the socket deliver DUT-initiated
                // frames (timer-driven TL retransmits). A short
                // window keeps command latency negligible.
                let _ = lifecycle.next_frame(Duration::from_millis(2)).await;
                continue;
            }
        };

        match command {
            Some(BridgeCmd::Inject { internal, done }) => {
                let tp1_frame = tp1::knx_to_tp1_vec_no_checksum(&internal);
                let result = lifecycle.step(|seq| RunnerMessage::Inject { seq, data: tp1_frame.clone() }).await;
                if result.is_ok() {
                    // The interface-side confirmation: the frame made
                    // it onto the "bus". Sent before the DUT's
                    // response frames, mirroring real timing.
                    let con = internal_to_cemi(&internal, CemiMessageCode::LDataCon);
                    let _ = frame_tx.send(con).await;
                    drain_frames(&mut lifecycle, &frame_tx).await;
                }
                let _ = done.send(result.map(|_| ()));
            }
            Some(BridgeCmd::SetProgrammingMode { enabled, done }) => {
                let result = lifecycle.step(|seq| RunnerMessage::SetProgrammingMode { seq, enabled }).await;
                let _ = done.send(result.map(|_| ()));
            }
            Some(BridgeCmd::FullReset { done }) => {
                let result = lifecycle.full_reset().await;
                let _ = done.send(result);
            }
            Some(BridgeCmd::MasterReset { erase_code, done }) => {
                let result = async {
                    lifecycle.step_exiting(RunnerMessage::MasterReset { erase_code }, Duration::from_secs(2)).await?;
                    lifecycle.auto_respawn_if_dead(false).await
                }
                .await;
                let _ = done.send(result);
            }
            Some(BridgeCmd::PowerCycle { done }) => {
                let result = async {
                    lifecycle.step_exiting(RunnerMessage::PowerCycle, Duration::from_secs(2)).await?;
                    lifecycle.auto_respawn_if_dead(false).await
                }
                .await;
                let _ = done.send(result);
            }
            Some(BridgeCmd::TriggerGroupWrite { asap, done }) => {
                let result = lifecycle.step(|seq| RunnerMessage::TriggerWrite { seq, asap }).await;
                if result.is_ok() {
                    drain_frames(&mut lifecycle, &frame_tx).await;
                }
                let _ = done.send(result.map(|_| ()));
            }
            Some(BridgeCmd::Close { done }) => {
                lifecycle.kill().await;
                let _ = done.send(());
                return;
            }
            None => {
                // Client side dropped everything — tear the DUT down.
                lifecycle.kill().await;
                return;
            }
        }
    }
}

/// Forward every buffered DUT frame to the client as `L_Data.ind`.
async fn drain_frames(lifecycle: &mut ChildLifecycle, frame_tx: &mpsc::Sender<Vec<u8>>) {
    while let Some(tagged) = lifecycle.pop_unsolicited() {
        let cemi = captured_to_cemi(&tagged.message.data);
        if frame_tx.send(cemi).await.is_err() {
            // Client gone; the pump's command loop will notice on the
            // next recv and shut down.
            return;
        }
    }
}
