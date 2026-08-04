//! The background bus task: one tokio loop driving a connector, the TL
//! client state machine, and the single in-flight management procedure.
//!
//! The task is an actor: the API handles talk to it through
//! [`BusCommand`]s carrying oneshot response channels. It serializes
//! management procedures — one at a time — which matches how the bus
//! behaves anyway (one TL connection, request/response protocols).
//! Group telegrams are the exception: they fan out through a broadcast
//! channel to any number of subscribers, independent of the pending
//! procedure.

use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::encoding::cemi::CemiMessageCode;
use zweidraehte_proto::messages::knx::{ApciCode, DestinationAddress, KnxMessageBuffer, Tpci, offsets};
use zweidraehte_proto::transport::{TlAction, TlEvent};

use crate::connector::{ConnectorInfo, KnxConnector};
use crate::core::frames;
use crate::core::group::GroupTelegram;
use crate::core::management::{RESPONSE_TIMEOUT, ResponseMatcher};
use crate::core::tl_client::{TL_ACK_TIMEOUT, TL_CONNECTION_TIMEOUT, TlClientCore};
use crate::error::{Error, Result};

// ============================================================================
// Commands
// ============================================================================

/// Requests from the API handles to the bus task.
///
/// Frames travel in the internal message format; the task converts to cEMI
/// at the connector boundary (and stamps TL sequence numbers for connected
/// frames).
pub enum BusCommand {
    /// Send a frame and resolve as soon as the interface accepted it
    /// (group writes/reads, NM broadcasts without replies).
    SendOnly { frame: Vec<u8>, tx: oneshot::Sender<Result<()>> },
    /// Connectionless request: send, then await the one frame matching
    /// `matcher` (RCl management, unconnected device descriptor reads).
    Unconnected { frame: Vec<u8>, matcher: ResponseMatcher, tx: oneshot::Sender<Result<Vec<u8>>> },
    /// Broadcast request collecting every matching answer within `window`
    /// (NM_IndividualAddress_Read scans).
    Scan { frame: Vec<u8>, matcher: ResponseMatcher, window: Duration, tx: oneshot::Sender<Result<Vec<Vec<u8>>>> },
    /// Open the (single) transport connection to `dest`.
    TlOpen { dest: IndividualAddress, tx: oneshot::Sender<Result<()>> },
    /// Connected request on the open transport connection. The frame was
    /// built with `Tpci::DataConnected(0)`; the task stamps the live
    /// sequence number. With `expects_response: false` the request resolves
    /// on the device's T_ACK (empty response); otherwise on the response
    /// frame matching `expected_apci` (`None` = any service from the peer,
    /// for responses without an `ApciCode` mapping like A_Restart_Response).
    TlRequest {
        frame: Vec<u8>,
        expects_response: bool,
        expected_apci: Option<ApciCode>,
        tx: oneshot::Sender<Result<Vec<u8>>>,
    },
    /// Close the transport connection.
    TlClose { tx: oneshot::Sender<Result<()>> },
    /// Tear the bus connection down and end the task.
    Shutdown { tx: oneshot::Sender<Result<()>> },
}

// ============================================================================
// Pending procedure state
// ============================================================================

enum Pending {
    Unconnected {
        matcher: ResponseMatcher,
        deadline: Instant,
        tx: oneshot::Sender<Result<Vec<u8>>>,
    },
    Scan {
        matcher: ResponseMatcher,
        deadline: Instant,
        collected: Vec<Vec<u8>>,
        tx: oneshot::Sender<Result<Vec<Vec<u8>>>>,
    },
    TlOpen {
        dest: IndividualAddress,
        tx: oneshot::Sender<Result<()>>,
    },
    TlRequest {
        matcher: ResponseMatcher,
        /// `None` until the device's T_ACK arrives; then the response wait
        /// deadline. Requests without an expected response resolve on the
        /// T_ACK itself.
        response_deadline: Option<Instant>,
        expects_response: bool,
        tx: oneshot::Sender<Result<Vec<u8>>>,
    },
}

impl Pending {
    fn deadline(&self) -> Option<Instant> {
        match self {
            Pending::Unconnected { deadline, .. } => Some(*deadline),
            Pending::Scan { deadline, .. } => Some(*deadline),
            Pending::TlOpen { .. } => None, // bounded by the TL connection timer
            Pending::TlRequest { response_deadline, .. } => *response_deadline,
        }
    }

    fn fail(self, err: Error) {
        match self {
            Pending::Unconnected { tx, .. } => drop(tx.send(Err(err))),
            Pending::Scan { tx, .. } => drop(tx.send(Err(err))),
            Pending::TlOpen { tx, .. } => drop(tx.send(Err(err))),
            Pending::TlRequest { tx, .. } => drop(tx.send(Err(err))),
        }
    }
}

// ============================================================================
// Bus task
// ============================================================================

pub struct BusTask<C: KnxConnector> {
    connector: C,
    info: ConnectorInfo,
    cmd_rx: mpsc::Receiver<BusCommand>,
    group_tx: broadcast::Sender<GroupTelegram>,

    tl: TlClientCore,
    /// The seq-stamped internal-format frame of the in-flight connected
    /// request, kept for TL retransmissions.
    tl_pending_frame: Option<Vec<u8>>,
    tl_ack_deadline: Option<Instant>,
    tl_conn_deadline: Option<Instant>,

    pending: Option<Pending>,
}

impl<C: KnxConnector> BusTask<C> {
    pub fn new(
        connector: C,
        info: ConnectorInfo,
        cmd_rx: mpsc::Receiver<BusCommand>,
        group_tx: broadcast::Sender<GroupTelegram>,
    ) -> Self {
        Self {
            connector,
            info,
            cmd_rx,
            group_tx,
            tl: TlClientCore::new(),
            tl_pending_frame: None,
            tl_ack_deadline: None,
            tl_conn_deadline: None,
            pending: None,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            let deadline = self.next_deadline();

            tokio::select! {
                // Commands are only taken while no procedure is in flight —
                // the mpsc channel buffers the rest, preserving order.
                cmd = self.cmd_rx.recv(), if self.pending.is_none() => {
                    match cmd {
                        Some(BusCommand::Shutdown { tx }) => {
                            let result = self.connector.close().await;
                            let _ = tx.send(result);
                            return Ok(());
                        }
                        Some(cmd) => self.handle_command(cmd).await?,
                        // All API handles dropped: best-effort teardown.
                        None => {
                            let _ = self.connector.close().await;
                            return Ok(());
                        }
                    }
                }

                received = self.connector.recv_cemi() => {
                    match received {
                        Ok(cemi) => self.handle_frame(&cemi).await?,
                        Err(err) => {
                            // The bus access died (heartbeat lost, server
                            // disconnect...). Fail the pending procedure and
                            // end the task; API handles see WorkerGone after.
                            if let Some(pending) = self.pending.take() {
                                pending.fail(Error::Disconnected);
                            }
                            return Err(err);
                        }
                    }
                }

                _ = tokio::time::sleep_until(deadline.unwrap_or_else(far_future)), if deadline.is_some() => {
                    self.handle_timeouts().await?;
                }
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        [self.tl_ack_deadline, self.tl_conn_deadline, self.pending.as_ref().and_then(|p| p.deadline())]
            .into_iter()
            .flatten()
            .min()
    }

    // ========================================================================
    // Commands
    // ========================================================================

    async fn handle_command(&mut self, cmd: BusCommand) -> Result<()> {
        match cmd {
            BusCommand::SendOnly { frame, tx } => {
                let result = self.send_internal(&frame).await;
                let _ = tx.send(result);
            }

            BusCommand::Unconnected { frame, matcher, tx } => match self.send_internal(&frame).await {
                Ok(()) => {
                    self.pending =
                        Some(Pending::Unconnected { matcher, deadline: Instant::now() + RESPONSE_TIMEOUT, tx });
                }
                Err(err) => drop(tx.send(Err(err))),
            },

            BusCommand::Scan { frame, matcher, window, tx } => match self.send_internal(&frame).await {
                Ok(()) => {
                    self.pending =
                        Some(Pending::Scan { matcher, deadline: Instant::now() + window, collected: Vec::new(), tx });
                }
                Err(err) => drop(tx.send(Err(err))),
            },

            BusCommand::TlOpen { dest, tx } => {
                if !self.tl.is_closed() {
                    let _ = tx.send(Err(Error::ConnectionBusy));
                    return Ok(());
                }
                self.pending = Some(Pending::TlOpen { dest, tx });
                let result = self.tl.feed(TlEvent::RequestConnect { dest });
                self.execute_tl(result, None).await?;
            }

            BusCommand::TlRequest { mut frame, expects_response, expected_apci, tx } => {
                if self.tl.is_closed() {
                    let _ = tx.send(Err(Error::TransportClosed));
                    return Ok(());
                }
                let dest = self.tl.remote();
                frames::set_connected_seq(&mut frame, self.tl.send_seq());
                self.tl_pending_frame = Some(frame);
                self.pending = Some(Pending::TlRequest {
                    matcher: ResponseMatcher { source: Some(dest), apci: expected_apci },
                    response_deadline: None,
                    expects_response,
                    tx,
                });
                let result = self.tl.feed(TlEvent::RequestData { dest });
                self.execute_tl(result, None).await?;
            }

            BusCommand::TlClose { tx } => {
                if self.tl.is_closed() {
                    let _ = tx.send(Ok(()));
                    return Ok(());
                }
                let dest = self.tl.remote();
                // E26 resolves synchronously (A14/A15 emit ConfirmDisconnect
                // in the same action batch), so no Pending entry is needed.
                let result = self.tl.feed(TlEvent::RequestDisconnect { dest });
                let mut confirmed = false;
                for action in result.actions.iter() {
                    if matches!(action, TlAction::ConfirmDisconnect { .. }) {
                        confirmed = true;
                    }
                }
                self.execute_tl(result, None).await?;
                let _ = tx.send(if confirmed { Ok(()) } else { Err(Error::TransportClosed) });
            }

            BusCommand::Shutdown { .. } => unreachable!("handled in run()"),
        }
        Ok(())
    }

    // ========================================================================
    // Incoming frames
    // ========================================================================

    async fn handle_frame(&mut self, cemi: &[u8]) -> Result<()> {
        if cemi.is_empty() {
            return Ok(());
        }
        let msg_code = CemiMessageCode::from(cemi[0]);
        let internal = frames::cemi_to_internal(cemi);
        if internal.len() < offsets::MSG_TPCI + 1 {
            return Ok(());
        }

        match msg_code {
            CemiMessageCode::LDataCon => self.handle_confirmation(&internal).await,
            CemiMessageCode::LDataInd => self.handle_indication(&internal).await,
            other => {
                log::trace!("Ignoring cEMI {}", other);
                Ok(())
            }
        }
    }

    /// L_Data.con: the interface's confirmation of a frame we sent.
    async fn handle_confirmation(&mut self, internal: &[u8]) -> Result<()> {
        let msg = KnxMessageBuffer::from_buffer(internal);
        let negative = (internal[offsets::MSG_CONTROL] & 0x01) != 0;

        // A confirmed T_Connect is the state machine's E19/E20 (the
        // N_Data_Individual.con for our T_CONNECT_REQ_PDU).
        if msg.get_tpci() == Some(Tpci::Connect)
            && matches!(self.pending, Some(Pending::TlOpen { .. }))
            && msg.get_dest_addr() == DestinationAddress::Individual(self.tl.remote())
        {
            let result = self.tl.feed(TlEvent::ConnectConfirm { success: !negative });
            return self.execute_tl(result, None).await;
        }

        // A negative confirmation of connected data means the bus never
        // carried the frame; the TL ACK timer would retransmit, but the
        // procedure has lost its timing guarantees — fail it now.
        if negative
            && matches!(msg.get_tpci(), Some(Tpci::DataConnected(_)))
            && matches!(self.pending, Some(Pending::TlRequest { .. }))
        {
            if let Some(pending) = self.pending.take() {
                pending.fail(Error::NegativeConfirmation);
            }
            return Ok(());
        }

        if negative && let Some(pending) = self.pending.take() {
            pending.fail(Error::NegativeConfirmation);
        }
        Ok(())
    }

    /// L_Data.ind: traffic from the bus.
    async fn handle_indication(&mut self, internal: &[u8]) -> Result<()> {
        let msg = KnxMessageBuffer::from_buffer(internal);
        let source = msg.get_source_addr();

        match msg.get_dest_addr() {
            DestinationAddress::Group(_) => {
                if let Some(telegram) = GroupTelegram::parse(internal) {
                    // No receivers is fine — nobody subscribed (yet).
                    let _ = self.group_tx.send(telegram);
                }
                Ok(())
            }

            DestinationAddress::Broadcast | DestinationAddress::SystemBroadcast => {
                self.feed_pending_response(internal);
                Ok(())
            }

            DestinationAddress::Individual(dest) if dest == self.info.assigned_address => {
                match msg.get_tpci() {
                    Some(Tpci::Disconnect) => {
                        let result = self.tl.feed(TlEvent::ReceivedDisconnect { source });
                        self.execute_tl(result, None).await
                    }
                    Some(Tpci::Ack(seq_no)) => {
                        let result = self.tl.feed(TlEvent::ReceivedAck { source, seq_no });
                        self.execute_tl(result, None).await
                    }
                    Some(Tpci::Nack(seq_no)) => {
                        let result = self.tl.feed(TlEvent::ReceivedNack { source, seq_no });
                        self.execute_tl(result, None).await
                    }
                    Some(Tpci::DataConnected(seq_no)) => {
                        let result = self.tl.feed(TlEvent::ReceivedData { source, seq_no });
                        self.execute_tl(result, Some(internal)).await
                    }
                    Some(Tpci::DataIndividual) => {
                        self.feed_pending_response(internal);
                        Ok(())
                    }
                    Some(Tpci::Connect) => {
                        // A client doesn't accept incoming transport
                        // connections; reject unless it belongs to our open
                        // connection's peer (then the state machine decides).
                        if !self.tl.is_closed() && source == self.tl.remote() {
                            let result = self.tl.feed(TlEvent::ReceivedConnect { source });
                            self.execute_tl(result, None).await
                        } else {
                            let reject =
                                frames::build_transport_frame(self.info.assigned_address, source, Tpci::Disconnect);
                            self.send_internal(&reject).await
                        }
                    }
                    _ => Ok(()),
                }
            }

            _ => Ok(()),
        }
    }

    /// Offer a received application frame to the pending procedure.
    fn feed_pending_response(&mut self, internal: &[u8]) {
        match self.pending.take() {
            Some(Pending::Unconnected { matcher, deadline, tx }) => {
                if matcher.matches(internal) {
                    let _ = tx.send(Ok(internal.to_vec()));
                } else {
                    log::debug!("Skipping non-matching frame during unconnected request");
                    self.pending = Some(Pending::Unconnected { matcher, deadline, tx });
                }
            }
            Some(Pending::Scan { matcher, deadline, mut collected, tx }) => {
                if matcher.matches(internal) {
                    collected.push(internal.to_vec());
                }
                self.pending = Some(Pending::Scan { matcher, deadline, collected, tx });
            }
            Some(Pending::TlRequest { matcher, response_deadline, expects_response, tx }) => {
                if expects_response && matcher.matches(internal) {
                    let _ = tx.send(Ok(internal.to_vec()));
                } else {
                    self.pending = Some(Pending::TlRequest { matcher, response_deadline, expects_response, tx });
                }
            }
            other => self.pending = other,
        }
    }

    // ========================================================================
    // TL action execution
    // ========================================================================

    /// Execute the actions of one state-machine step, then apply the
    /// deferred state transition. `data_frame` carries the received frame
    /// for `IndicateData`.
    async fn execute_tl(
        &mut self,
        result: zweidraehte_proto::transport::ProcessResult,
        data_frame: Option<&[u8]>,
    ) -> Result<()> {
        let us = self.info.assigned_address;

        for action in result.actions.iter() {
            match action {
                TlAction::SendConnect { dest } => {
                    let frame = frames::build_transport_frame(us, dest, Tpci::Connect);
                    self.send_internal(&frame).await?;
                }
                TlAction::SendDisconnect { dest } => {
                    let frame = frames::build_transport_frame(us, dest, Tpci::Disconnect);
                    self.send_internal(&frame).await?;
                }
                TlAction::SendAck { dest, seq_no } => {
                    let frame = frames::build_transport_frame(us, dest, Tpci::Ack(seq_no));
                    self.send_internal(&frame).await?;
                }
                TlAction::SendNack { dest, seq_no } => {
                    let frame = frames::build_transport_frame(us, dest, Tpci::Nack(seq_no));
                    self.send_internal(&frame).await?;
                }
                TlAction::SendData { .. } | TlAction::Retransmit { .. } => {
                    if let Some(frame) = self.tl_pending_frame.clone() {
                        self.send_internal(&frame).await?;
                    } else {
                        log::warn!("TL wants to (re)send but no pending frame is stored");
                    }
                }
                TlAction::StorePendingMessage => {
                    // The driver stored the stamped frame when the request
                    // was accepted; nothing to do here.
                }
                TlAction::ClearPendingMessage => {
                    self.tl_pending_frame = None;
                }
                TlAction::StartAckTimer => {
                    self.tl_ack_deadline = Some(Instant::now() + TL_ACK_TIMEOUT);
                }
                TlAction::StopAckTimer => {
                    self.tl_ack_deadline = None;
                }
                TlAction::StartConnTimer => {
                    self.tl_conn_deadline = Some(Instant::now() + TL_CONNECTION_TIMEOUT);
                }
                TlAction::StopConnTimer => {
                    self.tl_conn_deadline = None;
                }

                TlAction::ConfirmConnect { success, .. } => {
                    if let Some(Pending::TlOpen { dest, tx }) = self.pending.take() {
                        let _ = tx.send(if success { Ok(()) } else { Err(Error::TransportConnectFailed(dest)) });
                    }
                }
                TlAction::ConfirmData { success, .. } => {
                    if let Some(Pending::TlRequest { matcher, expects_response, tx, .. }) = self.pending.take() {
                        if !success {
                            let _ = tx.send(Err(Error::NegativeConfirmation));
                        } else if expects_response {
                            // ACKed; now wait for the response frame.
                            self.pending = Some(Pending::TlRequest {
                                matcher,
                                response_deadline: Some(Instant::now() + RESPONSE_TIMEOUT),
                                expects_response,
                                tx,
                            });
                        } else {
                            let _ = tx.send(Ok(Vec::new()));
                        }
                    }
                }
                TlAction::ConfirmDisconnect { .. } => {
                    // Resolved synchronously by the TlClose command handler.
                }
                TlAction::IndicateConnected { source } => {
                    log::debug!("TL connection indication from {} (client role: unexpected)", source);
                }
                TlAction::IndicateDisconnected { .. } => {
                    self.tl_pending_frame = None;
                    match self.pending.take() {
                        Some(Pending::TlOpen { dest, tx }) => drop(tx.send(Err(Error::TransportConnectFailed(dest)))),
                        Some(Pending::TlRequest { tx, .. }) => drop(tx.send(Err(Error::TransportClosed))),
                        other => self.pending = other,
                    }
                }
                TlAction::IndicateData { .. } => {
                    if let Some(frame) = data_frame {
                        self.feed_pending_response(frame);
                    }
                }
                TlAction::QueueEvent { .. } | TlAction::DeliverQueuedData { .. } => {
                    // Only reachable with overlapping requests, which the
                    // one-pending-procedure rule prevents.
                    log::warn!("TL queue action with serialized procedures — dropped");
                }
            }
        }

        result.apply_state(&mut self.tl.conn);
        Ok(())
    }

    // ========================================================================
    // Timeouts
    // ========================================================================

    async fn handle_timeouts(&mut self) -> Result<()> {
        let now = Instant::now();

        if let Some(deadline) = self.tl_ack_deadline
            && now >= deadline
        {
            self.tl_ack_deadline = None;
            let result = self.tl.feed(TlEvent::AckTimeout);
            self.execute_tl(result, None).await?;
        }

        if let Some(deadline) = self.tl_conn_deadline
            && now >= deadline
        {
            self.tl_conn_deadline = None;
            let result = self.tl.feed(TlEvent::ConnectionTimeout);
            self.execute_tl(result, None).await?;
        }

        match self.pending.take() {
            Some(Pending::Unconnected { matcher, deadline, tx }) => {
                if now >= deadline {
                    let _ = tx.send(Err(Error::Timeout));
                } else {
                    self.pending = Some(Pending::Unconnected { matcher, deadline, tx });
                }
            }
            Some(Pending::Scan { matcher, deadline, collected, tx }) => {
                if now >= deadline {
                    let _ = tx.send(Ok(collected));
                } else {
                    self.pending = Some(Pending::Scan { matcher, deadline, collected, tx });
                }
            }
            Some(Pending::TlRequest { matcher, response_deadline, expects_response, tx }) => {
                if response_deadline.is_some_and(|d| now >= d) {
                    let _ = tx.send(Err(Error::Timeout));
                } else {
                    self.pending = Some(Pending::TlRequest { matcher, response_deadline, expects_response, tx });
                }
            }
            other => self.pending = other,
        }

        Ok(())
    }

    // ========================================================================
    // Sending
    // ========================================================================

    /// Convert an internal-format frame to cEMI and send it, stamping the
    /// connector's assigned address as the source — API-layer builders use
    /// a zero placeholder so only one place knows the real address.
    async fn send_internal(&mut self, internal: &[u8]) -> Result<()> {
        let mut frame = internal.to_vec();
        frame[offsets::MSG_SOURCE_ADDR..offsets::MSG_SOURCE_ADDR + 2]
            .copy_from_slice(self.info.assigned_address.as_bytes());
        let cemi = frames::internal_to_cemi(&frame, CemiMessageCode::LDataReq);
        self.connector.send_cemi(&cemi).await
    }
}

/// A deadline that never fires, for the disabled select arm.
fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86400 * 365)
}
