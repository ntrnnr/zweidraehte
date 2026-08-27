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

use std::future::Future;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::crypto::ccm;
use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
use zweidraehte_proto::encoding::cemi::CemiMessageCode;
use zweidraehte_proto::messages::apdu::secure::{self, SyncResRef};
use zweidraehte_proto::messages::knx::{
    ApciCode, DestinationAddress, KnxMessageBuffer, Tpci, decode_apci_code, offsets,
};
use zweidraehte_proto::transport::{TlAction, TlEvent};

use crate::connector::{ConnectorInfo, KnxConnector};
use crate::core::frames;
use crate::core::group::GroupTelegram;
use crate::core::management::{RESPONSE_TIMEOUT, ResponseMatcher};
use crate::core::tl_client::{TL_ACK_TIMEOUT, TL_CONNECTION_TIMEOUT, TlClientCore};
use crate::error::{Error, Result};
use crate::security::channel::{
    SecureChannel, group_unwrap, group_wrap, seq_from_bytes, seq_to_bytes, system_broadcast_wrap,
};
use crate::security::{SecureError, SecurityEntry, SecurityStore};

/// How long one S-A_Sync attempt waits for the response. The device
/// rate-limits sync responses to one per second, so this leaves headroom
/// beyond that window; one retry gives ~3 s total, inside the 6 s TL
/// connection timeout.
const SYNC_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1500);

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
    /// Protect and send serial-addressed commissioning data as a system
    /// broadcast. `at` identifies the security entry whose exact credential
    /// a preceding sync proved during this bus session.
    SecureSystemBroadcast { frame: Vec<u8>, at: IndividualAddress, key: [u8; 16], tx: oneshot::Sender<Result<()>> },
    /// Connectionless request: send, then await the one frame matching
    /// `matcher` (RCl management, unconnected device descriptor reads).
    Unconnected { frame: Vec<u8>, matcher: ResponseMatcher, tx: oneshot::Sender<Result<Vec<u8>>> },
    /// Broadcast request collecting every matching answer within `window`
    /// (NM_IndividualAddress_Read scans).
    Scan { frame: Vec<u8>, matcher: ResponseMatcher, window: Duration, tx: oneshot::Sender<Result<Vec<Vec<u8>>>> },
    /// Open the single transport connection to `dest`. Secure connections
    /// synchronize before resolving unless the same credential synchronized
    /// moments ago; `force_sync` bypasses that short freshness cache.
    TlOpen { dest: IndividualAddress, force_sync: bool, tx: oneshot::Sender<Result<TlOpenResult>> },
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
    /// The one connected request whose response changes encryption keys.
    /// The request is wrapped with the current key; immediately after it is
    /// sent, the live channel switches to `new_key` for the response.
    TlToolKeyWrite { frame: Vec<u8>, expected_apci: ApciCode, new_key: [u8; 16], tx: oneshot::Sender<Result<Vec<u8>>> },
    /// Close the transport connection.
    TlClose { tx: oneshot::Sender<Result<()>> },
    /// Register or replace a device's Data Secure keyring entry.
    SetDeviceSecurity { ia: IndividualAddress, entry: SecurityEntry, tx: oneshot::Sender<()> },
    /// Move a device entry after serial-number IA assignment.
    MoveDeviceSecurity { previous: IndividualAddress, current: IndividualAddress, tx: oneshot::Sender<()> },
    /// Remove a device entry before attempting plaintext management.
    RemoveDeviceSecurity { ia: IndividualAddress, tx: oneshot::Sender<()> },
    /// Register or replace the Data Secure key for one group address.
    SetGroupKey { ga: u16, key: [u8; 16], tx: oneshot::Sender<()> },
    /// Read the durable incoming floor for one managed device.
    DeviceSequenceFloor { serial: [u8; 6], tx: oneshot::Sender<u64> },
    /// Tear the bus connection down and end the task.
    Shutdown { tx: oneshot::Sender<Result<()>> },
}

/// State established while opening one transport connection.
pub(crate) struct TlOpenResult {
    /// Exact `SeqNrremote` from a verified `S-A_Sync_Res`. This is the
    /// device's next sending sequence number, not PID 59 readback and not the
    /// receiver-side `LastValidSeqNr` representation used by a live S-AL. A
    /// plain connection or one reusing a fresh sync has no new wire value.
    pub remote_next_sequence: Option<u64>,
}

/// An S-A_Sync handshake awaiting its response.
struct SyncPending {
    /// The challenge we encrypted into the request; XORed against the
    /// response's challenge_xor_random to recover the device's Random.
    challenge: [u8; 6],
    retry_count: u8,
    /// A Tool-Key sync inside an open TL connection is itself connected
    /// traffic. FDSK bootstrap remains a serial-addressed system broadcast.
    connected: bool,
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
        force_sync: bool,
        tx: oneshot::Sender<Result<TlOpenResult>>,
    },
    TlRequest {
        matcher: ResponseMatcher,
        /// `None` until the device's T_ACK arrives; then the response wait
        /// deadline. Requests without an expected response resolve on the
        /// T_ACK itself.
        response_deadline: Option<Instant>,
        expects_response: bool,
        /// Present only while `PID_TOOL_KEY` is changing. Receipt of a
        /// matching frame proves that the device accepted the new key,
        /// because only that key can authenticate the response.
        tool_key_rotation: Option<[u8; 16]>,
        tx: oneshot::Sender<Result<Vec<u8>>>,
    },
}

impl Pending {
    fn deadline(&self) -> Option<Instant> {
        match self {
            Pending::Unconnected { deadline, .. } => Some(*deadline),
            Pending::Scan { deadline, .. } => Some(*deadline),
            Pending::TlOpen { .. } => None,
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
    /// request, kept for TL retransmissions. On a secure connection this
    /// holds the *wrapped* frame — retransmissions must be byte-identical
    /// (re-encrypting would consume another secure sequence number and
    /// the device would treat the retry as new traffic).
    tl_pending_frame: Option<Vec<u8>>,
    tl_ack_deadline: Option<Instant>,
    tl_conn_deadline: Option<Instant>,

    pending: Option<Pending>,

    /// Keyring + sequence-counter store for Data Secure.
    security: SecurityStore,
    /// Secure wrap/unwrap state of the open TL connection, if the peer
    /// is keyed `Secure` in the keyring.
    tl_security: Option<SecureChannel>,
    tl_sync: Option<SyncPending>,
    tl_sync_deadline: Option<Instant>,
}

impl<C: KnxConnector> BusTask<C> {
    pub fn new(
        connector: C,
        info: ConnectorInfo,
        cmd_rx: mpsc::Receiver<BusCommand>,
        group_tx: broadcast::Sender<GroupTelegram>,
        security: SecurityStore,
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
            security,
            tl_security: None,
            tl_sync: None,
            tl_sync_deadline: None,
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
        [
            self.tl_ack_deadline,
            self.tl_conn_deadline,
            self.tl_sync_deadline,
            self.pending.as_ref().and_then(|p| p.deadline()),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    // ========================================================================
    // Commands
    // ========================================================================

    async fn handle_command(&mut self, cmd: BusCommand) -> Result<()> {
        match cmd {
            BusCommand::SendOnly { mut frame, tx } => {
                // A frame to a secured group address gets wrapped here —
                // the one place that knows both the group key and our
                // assigned bus address (the CCM nonce covers the source).
                // Both group_write and group_read arrive on this path.
                let msg = KnxMessageBuffer::from_buffer(frame.as_slice());
                if let DestinationAddress::Group(ga) = msg.get_dest_addr()
                    && let Some(&key) = self.security.get_group_key(u16::from_be_bytes(ga.0))
                {
                    // Reserve before wrapping or forwarding. A failed
                    // persistence operation prevents transmission.
                    let seq = self.security.reserve_sending_sequence()?;
                    let src = u16::from_be_bytes(self.info.assigned_address.0);
                    frame = group_wrap(&key, seq, src, &frame);
                }
                let result = self.send_internal(&frame).await;
                let _ = tx.send(result);
            }

            BusCommand::SecureSystemBroadcast { frame, at, key, tx } => {
                if !self.security.can_send_with(at, &key) {
                    let _ = tx.send(Err(Error::SecuritySyncRequired));
                    return Ok(());
                }
                // Reserve before wrapping or forwarding, just like connected
                // tool traffic. The shared client counter must survive a lost
                // link confirmation because the target may have accepted it.
                let result = match self.security.reserve_management_sequence() {
                    Ok(sequence) => {
                        let src = u16::from_be_bytes(self.info.assigned_address.0);
                        let frame = system_broadcast_wrap(&key, sequence, src, &frame);
                        self.send_internal(&frame).await
                    }
                    Err(error) => Err(error.into()),
                };
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

            BusCommand::TlOpen { dest, force_sync, tx } => {
                if !self.tl.is_closed() {
                    let _ = tx.send(Err(Error::ConnectionBusy));
                    return Ok(());
                }
                self.pending = Some(Pending::TlOpen { dest, force_sync, tx });
                let result = self.tl.feed(TlEvent::RequestConnect { dest });
                self.execute_tl(result, None).await?;
            }

            BusCommand::TlRequest { frame, expects_response, expected_apci, tx } => {
                self.start_tl_request(frame, expects_response, expected_apci, None, tx).await?;
            }

            BusCommand::TlToolKeyWrite { frame, expected_apci, new_key, tx } => {
                if self.tl_security.is_none() {
                    let _ = tx.send(Err(Error::SecurityMissingKey));
                    return Ok(());
                }
                self.start_tl_request(frame, true, Some(expected_apci), Some(new_key), tx).await?;
                // `start_tl_request` has completed the connector send before
                // returning. No receive can interleave in this actor loop, so
                // the channel is now ready for the new-key response.
                self.tl_security.as_mut().expect("secure channel checked above").rotate_key(new_key);
            }

            BusCommand::SetDeviceSecurity { ia, entry, tx } => {
                self.security.set_device_security(ia, entry);
                let _ = tx.send(());
            }

            BusCommand::MoveDeviceSecurity { previous, current, tx } => {
                self.security.move_device_security(previous, current);
                let _ = tx.send(());
            }

            BusCommand::RemoveDeviceSecurity { ia, tx } => {
                self.security.remove_device_security(ia);
                let _ = tx.send(());
            }

            BusCommand::SetGroupKey { ga, key, tx } => {
                self.security.set_group_key(ga, key);
                let _ = tx.send(());
            }

            BusCommand::DeviceSequenceFloor { serial, tx } => {
                let _ = tx.send(self.security.device_sequence_floor(&serial));
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
                self.clear_secure_state();
                let _ = tx.send(if confirmed { Ok(()) } else { Err(Error::TransportClosed) });
            }

            BusCommand::Shutdown { .. } => unreachable!("handled in run()"),
        }
        Ok(())
    }

    async fn start_tl_request(
        &mut self,
        mut frame: Vec<u8>,
        expects_response: bool,
        expected_apci: Option<ApciCode>,
        tool_key_rotation: Option<[u8; 16]>,
        tx: oneshot::Sender<Result<Vec<u8>>>,
    ) -> Result<()> {
        if self.tl.is_closed() {
            let _ = tx.send(Err(Error::TransportClosed));
            return Ok(());
        }
        let dest = self.tl.remote();
        frames::set_connected_seq(&mut frame, self.tl.send_seq());
        // Wrap once, here — SendData and every Retransmit then
        // send identical bytes.
        if let Some(channel) = &self.tl_security {
            // The same durable counter serves tool and group traffic.
            let sequence = self.security.reserve_management_sequence()?;
            let src = u16::from_be_bytes(self.info.assigned_address.0);
            frame = channel.wrap_at(sequence, src, &frame);
        }
        self.tl_pending_frame = Some(frame);
        self.pending = Some(Pending::TlRequest {
            matcher: ResponseMatcher { source: Some(dest), apci: expected_apci },
            response_deadline: None,
            expects_response,
            tool_key_rotation,
            tx,
        });
        let result = self.tl.feed(TlEvent::RequestData { dest });
        self.execute_tl(result, None).await?;
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
            DestinationAddress::Group(ga) => {
                let is_secure = decode_apci_code(internal) == Some(ApciCode::SecureService);
                match (self.security.get_group_key(u16::from_be_bytes(ga.0)), is_secure) {
                    (Some(&key), true) => {
                        // Replay protection is per sender IA — the same
                        // slot a device keeps in its SIAT; the floor
                        // only moves once the MAC has verified.
                        let floor = self.security.sender_seq_floor(source);
                        match group_unwrap(&key, internal, floor) {
                            Ok((plain, new_floor)) => {
                                self.security.save_sender_seq(source, new_floor)?;
                                if let Some(mut telegram) = GroupTelegram::parse(&plain) {
                                    telegram.secured = true;
                                    // No receivers is fine — nobody subscribed (yet).
                                    let _ = self.group_tx.send(telegram);
                                }
                            }
                            Err(SecureError::Replay { received, expected }) => {
                                // A retransmission carries floor - 1 and
                                // lands here like any older number.
                                log::debug!(
                                    "dropping replayed secure group frame from {source} on {ga} \
                                     (seq {received}, expected >= {expected})"
                                );
                            }
                            Err(e) => {
                                log::warn!("dropping secure group frame from {source} on {ga}: {e}");
                            }
                        }
                    }
                    (Some(_), false) => {
                        // Plaintext on a secured group address is the
                        // downgrade path — devices with a secured group
                        // object drop it, and so do we.
                        log::warn!("dropping plaintext group telegram from {source} on secured {ga}");
                    }
                    (None, true) => {
                        log::debug!("dropping secure group telegram on {ga} (no group key)");
                    }
                    (None, false) => {
                        if let Some(telegram) = GroupTelegram::parse(internal) {
                            // No receivers is fine — nobody subscribed (yet).
                            let _ = self.group_tx.send(telegram);
                        }
                    }
                }
                Ok(())
            }

            DestinationAddress::Broadcast | DestinationAddress::SystemBroadcast
                if self.is_pending_sync_response(source, internal) =>
            {
                self.handle_sync_response(internal).await
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
                        let is_sync_response = self.is_pending_sync_response(source, internal);
                        let result = self.tl.feed(TlEvent::ReceivedData { source, seq_no });
                        let sync_response_accepted = is_sync_response
                            && result.actions.iter().any(|action| matches!(action, TlAction::IndicateData { .. }));
                        // The TL still has to acknowledge and sequence a
                        // connected sync response, but S-A_Sync has its own
                        // authenticated payload format rather than S-A_Data.
                        self.execute_tl(result, (!is_sync_response).then_some(internal)).await?;
                        if sync_response_accepted { self.handle_sync_response(internal).await } else { Ok(()) }
                    }
                    Some(Tpci::DataIndividual) => {
                        // Standalone point-to-point sync uses RCl rather than
                        // the connected path handled above.
                        if self.is_pending_sync_response(source, internal) {
                            return self.handle_sync_response(internal).await;
                        }
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

    fn is_pending_sync_response(&self, source: IndividualAddress, frame: &[u8]) -> bool {
        self.tl_sync.is_some()
            && !self.tl.is_closed()
            && source == self.tl.remote()
            && decode_apci_code(frame) == Some(ApciCode::SecureService)
            && frame
                .get(secure::SCF)
                .and_then(|byte| SecurityControlField::parse(*byte).ok())
                .is_some_and(|scf| scf.service == SecureServiceType::SyncResponse)
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
            Some(Pending::TlRequest { matcher, response_deadline, expects_response, tool_key_rotation, tx }) => {
                if expects_response && matcher.matches(internal) {
                    if let Some(new_key) = tool_key_rotation {
                        self.security.commit_tool_key(self.tl.remote(), new_key);
                    }
                    let _ = tx.send(Ok(internal.to_vec()));
                } else {
                    self.pending = Some(Pending::TlRequest {
                        matcher,
                        response_deadline,
                        expects_response,
                        tool_key_rotation,
                        tx,
                    });
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
        // Set when an action decides the connection must go down (secure
        // unwrap failure); the disconnect is fed to the state machine only
        // after this batch's deferred state transition has been applied.
        let mut abort_connection = false;
        // `ConfirmConnect` is emitted before the state machine's deferred
        // CONNECTING -> OPEN_IDLE transition is applied. A connected sync
        // request is only valid after that transition.
        let mut start_sync_after_transition = false;

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
                    if !success {
                        if let Some(Pending::TlOpen { dest, tx, .. }) = self.pending.take() {
                            let _ = tx.send(Err(Error::TransportConnectFailed(dest)));
                        }
                    } else if let Some(Pending::TlOpen { dest, force_sync, .. }) = &self.pending {
                        // A secure management connection is not exposed until
                        // both peers have established their sequence state.
                        // Only an immediately preceding sync of this exact
                        // credential may suppress another wire exchange.
                        match self.security.make_channel(*dest) {
                            Ok(Some(channel)) => {
                                let reuse_recent_sync = !*force_sync && self.security.has_fresh_sync(*dest);
                                self.tl_security = Some(channel);
                                if reuse_recent_sync {
                                    log::debug!("reusing a recently synchronized secure credential");
                                    if let Some(Pending::TlOpen { tx, .. }) = self.pending.take() {
                                        let _ = tx.send(Ok(TlOpenResult { remote_next_sequence: None }));
                                    }
                                } else {
                                    start_sync_after_transition = true;
                                }
                            }
                            Ok(None) => {
                                if let Some(Pending::TlOpen { tx, .. }) = self.pending.take() {
                                    let _ = tx.send(Ok(TlOpenResult { remote_next_sequence: None }));
                                }
                            }
                            Err(SecureError::MissingKey) => {
                                if let Some(Pending::TlOpen { tx, .. }) = self.pending.take() {
                                    let _ = tx.send(Err(Error::SecurityMissingKey));
                                }
                                self.close_tl_connection().await?;
                            }
                            Err(e) => {
                                log::error!("secure channel setup failed: {e}");
                                if let Some(Pending::TlOpen { tx, .. }) = self.pending.take() {
                                    let _ = tx.send(Err(Error::SecurityMissingKey));
                                }
                                self.close_tl_connection().await?;
                            }
                        }
                    }
                }
                TlAction::ConfirmData { success, .. } => {
                    if self.tl_sync.as_ref().is_some_and(|sync| sync.connected) {
                        if success {
                            // Start the application response timer only after
                            // the peer acknowledged this connected sync PDU.
                            self.tl_sync_deadline = Some(Instant::now() + SYNC_ATTEMPT_TIMEOUT);
                        } else {
                            self.fail_secure_sync(Error::NegativeConfirmation).await?;
                        }
                        continue;
                    }
                    if let Some(Pending::TlRequest { matcher, expects_response, tool_key_rotation, tx, .. }) =
                        self.pending.take()
                    {
                        if !success {
                            let _ = tx.send(Err(Error::NegativeConfirmation));
                        } else if expects_response {
                            // ACKed; now wait for the response frame.
                            self.pending = Some(Pending::TlRequest {
                                matcher,
                                response_deadline: Some(Instant::now() + RESPONSE_TIMEOUT),
                                expects_response,
                                tool_key_rotation,
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
                    self.clear_secure_state();
                    match self.pending.take() {
                        Some(Pending::TlOpen { dest, tx, .. }) => {
                            drop(tx.send(Err(Error::TransportConnectFailed(dest))))
                        }
                        Some(Pending::TlRequest { tx, .. }) => drop(tx.send(Err(Error::TransportClosed))),
                        other => self.pending = other,
                    }
                }
                TlAction::IndicateData { .. } => {
                    if let Some(frame) = data_frame {
                        if let Some(sec) = self.tl_security.as_mut() {
                            match decode_apci_code(frame) {
                                Some(ApciCode::SecureService) => {
                                    log::trace!(
                                        "received secure connected frame ({} bytes): {:02X?}",
                                        frame.len(),
                                        frame
                                    );
                                    match sec.unwrap(frame) {
                                        Ok((plain, new_table_seq)) => {
                                            if let Some(serial) = sec.serial().copied() {
                                                self.security.save_device_seq(&serial, new_table_seq)?;
                                            }
                                            self.feed_pending_response(&plain);
                                        }
                                        Err(SecureError::Replay { received, expected }) => {
                                            log::warn!(
                                                "dropping replayed secure frame (seq {received}, expected >= {expected})"
                                            );
                                        }
                                        Err(e) => {
                                            log::warn!("secure unwrap failed: {e} — closing connection");
                                            if let Some(pending) = self.pending.take() {
                                                pending.fail(Error::SecurityMacMismatch);
                                            }
                                            // Deferred: we're mid-action-batch, the
                                            // disconnect runs after apply_state.
                                            abort_connection = true;
                                        }
                                    }
                                }
                                _ => {
                                    // A device in secure mode never answers
                                    // tool traffic plain; accepting this would
                                    // be a downgrade path.
                                    log::warn!("dropping plaintext frame on secure connection");
                                }
                            }
                        } else {
                            self.feed_pending_response(frame);
                        }
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

        if abort_connection {
            self.close_tl_connection().await?;
        } else if start_sync_after_transition {
            self.start_secure_sync().await?;
        }
        Ok(())
    }

    /// Actively close the open TL connection (E26) and drop any secure
    /// state riding on it.
    ///
    /// Boxed because it re-enters `execute_tl` for the disconnect's own
    /// action batch (async recursion needs a pinned indirection).
    fn close_tl_connection(&mut self) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            self.clear_secure_state();
            if !self.tl.is_closed() {
                let dest = self.tl.remote();
                let result = self.tl.feed(TlEvent::RequestDisconnect { dest });
                self.execute_tl(result, None).await?;
            }
            Ok(())
        })
    }

    fn clear_secure_state(&mut self) {
        self.tl_security = None;
        self.tl_sync = None;
        self.tl_sync_deadline = None;
    }

    // ========================================================================
    // Data Secure sync handshake
    // ========================================================================

    /// Send an S-A_Sync_Req before exposing a secure connection.
    async fn start_secure_sync(&mut self) -> Result<()> {
        let mut challenge = [0u8; 6];
        getrandom::fill(&mut challenge).expect("OS CSPRNG is available");
        let connected = self.secure_sync_is_connected();
        self.tl_sync = Some(SyncPending { challenge, retry_count: 0, connected });
        self.send_secure_sync_attempt().await
    }

    /// Application Layer §5.3.2 requires point-to-point sync to use the
    /// existing connection's communication mode. Only initial FDSK access
    /// remains a serial-addressed system broadcast outside TL.
    fn secure_sync_is_connected(&self) -> bool {
        let remote = self.tl.remote();
        !self.security.get_entry(remote).is_some_and(|entry| entry.tool_key().is_none() && entry.fdsk().is_some())
    }

    async fn send_secure_sync_attempt(&mut self) -> Result<()> {
        let sync = self.tl_sync.as_ref().expect("sync state exists before sending");
        let frame = self.build_secure_sync_frame(&sync.challenge);
        if sync.connected {
            self.tl_pending_frame = Some(frame);
            self.tl_sync_deadline = None;
            let dest = self.tl.remote();
            let result = self.tl.feed(TlEvent::RequestData { dest });
            Box::pin(self.execute_tl(result, None)).await
        } else {
            self.tl_sync_deadline = Some(Instant::now() + SYNC_ATTEMPT_TIMEOUT);
            self.send_internal(&frame).await
        }
    }

    /// Initial FDSK access is selected by serial number on system broadcast;
    /// an installed Tool Key uses the ordinary point-to-point form. Both
    /// forms establish the same per-peer sequence state for the open
    /// transport connection.
    fn build_secure_sync_frame(&self, challenge: &[u8; 6]) -> Vec<u8> {
        let remote = self.tl.remote();
        let sec = self.tl_security.as_ref().expect("secure channel is set before the sync starts");
        let sequence = seq_to_bytes(self.security.client_sequence());
        let factory_serial = self.security.get_entry(remote).and_then(|entry| {
            (entry.tool_key().is_none() && entry.fdsk().is_some()).then_some(entry.serial()).flatten()
        });
        match factory_serial {
            Some(serial) => {
                log::debug!("starting serial-addressed system-broadcast S-A_Sync for FDSK access");
                frames::build_system_broadcast_sync_req_frame(
                    self.info.assigned_address,
                    &serial,
                    sec.key(),
                    &sequence,
                    challenge,
                )
            }
            None => {
                let tpci = Tpci::DataConnected(self.tl.send_seq());
                let serial = sec.serial().copied().unwrap_or([0; 6]);

                log::debug!("starting serial-qualified point-to-point S-A_Sync for Tool Key access");
                frames::build_sync_req_frame(
                    self.info.assigned_address,
                    remote,
                    tpci,
                    &serial,
                    sec.key(),
                    &sequence,
                    challenge,
                )
            }
        }
    }

    async fn fail_secure_sync(&mut self, error: Error) -> Result<()> {
        self.tl_sync = None;
        self.tl_sync_deadline = None;
        match self.pending.take() {
            Some(Pending::TlOpen { tx, .. }) => drop(tx.send(Err(error))),
            other => self.pending = other,
        }
        self.close_tl_connection().await
    }

    /// Verify the `S-A_Sync_Res`, adopt both counters, and resolve the pending
    /// open or explicit synchronization.
    ///
    /// `seq_nr_remote` is deliberately kept in two forms. The channel and
    /// durable store retain a forward-only next-acceptable floor. The caller
    /// receives the exact authenticated wire value for project-image generation,
    /// even though 03/03/07 describes a live S-AL's receiver state as
    /// `SeqNrremote - 1`.
    async fn handle_sync_response(&mut self, frame: &[u8]) -> Result<()> {
        let Some(sync) = self.tl_sync.take() else {
            return Ok(());
        };
        self.tl_sync_deadline = None;

        let key = match &self.tl_security {
            Some(sec) => *sec.key(),
            None => return Ok(()),
        };

        let verified = SyncResRef::parse(frame).ok().and_then(|res| {
            // Random = our challenge XOR the response's
            // challenge_xor_random; it is the CCM nonce of the response
            // (03/03/07 §5.3.2).
            let cxr = res.challenge_xor_random();
            let mut random = [0u8; 6];
            for i in 0..6 {
                random[i] = sync.challenge[i] ^ cxr[i];
            }

            let mut payload = res.payload_enc();
            ccm::verify_and_decrypt_sync_res(
                &key,
                &random,
                res.src(),
                res.dst(),
                res.addr_type(),
                res.tpci_apci(),
                res.scf_byte(),
                &mut payload,
                &res.mac(),
            )
            .ok()
            .map(|()| payload)
        });

        let Some(payload) = verified else {
            log::warn!("S-A_Sync_Res verification failed — wrong key or malformed frame");
            match self.pending.take() {
                Some(Pending::TlOpen { tx, .. }) => drop(tx.send(Err(Error::SecurityMacMismatch))),
                other => self.pending = other,
            }
            return self.close_tl_connection().await;
        };

        let seq_nr_remote = seq_from_bytes(&payload[0..6].try_into().expect("6-byte slice"));
        let seq_nr_local = seq_from_bytes(&payload[6..12].try_into().expect("6-byte slice"));

        let (serial, table_seq) = {
            let sec = self.tl_security.as_mut().expect("checked above");
            (sec.serial().copied(), sec.apply_remote_sync(seq_nr_remote))
        };
        let client_seq = self.security.advance_client_sequence(seq_nr_local)?;
        if let Some(serial) = serial {
            self.security.save_device_seq(&serial, table_seq)?;
        }
        self.security.mark_synchronized(self.tl.remote());

        log::debug!("secure sync complete: client_seq={client_seq}, device_seq={table_seq}");
        match self.pending.take() {
            Some(Pending::TlOpen { tx, .. }) => {
                drop(tx.send(Ok(TlOpenResult { remote_next_sequence: Some(seq_nr_remote) })))
            }
            other => self.pending = other,
        }
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

        if let Some(deadline) = self.tl_sync_deadline
            && now >= deadline
        {
            self.tl_sync_deadline = None;
            if let Some(mut sync) = self.tl_sync.take() {
                let can_retry = sync.retry_count == 0 && !self.tl.is_closed();
                if can_retry {
                    // One retry with a fresh challenge — the first attempt
                    // may have fallen into the device's 1 s sync-response
                    // rate-limit window.
                    sync.retry_count = 1;
                    getrandom::fill(&mut sync.challenge).expect("OS CSPRNG is available");
                    self.tl_sync = Some(sync);
                    self.send_secure_sync_attempt().await?;
                } else {
                    log::warn!("S-A_Sync handshake timed out");
                    match self.pending.take() {
                        Some(Pending::TlOpen { tx, .. }) => drop(tx.send(Err(Error::SecuritySyncTimeout))),
                        other => self.pending = other,
                    }
                    // Nothing owns the connection once the open failed —
                    // close it rather than leaving it to hit ConnectionBusy.
                    self.close_tl_connection().await?;
                }
            }
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
            Some(Pending::TlRequest { matcher, response_deadline, expects_response, tool_key_rotation, tx }) => {
                if response_deadline.is_some_and(|d| now >= d) {
                    let _ = tx.send(Err(Error::Timeout));
                } else {
                    self.pending = Some(Pending::TlRequest {
                        matcher,
                        response_deadline,
                        expects_response,
                        tool_key_rotation,
                        tx,
                    });
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
