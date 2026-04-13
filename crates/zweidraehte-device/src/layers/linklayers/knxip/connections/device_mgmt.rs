//! Device Management connection handler (ConnectionType 0x03).
//!
//! Processes cEMI Local Management frames (M_PropRead/M_PropWrite) by
//! delegating to a [`PropertyServiceHandler`]. Uses a trait object reference
//! so that no generics leak out of this module.

use embassy_time::Instant;

use embassy_sync::channel::DynamicSender;

use zweidraehte_proto::encoding::cemi::{CemiLocalMgmt, CemiMessageCode};
use crate::layers::transport::cemi::CemiEvent;
use zweidraehte_proto::messages::buffers::{Buffer, DynBufferManager, MessageBuffer};
use zweidraehte_proto::messages::knxip::substructs::{CRD, CRI, DeviceManagementCRD};
use zweidraehte_proto::messages::knxip::{
    ConnectionStatus, DeviceConfigurationAck, DeviceConfigurationAckBuilder, DeviceConfigurationRequest,
    DeviceConfigurationRequestBuilder, KNXnetIPServiceType,
};
use zweidraehte_proto::AccessContext;
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, PropertyServiceHandler,
};
use zweidraehte_proto::util::packets::{ParseBuffer, SerializeBuffer};

use super::super::types::{PendingResponse, ServerError};
use super::{AcceptedConnection, ConnectionContext, ConnectionTransport, ConnectionTypeHandler, DataFrameAction, PendingAck};

// ============================================================================
// Handler
// ============================================================================

/// Handler for Device Management connections (ConnectionType 0x03).
///
/// Processes cEMI Local Management frames (M_PropRead/M_PropWrite) by
/// delegating to a [`PropertyServiceHandler`].
///
/// cEMI Transport Layer frames (T_Data_Connected/T_Data_Individual) are
/// forwarded to the [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer)
/// via the `cemi_event_sender` channel. The CemiTL patches the message code
/// from `.req` to `.ind` and routes the frame to the Application Layer.
/// AL responses flow back through the `cemi_response` channel and are
/// picked up by the KNX/IP runtime.
pub struct DeviceMgmtConnectionHandler<'a> {
    property_handler: &'a dyn PropertyServiceHandler,
    /// Buffer manager for allocating internal message buffers.
    buffer_manager: &'a DynBufferManager<'static>,
    /// Channel ID of the active Device Management connection, if any.
    /// Only one Device Management connection is allowed at a time.
    active_channel: Option<u8>,
    /// Sender for cEMI events to the CemiTransportLayer.
    cemi_event_sender: DynamicSender<'a, CemiEvent>,
}

impl<'a> DeviceMgmtConnectionHandler<'a> {
    /// Create a new Device Management connection handler.
    pub fn new(
        property_handler: &'a dyn PropertyServiceHandler,
        buffer_manager: &'a DynBufferManager<'static>,
        cemi_event_sender: DynamicSender<'a, CemiEvent>,
    ) -> Self {
        Self { property_handler, buffer_manager, active_channel: None, cemi_event_sender }
    }

    /// Parse and process a cEMI frame from a DeviceConfigurationRequest.
    ///
    /// Returns `Ok(Some(bytes))` when a cEMI response should be sent back,
    /// `Ok(None)` when the frame is recognized but no response is needed
    /// (the DeviceConfigurationRequest is still ACKed), or `Err` on failure.
    async fn process_cemi_frame(&self, payload: &[u8]) -> Result<Option<Buffer<'static>>, ConnectionStatus> {
        // Peek at the message code to determine the frame type before parsing,
        // since Local Management and Transport Layer frames have different
        // wire formats.
        let mc_byte = *payload.first().ok_or_else(|| {
            debug!("Empty cEMI payload");
            ConnectionStatus::DataConnectionError
        })?;
        let message_code = CemiMessageCode::from(mc_byte);

        // Transport Layer frames (T_Data_Individual.req, T_Data_Connected.req):
        // Convert to internal format and route through the application layer.
        if message_code.is_transport_layer() {
            debug!("cEMI: TL frame {:?} ({} bytes)", message_code, payload.len());
            return self.handle_cemi_transport(payload, message_code).await;
        }

        debug!("cEMI: Local Management frame {:?} ({} bytes)", message_code, payload.len());
        // Local Management frames (M_PropRead/M_PropWrite)
        let mut buf = payload;
        let frame = buf.parse::<CemiLocalMgmt<_>>().map_err(|_| {
            debug!("Failed to parse cEMI Local Management frame ({} bytes)", payload.len());
            ConnectionStatus::DataConnectionError
        })?;

        let object_idx = self.property_handler.resolve_object_index(frame.object_type, frame.object_instance)
            .ok_or_else(|| {
                debug!(
                    "Unknown interface object: type=0x{:04x}, instance={}",
                    frame.object_type, frame.object_instance
                );
                ConnectionStatus::DataConnectionError
            })?;

        let mut out = self.buffer_manager.alloc_no_headroom().await;

        match frame.message_code {
            CemiMessageCode::MPropReadReq => self.handle_prop_read(&frame, object_idx, &mut out)?,
            CemiMessageCode::MPropWriteReq => self.handle_prop_write(&frame, object_idx, &mut out)?,
            _ => {
                debug!("Unsupported cEMI message code: {:?}", frame.message_code);
                return Err(ConnectionStatus::DataConnectionError);
            }
        }

        Ok(Some(out))
    }

    /// Handle a cEMI Transport Layer frame (T_Data_Connected.req / T_Data_Individual.req).
    ///
    /// Patches the message code from `.req` to `.ind` and forwards the full
    /// cEMI TL frame to the [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer)
    /// via the event channel. The CemiTL converts it to internal format and
    /// delivers it to AL.
    ///
    /// Returns `Ok(None)` — no immediate cEMI response. The AL's response
    /// will arrive asynchronously via the cemi_response channel and be
    /// sent by the KNX/IP runtime as a separate DeviceConfigurationRequest.
    async fn handle_cemi_transport(
        &self,
        payload: &[u8],
        message_code: CemiMessageCode,
    ) -> Result<Option<Buffer<'static>>, ConnectionStatus> {
        // Patch .req → .ind in the message code byte.
        let ind_code = message_code.to_indication().ok_or_else(|| {
            debug!("cEMI TL: not a .req code: {:?}", message_code);
            ConnectionStatus::DataConnectionError
        })?;

        // Allocate a buffer and copy the frame with the patched message code.
        let mut buf = self.buffer_manager.alloc_no_headroom().await;
        buf.fill_from_slice(payload);
        // Overwrite message code byte with .ind variant
        buf[0] = ind_code.into();

        // Send to CemiTransportLayer. Use try_send — if the channel is
        // full, the previous frame hasn't been consumed yet. Drop this
        // frame and let the cEMI client retransmit.
        if self.cemi_event_sender.try_send(CemiEvent::Frame(buf)).is_err() {
            warn!("cEMI TL: event channel full, dropping frame");
            return Err(ConnectionStatus::DataConnectionError);
        }

        // No immediate cEMI response — ACK only.
        Ok(None)
    }

    /// Build a DeviceConfigurationAck as a `PendingResponse`.
    async fn build_ack(
        &self,
        channel_id: u8,
        sequence_counter: u8,
        status: ConnectionStatus,
        conn: &ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> PendingResponse {
        let builder = DeviceConfigurationAckBuilder::new(channel_id, sequence_counter, status);
        let mut buffer = buffer_manager.alloc().await;
        buffer.serialize(&builder);
        PendingResponse {
            buffer,
            target: conn.response_target(),
        }
    }

    fn handle_prop_read(
        &self,
        frame: &CemiLocalMgmt<&[u8]>,
        object_idx: u16,
        out: &mut Buffer<'_>,
    ) -> Result<(), ConnectionStatus> {
        // Read the property value into a temp buffer
        let mut data_buf = [0u8; 52]; // Leave room for the 7-byte header
        // Full access for ETS device management connections.
        // TODO: Revisit when secure tunneling is implemented.
        let req = FullPropertyReadRequest {
            object_idx,
            pid: frame.property_id,
            start_idx: frame.start_index,
            count: frame.count,
            ctx: AccessContext::MAX_ACCESS,
        };
        let response_builder = match self.property_handler.property_value_read(&req, &mut data_buf) {
            Ok(bytes_read) => {
                // Success: echo count + start_index from request, append read data
                frame.response_builder(frame.count, frame.start_index, &data_buf[..bytes_read])
            }
            Err(_e) => {
                // Error: count=0 signals error, keep start index
                debug!(
                    "Property read error: obj={} pid={} start={}: {:?}",
                    object_idx, frame.property_id, frame.start_index, _e
                );
                frame.response_builder(0, frame.start_index, &[])
            }
        };

        out.serialize(&response_builder);
        Ok(())
    }

    fn handle_prop_write(
        &self,
        frame: &CemiLocalMgmt<&[u8]>,
        object_idx: u16,
        out: &mut Buffer<'_>,
    ) -> Result<(), ConnectionStatus> {
        let req = FullPropertyWriteRequest {
            object_idx,
            pid: frame.property_id,
            count: frame.count,
            start_idx: frame.start_index,
            data: frame.data,
            ctx: AccessContext::MAX_ACCESS,
        };
        let response_builder = match self.property_handler.property_value_write(&req) {
            Ok(_write_response) => {
                // Success: echo back the count + start index and the written data
                frame.response_builder(frame.count, frame.start_index, frame.data)
            }
            Err(_e) => {
                // Error: count=0 signals error
                debug!(
                    "Property write error: obj={} pid={} start={}: {:?}",
                    object_idx, frame.property_id, frame.start_index, _e
                );
                frame.response_builder(0, frame.start_index, &[])
            }
        };

        out.serialize(&response_builder);
        Ok(())
    }
}

impl ConnectionTypeHandler for DeviceMgmtConnectionHandler<'_> {
    fn accept_connection(&mut self, channel_id: u8, _cri: &CRI) -> Result<AcceptedConnection, ConnectionStatus> {
        // Only one Device Management connection at a time.
        if let Some(existing) = self.active_channel {
            debug!("Rejecting Device Management connection: already active on channel {}", existing);
            return Err(ConnectionStatus::NoMoreConnections);
        }

        self.active_channel = Some(channel_id);
        debug!("Accepted Device Management connection on channel {}", channel_id);

        // Activate cEMI TL mode — force-close bus connections and route
        // connection-oriented traffic through the cEMI path.
        if self.cemi_event_sender.try_send(CemiEvent::Activate).is_err() {
            warn!("cEMI TL: failed to send Activate (channel full)");
        }

        Ok(AcceptedConnection { crd: CRD::DeviceManagement(DeviceManagementCRD) })
    }

    fn close_connection(&mut self, channel_id: u8) {
        if self.active_channel == Some(channel_id) {
            debug!("Closed Device Management connection on channel {}", channel_id);
            self.active_channel = None;

            // Deactivate cEMI TL mode — unlock bus connections.
            if self.cemi_event_sender.try_send(CemiEvent::Deactivate).is_err() {
                warn!("cEMI TL: failed to send Deactivate (channel full)");
            }
        }
    }

    async fn on_data_frame(
        &mut self,
        _channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
        debug!("DevMgmt raw data ({} bytes): {:?}", data.len(), zweidraehte_util::fmt::Bytes(data));
        // Parse the DeviceConfigurationRequest header (consumes KNXnet/IP + connection headers)
        let mut buf = data;
        let request = match buf.parse::<DeviceConfigurationRequest>() {
            Ok(req) => req,
            Err(_) => return Err(ServerError::ParseError),
        };

        let sequence_counter = request.sequence_counter;
        let expected_seq = conn.recv_sequence_counter;

        // Per KNX spec 3/8/2 §8.4.3.4: TCP provides reliable ordered delivery,
        // so sequence counter validation is skipped for TCP connections.
        let is_tcp = matches!(conn.transport, ConnectionTransport::Tcp { .. });
        let is_retransmission = !is_tcp && sequence_counter == expected_seq.wrapping_sub(1);
        let is_expected = is_tcp || sequence_counter == expected_seq;

        if !is_expected && !is_retransmission {
            debug!(
                "Sequence counter mismatch: got {}, expected {} (channel {})",
                sequence_counter, expected_seq, conn.channel_id
            );
            let ack = self
                .build_ack(
                    conn.channel_id,
                    sequence_counter,
                    ConnectionStatus::DataConnectionError,
                    conn,
                    buffer_manager,
                )
                .await;
            return Ok(DataFrameAction::AckOnly(ack));
        }

        // Extract cEMI payload: everything after KNXnet/IP header (6) + connection header (4)
        let cemi_offset = 6 + 4;
        let cemi_payload = if data.len() > cemi_offset { &data[cemi_offset..] } else { &[] };

        // Process the frame (only if not a retransmission)
        let response_cemi = if is_expected {
            conn.recv_sequence_counter = expected_seq.wrapping_add(1);
            conn.last_activity = Instant::now();

            match self.process_cemi_frame(cemi_payload).await {
                Ok(response) => response,
                Err(status) => {
                    let ack = self.build_ack(conn.channel_id, sequence_counter, status, conn, buffer_manager).await;
                    return Ok(DataFrameAction::AckOnly(ack));
                }
            }
        } else {
            // Retransmission: just re-ACK, don't re-process
            None
        };

        // Build responses. Use try_alloc for ACK and data response buffers
        // to avoid blocking — if no buffer is available, the remote side will
        // retransmit and we'll try again.
        let mut responses = heapless::Vec::<_, 4>::new();

        // 1. ACK
        let ack_builder =
            DeviceConfigurationAckBuilder::new(conn.channel_id, sequence_counter, ConnectionStatus::NoError);
        if let Some(mut ack_buffer) = buffer_manager.try_alloc() {
            ack_buffer.serialize(&ack_builder);
            let _ = responses.push(PendingResponse {
                buffer: ack_buffer,
                target: conn.response_target(),
            });
        } else {
            warn!("DevMgmt: skipping ACK for channel {} (no free buffers)", conn.channel_id);
        }

        // 2. If handler returned a response, send it as a DeviceConfigurationRequest
        //    (server → client direction) with the cEMI payload embedded.
        if let Some(cemi_response) = response_cemi {
            let send_seq = conn.send_sequence_counter;
            conn.send_sequence_counter = send_seq.wrapping_add(1);

            let req_builder =
                DeviceConfigurationRequestBuilder::with_payload(conn.channel_id, send_seq, &cemi_response);

            if let Some(mut resp_buffer) = buffer_manager.try_alloc() {
                resp_buffer.serialize(&req_builder);
                let target = conn.response_target();

                // For UDP connections, save a copy for retransmission if the
                // client doesn't ACK within the timeout. If no buffer is
                // available for the copy, fall back to fire-and-forget.
                if matches!(conn.transport, ConnectionTransport::Udp)
                    && let Some(retransmit_buffer) = buffer_manager.try_alloc_from_slice(&resp_buffer)
                {
                    conn.pending_ack = Some(PendingAck {
                        sequence_counter: send_seq,
                        buffer: retransmit_buffer,
                        target,
                        sent_at: Instant::now(),
                        attempt: 0,
                    });
                }

                let _ = responses.push(PendingResponse {
                    buffer: resp_buffer,
                    target,
                });
            } else {
                warn!("DevMgmt: skipping data response for channel {} (no free buffers)", conn.channel_id);
            }
        }

        debug!("DevMgmt on_data_frame: returning {} response(s)", responses.len());
        Ok(DataFrameAction::Responses(responses))
    }

    fn on_data_ack(&mut self, _channel_id: u8, data: &[u8], conn: &mut ConnectionContext) -> Result<(), ServerError> {
        let mut buf = data;
        let ack = match buf.parse::<DeviceConfigurationAck>() {
            Ok(a) => a,
            Err(_) => return Err(ServerError::ParseError),
        };

        conn.last_activity = Instant::now();

        // Verify the ACK matches our pending outgoing frame.
        if let Some(pending) = &conn.pending_ack {
            if ack.sequence_counter == pending.sequence_counter {
                if ack.status == ConnectionStatus::NoError {
                    trace!(
                        "DeviceConfigurationAck: channel={}, seq={} — acknowledged",
                        ack.communication_channel_id, ack.sequence_counter
                    );
                } else {
                    warn!(
                        "DeviceConfigurationAck: channel={}, seq={}, error status {:?}",
                        ack.communication_channel_id, ack.sequence_counter, ack.status
                    );
                }
                // Clear the pending frame — either successfully ACKed or
                // explicitly rejected (don't retransmit a rejected frame).
                conn.pending_ack = None;
            } else {
                warn!(
                    "DeviceConfigurationAck: channel={}, seq={} doesn't match pending seq {}",
                    ack.communication_channel_id, ack.sequence_counter, pending.sequence_counter
                );
            }
        } else {
            trace!(
                "DeviceConfigurationAck: channel={}, seq={} (no pending frame)",
                ack.communication_channel_id, ack.sequence_counter
            );
        }

        Ok(())
    }

    fn handled_service_types(&self) -> &[KNXnetIPServiceType] {
        &[KNXnetIPServiceType::DeviceConfigurationRequest, KNXnetIPServiceType::DeviceConfigurationAck]
    }
}
