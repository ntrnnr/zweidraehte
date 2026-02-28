//! Device Management connection handler (ConnectionType 0x03).
//!
//! Processes cEMI Local Management frames (M_PropRead/M_PropWrite) by
//! delegating to a [`PropertyServiceHandler`]. Uses a trait object reference
//! so that no generics leak out of this module.

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, DynamicSender};
use embassy_time::Instant;

use crate::encoding::cemi::{self, CemiLocalMgmt, CemiMessageCode, CemiTransportBuilder};
use crate::messages::buffers::{Buffer, DynBufferManager};
use crate::messages::builder::{IndicationMessage, RequestMessage};
use crate::messages::knx::*;
use crate::messages::knxip::substructs::{CRD, CRI, DeviceManagementCRD};
use crate::messages::knxip::{
    ConnectionStatus, DeviceConfigurationAck, DeviceConfigurationAckBuilder, DeviceConfigurationRequest,
    DeviceConfigurationRequestBuilder, KNXnetIPServiceType,
};
use crate::{AccessContext, AccessSource};
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, PropertyServiceHandler,
};
use crate::util::packets::{ParseBuffer, SerializeBuffer};

use super::super::{PendingResponse, ServerError};
use super::{AcceptedConnection, ConnectionContext, ConnectionTransport, ConnectionTypeHandler, DataFrameAction, PendingAck};

// ============================================================================
// Handler
// ============================================================================

/// Handler for Device Management connections (ConnectionType 0x03).
///
/// Processes cEMI Local Management frames (M_PropRead/M_PropWrite) by
/// delegating to a [`PropertyServiceHandler`], and cEMI Transport Layer
/// frames (T_Data_Connected/T_Data_Individual) by converting them to
/// internal format and routing them through the application layer.
pub struct DeviceMgmtConnectionHandler<'a> {
    property_handler: &'a dyn PropertyServiceHandler,
    /// Sender to the application layer's indication channel, for cEMI Transport Layer mode.
    al_sender: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    /// Buffer manager for allocating internal message buffers.
    buffer_manager: &'a DynBufferManager<'static>,
    /// Channel ID of the active Device Management connection, if any.
    /// Only one Device Management connection is allowed at a time.
    active_channel: Option<u8>,
}

impl<'a> DeviceMgmtConnectionHandler<'a> {
    /// Create a new Device Management connection handler.
    pub fn new(
        property_handler: &'a dyn PropertyServiceHandler,
        al_sender: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        buffer_manager: &'a DynBufferManager<'static>,
    ) -> Self {
        Self { property_handler, al_sender, buffer_manager, active_channel: None }
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
        let message_code = CemiMessageCode::try_from(mc_byte).map_err(|_| {
            debug!("Unknown cEMI message code: 0x{:02x}", mc_byte);
            ConnectionStatus::DataConnectionError
        })?;

        // Transport Layer frames (T_Data_Individual.req, T_Data_Connected.req):
        // Convert to internal format and route through the application layer.
        if message_code.is_transport_layer() {
            return self.handle_cemi_transport(payload, message_code).await;
        }

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
    /// These frames carry APCI services (DeviceDescriptorRead, MemoryRead/Write,
    /// Authorize, etc.) from ETS via the Device Management connection. They are
    /// NOT full TL connections — no T_Connect/T_Disconnect, no sequence numbering.
    ///
    /// The flow is:
    /// 1. Convert cEMI transport frame to internal KNX message format using
    ///    `cemi_to_knx_message` (the 6 reserved zero bytes map to CTRL/SRC/DST/NPDU)
    /// 2. Apply post-fixups (CTRL, DST, address type, access level, service type)
    /// 3. Send as `Indication` (with response route) to the application layer
    /// 4. Await response on the local channel
    /// 5. Convert response back to cEMI transport format using `CemiTransportBuilder`
    async fn handle_cemi_transport(
        &self,
        payload: &[u8],
        message_code: CemiMessageCode,
    ) -> Result<Option<Buffer<'static>>, ConnectionStatus> {
        debug!("cEMI Transport Layer frame: {:?} ({} bytes)", message_code, payload.len());

        // Determine the internal service type based on the cEMI message code.
        // T_Data_Connected.req → T_Data_Ind (connection-oriented APCI services)
        // T_Data_Individual.req → T_DataUnack_Ind (connectionless APCI services)
        let service_type = match message_code {
            CemiMessageCode::TDataConnectedReq => ServiceType::T_Data_Ind,
            CemiMessageCode::TDataIndividualReq => ServiceType::T_DataUnack_Ind,
            _ => {
                debug!("Unexpected transport message code: {:?}", message_code);
                return Ok(None);
            }
        };

        // ================================================================
        // Inbound: cEMI transport → internal format
        // ================================================================

        // Allocate a buffer and copy the raw cEMI payload into it.
        // cemi_to_knx_message works in-place, converting the cEMI format
        // to internal format. The 6 reserved zero bytes in the cEMI transport
        // frame occupy the same positions as CTRL1+CTRL2+SRC+DST in cEMI L_Data,
        // so the conversion produces zeroed CTRL/SRC/DST/NPDU fields which we
        // then fix up below.
        let mut buf = self.buffer_manager.alloc_zeroed(payload.len()).await;
        buf[..payload.len()].copy_from_slice(payload);

        let buf = cemi::cemi_to_knx_message(buf);
        let mut msg = KnxMessageBuffer::new(buf, service_type);

        // Post-fixups: the conversion produced zeroed control fields, so set
        // the fields that matter for internal routing.

        // Set CTRL: standard frame, system priority (management traffic)
        msg.ctrl_field_mut().set_ft(FrameType::Standard);
        msg.ctrl_field_mut().set_priority(Priority::System);

        // Individual address type (these are point-to-point management services)
        msg.set_address_type(AddressType::Individual);

        // Full access for ETS Device Management connections.
        // TODO: Revisit when secure tunneling is implemented.
        msg.set_access_source(AccessSource::Explicit(AccessContext::MAX_ACCESS));

        let indication = IndicationMessage::indication(msg);

        // ================================================================
        // Route to AL with response route and await response
        // ================================================================

        // Create a stack-local channel for the response. Same transmute pattern
        // as ActorRequest::request() — the channel lives on this stack frame
        // and we guarantee it outlives the sender.
        let response_channel: Channel<NoopRawMutex, Option<RequestMessage<Buffer<'static>>>, 1> = Channel::new();
        let sender: DynamicSender<'_, Option<RequestMessage<Buffer<'static>>>> = response_channel.sender().into();

        // Safety: the channel lives on this stack frame and we await the
        // response before returning, so the sender cannot outlive the channel.
        let response_route = *unsafe {
            core::mem::transmute::<
                &DynamicSender<'_, Option<RequestMessage<Buffer<'static>>>>,
                &DynamicSender<'static, Option<RequestMessage<Buffer<'static>>>>,
            >(&sender)
        };

        let indication = indication.with_response_route(response_route);
        self.al_sender.send(indication).await;

        let response = response_channel.receive().await;

        // ================================================================
        // Outbound: internal format → cEMI transport
        // ================================================================

        let Some(response_msg) = response else {
            // No response generated (unrecognized APCI, write-only service, etc.)
            debug!("cEMI Transport: no response from AL");
            return Ok(None);
        };

        // Determine the .ind message code for the response
        let response_mc = message_code.to_indication().ok_or_else(|| {
            error!("No indication message code for {:?}", message_code);
            ConnectionStatus::DataConnectionError
        })?;

        // Extract TPDU from internal format: everything from offset MSG_TPCI onwards
        let tpdu = &response_msg.buf()[offsets::MSG_TPCI..];

        // Serialize using CemiTransportBuilder directly into a pool Buffer
        let builder = CemiTransportBuilder { message_code: response_mc, tpdu };

        let mut out = self.buffer_manager.alloc_no_headroom().await;
        out.serialize(&builder);

        debug!("cEMI Transport response: {:?} ({} bytes)", response_mc, out.len());
        Ok(Some(out))
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

        Ok(AcceptedConnection { crd: CRD::DeviceManagement(DeviceManagementCRD) })
    }

    fn close_connection(&mut self, channel_id: u8) {
        if self.active_channel == Some(channel_id) {
            debug!("Closed Device Management connection on channel {}", channel_id);
            self.active_channel = None;
        }
    }

    async fn on_data_frame(
        &mut self,
        _channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
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
