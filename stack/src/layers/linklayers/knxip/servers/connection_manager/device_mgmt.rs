//! Device Management connection handler (ConnectionType 0x03).
//!
//! Processes cEMI Local Management frames (M_PropRead/M_PropWrite) by
//! delegating to a [`PropertyServiceHandler`]. Uses a trait object reference
//! so that no generics leak out of this module.

use core::cell::RefCell;

use embassy_time::Instant;
use heapless::Vec;

use crate::encoding::cemi::{CemiLocalMgmt, CemiMessageCode};
use crate::messages::buffers::DynBufferManager;
use crate::messages::knxip::{
    ConnectionStatus, DeviceConfigurationAck, DeviceConfigurationAckBuilder,
    DeviceConfigurationRequest, DeviceConfigurationRequestBuilder, KNXnetIPServiceType,
};
use crate::messages::knxip::substructs::{CRD, CRI, DeviceManagementCRD};
use crate::objects::interface::PropertyServiceHandler;
use crate::util::packets::{ParseBuffer, SerializeBuffer};

use super::super::{PendingResponse, ServerError};
use super::{AcceptedConnection, ConnectionContext, ConnectionTypeHandler, DataFrameAction};

// ============================================================================
// Handler
// ============================================================================

/// Handler for Device Management connections (ConnectionType 0x03).
///
/// Processes cEMI Local Management frames (M_PropRead/M_PropWrite) by
/// delegating to a [`PropertyServiceHandler`]. Uses a trait object reference
/// so that no generics leak out of this module.
pub struct DeviceMgmtConnectionHandler<'a> {
    property_handler: &'a dyn PropertyServiceHandler,
}

impl<'a> DeviceMgmtConnectionHandler<'a> {
    /// Create a new Device Management connection handler.
    pub fn new(property_handler: &'a dyn PropertyServiceHandler) -> Self {
        Self { property_handler }
    }

    /// Parse and process a cEMI frame from a DeviceConfigurationRequest.
    ///
    /// Returns `Ok(Some(bytes))` when a cEMI response should be sent back,
    /// `Ok(None)` when the frame is recognized but no response is needed
    /// (the DeviceConfigurationRequest is still ACKed), or `Err` on failure.
    fn process_cemi_frame(&self, payload: &[u8]) -> Result<Option<Vec<u8, 64>>, ConnectionStatus> {
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
        // Per KNX spec 03/08/03 §2.6.1.3, if cEMI Transport Layer mode is not
        // (yet) supported, the frame is silently ignored but the
        // DEVICE_CONFIGURATION_REQUEST is still ACKed.
        if message_code.is_transport_layer() {
            // TODO: Implement cEMI Transport Layer mode (KNX spec 03/08/03 §2.6).
            // These frames should be injected into the transport layer, bypassing
            // the network layer entirely (they carry no source/destination addresses).
            // See SESSION.md for architectural notes.
            debug!(
                "cEMI Transport Layer frame ignored (not yet supported): {:?}",
                message_code
            );
            return Ok(None);
        }

        // Local Management frames (M_PropRead/M_PropWrite)
        let mut buf = payload;
        let frame = buf.parse::<CemiLocalMgmt<_>>().map_err(|_| {
            debug!("Failed to parse cEMI Local Management frame ({} bytes)", payload.len());
            ConnectionStatus::DataConnectionError
        })?;

        // TODO: Proper object type → index translation. Currently uses
        // object_instance - 1 as the index, which works when each object
        // type has exactly one instance (the common case).
        let object_idx = if frame.object_instance > 0 { (frame.object_instance - 1) as u16 } else { 0 };

        match frame.message_code {
            CemiMessageCode::MPropReadReq => self.handle_prop_read(&frame, object_idx).map(Some),
            CemiMessageCode::MPropWriteReq => self.handle_prop_write(&frame, object_idx).map(Some),
            _ => {
                debug!("Unsupported cEMI message code: {:?}", frame.message_code);
                Err(ConnectionStatus::DataConnectionError)
            }
        }
    }

    /// Build a DeviceConfigurationAck as a `PendingResponse`.
    async fn build_ack(
        &self,
        channel_id: u8,
        sequence_counter: u8,
        status: ConnectionStatus,
        conn: &ConnectionContext,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> PendingResponse {
        let builder = DeviceConfigurationAckBuilder::new(channel_id, sequence_counter, status);
        let mut buffer = buffer_manager.borrow().alloc().await;
        buffer.serialize(&builder);
        PendingResponse {
            buffer,
            destination: conn.data_endpoint,
            socket_idx: conn.socket_idx,
        }
    }

    fn handle_prop_read(
        &self,
        frame: &CemiLocalMgmt<&[u8]>,
        object_idx: u16,
    ) -> Result<Vec<u8, 64>, ConnectionStatus> {
        // Read the property value into a temp buffer
        let mut data_buf = [0u8; 52]; // Leave room for the 7-byte header in the 64-byte response
        // Access level 0 = full access for ETS device management connections.
        // TODO: Revisit when secure tunneling is implemented.
        let response_builder = match self.property_handler.property_value_read(
            object_idx,
            frame.property_id,
            frame.start_index,
            frame.count,
            &mut data_buf,
            0,
        ) {
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

        // Serialize the response into a heapless Vec
        let mut response_bytes = [0u8; 64];
        let mut cursor = &mut response_bytes[..];
        let (written, _) = cursor.serialize(&response_builder);
        let len = written.len();
        let mut result = Vec::new();
        let _ = result.extend_from_slice(&response_bytes[..len]);
        Ok(result)
    }

    fn handle_prop_write(
        &self,
        frame: &CemiLocalMgmt<&[u8]>,
        object_idx: u16,
    ) -> Result<Vec<u8, 64>, ConnectionStatus> {
        let response_builder = match self.property_handler.property_value_write(
            object_idx,
            frame.property_id,
            frame.start_index,
            frame.data,
            0,
        ) {
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

        // Serialize the response into a heapless Vec
        let mut response_bytes = [0u8; 64];
        let mut cursor = &mut response_bytes[..];
        let (written, _) = cursor.serialize(&response_builder);
        let len = written.len();
        let mut result = Vec::new();
        let _ = result.extend_from_slice(&response_bytes[..len]);
        Ok(result)
    }
}

impl ConnectionTypeHandler for DeviceMgmtConnectionHandler<'_> {
    fn accept_connection(
        &mut self,
        _channel_id: u8,
        _cri: &CRI,
    ) -> Result<AcceptedConnection, ConnectionStatus> {
        // Device Management CRI has no additional fields beyond the header.
        // Accept unconditionally — the connection manager enforces max connections.
        Ok(AcceptedConnection {
            crd: CRD::DeviceManagement(DeviceManagementCRD),
        })
    }

    fn close_connection(&mut self, _channel_id: u8) {
        // No per-connection resources to release for device management
    }

    async fn on_data_frame(
        &mut self,
        _channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<DataFrameAction, ServerError> {
        // Parse the DeviceConfigurationRequest header (consumes KNXnet/IP + connection headers)
        let mut buf = &data[..];
        let request = match buf.parse::<DeviceConfigurationRequest>() {
            Ok(req) => req,
            Err(_) => return Err(ServerError::ParseError),
        };

        let sequence_counter = request.sequence_counter;
        let expected_seq = conn.recv_sequence_counter;

        // Validate sequence counter
        let is_retransmission = sequence_counter == expected_seq.wrapping_sub(1);
        let is_expected = sequence_counter == expected_seq;

        if !is_expected && !is_retransmission {
            debug!(
                "Sequence counter mismatch: got {}, expected {} (channel {})",
                sequence_counter, expected_seq, conn.channel_id
            );
            let ack = self.build_ack(
                conn.channel_id, sequence_counter,
                ConnectionStatus::DataConnectionError,
                conn, buffer_manager,
            ).await;
            return Ok(DataFrameAction::AckOnly(ack));
        }

        // Extract cEMI payload: everything after KNXnet/IP header (6) + connection header (4)
        let cemi_offset = 6 + 4;
        let cemi_payload = if data.len() > cemi_offset { &data[cemi_offset..] } else { &[] };

        // Process the frame (only if not a retransmission)
        let response_cemi = if is_expected {
            conn.recv_sequence_counter = expected_seq.wrapping_add(1);
            conn.last_activity = Instant::now();

            match self.process_cemi_frame(cemi_payload) {
                Ok(response) => response,
                Err(status) => {
                    let ack = self.build_ack(
                        conn.channel_id, sequence_counter, status,
                        conn, buffer_manager,
                    ).await;
                    return Ok(DataFrameAction::AckOnly(ack));
                }
            }
        } else {
            // Retransmission: just re-ACK, don't re-process
            None
        };

        // Build responses
        let mut responses = Vec::new();

        // 1. ACK
        let ack_builder = DeviceConfigurationAckBuilder::new(
            conn.channel_id, sequence_counter, ConnectionStatus::NoError,
        );
        let mut ack_buffer = buffer_manager.borrow().alloc().await;
        ack_buffer.serialize(&ack_builder);
        let _ = responses.push(PendingResponse {
            buffer: ack_buffer,
            destination: conn.data_endpoint,
            socket_idx: conn.socket_idx,
        });

        // 2. If handler returned a response, send it as a DeviceConfigurationRequest
        //    (server → client direction) with the cEMI payload embedded.
        if let Some(cemi_response) = response_cemi {
            let send_seq = conn.send_sequence_counter;
            conn.send_sequence_counter = send_seq.wrapping_add(1);

            let req_builder = DeviceConfigurationRequestBuilder::with_payload(
                conn.channel_id, send_seq, &cemi_response,
            );

            let mut resp_buffer = buffer_manager.borrow().alloc().await;
            resp_buffer.serialize(&req_builder);

            let _ = responses.push(PendingResponse {
                buffer: resp_buffer,
                destination: conn.data_endpoint,
                socket_idx: conn.socket_idx,
            });
        }

        Ok(DataFrameAction::Responses(responses))
    }

    fn on_data_ack(
        &mut self,
        _channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        let mut buf = &data[..];
        let ack = match buf.parse::<DeviceConfigurationAck>() {
            Ok(a) => a,
            Err(_) => return Err(ServerError::ParseError),
        };

        conn.last_activity = Instant::now();
        // TODO: Implement retransmission tracking — verify this ACK matches
        // our last sent sequence number, and handle timeout/retransmission
        // if the ACK doesn't arrive.
        trace!(
            "DeviceConfigurationAck: channel={}, seq={}, status={:?}",
            ack.communication_channel_id, ack.sequence_counter, ack.status
        );
        Ok(())
    }

    fn handled_service_types(&self) -> &[KNXnetIPServiceType] {
        &[
            KNXnetIPServiceType::DeviceConfigurationRequest,
            KNXnetIPServiceType::DeviceConfigurationAck,
        ]
    }
}
