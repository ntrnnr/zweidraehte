//! Device Management connection handler (ConnectionType 0x03).
//!
//! Processes cEMI Local Management frames (M_PropRead/M_PropWrite) by
//! delegating to a [`PropertyServiceHandler`]. Uses a trait object reference
//! so that no generics leak out of this module.

use core::cell::RefCell;

use embassy_time::Instant;
use heapless::Vec;

use crate::messages::buffers::{DynBufferManager, MessageBuffer};
use crate::messages::knxip::{
    ConnectionStatus, DeviceConfigurationAck, DeviceConfigurationAckBuilder,
    DeviceConfigurationRequest, DeviceConfigurationRequestBuilder, KNXnetIPServiceType,
};
use crate::messages::knxip::substructs::ConnectionType;
use crate::objects::interface::PropertyServiceHandler;
use crate::util::packets::{ParseBuffer, SerializeBuffer};

use super::super::{PendingResponse, ServerError};
use super::{AcceptedConnection, ConnectionContext, ConnectionTypeHandler, DataFrameAction};

// ============================================================================
// cEMI Local Management message codes
// ============================================================================

mod cemi_local {
    pub const M_PROP_READ_REQ: u8 = 0xFC;
    pub const M_PROP_READ_CON: u8 = 0xFB;
    pub const M_PROP_WRITE_REQ: u8 = 0xF6;
    pub const M_PROP_WRITE_CON: u8 = 0xF5;
}

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

    /// Parse and process a cEMI Local Management frame, returning a response frame.
    ///
    /// Frame format:
    /// - Byte 0: message code (0xFC = M_PropRead.req, 0xF6 = M_PropWrite.req)
    /// - Bytes 1-2: object type (u16 big-endian)
    /// - Byte 3: object instance (1-based)
    /// - Byte 4: property ID
    /// - Bytes 5-6: count (4 bits) | start index (12 bits)
    /// - Bytes 7+: data (for writes)
    fn process_cemi_frame(&self, payload: &[u8]) -> Result<Vec<u8, 64>, ConnectionStatus> {
        if payload.len() < 7 {
            debug!("cEMI Local Management frame too short: {} bytes", payload.len());
            return Err(ConnectionStatus::DataConnectionError);
        }

        let message_code = payload[0];
        let _object_type = u16::from_be_bytes([payload[1], payload[2]]);
        let object_instance = payload[3];
        let property_id = payload[4];
        let count_start = u16::from_be_bytes([payload[5], payload[6]]);
        let count = (count_start >> 12) as u16;
        let start_index = count_start & 0x0FFF;

        // TODO: Proper object type → index translation. Currently uses
        // object_instance - 1 as the index, which works when each object
        // type has exactly one instance (the common case).
        let object_idx = if object_instance > 0 { (object_instance - 1) as u16 } else { 0 };

        match message_code {
            cemi_local::M_PROP_READ_REQ => {
                self.handle_prop_read(payload, object_idx, property_id, start_index, count)
            }
            cemi_local::M_PROP_WRITE_REQ => {
                self.handle_prop_write(payload, object_idx, property_id, start_index, count)
            }
            _ => {
                debug!("Unsupported cEMI Local Management message code: 0x{:02x}", message_code);
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
        original: &[u8],
        object_idx: u16,
        property_id: u8,
        start_index: u16,
        count: u16,
    ) -> Result<Vec<u8, 64>, ConnectionStatus> {
        let mut response = Vec::<u8, 64>::new();

        // Response header: same structure but with M_PropRead.con message code
        let _ = response.push(cemi_local::M_PROP_READ_CON);
        let _ = response.extend_from_slice(&original[1..5]); // object type + instance + property ID

        // Read the property value into a temp buffer
        let mut data_buf = [0u8; 52]; // Leave room for the 7-byte header in the 64-byte response
        // Access level 0 = full access for ETS device management connections.
        // TODO: Revisit when secure tunneling is implemented.
        match self.property_handler.property_value_read(
            object_idx,
            property_id,
            start_index,
            count,
            &mut data_buf,
            0,
        ) {
            Ok(bytes_read) => {
                // Success: count + start index as requested
                let _ = response.extend_from_slice(&original[5..7]);
                let _ = response.extend_from_slice(&data_buf[..bytes_read]);
            }
            Err(_e) => {
                // Error: count=0 signals error, keep start index
                debug!(
                    "Property read error: obj={} pid={} start={}: {:?}",
                    object_idx, property_id, start_index, _e
                );
                let error_count_start = start_index; // count=0, keep start index
                let _ = response.extend_from_slice(&error_count_start.to_be_bytes());
            }
        }

        Ok(response)
    }

    fn handle_prop_write(
        &self,
        original: &[u8],
        object_idx: u16,
        property_id: u8,
        start_index: u16,
        _count: u16,
    ) -> Result<Vec<u8, 64>, ConnectionStatus> {
        let write_data = &original[7..];

        let mut response = Vec::<u8, 64>::new();

        // Response header: M_PropWrite.con message code
        let _ = response.push(cemi_local::M_PROP_WRITE_CON);
        let _ = response.extend_from_slice(&original[1..5]); // object type + instance + property ID

        match self.property_handler.property_value_write(
            object_idx,
            property_id,
            start_index,
            write_data,
            0,
        ) {
            Ok(_write_response) => {
                // Success: echo back the count + start index and the written data
                let _ = response.extend_from_slice(&original[5..7]);
                let _ = response.extend_from_slice(write_data);
            }
            Err(_e) => {
                // Error: count=0 signals error
                debug!(
                    "Property write error: obj={} pid={} start={}: {:?}",
                    object_idx, property_id, start_index, _e
                );
                let error_count_start = start_index; // count=0, keep start index
                let _ = response.extend_from_slice(&error_count_start.to_be_bytes());
            }
        }

        Ok(response)
    }
}

impl ConnectionTypeHandler for DeviceMgmtConnectionHandler<'_> {
    fn accept_connection(
        &mut self,
        _channel_id: u8,
        _cri_data: &[u8],
    ) -> Result<AcceptedConnection, ConnectionStatus> {
        // Device Management CRI has no additional fields beyond the header.
        // Accept unconditionally — the connection manager enforces max connections.
        //
        // CRD is just the 2-byte header: struct_len=0x02, struct_type=0x03
        let mut crd_bytes = Vec::new();
        let _ = crd_bytes.push(0x02); // struct_len
        let _ = crd_bytes.push(ConnectionType::DeviceManagement.into()); // struct_type
        Ok(AcceptedConnection { crd_bytes })
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
        // Parse the DeviceConfigurationRequest header
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
                Ok(response) => Some(response),
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
        //    (server → client direction)
        if let Some(cemi_response) = response_cemi {
            let send_seq = conn.send_sequence_counter;
            conn.send_sequence_counter = send_seq.wrapping_add(1);

            let req_builder = DeviceConfigurationRequestBuilder::new(
                conn.channel_id, send_seq,
            );

            let mut resp_buffer = buffer_manager.borrow().alloc().await;
            resp_buffer.serialize(&req_builder);
            let header_len = resp_buffer.len();
            let total_len = header_len + cemi_response.len();

            // Append cEMI payload after the header
            let buf = resp_buffer.as_mut();
            buf[header_len..total_len].copy_from_slice(&cemi_response);

            // Patch total_length in the KNXnet/IP header (bytes 4-5)
            let total_bytes = (total_len as u16).to_be_bytes();
            buf[4] = total_bytes[0];
            buf[5] = total_bytes[1];

            resp_buffer.set_len(total_len);

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
