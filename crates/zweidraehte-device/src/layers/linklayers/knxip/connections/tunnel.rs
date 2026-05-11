//! Tunneling connection handler (ConnectionType 0x04).
//!
//! Manages KNX/IP Tunneling connections per KNX spec 03/08/04. Each tunneling
//! connection gets assigned one of the device's additional individual addresses
//! (from PID_ADDITIONAL_INDIVIDUAL_ADDRESSES) and provides transparent access
//! to the KNX bus via cEMI L_Data frames.
//!
//! ## Connection acceptance (spec §4.3, Figure 6)
//!
//! The server supports both Basic CRI (auto-assign an available IA) and
//! Extended CRI (client requests a specific IA). Only the Data Link Layer
//! tunneling layer (0x02) is supported; Raw and BusMonitor are rejected.
//!
//! ## Frame flow
//!
//! Client → server: `TunnelingRequest` with cEMI `L_Data.req` → ACK'd and
//! injected into the network layer via `DataFrameAction::AckAndInject`.
//! Source address 0x0000 in the cEMI is replaced with the connection's IA.
//!
//! Server → client: Bus indications are forwarded by the composite link layer
//! (Phase 3/4) — this handler provides the slot and sequence state but the
//! actual forwarding is driven externally.
//!
//! ## Feature services (spec §4.6)
//!
//! Eight interface features are supported via `TunnelingFeatureGet` /
//! `TunnelingFeatureSet` / `TunnelingFeatureResponse`:
//!
//! | ID | Feature | Get | Set |
//! |----|---------|-----|-----|
//! | 0x01 | Supported EMI type | yes | no |
//! | 0x02 | Host Device Descriptor Type 0 | yes | no |
//! | 0x03 | Bus connection status | yes | no |
//! | 0x04 | KNX manufacturer code | yes | no |
//! | 0x05 | Active EMI type | yes | no |
//! | 0x06 | Individual address | yes | no |
//! | 0x07 | Max APDU length | yes | no |
//! | 0x08 | Feature info enable | yes | yes |

use embassy_time::Instant;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::buffers::DynBufferManager;
use zweidraehte_proto::messages::knxip::substructs::{CRD, CRI, TunnelingCRD, TunnelingLayer, TunnelingSlotInfo};
use zweidraehte_proto::messages::knxip::{
    ConnectionStatus, KNXnetIPServiceType, TunnelingAck, TunnelingAckBuilder, TunnelingFeatureGet,
    TunnelingFeatureResponseBuilder, TunnelingFeatureSet, TunnelingRequest, TunnelingRequestBuilder,
};
use zweidraehte_proto::util::packets::{ParseBuffer, SerializeBuffer};

use super::super::types::{PendingResponse, ResponseTarget, ServerError};
use super::{AcceptedConnection, ConnectionContext, ConnectionTransport, ConnectionTypeHandler, DataFrameAction};

// ============================================================================
// Tunneling Slot
// ============================================================================

/// State for a single tunneling slot (one per additional individual address).
#[derive(Debug)]
struct TunnelSlot {
    /// The individual address assigned to this slot.
    individual_address: IndividualAddress,
    /// The channel ID currently using this slot, if any.
    active_channel: Option<u8>,
}

use zweidraehte_proto::messages::knxip::tunneling_feature_id as feature_id;

// ============================================================================
// Handler
// ============================================================================

/// Handler for Tunneling connections (ConnectionType 0x04).
///
/// Manages a fixed set of tunneling slots, one per additional individual
/// address configured on the device. Each slot can be bound to at most one
/// active connection. Only Data Link Layer tunneling (0x02) is supported.
///
/// The const generic `N` is the maximum number of tunneling slots
/// (additional individual addresses).
pub struct TunnelConnectionHandler<'a, const N: usize> {
    /// Fixed array of tunnel slots, one per additional IA.
    /// Allocated at construction time from the device's additional addresses.
    slots: heapless::Vec<TunnelSlot, N>,

    /// Device Descriptor Type 0 for feature responses.
    device_descriptor_type_0: u16,

    /// KNX manufacturer code (big-endian, 2 bytes).
    manufacturer_code: u16,

    /// Maximum APDU length supported by the device.
    max_apdu_length: u16,

    /// Per-connection feature info enable bitmask.
    /// Bit M = feature M is enabled for unsolicited notifications.
    /// Indexed by slot index. Stored as a simple array parallel to `slots`.
    feature_info_enable: [u8; N],

    /// Bus connection status: true = bus is connected.
    /// This would be updated by the composite link layer when the bus
    /// link goes up/down.
    bus_connected: bool,

    /// Live count of currently-open tunnel connections, kept in sync
    /// with `slots[..].active_channel`. Read by the composite IP-Interface
    /// address checker to decide whether to over-ACK group frames.
    tunnel_occupancy: &'a super::TunnelOccupancy,
}

impl<'a, const N: usize> TunnelConnectionHandler<'a, N> {
    /// Create a new tunneling handler for the given set of additional
    /// individual addresses.
    ///
    /// `additional_addresses` determines the tunnel capacity — one connection
    /// per address. These correspond to `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`
    /// on the IP Parameter interface object.
    pub fn new(
        additional_addresses: &[IndividualAddress],
        device_descriptor_type_0: u16,
        manufacturer_code: u16,
        max_apdu_length: u16,
        tunnel_occupancy: &'a super::TunnelOccupancy,
    ) -> Self {
        let mut slots = heapless::Vec::new();
        for &addr in additional_addresses {
            let _ = slots.push(TunnelSlot { individual_address: addr, active_channel: None });
        }

        Self {
            slots,
            device_descriptor_type_0,
            manufacturer_code,
            max_apdu_length,
            feature_info_enable: [0u8; N],
            bus_connected: true,
            tunnel_occupancy,
        }
    }

    /// Set the bus connection status. When the bus goes down, tunnel
    /// clients that enabled feature info for bus status should be notified.
    pub fn set_bus_connected(&mut self, connected: bool) {
        self.bus_connected = connected;
    }

    /// Return a snapshot of the current tunneling slot status for use in
    /// the TunnelingInfo DIB (SearchResponseExtended).
    ///
    /// Each slot produces a `TunnelingSlotInfo` with:
    /// - The slot's individual address
    /// - A 16-bit status word where bit 0 = 1 means "slot is not free"
    ///   (i.e., currently occupied by an active connection)
    ///
    /// Also returns the device's max APDU length (needed by the DIB header).
    pub fn slot_info(&self) -> (u16, heapless::Vec<TunnelingSlotInfo, N>) {
        let mut infos = heapless::Vec::new();
        for slot in &self.slots {
            let occupied = slot.active_channel.is_some();
            // Bit 0: 1 = not free (occupied), 0 = free
            let status_word: u16 = if occupied { 0x0001 } else { 0x0000 };
            let _ = infos
                .push(TunnelingSlotInfo { individual_address: slot.individual_address, status: status_word.into() });
        }
        (self.max_apdu_length, infos)
    }

    /// Determine which active tunnel channels should receive a forwarded
    /// bus indication, based on the cEMI destination address.
    ///
    /// Returns channel IDs for all matching connections:
    /// - Group-addressed / broadcast frames → all active connections
    /// - Individually-addressed frames → only the connection whose
    ///   assigned IA matches the destination
    ///
    /// The `cemi_data` must be a raw cEMI L_Data.ind frame. The destination
    /// address is extracted from the cEMI header:
    ///   `[mc(1) + add_info_len(1) + add_info(N) + ctrl1(1) + ctrl2(1) + src(2) + dst(2)]`
    /// where `ctrl2` bit 7 is the address type flag (1 = group).
    pub fn channels_for_bus_indication(&self, cemi_data: &[u8]) -> heapless::Vec<u8, N> {
        let mut channels = heapless::Vec::new();

        // Parse cEMI to extract destination address type and address.
        // We need at least: mc(1) + add_info_len(1) + ctrl1(1) + ctrl2(1) + src(2) + dst(2) = 8 bytes
        // (with add_info_len = 0).
        if cemi_data.len() < 2 {
            return channels;
        }
        let add_info_len = cemi_data[1] as usize;
        let ctrl2_offset = 2 + add_info_len + 1; // skip mc + add_info_len + add_info + ctrl1
        let dst_offset = ctrl2_offset + 1 + 2; // skip ctrl2 + src(2)

        if cemi_data.len() < dst_offset + 2 {
            return channels;
        }

        let ctrl2 = cemi_data[ctrl2_offset];
        let is_group_addressed = (ctrl2 & 0x80) != 0;
        let dst_hi = cemi_data[dst_offset];
        let dst_lo = cemi_data[dst_offset + 1];

        if is_group_addressed || (dst_hi == 0 && dst_lo == 0) {
            // Group address or broadcast: forward to all active connections.
            for slot in &self.slots {
                if let Some(channel_id) = slot.active_channel {
                    let _ = channels.push(channel_id);
                }
            }
        } else {
            // Individual address: forward only to the connection whose IA matches.
            let dst_addr = IndividualAddress::from_bytes(&[dst_hi, dst_lo]);
            for slot in &self.slots {
                if slot.individual_address == dst_addr {
                    if let Some(channel_id) = slot.active_channel {
                        let _ = channels.push(channel_id);
                    }
                    break;
                }
            }
        }

        channels
    }

    /// Build a `TunnelingRequest` wrapping a cEMI frame for a specific
    /// channel. The caller must supply and increment the send sequence
    /// counter from the `ConnectionContext`.
    pub fn build_tunneling_request(
        channel_id: u8,
        sequence_counter: u8,
        cemi_data: &[u8],
        target: ResponseTarget,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        let builder = TunnelingRequestBuilder::with_payload(channel_id, sequence_counter, cemi_data);
        let mut buffer = buffer_manager.try_alloc()?;
        buffer.serialize(&builder);
        Some(PendingResponse { buffer, target })
    }

    /// Find a slot by channel ID.
    fn slot_index_for_channel(&self, channel_id: u8) -> Option<usize> {
        self.slots.iter().position(|s| s.active_channel == Some(channel_id))
    }

    /// Find a slot by individual address.
    fn slot_index_for_address(&self, addr: IndividualAddress) -> Option<usize> {
        self.slots.iter().position(|s| s.individual_address == addr)
    }

    /// Find the first free (unassigned) slot.
    fn first_free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.active_channel.is_none())
    }

    /// Build a TunnelingAck as a `PendingResponse`.
    fn build_ack(
        channel_id: u8,
        sequence_counter: u8,
        status: ConnectionStatus,
        conn: &ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        let builder = TunnelingAckBuilder::new(channel_id, sequence_counter, status);
        let mut buffer = buffer_manager.try_alloc()?;
        buffer.serialize(&builder);
        Some(PendingResponse { buffer, target: conn.response_target() })
    }

    /// Handle a tunneling feature GET request.
    ///
    /// Returns the feature value bytes for the requested feature, or `None`
    /// if the feature is unknown.
    fn get_feature_value(&self, feature_id: u8, slot_idx: usize) -> Option<heapless::Vec<u8, 4>> {
        let mut value = heapless::Vec::new();

        match feature_id {
            feature_id::SUPPORTED_EMI_TYPE => {
                // 0x01 = cEMI only
                let _ = value.push(0x01);
            }
            feature_id::HOST_DEVICE_DESCRIPTOR_TYPE_0 => {
                let _ = value.extend_from_slice(&self.device_descriptor_type_0.to_be_bytes());
            }
            feature_id::BUS_CONNECTION_STATUS => {
                let _ = value.push(if self.bus_connected { 0x01 } else { 0x00 });
            }
            feature_id::KNX_MANUFACTURER_CODE => {
                let _ = value.extend_from_slice(&self.manufacturer_code.to_be_bytes());
            }
            feature_id::ACTIVE_EMI_TYPE => {
                // 0x01 = cEMI (always)
                let _ = value.push(0x01);
            }
            feature_id::INDIVIDUAL_ADDRESS => {
                let addr = self.slots[slot_idx].individual_address;
                let _ = value.extend_from_slice(addr.as_bytes());
            }
            feature_id::MAX_APDU_LENGTH => {
                let _ = value.extend_from_slice(&self.max_apdu_length.to_be_bytes());
            }
            feature_id::FEATURE_INFO_ENABLE => {
                let _ = value.push(self.feature_info_enable[slot_idx]);
            }
            _ => return None,
        }

        Some(value)
    }

    /// Handle a tunneling feature SET request.
    ///
    /// Returns `true` if the feature was set successfully, `false` if the
    /// feature is read-only or unknown.
    fn set_feature_value(&mut self, feature_id: u8, slot_idx: usize, data: &[u8]) -> bool {
        match feature_id {
            feature_id::FEATURE_INFO_ENABLE => {
                // Only feature info enable is writable. Single byte value.
                if let Some(&val) = data.first() {
                    self.feature_info_enable[slot_idx] = val;
                    true
                } else {
                    false
                }
            }
            // All other features are read-only.
            _ => false,
        }
    }

    /// Process a `TunnelingFeatureGet` request and build the response.
    fn handle_feature_get(
        &self,
        channel_id: u8,
        sequence_counter: u8,
        feature_id: u8,
        slot_idx: usize,
        conn: &ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        let (return_code, value) = match self.get_feature_value(feature_id, slot_idx) {
            Some(v) => (0x00u8, v),                 // success
            None => (0x01u8, heapless::Vec::new()), // unknown feature
        };

        let builder =
            TunnelingFeatureResponseBuilder::with_value(channel_id, sequence_counter, feature_id, return_code, &value);
        let mut buffer = buffer_manager.try_alloc()?;
        buffer.serialize(&builder);
        Some(PendingResponse { buffer, target: conn.response_target() })
    }

    /// Process a `TunnelingFeatureSet` request and build the response.
    fn handle_feature_set(
        &mut self,
        channel_id: u8,
        sequence_counter: u8,
        feature_id: u8,
        feature_data: &[u8],
        slot_idx: usize,
        conn: &ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        let return_code = if self.set_feature_value(feature_id, slot_idx, feature_data) {
            0x00u8 // success
        } else {
            0x01u8 // error (read-only or unknown)
        };

        let builder = TunnelingFeatureResponseBuilder::new(channel_id, sequence_counter, feature_id, return_code);
        let mut buffer = buffer_manager.try_alloc()?;
        buffer.serialize(&builder);
        Some(PendingResponse { buffer, target: conn.response_target() })
    }
}

impl<const N: usize> ConnectionTypeHandler for TunnelConnectionHandler<'_, N> {
    fn accept_connection(&mut self, channel_id: u8, cri: &CRI) -> Result<AcceptedConnection, ConnectionStatus> {
        let CRI::Tunnel(tunnel_cri) = cri else {
            return Err(ConnectionStatus::ConnectionTypeNotSupported);
        };

        // Only Data Link Layer tunneling is supported.
        if tunnel_cri.knx_layer != TunnelingLayer::LinkLayer {
            debug!("Rejecting tunnel connection: unsupported layer {:?}", tunnel_cri.knx_layer);
            return Err(ConnectionStatus::LayerNotSupported);
        }

        // Determine which slot to assign based on CRI type:
        // - Extended CRI: client requests a specific IA
        // - Basic CRI: auto-assign the first available slot
        let slot_idx = if let Some(requested_addr) = tunnel_cri.individual_address {
            // Extended CRI: client wants a specific address.
            let idx = self.slot_index_for_address(requested_addr).ok_or_else(|| {
                debug!("Rejecting tunnel connection: requested IA {} not configured", requested_addr);
                // Per spec: E_CONNECTION_OPTION if the IA is not in our pool.
                ConnectionStatus::ConnectionOptionsNotSupported
            })?;

            // Check if that specific slot is already in use.
            if self.slots[idx].active_channel.is_some() {
                debug!("Rejecting tunnel connection: IA {} already in use", requested_addr);
                // Per spec §4.3: E_NO_MORE_UNIQUE_CONNECTIONS when the
                // requested IA is already assigned to another connection.
                return Err(ConnectionStatus::NoMoreUniqueConnections);
            }

            idx
        } else {
            // Basic CRI: auto-assign the first free slot.
            self.first_free_slot().ok_or_else(|| {
                debug!("Rejecting tunnel connection: no free tunnel slots");
                ConnectionStatus::NoMoreConnections
            })?
        };

        // Assign the slot to this channel.
        let assigned_addr = self.slots[slot_idx].individual_address;
        self.slots[slot_idx].active_channel = Some(channel_id);
        self.feature_info_enable[slot_idx] = 0;
        self.tunnel_occupancy.on_connect();

        info!("Accepted tunneling connection: channel={}, IA={}, slot={}", channel_id, assigned_addr, slot_idx);

        Ok(AcceptedConnection { crd: CRD::Tunnel(TunnelingCRD::new(assigned_addr)) })
    }

    fn close_connection(&mut self, channel_id: u8) {
        if let Some(slot_idx) = self.slot_index_for_channel(channel_id) {
            let addr = self.slots[slot_idx].individual_address;
            // Only decrement on an occupied→free transition. `close_connection`
            // can race against itself (DISCONNECT_REQUEST + TCP-close +
            // heartbeat timeout); `TunnelOccupancy::on_disconnect` is
            // saturating but we still want to avoid double-counting.
            let was_occupied = self.slots[slot_idx].active_channel.is_some();
            self.slots[slot_idx].active_channel = None;
            self.feature_info_enable[slot_idx] = 0;
            if was_occupied {
                self.tunnel_occupancy.on_disconnect();
            }
            info!("Closed tunneling connection: channel={}, IA={}", channel_id, addr);
        }
    }

    async fn on_data_frame(
        &mut self,
        _channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
        // Peek at the service type to determine what kind of frame this is.
        // The service type is at offset 2-3 in the KNXnet/IP header.
        if data.len() < 6 + 4 {
            return Err(ServerError::InvalidMessage);
        }
        let service_type_raw = u16::from_be_bytes([data[2], data[3]]);
        let service_type = KNXnetIPServiceType::from(service_type_raw);

        match service_type {
            KNXnetIPServiceType::TunnelingRequest => self.handle_tunneling_request(data, conn, buffer_manager).await,
            KNXnetIPServiceType::TunnelingFeatureGet => self.handle_feature_get_request(data, conn, buffer_manager),
            KNXnetIPServiceType::TunnelingFeatureSet => self.handle_feature_set_request(data, conn, buffer_manager),
            _ => {
                debug!("Unexpected service type in tunnel handler: {:?}", service_type);
                Err(ServerError::InvalidMessage)
            }
        }
    }

    fn on_data_ack(&mut self, _channel_id: u8, data: &[u8], conn: &mut ConnectionContext) -> Result<(), ServerError> {
        let mut buf = data;
        let ack = match buf.parse::<TunnelingAck>() {
            Ok(a) => a,
            Err(_) => return Err(ServerError::ParseError),
        };

        conn.last_activity = Instant::now();

        // Verify the ACK matches our pending outgoing frame.
        if let Some(pending) = &conn.pending_ack {
            if ack.sequence_counter == pending.sequence_counter {
                if ack.status == ConnectionStatus::NoError {
                    trace!(
                        "TunnelingAck: channel={}, seq={} — acknowledged",
                        ack.communication_channel_id, ack.sequence_counter
                    );
                } else {
                    warn!(
                        "TunnelingAck: channel={}, seq={}, error status {:?}",
                        ack.communication_channel_id, ack.sequence_counter, ack.status
                    );
                }
                conn.pending_ack = None;
            } else {
                warn!(
                    "TunnelingAck: channel={}, seq={} doesn't match pending seq {}",
                    ack.communication_channel_id, ack.sequence_counter, pending.sequence_counter
                );
            }
        } else {
            trace!(
                "TunnelingAck: channel={}, seq={} (no pending frame)",
                ack.communication_channel_id, ack.sequence_counter
            );
        }

        Ok(())
    }

    fn handled_service_types(&self) -> &[KNXnetIPServiceType] {
        &[
            KNXnetIPServiceType::TunnelingRequest,
            KNXnetIPServiceType::TunnelingAck,
            KNXnetIPServiceType::TunnelingFeatureGet,
            KNXnetIPServiceType::TunnelingFeatureSet,
        ]
    }
}

// ============================================================================
// Private: Frame Handling
// ============================================================================

impl<const N: usize> TunnelConnectionHandler<'_, N> {
    /// Handle a `TunnelingRequest` containing a cEMI L_Data frame.
    ///
    /// The cEMI frame is extracted, source address substitution is applied
    /// (src 0x0000 → connection IA), and the frame is injected into the
    /// network layer via `AckAndInject`.
    async fn handle_tunneling_request(
        &mut self,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
        let mut buf = data;
        let request = match buf.parse::<TunnelingRequest>() {
            Ok(req) => req,
            Err(_) => return Err(ServerError::ParseError),
        };

        let sequence_counter = request.sequence_counter;
        let expected_seq = conn.recv_sequence_counter;

        // Sequence counter validation (UDP only, per spec §4.4.7).
        let is_tcp = matches!(conn.transport, ConnectionTransport::Tcp { .. });
        let is_retransmission = !is_tcp && sequence_counter == expected_seq.wrapping_sub(1);
        let is_expected = is_tcp || sequence_counter == expected_seq;

        if !is_expected && !is_retransmission {
            debug!(
                "Tunnel sequence counter mismatch: got {}, expected {} (channel {})",
                sequence_counter, expected_seq, conn.channel_id
            );
            let ack = Self::build_ack(
                conn.channel_id,
                sequence_counter,
                ConnectionStatus::DataConnectionError,
                conn,
                buffer_manager,
            );
            return match ack {
                Some(ack) => Ok(DataFrameAction::AckOnly(ack)),
                None => {
                    warn!("Tunnel: no buffer for error ACK (channel {})", conn.channel_id);
                    Err(ServerError::InternalError)
                }
            };
        }

        // Extract cEMI payload: everything after KNXnet/IP header (6) + tunneling header (4).
        let cemi_offset = 6 + 4;
        let cemi_payload = if data.len() > cemi_offset { &data[cemi_offset..] } else { &[] };

        if is_expected {
            conn.recv_sequence_counter = expected_seq.wrapping_add(1);
            conn.last_activity = Instant::now();

            // Source address substitution: if the cEMI source address is
            // 0x0000, replace it with the connection's individual address.
            //
            // cEMI L_Data format: message code (1) + additional info length (1)
            // + [additional info] + ctrl1 (1) + ctrl2 (1) + source (2) + dest (2) + ...
            //
            // For standard L_Data.req (mc=0x11), the source address is at
            // offset 4 after message code + add.info.len + add.info.
            let slot_idx = self.slot_index_for_channel(conn.channel_id);
            let connection_ia = slot_idx.map(|i| self.slots[i].individual_address);

            let mut cemi_buffer = buffer_manager.alloc_zeroed(cemi_payload.len()).await;
            cemi_buffer[..cemi_payload.len()].copy_from_slice(cemi_payload);

            // Apply source address substitution if needed.
            if let Some(ia) = connection_ia {
                self.apply_source_address_substitution(&mut cemi_buffer, ia);
            }

            // Reject frames whose APDU exceeds the device's maximum.
            // cEMI: msg_code(1) + add_info_len(1) + [add_info] + ctrl1(1) + ctrl2(1) + src(2) + dst(2) + npdu_len(1)
            let add_info_len = if cemi_buffer.len() > 1 { cemi_buffer[1] as usize } else { 0 };
            let npdu_len_offset = 2 + add_info_len + 6;
            if cemi_buffer.len() > npdu_len_offset && (cemi_buffer[npdu_len_offset] as u16) > self.max_apdu_length {
                warn!(
                    "Tunnel: NPDU length {} exceeds max {} - ACK but dropping frame (channel {})",
                    cemi_buffer[npdu_len_offset], self.max_apdu_length, conn.channel_id
                );
                let ack =
                    Self::build_ack(conn.channel_id, sequence_counter, ConnectionStatus::NoError, conn, buffer_manager);
                return match ack {
                    Some(ack) => Ok(DataFrameAction::AckOnly(ack)),
                    None => {
                        warn!("Tunnel: no buffer for ACK (channel {})", conn.channel_id);
                        Err(ServerError::InternalError)
                    }
                };
            }

            // Build ACK
            let ack =
                Self::build_ack(conn.channel_id, sequence_counter, ConnectionStatus::NoError, conn, buffer_manager);
            let Some(ack) = ack else {
                warn!("Tunnel: no buffer for ACK (channel {})", conn.channel_id);
                return Err(ServerError::InternalError);
            };

            Ok(DataFrameAction::AckAndInject { ack, cemi_buffer })
        } else {
            // Retransmission: just re-ACK, don't re-process.
            let ack =
                Self::build_ack(conn.channel_id, sequence_counter, ConnectionStatus::NoError, conn, buffer_manager);
            match ack {
                Some(ack) => Ok(DataFrameAction::AckOnly(ack)),
                None => {
                    warn!("Tunnel: no buffer for retransmit ACK (channel {})", conn.channel_id);
                    Err(ServerError::InternalError)
                }
            }
        }
    }

    /// Apply source address substitution on a cEMI L_Data frame buffer.
    ///
    /// Per KNX spec 03/08/04 §4.4.6: if the client sends a frame with
    /// source address 0x0000, the server replaces it with the connection's IA.
    fn apply_source_address_substitution(&self, cemi_buf: &mut [u8], connection_ia: IndividualAddress) {
        // cEMI L_Data.req layout:
        //   [0]: message code (0x11)
        //   [1]: additional info length (N)
        //   [2..2+N]: additional info
        //   [2+N]: ctrl1
        //   [2+N+1]: ctrl2
        //   [2+N+2..2+N+4]: source address (2 bytes)
        if cemi_buf.len() < 2 {
            return;
        }
        let add_info_len = cemi_buf[1] as usize;
        let src_offset = 2 + add_info_len + 2; // skip mc + add_info_len + add_info + ctrl1 + ctrl2

        if cemi_buf.len() < src_offset + 2 {
            return;
        }

        let src = [cemi_buf[src_offset], cemi_buf[src_offset + 1]];
        if src == [0x00, 0x00] {
            let ia_bytes = connection_ia.as_bytes();
            cemi_buf[src_offset] = ia_bytes[0];
            cemi_buf[src_offset + 1] = ia_bytes[1];
            trace!("Source address substitution: 0.0.0 → {}", connection_ia);
        }
    }

    /// Handle a `TunnelingFeatureGet` service type.
    fn handle_feature_get_request(
        &self,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
        let mut buf = data;
        let request = match buf.parse::<TunnelingFeatureGet>() {
            Ok(r) => r,
            Err(_) => return Err(ServerError::ParseError),
        };

        conn.last_activity = Instant::now();

        let slot_idx = self.slot_index_for_channel(conn.channel_id).ok_or(ServerError::InvalidMessage)?;

        let mut responses = heapless::Vec::<_, 4>::new();

        if let Some(response) = self.handle_feature_get(
            conn.channel_id,
            request.sequence_counter,
            request.feature_identifier,
            slot_idx,
            conn,
            buffer_manager,
        ) {
            let _ = responses.push(response);
        } else {
            warn!("Tunnel: no buffer for feature response (channel {})", conn.channel_id);
        }

        Ok(DataFrameAction::Responses(responses))
    }

    /// Handle a `TunnelingFeatureSet` service type.
    fn handle_feature_set_request(
        &mut self,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
        let mut buf = data;
        let request = match buf.parse::<TunnelingFeatureSet>() {
            Ok(r) => r,
            Err(_) => return Err(ServerError::ParseError),
        };

        conn.last_activity = Instant::now();

        let slot_idx = self.slot_index_for_channel(conn.channel_id).ok_or(ServerError::InvalidMessage)?;

        // Feature value: everything after KNXnet/IP header (6) + feature header (4).
        let value_offset = 6 + 4;
        let feature_data = if data.len() > value_offset { &data[value_offset..] } else { &[] };

        let mut responses = heapless::Vec::<_, 4>::new();

        if let Some(response) = self.handle_feature_set(
            conn.channel_id,
            request.sequence_counter,
            request.feature_identifier,
            feature_data,
            slot_idx,
            conn,
            buffer_manager,
        ) {
            let _ = responses.push(response);
        } else {
            warn!("Tunnel: no buffer for feature set response (channel {})", conn.channel_id);
        }

        Ok(DataFrameAction::Responses(responses))
    }
}
