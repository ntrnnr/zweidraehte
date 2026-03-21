//! Connected device handle for point-to-point management.
//!
//! A `DeviceConnection` represents an open transport connection to a specific
//! KNX device. Management services are sent as numbered (connected) data
//! packets with automatic sequence number management.

use tokio::sync::oneshot;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::knx::{ApciCode, decode_apci_code, offsets};
use zweidraehte_proto::messages::apdu::property::PropertyValueHeader;
use zweidraehte_proto::messages::apdu::function_property::FunctionPropertyResponse;

use crate::error::{Error, Result};
use crate::management::{self, FunctionPropertyResult, PropertyDescription};
use crate::transport;
use crate::tunnel::worker::{Command, CommandSender};

/// A point-to-point transport connection to a KNX device.
///
/// Created via [`KnxClient::open_connection`](crate::KnxClient::open_connection).
/// All management methods use connected (numbered) transport, which provides
/// reliable delivery with acknowledgement.
pub struct DeviceConnection {
    remote: IndividualAddress,
    source: IndividualAddress,
    cmd_tx: CommandSender,
    send_seq: u8,
}

impl DeviceConnection {
    pub(crate) fn new(
        remote: IndividualAddress,
        source: IndividualAddress,
        cmd_tx: CommandSender,
    ) -> Self {
        Self {
            remote,
            source,
            cmd_tx,
            send_seq: 0,
        }
    }

    /// Send a connected management request and return the response in internal
    /// message format.
    async fn send_management_request(&mut self, apci_data: &[u8]) -> Result<Vec<u8>> {
        let cemi = transport::build_connected_data_cemi(
            self.source,
            self.remote,
            self.send_seq,
            apci_data,
        );

        let expected_apci = Self::derive_expected_apci(apci_data);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SendFrame {
                cemi,
                expected_source: Some(self.remote),
                expected_apci,
                response_tx: tx,
            })
            .await
            .map_err(|_| Error::WorkerGone)?;

        let result = rx.await.map_err(|_| Error::WorkerGone)??;
        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(result) // Already in internal format from worker.
    }

    /// Send a fire-and-forget connected frame (no bus response expected).
    async fn send_no_response(&mut self, cemi: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SendFrameNoResponse {
                cemi,
                response_tx: tx,
            })
            .await
            .map_err(|_| Error::WorkerGone)?;

        rx.await.map_err(|_| Error::WorkerGone)??;
        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(())
    }

    /// Derive the expected response APCI from outgoing APCI data bytes.
    fn derive_expected_apci(apci_data: &[u8]) -> Option<ApciCode> {
        if apci_data.len() < 2 {
            return None;
        }
        let mut buf = vec![0u8; offsets::MSG_APCI + 2];
        buf[offsets::MSG_APCI] = apci_data[0];
        buf[offsets::MSG_APCI + 1] = apci_data[1];
        let request_apci = decode_apci_code(&buf)?;
        crate::management::expected_response_apci(request_apci)
    }

    // ========================================================================
    // Management services
    // ========================================================================

    /// Execute a function property command on the device.
    pub async fn function_property_command(
        &mut self,
        obj_idx: u8,
        prop_id: u8,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let apci = management::build_function_property_command(obj_idx, prop_id, service_data);
        let buf = self.send_management_request(&apci).await?;
        let resp = FunctionPropertyResponse::parse(&buf)
            .ok_or(Error::Parse("FunctionPropertyResponse too short"))?;
        Ok(FunctionPropertyResult {
            return_code: resp.return_code,
            data: resp.data(&buf).to_vec(),
        })
    }

    /// Read the state of a function property.
    pub async fn function_property_state_read(
        &mut self,
        obj_idx: u8,
        prop_id: u8,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let apci = management::build_function_property_state_read(obj_idx, prop_id, service_data);
        let buf = self.send_management_request(&apci).await?;
        let resp = FunctionPropertyResponse::parse(&buf)
            .ok_or(Error::Parse("FunctionPropertyResponse too short"))?;
        Ok(FunctionPropertyResult {
            return_code: resp.return_code,
            data: resp.data(&buf).to_vec(),
        })
    }

    /// Read a property value from the device.
    pub async fn property_read(
        &mut self,
        obj_idx: u8,
        prop_id: u8,
        start_idx: u16,
        count: u16,
    ) -> Result<Vec<u8>> {
        let apci = management::build_property_read(obj_idx, prop_id, count, start_idx);
        let buf = self.send_management_request(&apci).await?;
        let hdr = PropertyValueHeader::parse(&buf)
            .ok_or(Error::Parse("PropertyValueResponse too short"))?;
        if hdr.count == 0 {
            return Err(Error::DeviceError(0));
        }
        Ok(hdr.data(&buf).to_vec())
    }

    /// Write a property value to the device.
    pub async fn property_write(
        &mut self,
        obj_idx: u8,
        prop_id: u8,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()> {
        let apci = management::build_property_write(obj_idx, prop_id, count, start_idx, data);
        let buf = self.send_management_request(&apci).await?;
        let hdr = PropertyValueHeader::parse(&buf)
            .ok_or(Error::Parse("PropertyValueResponse too short"))?;
        if hdr.count == 0 {
            return Err(Error::DeviceError(0));
        }
        Ok(())
    }

    /// Read a property description from the device.
    pub async fn property_description_read(
        &mut self,
        obj_idx: u8,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescription> {
        let apci = management::build_property_description_read(obj_idx, prop_id, prop_idx);
        let buf = self.send_management_request(&apci).await?;
        // PropertyDescriptionResponse layout: APCI+2=obj_idx, +3=prop_id,
        // +4=prop_idx, +5=type, +6-7=max_elements, +8=access
        if buf.len() < offsets::MSG_APCI + 9 {
            return Err(Error::Parse("PropertyDescriptionResponse too short"));
        }
        let base = offsets::MSG_APCI;
        let type_byte = buf[base + 5];
        Ok(PropertyDescription {
            prop_id: buf[base + 3],
            prop_idx: buf[base + 4],
            write_enabled: (type_byte & 0x80) != 0,
            pdt: type_byte & 0x3F,
            max_elements: u16::from_be_bytes([buf[base + 6], buf[base + 7]]),
            read_access: (buf[base + 8] >> 4) & 0x0F,
            write_access: buf[base + 8] & 0x0F,
        })
    }

    /// Read memory from the device.
    pub async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>> {
        let apci = management::build_memory_read(count, address);
        let buf = self.send_management_request(&apci).await?;
        // Memory response data starts at MSG_APDU (offset 8) + 2 (address bytes).
        let data_start = offsets::MSG_APDU + 2;
        if buf.len() < data_start {
            return Err(Error::Parse("MemoryResponse too short"));
        }
        Ok(buf[data_start..].to_vec())
    }

    /// Write memory to the device.
    pub async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()> {
        let apci = management::build_memory_write(address, data);
        let cemi = transport::build_connected_data_cemi(
            self.source,
            self.remote,
            self.send_seq,
            &apci,
        );
        self.send_no_response(cemi).await
    }

    /// Authorize with the device using a key.
    pub async fn authorize(&mut self, key: &[u8; 4]) -> Result<u8> {
        let apci = management::build_authorize_request(key);
        let buf = self.send_management_request(&apci).await?;
        // Authorize response: APCI+2 = access level.
        if buf.len() < offsets::MSG_APCI + 3 {
            return Err(Error::Parse("AuthorizeResponse too short"));
        }
        Ok(buf[offsets::MSG_APCI + 2])
    }

    /// Restart the device.
    pub async fn restart(&mut self) -> Result<()> {
        let apci = management::build_restart();
        let cemi = transport::build_connected_data_cemi(
            self.source,
            self.remote,
            self.send_seq,
            &apci,
        );
        self.send_no_response(cemi).await
    }

    /// Close the transport connection.
    pub async fn close(self) -> Result<()> {
        let cemi = transport::build_disconnect_cemi(self.source, self.remote);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SendFrameNoResponse {
                cemi,
                response_tx: tx,
            })
            .await
            .map_err(|_| Error::WorkerGone)?;

        rx.await.map_err(|_| Error::WorkerGone)??;
        Ok(())
    }
}
