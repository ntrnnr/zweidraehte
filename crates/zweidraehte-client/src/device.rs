//! Connected device handle for point-to-point management.
//!
//! A `DeviceConnection` represents an open transport connection to a specific
//! KNX device. Management services are sent as numbered (connected) data
//! packets with automatic sequence number management.

use tokio::sync::oneshot;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::encoding::cemi::CemiLData;
use zweidraehte_proto::util::packets::ParseBuffer;

/// Offset of TPCI/APCI in the cEMI body (after ctrl1, ctrl2, src(2), dst(2), npdu_len).
const CEMI_BODY_TPCI_OFFSET: usize = 7;

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

    /// Send a connected management request and return the response APCI data.
    async fn send_management_request(&mut self, apci_data: &[u8]) -> Result<Vec<u8>> {
        let cemi = transport::build_connected_data_cemi(
            self.source,
            self.remote,
            self.send_seq,
            apci_data,
        );

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SendFrame {
                cemi,
                response_tx: tx,
            })
            .await
            .map_err(|_| Error::WorkerGone)?;

        let result = rx.await.map_err(|_| Error::WorkerGone)??;
        self.send_seq = self.send_seq.wrapping_add(1);
        self.extract_apci_data(&result)
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

    /// Extract the APCI data region from a cEMI L_Data.ind response.
    fn extract_apci_data(&self, cemi_data: &[u8]) -> Result<Vec<u8>> {
        let mut slice: &[u8] = cemi_data;
        let cemi: CemiLData<&[u8]> = slice
            .parse()
            .map_err(|_| Error::Parse("invalid cEMI in response"))?;

        let cemi_body = cemi.data();
        if cemi_body.len() < CEMI_BODY_TPCI_OFFSET + 2 {
            return Err(Error::Parse("cEMI body too short for APCI"));
        }

        Ok(cemi_body[CEMI_BODY_TPCI_OFFSET..].to_vec())
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
        let response = self.send_management_request(&apci).await?;
        management::parse_function_property_response(&response)
    }

    /// Read the state of a function property.
    pub async fn function_property_state_read(
        &mut self,
        obj_idx: u8,
        prop_id: u8,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let apci = management::build_function_property_state_read(obj_idx, prop_id, service_data);
        let response = self.send_management_request(&apci).await?;
        management::parse_function_property_response(&response)
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
        let response = self.send_management_request(&apci).await?;
        let (resp_count, _start, data) = management::parse_property_value_response(&response)?;
        if resp_count == 0 {
            return Err(Error::DeviceError(0));
        }
        Ok(data)
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
        let response = self.send_management_request(&apci).await?;
        let (resp_count, _, _) = management::parse_property_value_response(&response)?;
        if resp_count == 0 {
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
        let response = self.send_management_request(&apci).await?;
        management::parse_property_description_response(&response)
    }

    /// Read memory from the device.
    pub async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>> {
        let apci = management::build_memory_read(count, address);
        let response = self.send_management_request(&apci).await?;
        if response.len() < 4 {
            return Err(Error::Parse("MemoryResponse too short"));
        }
        Ok(response[4..].to_vec())
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
        let response = self.send_management_request(&apci).await?;
        management::parse_authorize_response(&response)
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
