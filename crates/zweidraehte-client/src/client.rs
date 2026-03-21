//! Top-level KNX/IP client API.

use core::net::SocketAddrV4;

use tokio::sync::{mpsc, oneshot};

use zweidraehte_proto::encoding::cemi::CemiLData;
use zweidraehte_proto::util::packets::ParseBuffer;

/// Offset of the TPCI/APCI region within the cEMI body (after msg_code and
/// add_info_len have been stripped by the parser).
///
/// cEMI body: [ctrl1, ctrl2, src_hi, src_lo, dst_hi, dst_lo, npdu_len, tpci/apci...]
const CEMI_BODY_TPCI_OFFSET: usize = 7;

use crate::device::DeviceConnection;
use crate::error::{Error, Result};
use crate::management;
use crate::transport;
use crate::tunnel::CemiMode;
use crate::tunnel::worker::{Command, CommandSender, TunnelWorker};

/// A KNX/IP tunneling client.
///
/// Connects to a KNX/IP interface and provides management services for
/// communicating with KNX devices on the bus.
pub struct KnxClient {
    cmd_tx: CommandSender,
    assigned_address: zweidraehte_proto::address::IndividualAddress,
    cemi_mode: CemiMode,
    /// Maximum APDU length the KNX/IP tunnel itself supports (IP-side).
    /// Does NOT account for TP1 bus-side constraints. Read PID 56 from
    /// the target device to get the device-side limit, then take
    /// `min(tunnel_max_apdu, device_max_apdu)` for the effective limit.
    tunnel_max_apdu: u16,
}

impl KnxClient {
    /// Connect to a KNX/IP interface via tunneling.
    ///
    /// Returns the client handle and the worker. The caller must spawn the
    /// worker's `run` method on a tokio task:
    ///
    /// ```rust,ignore
    /// let (client, mut worker, mut cmd_rx) = KnxClient::connect(addr).await?;
    /// tokio::spawn(async move { worker.run(&mut cmd_rx).await });
    /// ```
    pub async fn connect(
        server_addr: SocketAddrV4,
    ) -> Result<(Self, TunnelWorker, crate::tunnel::worker::CommandReceiver)> {
        let worker = TunnelWorker::connect(server_addr).await?;
        let assigned_address = worker.assigned_address();
        let tunnel_max_apdu = worker.tunnel_max_apdu();

        let (cmd_tx, cmd_rx) = mpsc::channel(8);

        let client = Self {
            cmd_tx,
            assigned_address,
            cemi_mode: CemiMode::LData,
            tunnel_max_apdu,
        };

        Ok((client, worker, cmd_rx))
    }

    /// Set the cEMI framing mode for outgoing messages.
    pub fn set_cemi_mode(&mut self, mode: CemiMode) {
        self.cemi_mode = mode;
    }

    /// The individual address assigned to this tunnel connection.
    pub fn assigned_address(&self) -> zweidraehte_proto::address::IndividualAddress {
        self.assigned_address
    }

    /// Maximum APDU length the KNX/IP tunnel itself supports (IP-side).
    ///
    /// This does NOT account for TP1 bus-side constraints. The effective
    /// max APDU for a target device is `min(tunnel_max_apdu, device_max_apdu)`
    /// where `device_max_apdu` comes from reading PID 56 on the target.
    pub fn tunnel_max_apdu(&self) -> u16 {
        self.tunnel_max_apdu
    }

    // ========================================================================
    // Unconnected management services
    // ========================================================================

    /// Read the device descriptor from a device (unconnected).
    pub async fn device_descriptor_read(
        &self,
        addr: zweidraehte_proto::address::IndividualAddress,
        descriptor_type: u8,
    ) -> Result<Vec<u8>> {
        let apci = management::build_device_descriptor_read(descriptor_type);
        let response = self.send_unconnected(addr, &apci).await?;
        management::parse_device_descriptor_response(&response)
    }

    /// Read a property value from a device (unconnected).
    pub async fn property_read(
        &self,
        addr: zweidraehte_proto::address::IndividualAddress,
        obj_idx: u8,
        prop_id: u8,
        start_idx: u16,
        count: u16,
    ) -> Result<Vec<u8>> {
        let apci = management::build_property_read(obj_idx, prop_id, count, start_idx);
        let response = self.send_unconnected(addr, &apci).await?;
        let (resp_count, _, data) = management::parse_property_value_response(&response)?;
        if resp_count == 0 {
            return Err(Error::DeviceError(0));
        }
        Ok(data)
    }

    /// Execute a function property command on a device (unconnected).
    pub async fn function_property_command(
        &self,
        addr: zweidraehte_proto::address::IndividualAddress,
        obj_idx: u8,
        prop_id: u8,
        service_data: &[u8],
    ) -> Result<crate::FunctionPropertyResult> {
        let apci = management::build_function_property_command(obj_idx, prop_id, service_data);
        let response = self.send_unconnected(addr, &apci).await?;
        management::parse_function_property_response(&response)
    }

    /// Read the state of a function property on a device (unconnected).
    pub async fn function_property_state_read(
        &self,
        addr: zweidraehte_proto::address::IndividualAddress,
        obj_idx: u8,
        prop_id: u8,
        service_data: &[u8],
    ) -> Result<crate::FunctionPropertyResult> {
        let apci = management::build_function_property_state_read(obj_idx, prop_id, service_data);
        let response = self.send_unconnected(addr, &apci).await?;
        management::parse_function_property_response(&response)
    }

    // ========================================================================
    // Connected transport
    // ========================================================================

    /// Open a point-to-point transport connection to a device.
    ///
    /// Sends a T_Connect PDU and waits for the bus confirmation.
    pub async fn open_connection(
        &self,
        addr: zweidraehte_proto::address::IndividualAddress,
    ) -> Result<DeviceConnection> {
        let cemi = transport::build_connect_cemi(self.assigned_address, addr);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SendFrameNoResponse {
                cemi,
                response_tx: tx,
            })
            .await
            .map_err(|_| Error::WorkerGone)?;

        rx.await.map_err(|_| Error::WorkerGone)??;

        Ok(DeviceConnection::new(
            addr,
            self.assigned_address,
            self.cmd_tx.clone(),
        ))
    }

    /// Disconnect from the KNX/IP interface.
    pub async fn disconnect(self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Disconnect { response_tx: tx })
            .await
            .map_err(|_| Error::WorkerGone)?;

        rx.await.map_err(|_| Error::WorkerGone)?
    }

    // ========================================================================
    // Internal
    // ========================================================================

    async fn send_unconnected(
        &self,
        dest: zweidraehte_proto::address::IndividualAddress,
        apci_data: &[u8],
    ) -> Result<Vec<u8>> {
        let cemi = transport::build_unconnected_cemi(
            self.assigned_address,
            dest,
            apci_data,
            self.cemi_mode,
        );

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SendFrame {
                cemi,
                response_tx: tx,
            })
            .await
            .map_err(|_| Error::WorkerGone)?;

        let cemi_response = rx.await.map_err(|_| Error::WorkerGone)??;

        // Parse the cEMI response to extract APCI data.
        let mut slice: &[u8] = &cemi_response;
        let cemi: CemiLData<&[u8]> = slice
            .parse()
            .map_err(|_| Error::Parse("invalid cEMI in response"))?;

        let cemi_body = cemi.data();
        if cemi_body.len() < CEMI_BODY_TPCI_OFFSET + 2 {
            return Err(Error::Parse("cEMI body too short for APCI"));
        }

        let apci_data = &cemi_body[CEMI_BODY_TPCI_OFFSET..];
        log::debug!(
            "Response APCI ({} bytes): {:02x?}",
            apci_data.len(),
            apci_data,
        );

        Ok(apci_data.to_vec())
    }
}
