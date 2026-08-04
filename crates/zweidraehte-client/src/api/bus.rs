//! The root bus handle.

use std::net::SocketAddrV4;

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::apdu::group_value::{
    GroupValueEncoding, GroupValueReadRequest, GroupValueWriteRequest,
};
use zweidraehte_proto::messages::knx::ApciCode;

use crate::api::device_conn::DeviceConnection;
use crate::api::network_mgmt::NetworkManagement;
use crate::connector::{ConnectorInfo, IpTunnelConnector, KnxConnector};
use crate::core::frames;
use crate::core::group::GroupTelegram;
use crate::driver::{BusCommand, BusTask};
use crate::error::{Error, Result};

/// Capacity of the command channel between API handles and the bus task.
const COMMAND_CHANNEL_CAPACITY: usize = 8;

/// Capacity of the group-telegram broadcast channel. Slow subscribers see
/// `RecvError::Lagged` once they fall this far behind.
const GROUP_CHANNEL_CAPACITY: usize = 64;

/// A connection to a KNX installation through some bus access (KNX/IP
/// tunnel, USB interface, ...).
///
/// The bus handle is the root of the API: group traffic happens directly
/// on it, device management goes through [`connect_device`]
/// (KnxBus::connect_device), network management through
/// [`network_management`](KnxBus::network_management). The background task
/// driving the connector is spawned internally and stops when
/// [`disconnect`](KnxBus::disconnect) is called or the handle is dropped.
pub struct KnxBus {
    cmd_tx: mpsc::Sender<BusCommand>,
    group_tx: broadcast::Sender<GroupTelegram>,
    info: ConnectorInfo,
    task: JoinHandle<Result<()>>,
}

impl KnxBus {
    /// Connect through a KNX/IP interface via tunneling.
    pub async fn connect_ip(server: SocketAddrV4) -> Result<Self> {
        let (connector, info) = IpTunnelConnector::connect(server).await?;
        Ok(Self::with_connector(connector, info))
    }

    /// Wrap an already opened custom connector.
    pub fn with_connector<C: KnxConnector>(connector: C, info: ConnectorInfo) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (group_tx, _) = broadcast::channel(GROUP_CHANNEL_CAPACITY);
        let task = tokio::spawn(BusTask::new(connector, info, cmd_rx, group_tx.clone()).run());
        Self { cmd_tx, group_tx, info, task }
    }

    /// The individual address this bus access sends from.
    pub fn assigned_address(&self) -> IndividualAddress {
        self.info.assigned_address
    }

    /// The interface-side maximum APDU length. The effective limit towards
    /// a target device is `min(this, device max APDU from PID 56)`.
    pub fn max_apdu(&self) -> u16 {
        self.info.max_apdu
    }

    // ========================================================================
    // Group communication
    // ========================================================================

    /// Send an `A_GroupValue_Write`.
    ///
    /// `Short` encoding packs a single value ≤ 6 bits into the APCI byte
    /// (DPT 1.x, 2.x, 3.x); `Full` carries `data` after the APCI. Which one
    /// a group object expects follows from its DPT.
    pub async fn group_write(&self, group: GroupAddress, data: &[u8], encoding: GroupValueEncoding) -> Result<()> {
        let frame = match encoding {
            GroupValueEncoding::Short => {
                let [value] = data else {
                    return Err(Error::Parse("short group encoding takes exactly one byte"));
                };
                if *value > 0x3F {
                    return Err(Error::Parse("short group encoding takes a 6-bit value"));
                }
                let value = *value;
                frames::build_group_frame(
                    self.info.assigned_address,
                    group,
                    ApciCode::GroupValueWrite,
                    GroupValueWriteRequest::SHORT_MSG_LEN,
                    move |buf| GroupValueWriteRequest::write_short(buf, value),
                )
            }
            GroupValueEncoding::Full => frames::build_group_frame(
                self.info.assigned_address,
                group,
                ApciCode::GroupValueWrite,
                GroupValueWriteRequest::full_msg_len(data.len()),
                |buf| GroupValueWriteRequest::write_full(buf, data),
            ),
        };
        self.send_only(frame).await
    }

    /// Send an `A_GroupValue_Read`. The answering device's
    /// `A_GroupValue_Response` arrives through [`group_events`]
    /// (KnxBus::group_events), like any other group traffic.
    pub async fn group_read(&self, group: GroupAddress) -> Result<()> {
        let frame = frames::build_group_frame(
            self.info.assigned_address,
            group,
            ApciCode::GroupValueRead,
            GroupValueReadRequest::MSG_LEN,
            GroupValueReadRequest::write,
        );
        self.send_only(frame).await
    }

    /// Subscribe to all group telegrams observed on the bus.
    pub fn group_events(&self) -> broadcast::Receiver<GroupTelegram> {
        self.group_tx.subscribe()
    }

    // ========================================================================
    // Management surfaces
    // ========================================================================

    /// Open a connection-oriented management session (RCo) with a device.
    ///
    /// One transport connection at a time: a second call while one is open
    /// fails with [`Error::ConnectionBusy`].
    pub async fn connect_device(&self, addr: IndividualAddress) -> Result<DeviceConnection> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::TlOpen { dest: addr, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)??;
        Ok(DeviceConnection::new(addr, self.cmd_tx.clone()))
    }

    /// Network-management operations (NM_*: programming-mode addressing,
    /// scanning, connectionless management).
    pub fn network_management(&self) -> NetworkManagement<'_> {
        NetworkManagement::new(&self.cmd_tx, self.info.assigned_address)
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /// Close the bus connection and stop the background task.
    pub async fn disconnect(self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::Shutdown { tx }).await.map_err(|_| Error::WorkerGone)?;
        let result = rx.await.map_err(|_| Error::WorkerGone)?;
        let _ = self.task.await;
        result
    }

    // ========================================================================
    // Internal
    // ========================================================================

    async fn send_only(&self, frame: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::SendOnly { frame, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }
}

// No Drop impl: dropping the handle drops `cmd_tx`, the bus task sees the
// closed command channel and tears the tunnel down gracefully on its own
// (the detached `JoinHandle` lets it run to completion).
