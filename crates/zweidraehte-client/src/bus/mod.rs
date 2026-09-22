//! The root bus handle.

use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::apdu::group_value::{
    GroupValueEncoding, GroupValueReadRequest, GroupValueWriteRequest,
};
use zweidraehte_proto::messages::knx::ApciCode;

use self::error::{BusError as Error, BusResult as Result};
use crate::bus::driver::{BusCommand, BusTask};
use crate::bus::group::GroupTelegram;
use crate::connector::{ConnectorInfo, IpTunnelConnector, KnxConnector};
mod error;
use crate::security::{SecurityEntry, SecurityStore};
pub use device::{DeviceConnection, RestartAck};
pub use error::{BusError, BusResult};
pub use network::{NetworkManagement, ProgrammingModeDevice, SerialAddressAssignment};

/// Capacity of the command channel between API handles and the bus task.
const COMMAND_CHANNEL_CAPACITY: usize = 8;

/// Capacity of the group-telegram broadcast channel. Slow subscribers see
/// `RecvError::Lagged` once they fall this far behind.
const GROUP_CHANNEL_CAPACITY: usize = 64;

/// Process-local identity for binding prepared commissioning work to the bus
/// session which performed its discovery.
static NEXT_BUS_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

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
    instance_id: u64,
    cmd_tx: mpsc::Sender<BusCommand>,
    group_tx: broadcast::Sender<GroupTelegram>,
    info: ConnectorInfo,
    task: JoinHandle<Result<()>>,
}

impl std::fmt::Debug for KnxBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Distinguish concurrent sessions without exposing driver credentials.
        f.debug_struct("KnxBus")
            .field("instance_id", &self.instance_id())
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl KnxBus {
    /// Connect through a KNX/IP interface via tunneling.
    pub async fn connect_ip(server: SocketAddrV4) -> Result<Self> {
        let (connector, info) = IpTunnelConnector::connect(server).await?;
        Ok(Self::with_connector(connector, info))
    }

    /// [`connect_ip`](Self::connect_ip) with a pre-built security store
    /// (keyring entries and a caller-owned sequence-number store).
    pub async fn connect_ip_with_security(server: SocketAddrV4, security: SecurityStore) -> Result<Self> {
        let (connector, info) = IpTunnelConnector::connect(server).await?;
        Ok(Self::with_connector_and_security(connector, info, security))
    }

    /// Wrap an already opened custom connector.
    ///
    /// Data Secure starts disabled (empty keyring, in-memory sequence
    /// counters); add devices with
    /// [`set_device_security`](Self::set_device_security) or start from
    /// [`with_connector_and_security`](Self::with_connector_and_security).
    pub fn with_connector<C: KnxConnector>(connector: C, info: ConnectorInfo) -> Self {
        Self::with_connector_and_security(connector, info, SecurityStore::new())
    }

    /// Wrap an already opened custom connector with a pre-built security
    /// store.
    pub fn with_connector_and_security<C: KnxConnector>(
        connector: C,
        info: ConnectorInfo,
        security: SecurityStore,
    ) -> Self {
        // A prepared commissioning value is meaningful only on the live bus
        // which discovered it. Relaxed ordering is sufficient because the ID
        // carries identity, not synchronization between bus tasks.
        let instance_id = NEXT_BUS_INSTANCE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| current.checked_add(1))
            .expect("KNX bus instance ID space is exhausted");
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (group_tx, _) = broadcast::channel(GROUP_CHANNEL_CAPACITY);
        let task = tokio::spawn(BusTask::new(connector, info, cmd_rx, group_tx.clone(), security).run());
        Self { instance_id, cmd_tx, group_tx, info, task }
    }

    pub(crate) const fn instance_id(&self) -> u64 {
        self.instance_id
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
        self.connect_device_with_sync(addr, false).await
    }

    /// Open secure management and force a fresh S-A_Sync before returning.
    ///
    /// Ordinary secure connections also synchronize before returning, but may
    /// reuse the same credential's sync from the preceding two seconds. This
    /// method bypasses that cache for state-query and recovery workflows.
    pub async fn connect_device_synchronized(&self, addr: IndividualAddress) -> Result<DeviceConnection> {
        self.connect_device_with_sync(addr, true).await
    }

    async fn connect_device_with_sync(&self, addr: IndividualAddress, force_sync: bool) -> Result<DeviceConnection> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::TlOpen { dest: addr, force_sync, tx }).await.map_err(|_| Error::WorkerGone)?;
        let result = rx.await.map_err(|_| Error::WorkerGone)??;
        Ok(DeviceConnection::new(
            addr,
            self.cmd_tx.clone(),
            result.secure_management,
            result.remote_next_sequence,
            result.connection,
        ))
    }

    /// Network-management operations (NM_*: programming-mode addressing,
    /// scanning, connectionless management).
    pub fn network_management(&self) -> NetworkManagement<'_> {
        NetworkManagement::new(&self.cmd_tx, self.info.assigned_address)
    }

    // ========================================================================
    // Data Secure
    // ========================================================================

    /// Register or replace a device's Data Secure keyring entry.
    ///
    /// A subsequent [`connect_device`](Self::connect_device) to an IA
    /// whose entry has [`DeviceSecurityMode::Secure`]
    /// (crate::DeviceSecurityMode::Secure) wraps management traffic under
    /// the entry's active key. A Tool-Key session with authoritative stored
    /// counters synchronizes before it is exposed to the caller. Only an
    /// immediately preceding synchronization of the same credential may be
    /// reused to avoid the device's response rate limit. Entries with
    /// mode `Plain` document known keys without enabling security —
    /// required for secure-capable devices whose security mode is
    /// switched off.
    ///
    /// Takes effect for connections opened afterwards, not for one
    /// already open.
    pub async fn set_device_security(&self, ia: IndividualAddress, entry: SecurityEntry) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::SetDeviceSecurity { ia, entry, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)
    }

    /// Move a registered security entry after changing a device's IA.
    pub async fn move_device_security(&self, previous: IndividualAddress, current: IndividualAddress) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BusCommand::MoveDeviceSecurity { previous, current, tx })
            .await
            .map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)
    }

    /// Remove a device security entry so subsequent connections are plain.
    pub async fn remove_device_security(&self, ia: IndividualAddress) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::RemoveDeviceSecurity { ia, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)
    }

    /// Register or replace the Data Secure key for a group address.
    ///
    /// Subsequent outgoing group telegrams are protected with this key.
    /// Incoming secure telegrams are authenticated with it, while plaintext
    /// traffic on the same address is rejected as a downgrade.
    pub async fn set_group_key(&self, group: GroupAddress, key: [u8; 16]) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let ga = u16::from_be_bytes(group.0);
        self.cmd_tx.send(BusCommand::SetGroupKey { ga, key, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)
    }

    /// Return the durable next sequence number expected from a managed
    /// device. The programming pipeline combines this observation with the
    /// live PID 59 value before advancing the device.
    pub async fn device_sequence_floor(&self, serial: [u8; 6]) -> Result<u64> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::DeviceSequenceFloor { serial, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)
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

pub(crate) mod access;
mod device;
pub(crate) mod driver;
pub(crate) mod frames;
pub(crate) mod group;
pub(crate) mod management;
mod network;
pub(crate) mod reads;
#[cfg(test)]
mod secure_tests;

#[cfg(all(test, feature = "commissioning"))]
mod scripted {
    use super::*;

    impl KnxBus {
        /// A scripted peer observes the real DeviceConnection's encoded requests.
        pub(crate) fn scripted(info: ConnectorInfo) -> (Self, mpsc::Receiver<BusCommand>) {
            let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
            let (group_tx, _) = broadcast::channel(GROUP_CHANNEL_CAPACITY);
            let task = tokio::spawn(async { Ok(()) });
            let instance_id = NEXT_BUS_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
            (Self { instance_id, cmd_tx, group_tx, info, task }, cmd_rx)
        }
    }
}
