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
use crate::connector::{ConnectorInfo, IpTunnelConnector, KnxConnector, UsbConnector, UsbSelector};
use crate::core::frames;
use crate::core::group::GroupTelegram;
use crate::driver::{BusCommand, BusTask};
use crate::error::{Error, Result};
use crate::security::{SecurityEntry, SecurityStore};

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

    /// [`connect_ip`](Self::connect_ip) with a pre-built security store
    /// (keyring entries and/or a persistent sequence-number store such
    /// as [`crate::JsonSeqStore`]).
    pub async fn connect_ip_with_security(server: SocketAddrV4, security: SecurityStore) -> Result<Self> {
        let (connector, info) = IpTunnelConnector::connect(server).await?;
        Ok(Self::with_connector_and_security(connector, info, security))
    }

    /// Connect through a KNX USB interface.
    pub async fn connect_usb(selector: &UsbSelector) -> Result<Self> {
        let (connector, info) = UsbConnector::connect(selector).await?;
        Ok(Self::with_connector(connector, info))
    }

    /// [`connect_usb`](Self::connect_usb) with a pre-built security store.
    pub async fn connect_usb_with_security(selector: &UsbSelector, security: SecurityStore) -> Result<Self> {
        let (connector, info) = UsbConnector::connect(selector).await?;
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
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (group_tx, _) = broadcast::channel(GROUP_CHANNEL_CAPACITY);
        let task = tokio::spawn(BusTask::new(connector, info, cmd_rx, group_tx.clone(), security).run());
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
        self.connect_device_with_sync(addr, false).await
    }

    /// Open secure management and force S-A_Sync before returning.
    ///
    /// Ordinary callers should use [`connect_device`](Self::connect_device),
    /// which reuses authoritative counters and synchronizes only for unknown
    /// or stale state. This method is for explicit synchronization and state
    /// recovery workflows.
    pub async fn connect_device_synchronized(&self, addr: IndividualAddress) -> Result<DeviceConnection> {
        self.connect_device_with_sync(addr, true).await
    }

    async fn connect_device_with_sync(&self, addr: IndividualAddress, synchronize: bool) -> Result<DeviceConnection> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::TlOpen { dest: addr, synchronize, tx }).await.map_err(|_| Error::WorkerGone)?;
        let needs_security_validation = rx.await.map_err(|_| Error::WorkerGone)??;
        Ok(DeviceConnection::new(addr, self.cmd_tx.clone(), needs_security_validation))
    }

    /// Network-management operations (NM_*: programming-mode addressing,
    /// scanning, connectionless management).
    pub fn network_management(&self) -> NetworkManagement<'_> {
        NetworkManagement::new(&self.cmd_tx, self.info.assigned_address)
    }

    /// Run the full ETS-style configuration download against a device:
    /// unload, write tables and parameters, load, restart (03/05/02 download
    /// procedures).
    ///
    /// Takes the three layers a download draws on — the mask facts
    /// from `knx_master.xml`, the product file, and what this
    /// installation wants — exactly as ETS does. See
    /// [`download`](crate::download) for how to obtain the first two.
    ///
    /// The device must already carry `project.individual_address` —
    /// assign it via [`network_management`](Self::network_management)
    /// programming-mode addressing first when configuring from
    /// factory state. On success the device restarts; give it a
    /// moment before reconnecting.
    ///
    /// For finer control (a different procedure, progress inspection)
    /// use [`download::compile`](crate::download::compile) and
    /// [`CompiledDownload::execute`](crate::download::CompiledDownload::execute)
    /// directly against a [`DeviceConnection`].
    pub async fn configure_device(
        &self,
        mask: &crate::download::MaskData<'_>,
        product: &crate::download::ProductData,
        project: &crate::download::ProjectConfig,
    ) -> Result<()> {
        // `compile` picks the load-control path from the mask family,
        // so this works for both System 7 (memory-mapped) and System B
        // (property) without a branch here.
        let compiled = crate::download::compile(mask, product, project)?;

        let mut device = self.connect_device(project.individual_address).await?;
        let wire_max_apdu = project.max_apdu.min(self.max_apdu());
        let max_apdu = crate::download::management_plaintext_apdu_budget(wire_max_apdu, project.security.is_some());
        let result = async {
            if project.security.is_some() {
                device.enable_security_mode().await?;
            }
            compiled.execute(&mut device, max_apdu).await
        }
        .await;

        // The procedure ends in a restart, which takes the device's
        // transport connection with it — closing afterwards is
        // best-effort cleanup of our side either way.
        let _ = device.close().await;
        result
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
    /// counters tries those counters first and synchronizes only if its first
    /// authenticated exchange fails. Unknown state and FDSK factory access
    /// synchronize eagerly. Entries with
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
