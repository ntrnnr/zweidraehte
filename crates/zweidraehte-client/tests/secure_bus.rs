//! Data Secure end-to-end tests over an in-memory connector.
//!
//! A channel-backed connector plays the bus; the test body plays the
//! secure device, using the same `SecureChannel` primitives from the
//! opposite side (wrap/unwrap are symmetric — the device's tool-access
//! traffic is the mirror image of ours). Time is tokio-paused, so the
//! sync-timeout paths run instantly.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio::time::Duration;

use zweidraehte_client::core::frames;
use zweidraehte_client::security::channel::{SecureChannel, seq_to_bytes};
use zweidraehte_client::security::{MemSeqStore, ResolvedKeyMaterial, SeqNumberStore};
use zweidraehte_client::{
    ConnectorInfo, Error, GroupAddress, GroupValueEncoding, IndividualAddress, InterfaceObjectType, KnxBus,
    KnxConnector, ManagementAccess, SecurityEntry, SecurityStore, connect_management,
};
use zweidraehte_proto::crypto::ccm;
use zweidraehte_proto::crypto::scf::SecurityControlField;
use zweidraehte_proto::encoding::cemi::CemiMessageCode;
use zweidraehte_proto::messages::apdu::property::PropertyValueResponse;
use zweidraehte_proto::messages::apdu::property_ext::{
    PropertyExtValueHeader, PropertyExtValueWriteConRes, PropertyReturnCode,
};
use zweidraehte_proto::messages::apdu::secure::{self, SyncReqRef};
use zweidraehte_proto::messages::knx::{ApciCode, DestinationAddress, KnxMessageBuffer, Tpci};

const FDSK: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const SERIAL: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

fn client_ia() -> IndividualAddress {
    IndividualAddress::new(15, 15, 250)
}
fn device_ia() -> IndividualAddress {
    IndividualAddress::new(1, 1, 42)
}

// ============================================================================
// Channel connector + mock-device plumbing
// ============================================================================

struct ChannelConnector {
    to_device: mpsc::UnboundedSender<Vec<u8>>,
    from_device: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl KnxConnector for ChannelConnector {
    async fn send_cemi(&mut self, cemi: &[u8]) -> zweidraehte_client::Result<()> {
        self.to_device.send(cemi.to_vec()).map_err(|_| Error::Disconnected)
    }

    async fn recv_cemi(&mut self) -> zweidraehte_client::Result<Vec<u8>> {
        self.from_device.recv().await.ok_or(Error::Disconnected)
    }

    async fn close(&mut self) -> zweidraehte_client::Result<()> {
        Ok(())
    }
}

/// The test's handle on the fake bus: receive what the client sent,
/// inject indications back.
struct MockBus {
    from_client: mpsc::UnboundedReceiver<Vec<u8>>,
    to_client: mpsc::UnboundedSender<Vec<u8>>,
}

impl MockBus {
    /// Next internal-format frame the client put on the bus.
    async fn recv(&mut self) -> Vec<u8> {
        let cemi = tokio::time::timeout(Duration::from_secs(30), self.from_client.recv())
            .await
            .expect("client frame within timeout")
            .expect("connector channel open");
        frames::cemi_to_internal(&cemi)
    }

    /// Positive L_Data.con echo of a frame the client sent.
    fn confirm(&self, internal: &[u8]) {
        let cemi = frames::internal_to_cemi(internal, CemiMessageCode::LDataCon);
        self.to_client.send(cemi).expect("connector channel open");
    }

    /// L_Data.ind of a device-originated frame.
    fn indicate(&self, internal: &[u8]) {
        let cemi = frames::internal_to_cemi(internal, CemiMessageCode::LDataInd);
        self.to_client.send(cemi).expect("connector channel open");
    }
}

/// A seq store the test can inspect after the bus task consumed it.
#[derive(Clone, Default)]
struct SharedSeqStore(Arc<Mutex<MemSeqStore>>);

impl SeqNumberStore for SharedSeqStore {
    fn has_client_seq(&self) -> bool {
        self.0.lock().expect("store mutex").has_client_seq()
    }

    fn load_client_seq(&self) -> u64 {
        self.0.lock().expect("store mutex").load_client_seq()
    }
    fn save_client_seq(&mut self, seq: u64) -> std::io::Result<()> {
        self.0.lock().expect("store mutex").save_client_seq(seq)
    }
    fn load_device_seq(&self, serial: &[u8; 6]) -> u64 {
        self.0.lock().expect("store mutex").load_device_seq(serial)
    }
    fn has_device_seq(&self, serial: &[u8; 6]) -> bool {
        self.0.lock().expect("store mutex").has_device_seq(serial)
    }
    fn save_device_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()> {
        self.0.lock().expect("store mutex").save_device_seq(serial, seq)
    }
    fn load_sender_seq(&self, ia: IndividualAddress) -> u64 {
        self.0.lock().expect("store mutex").load_sender_seq(ia)
    }
    fn save_sender_seq(&mut self, ia: IndividualAddress, seq: u64) -> std::io::Result<()> {
        self.0.lock().expect("store mutex").save_sender_seq(ia, seq)
    }
}

fn secure_bus(entry: SecurityEntry) -> (KnxBus, MockBus, SharedSeqStore) {
    let (to_device_tx, to_device_rx) = mpsc::unbounded_channel();
    let (to_client_tx, to_client_rx) = mpsc::unbounded_channel();
    let connector = ChannelConnector { to_device: to_device_tx, from_device: to_client_rx };
    let info = ConnectorInfo { assigned_address: client_ia(), max_apdu: 254 };

    let store = SharedSeqStore::default();
    let mut security = SecurityStore::with_store(Box::new(store.clone()));
    security.set_device_security(device_ia(), entry);

    let bus = KnxBus::with_connector_and_security(connector, info, security);
    (bus, MockBus { from_client: to_device_rx, to_client: to_client_tx }, store)
}

// ============================================================================
// Device-side crypto helpers
// ============================================================================

/// Answer a verified sync request: advertise the device's next sending
/// seq (`seq_remote`) and its expectation of the tool (`seq_local`).
fn build_sync_res(challenge: &[u8; 6], seq_remote: u64, seq_local: u64) -> Vec<u8> {
    build_sync_res_with_key(&FDSK, challenge, seq_remote, seq_local, true, None)
}

fn build_sync_res_with_key(
    key: &[u8; 16],
    challenge: &[u8; 6],
    seq_remote: u64,
    seq_local: u64,
    system_broadcast: bool,
    connected_seq: Option<u8>,
) -> Vec<u8> {
    let random: [u8; 6] = [0xAA; 6];
    let mut cxr = [0u8; 6];
    for i in 0..6 {
        cxr[i] = challenge[i] ^ random[i];
    }
    // SCF 0x93 is point-to-point; 0x9B additionally carries SBC.
    let scf_byte = if system_broadcast { 0x9B } else { 0x93 };
    let src = u16::from_be_bytes(device_ia().0);
    let dst = if system_broadcast { 0 } else { u16::from_be_bytes(client_ia().0) };
    let addr_type = if system_broadcast { 0x80 } else { 0x00 };

    let mut payload = [0u8; 12];
    payload[0..6].copy_from_slice(&seq_to_bytes(seq_remote));
    payload[6..12].copy_from_slice(&seq_to_bytes(seq_local));
    let tpci_high = connected_seq.map_or(0, |seq| 0x40 | ((seq & 0x0F) << 2));
    let tpci_apci = u16::from_be_bytes([tpci_high | 0x03, 0xF1]);
    let mac = ccm::encrypt_and_mac_sync_res(key, &random, src, dst, addr_type, tpci_apci, scf_byte, &mut payload);

    let mut buf = vec![0u8; secure::sync::FRAME_LEN];
    let mac_offset = secure::build_sync_response(
        &mut buf,
        if system_broadcast { 0xA0 } else { 0xB0 },
        src,
        dst,
        if system_broadcast { 0xE0 } else { 0x60 },
        tpci_high,
        scf_byte,
        &cxr,
        &payload[0..6].try_into().expect("6-byte slice"),
        &payload[6..12].try_into().expect("6-byte slice"),
    );
    buf[mac_offset..mac_offset + secure::MAC_LEN].copy_from_slice(&mac);
    buf
}

/// Drive the T_Connect + S-A_Sync opening from the device side.
///
/// Returns the device's `SecureChannel`, primed with the advertised
/// counters (`seq_remote` = its sending counter, `seq_local` = what it
/// expects from the tool).
async fn accept_secure_connect(bus: &mut MockBus, seq_remote: u64, seq_local: u64) -> SecureChannel {
    accept_secure_connect_with_key(bus, FDSK, seq_remote, seq_local, true).await
}

async fn accept_secure_connect_with_key(
    bus: &mut MockBus,
    key: [u8; 16],
    seq_remote: u64,
    seq_local: u64,
    system_broadcast: bool,
) -> SecureChannel {
    let connect = bus.recv().await;
    assert_eq!(KnxMessageBuffer::from_buffer(connect.as_slice()).get_tpci(), Some(Tpci::Connect));
    bus.confirm(&connect);

    answer_secure_sync(bus, key, seq_remote, seq_local, system_broadcast).await
}

async fn answer_secure_sync(
    bus: &mut MockBus,
    key: [u8; 16],
    seq_remote: u64,
    seq_local: u64,
    system_broadcast: bool,
) -> SecureChannel {
    let sync_req = bus.recv().await;
    let req = SyncReqRef::parse(&sync_req).unwrap_or_else(|error| {
        panic!(
            "31-byte sync request ({error:?}); got {} bytes with {:?}",
            sync_req.len(),
            KnxMessageBuffer::from_buffer(sync_req.as_slice()).get_tpci()
        )
    });
    let serial = req.knx_serial_number();
    let message = KnxMessageBuffer::from_buffer(sync_req.as_slice());
    assert_eq!(
        message.get_dest_addr(),
        if system_broadcast {
            DestinationAddress::SystemBroadcast
        } else {
            DestinationAddress::Individual(device_ia())
        }
    );
    assert_eq!(serial, if system_broadcast { SERIAL } else { [0u8; 6] });
    assert_eq!(SecurityControlField::parse(req.scf_byte()).expect("sync SCF").system_broadcast, system_broadcast);

    let request_seq = if system_broadcast {
        assert_eq!(message.get_tpci(), Some(Tpci::DataSystemBroadcast));
        None
    } else {
        let Some(Tpci::DataConnected(seq)) = message.get_tpci() else {
            panic!("Tool-Key sync inside an open TL connection must be connected")
        };
        Some(seq)
    };

    let mut challenge = [0u8; 6];
    challenge.copy_from_slice(req.challenge());
    let ctx = req.ccm_context();
    let mac = req.mac();
    ccm::verify_and_decrypt_sync_req(&key, &ctx, req.scf_byte(), &serial, &mut challenge, &mac)
        .expect("sync request verifies under the active key");

    if let Some(seq) = request_seq {
        bus_ack(bus, seq);
    }
    bus.indicate(&build_sync_res_with_key(
        &key,
        &challenge,
        seq_remote,
        seq_local,
        system_broadcast,
        (!system_broadcast).then_some(0),
    ));
    if !system_broadcast {
        let response_ack = bus.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(response_ack.as_slice()).get_tpci(), Some(Tpci::Ack(0)));
    }

    // The device tracks the tool's traffic with the mirrored counters.
    SecureChannel::new(key, SERIAL, seq_remote, seq_local)
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test(start_paused = true)]
async fn successful_secure_sync_selects_fdsk_without_probing_dd0() {
    let (bus, mut mock, _) = secure_bus(SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

    let device = tokio::spawn(async move {
        accept_secure_connect(&mut mock, 100, 50).await;

        // S-A_Sync has already authenticated the FDSK. The descriptor has an
        // independent access policy, so credential selection must not issue a
        // DD0 read which a factory device may mask with FFFFh.
        let disconnect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(disconnect.as_slice()).get_tpci(), Some(Tpci::Disconnect));
    });
    let keys = ResolvedKeyMaterial::new(Some(SERIAL)).with_fdsk(Some(FDSK));

    let (connection, access) =
        connect_management(&bus, device_ia(), &keys, false).await.expect("verified FDSK opens management access");
    assert_eq!(access, ManagementAccess::Fdsk);
    connection.close().await.expect("management connection closes");
    device.await.expect("mock device runs to completion");
}

#[tokio::test(start_paused = true)]
async fn fdsk_sync_is_reused_only_within_the_current_bus_session() {
    let (bus, mut mock, _) = secure_bus(SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

    let device = tokio::spawn(async move {
        let mut channel = accept_secure_connect(&mut mock, 100, 50).await;

        let disconnect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(disconnect.as_slice()).get_tpci(), Some(Tpci::Disconnect));

        let connect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(connect.as_slice()).get_tpci(), Some(Tpci::Connect));
        mock.confirm(&connect);

        // A sync proven moments ago in this process can be reused by the
        // programming pass following preflight. Merely persisted FDSK floors
        // do not enable this path in a new SecurityStore.
        let request = mock.recv().await;
        assert!(SyncReqRef::parse(&request).is_err(), "a freshly synchronized FDSK is tried directly");
        let (plain, _) = channel.unwrap(&request).expect("the direct FDSK request verifies");
        assert_eq!(KnxMessageBuffer::from_buffer(plain.as_slice()).get_apci_code(), ApciCode::PropertyValueRead);
        bus_ack(&mock, 0);

        let mut response = frames::build_individual_frame(
            device_ia(),
            client_ia(),
            Tpci::DataConnected(0),
            ApciCode::PropertyValueResponse,
            PropertyValueResponse::msg_len(6),
            |buf| PropertyValueResponse::write(buf, 0, 11, 1, 1, &SERIAL),
        );
        frames::set_connected_seq(&mut response, 0);
        let (wrapped, _) = channel.wrap(u16::from_be_bytes(device_ia().0), &response);
        mock.indicate(&wrapped);
        mock
    });

    let first = bus.connect_device(device_ia()).await.expect("initial FDSK sync succeeds");
    first.close().await.expect("first connection closes");
    let mut second = bus.connect_device(device_ia()).await.expect("recent FDSK state opens directly");
    let value = second.property_read(0, 11, 1, 1).await.expect("direct FDSK request succeeds");
    assert_eq!(value, SERIAL);
    drop(device.await.expect("mock device runs to completion"));
}

#[tokio::test(start_paused = true)]
async fn secure_connect_and_property_read_roundtrip() {
    let (bus, mut mock, store) = secure_bus(SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

    let device = tokio::spawn(async move {
        let mut dev_channel = accept_secure_connect(&mut mock, 100, 50).await;

        // The wrapped property read arrives; unwrap it device-side.
        let request = mock.recv().await;
        let (plain, _) = dev_channel.unwrap(&request).expect("client frame verifies");
        let msg = KnxMessageBuffer::from_buffer(plain.as_slice());
        assert_eq!(msg.get_apci_code(), ApciCode::PropertyValueRead);
        assert_eq!(msg.get_tpci(), Some(Tpci::DataConnected(0)));
        bus_ack(&mock, 0);

        // Wrapped response: serial number property, 6 bytes.
        let mut response = frames::build_individual_frame(
            device_ia(),
            client_ia(),
            Tpci::DataConnected(0),
            ApciCode::PropertyValueResponse,
            PropertyValueResponse::msg_len(6),
            |buf| PropertyValueResponse::write(buf, 0, 11, 1, 1, &SERIAL),
        );
        frames::set_connected_seq(&mut response, 0);
        let (wrapped, _) = dev_channel.wrap(u16::from_be_bytes(device_ia().0), &response);
        mock.indicate(&wrapped);

        mock
    });

    let mut dev = bus.connect_device(device_ia()).await.expect("secure connect succeeds");
    let value = dev.property_read(0, 11, 1, 1).await.expect("wrapped property read succeeds");
    assert_eq!(value, SERIAL);

    device.await.expect("mock device runs to completion");

    // The device used seq 100 → we now require 101; our first frame
    // consumed the advertised tool seq 50 → next is 51.
    assert_eq!(store.load_device_seq(&SERIAL), 101);
    assert!(store.load_client_seq() > 200_000_000_000);
}

#[tokio::test(start_paused = true)]
async fn tool_key_write_uses_old_key_for_request_and_new_key_for_response_and_reconnect() {
    const NEW_KEY: [u8; 16] = [0x5A; 16];
    let (bus, mut mock, _) = secure_bus(SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

    let device = tokio::spawn(async move {
        let mut old_channel = accept_secure_connect(&mut mock, 100, 50).await;

        let request = mock.recv().await;
        let (plain, next_tool_seq) = old_channel.unwrap(&request).expect("tool-key write uses the FDSK");
        let request_header = PropertyExtValueHeader::parse(&plain).expect("extended write header");
        assert_eq!(KnxMessageBuffer::from_buffer(plain.as_slice()).get_apci_code(), ApciCode::PropertyExtValueWriteCon);
        assert_eq!(
            (request_header.object_type, request_header.object_instance, request_header.prop_id),
            (u16::from(InterfaceObjectType::Security), 1, zweidraehte_proto::pid::security::TOOL_KEY)
        );
        assert_eq!(request_header.data(&plain), NEW_KEY);
        bus_ack(&mock, 0);

        // The request changed the device's key. Preserve the two synced
        // counters while replacing only the cipher key, then answer under it.
        let mut new_channel = SecureChannel::new(NEW_KEY, SERIAL, old_channel.peek_tool_seq(), next_tool_seq);
        let mut response = frames::build_individual_frame(
            device_ia(),
            client_ia(),
            Tpci::DataConnected(0),
            ApciCode::PropertyExtValueWriteConRes,
            PropertyExtValueWriteConRes::MSG_LEN,
            |buf| {
                PropertyExtValueWriteConRes::write_success(
                    buf,
                    u16::from(InterfaceObjectType::Security),
                    1,
                    zweidraehte_proto::pid::security::TOOL_KEY,
                    1,
                    1,
                    PropertyReturnCode::Success,
                )
            },
        );
        frames::set_connected_seq(&mut response, 0);
        let (wrapped, _) = new_channel.wrap(u16::from_be_bytes(device_ia().0), &response);
        mock.indicate(&wrapped);

        // Closing and reconnecting proves the bus task committed NEW_KEY to
        // its keyring rather than changing only the live channel. Both
        // authenticated floors are now persisted, so the next session sends
        // protected data directly instead of synchronizing again.
        let response_ack = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(response_ack.as_slice()).get_tpci(), Some(Tpci::Ack(0)));
        let disconnect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(disconnect.as_slice()).get_tpci(), Some(Tpci::Disconnect));

        let connect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(connect.as_slice()).get_tpci(), Some(Tpci::Connect));
        mock.confirm(&connect);

        let request = mock.recv().await;
        assert!(SyncReqRef::parse(&request).is_err(), "known counters skip S-A_Sync");
        let (plain, _) = new_channel.unwrap(&request).expect("persisted client counter verifies");
        assert_eq!(KnxMessageBuffer::from_buffer(plain.as_slice()).get_apci_code(), ApciCode::PropertyValueRead);
        bus_ack(&mock, 0);

        let mut response = frames::build_individual_frame(
            device_ia(),
            client_ia(),
            Tpci::DataConnected(0),
            ApciCode::PropertyValueResponse,
            PropertyValueResponse::msg_len(6),
            |buf| PropertyValueResponse::write(buf, 0, 11, 1, 1, &SERIAL),
        );
        frames::set_connected_seq(&mut response, 0);
        let (wrapped, _) = new_channel.wrap(u16::from_be_bytes(device_ia().0), &response);
        mock.indicate(&wrapped);
        let response_ack = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(response_ack.as_slice()).get_tpci(), Some(Tpci::Ack(0)));
        mock
    });

    let mut connection = bus.connect_device(device_ia()).await.expect("FDSK connect succeeds");
    connection.write_tool_key(NEW_KEY).await.expect("new-key confirmation authenticates");
    connection.close().await.expect("first connection closes");
    let mut connection = bus.connect_device(device_ia()).await.expect("reconnect uses the committed tool key");
    let value = connection.property_read(0, 11, 1, 1).await.expect("known counters work without another sync");
    assert_eq!(value, SERIAL);

    drop(device.await.expect("mock device runs to completion"));
}

#[tokio::test(start_paused = true)]
async fn stale_persisted_counters_sync_only_after_the_direct_request_fails() {
    const TOOL_KEY: [u8; 16] = [0x4B; 16];
    const DEVICE_EXPECTS_CLIENT: u64 = 1_000_000_000_000;
    let (bus, mut mock, store) = secure_bus(SecurityEntry::secure_with_tool_key(TOOL_KEY, SERIAL));
    let mut seed = store.clone();
    seed.save_client_seq(20).expect("client floor seeds");
    seed.save_device_seq(&SERIAL, 100).expect("device floor seeds");

    let device = tokio::spawn(async move {
        let connect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(connect.as_slice()).get_tpci(), Some(Tpci::Connect));
        mock.confirm(&connect);

        // The first frame is protected data, not S-A_Sync. Pretend another
        // tool moved the receiver's expected client counter beyond our
        // persisted value: TL acknowledges it, while secure AL drops it.
        let direct = mock.recv().await;
        assert!(SyncReqRef::parse(&direct).is_err(), "known state is tried before sync");
        bus_ack(&mock, 0);

        // The unanswered protected request triggers exactly one sync on the
        // still-open connection. Its response moves both floors forward.
        let mut channel = answer_secure_sync(&mut mock, TOOL_KEY, 100, DEVICE_EXPECTS_CLIENT, false).await;

        let retry = mock.recv().await;
        let (plain, _) = channel.unwrap(&retry).expect("retry uses the synchronized client floor");
        assert_eq!(KnxMessageBuffer::from_buffer(plain.as_slice()).get_apci_code(), ApciCode::PropertyValueRead);
        assert_eq!(KnxMessageBuffer::from_buffer(plain.as_slice()).get_tpci(), Some(Tpci::DataConnected(2)));
        bus_ack(&mock, 2);

        let mut response = frames::build_individual_frame(
            device_ia(),
            client_ia(),
            Tpci::DataConnected(0),
            ApciCode::PropertyValueResponse,
            PropertyValueResponse::msg_len(6),
            |buf| PropertyValueResponse::write(buf, 0, 11, 1, 1, &SERIAL),
        );
        frames::set_connected_seq(&mut response, 1);
        let (wrapped, _) = channel.wrap(u16::from_be_bytes(device_ia().0), &response);
        mock.indicate(&wrapped);
        mock
    });

    let mut connection = bus.connect_device(device_ia()).await.expect("known-state connection opens without sync");
    let value = connection.property_read(0, 11, 1, 1).await.expect("sync recovery retries the property read");
    assert_eq!(value, SERIAL);
    drop(device.await.expect("mock device runs to completion"));
    assert!(store.load_client_seq() > DEVICE_EXPECTS_CLIENT);
}

#[tokio::test(start_paused = true)]
async fn explicit_synchronized_connect_ignores_usable_persisted_state() {
    const TOOL_KEY: [u8; 16] = [0x4D; 16];
    let (bus, mut mock, store) = secure_bus(SecurityEntry::secure_with_tool_key(TOOL_KEY, SERIAL));
    let mut seed = store.clone();
    seed.save_client_seq(20).expect("client floor seeds");
    seed.save_device_seq(&SERIAL, 100).expect("device floor seeds");

    let device = tokio::spawn(async move {
        accept_secure_connect_with_key(&mut mock, TOOL_KEY, 100, 20, false).await;
        mock
    });
    bus.connect_device_synchronized(device_ia()).await.expect("explicit sync succeeds");
    drop(device.await.expect("mock device runs to completion"));
}

#[tokio::test(start_paused = true)]
async fn credential_fallback_tries_stored_tool_state_then_tool_sync_then_fdsk_sync() {
    const STALE_TOOL_KEY: [u8; 16] = [0x6C; 16];
    let (bus, mut mock, store) = secure_bus(SecurityEntry::secure_with_tool_key(STALE_TOOL_KEY, SERIAL));
    let mut seed = store.clone();
    seed.save_client_seq(20).expect("client floor seeds");
    seed.save_device_seq(&SERIAL, 100).expect("device floor seeds");

    let device = tokio::spawn(async move {
        let connect = mock.recv().await;
        mock.confirm(&connect);

        let direct = mock.recv().await;
        assert!(SyncReqRef::parse(&direct).is_err(), "stored Tool Key is tried directly first");
        bus_ack(&mock, 0);

        for _ in 0..2 {
            let sync = mock.recv().await;
            let request = SyncReqRef::parse(&sync).expect("Tool-Key recovery uses S-A_Sync");
            assert_eq!(request.knx_serial_number(), [0; 6]);
            assert!(!SecurityControlField::parse(request.scf_byte()).expect("valid SCF").system_broadcast);
            let Some(Tpci::DataConnected(seq)) = KnxMessageBuffer::from_buffer(sync.as_slice()).get_tpci() else {
                panic!("Tool-Key recovery sync must use the open TL connection")
            };
            bus_ack(&mock, seq);
        }
        let disconnect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(disconnect.as_slice()).get_tpci(), Some(Tpci::Disconnect));

        let _channel = accept_secure_connect_with_key(&mut mock, FDSK, 200, 300, true).await;
        let disconnect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(disconnect.as_slice()).get_tpci(), Some(Tpci::Disconnect));
        // Keep the channel and connector alive until the caller has observed
        // successful FDSK selection and closed the connection.
        mock
    });

    let keys = ResolvedKeyMaterial::new(Some(SERIAL)).with_fdsk(Some(FDSK)).with_tool_key(Some(STALE_TOOL_KEY));
    let (connection, access) =
        connect_management(&bus, device_ia(), &keys, false).await.expect("FDSK fallback opens management access");
    assert_eq!(access, ManagementAccess::Fdsk);
    connection.close().await.expect("FDSK connection closes");
    drop(device.await.expect("mock device runs to completion"));
}

#[tokio::test(start_paused = true)]
async fn interrupted_tool_key_rotation_is_retryable_with_the_persisted_key() {
    const NEW_KEY: [u8; 16] = [0x6A; 16];
    let (first_bus, mut first_mock, _) = secure_bus(SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

    let first_device = tokio::spawn(async move {
        let mut old_channel = accept_secure_connect(&mut first_mock, 100, 50).await;
        let request = first_mock.recv().await;
        let (plain, _) = old_channel.unwrap(&request).expect("tool-key write uses the FDSK");
        let header = PropertyExtValueHeader::parse(&plain).expect("extended write header");
        assert_eq!(header.data(&plain), NEW_KEY);
        bus_ack(&first_mock, 0);

        // The device has committed NEW_KEY, but its confirmation is lost.
        // The client eventually tears down the inconclusive connection.
        let disconnect = first_mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(disconnect.as_slice()).get_tpci(), Some(Tpci::Disconnect));
    });

    let mut connection = first_bus.connect_device(device_ia()).await.expect("FDSK connect succeeds");
    let error = connection.write_tool_key(NEW_KEY).await.expect_err("lost confirmation times out");
    assert!(matches!(error, Error::Timeout), "got {error:?}");
    first_device.await.expect("first device run completes");
    drop(first_bus);

    // A commissioning frontend persisted NEW_KEY before the first bus write.
    // Its next invocation therefore tries that key first and can recover even
    // though the previous client never observed the rotation response.
    let (retry_bus, mut retry_mock, _) = secure_bus(SecurityEntry::secure_with_tool_key(NEW_KEY, SERIAL));
    let retry_device = tokio::spawn(async move {
        accept_secure_connect_with_key(&mut retry_mock, NEW_KEY, 101, 51, false).await;
    });
    retry_bus.connect_device(device_ia()).await.expect("retry syncs under the persisted tool key");
    retry_device.await.expect("retry device run completes");
}

fn bus_ack(mock: &MockBus, seq: u8) {
    let ack = frames::build_transport_frame(device_ia(), client_ia(), Tpci::Ack(seq));
    mock.indicate(&ack);
}

#[tokio::test(start_paused = true)]
async fn plain_device_skips_handshake() {
    let (bus, mut mock, _) = secure_bus(SecurityEntry::plain(SERIAL));

    let device = tokio::spawn(async move {
        let connect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(connect.as_slice()).get_tpci(), Some(Tpci::Connect));
        mock.confirm(&connect);
    });

    bus.connect_device(device_ia()).await.expect("plain connect succeeds without sync");
    device.await.expect("mock device runs to completion");
}

#[tokio::test(start_paused = true)]
async fn sync_timeout_retries_once_then_fails() {
    let (bus, mut mock, _) = secure_bus(SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

    let device = tokio::spawn(async move {
        let connect = mock.recv().await;
        mock.confirm(&connect);

        // Two sync requests (initial + retry), never answered.
        let first = mock.recv().await;
        SyncReqRef::parse(&first).expect("first sync request");
        let second = mock.recv().await;
        SyncReqRef::parse(&second).expect("retried sync request");
        assert_ne!(
            SyncReqRef::parse(&first).expect("parsed above").challenge(),
            SyncReqRef::parse(&second).expect("parsed above").challenge(),
            "retry uses a fresh challenge"
        );

        // The failed open closes the connection.
        let disconnect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(disconnect.as_slice()).get_tpci(), Some(Tpci::Disconnect));
    });

    let Err(err) = bus.connect_device(device_ia()).await else { panic!("sync must time out") };
    assert!(matches!(err, Error::SecuritySyncTimeout), "got {err:?}");
    device.await.expect("mock device runs to completion");
}

#[tokio::test(start_paused = true)]
async fn tampered_sync_response_fails_connect() {
    let (bus, mut mock, _) = secure_bus(SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

    let device = tokio::spawn(async move {
        let connect = mock.recv().await;
        mock.confirm(&connect);

        let sync_req = mock.recv().await;
        let req = SyncReqRef::parse(&sync_req).expect("sync request");
        let mut challenge = [0u8; 6];
        challenge.copy_from_slice(req.challenge());
        let ctx = req.ccm_context();
        let mac = req.mac();
        ccm::verify_and_decrypt_sync_req(&FDSK, &ctx, req.scf_byte(), &req.knx_serial_number(), &mut challenge, &mac)
            .expect("sync request verifies");

        let mut res = build_sync_res(&challenge, 100, 50);
        let last = res.len() - 1;
        res[last] ^= 0x01;
        mock.indicate(&res);

        let disconnect = mock.recv().await;
        assert_eq!(KnxMessageBuffer::from_buffer(disconnect.as_slice()).get_tpci(), Some(Tpci::Disconnect));
    });

    let Err(err) = bus.connect_device(device_ia()).await else { panic!("tampered sync response must fail") };
    assert!(matches!(err, Error::SecurityMacMismatch), "got {err:?}");
    device.await.expect("mock device runs to completion");
}

#[tokio::test(start_paused = true)]
async fn missing_key_fails_secure_connect() {
    let error =
        SecurityEntry::with_credentials(zweidraehte_client::DeviceSecurityMode::Secure, None, None, Some(SERIAL))
            .expect_err("keyless secure entries are rejected");
    assert!(matches!(error, zweidraehte_client::security::SecureError::MissingKey));
}

#[tokio::test(start_paused = true)]
async fn replayed_device_frame_is_dropped() {
    let (bus, mut mock, _) = secure_bus(SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

    let device = tokio::spawn(async move {
        let mut dev_channel = accept_secure_connect(&mut mock, 100, 50).await;

        let request = mock.recv().await;
        dev_channel.unwrap(&request).expect("client frame verifies");
        bus_ack(&mock, 0);

        // A stale frame (secure seq below the synced 100) must be
        // ignored, the genuine response afterwards still delivered.
        // The two frames need distinct TL sequence numbers — the stale
        // one is dropped at the *secure* layer, after the transport
        // layer has already consumed its sequence number.
        let build_response = |tl_seq: u8| {
            let mut response = frames::build_individual_frame(
                device_ia(),
                client_ia(),
                Tpci::DataConnected(0),
                ApciCode::PropertyValueResponse,
                PropertyValueResponse::msg_len(1),
                |buf| PropertyValueResponse::write(buf, 0, 11, 1, 1, &[0xEE]),
            );
            frames::set_connected_seq(&mut response, tl_seq);
            response
        };

        let mut stale_channel = SecureChannel::new(FDSK, SERIAL, 3, 1);
        let (stale, _) = stale_channel.wrap(u16::from_be_bytes(device_ia().0), &build_response(0));
        mock.indicate(&stale);

        let (genuine, _) = dev_channel.wrap(u16::from_be_bytes(device_ia().0), &build_response(1));
        mock.indicate(&genuine);

        // Keep the channels open — the client still sends T_ACKs for
        // both incoming data frames; a closed connector kills the task.
        mock
    });

    let mut dev = bus.connect_device(device_ia()).await.expect("secure connect succeeds");
    let value = dev.property_read(0, 11, 1, 1).await.expect("genuine response arrives after the replay");
    assert_eq!(value, [0xEE]);
    drop(device.await.expect("mock device runs to completion"));
}

// ============================================================================
// Group traffic
// ============================================================================

const GROUP_KEY: [u8; 16] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, //
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];

fn secured_ga() -> GroupAddress {
    GroupAddress::from_three_level(2, 0, 3)
}

fn secured_ga_raw() -> u16 {
    u16::from_be_bytes(secured_ga().0)
}

/// A bus whose keyring secures [`secured_ga`] and nothing else.
fn group_secure_bus() -> (KnxBus, MockBus, SharedSeqStore) {
    let (to_device_tx, to_device_rx) = mpsc::unbounded_channel();
    let (to_client_tx, to_client_rx) = mpsc::unbounded_channel();
    let connector = ChannelConnector { to_device: to_device_tx, from_device: to_client_rx };
    let info = ConnectorInfo { assigned_address: client_ia(), max_apdu: 254 };

    let store = SharedSeqStore::default();
    let mut security = SecurityStore::with_store(Box::new(store.clone()));
    security.set_group_key(secured_ga_raw(), GROUP_KEY);

    let bus = KnxBus::with_connector_and_security(connector, info, security);
    (bus, MockBus { from_client: to_device_rx, to_client: to_client_tx }, store)
}

/// A plain A_GroupValue_Write, value 1 (6-bit), from `source`.
fn plain_group_write(source: IndividualAddress, ga: GroupAddress) -> Vec<u8> {
    use zweidraehte_proto::messages::apdu::group_value::GroupValueWriteRequest;
    frames::build_group_frame(source, ga, ApciCode::GroupValueWrite, GroupValueWriteRequest::SHORT_MSG_LEN, |buf| {
        GroupValueWriteRequest::write_short(buf, 1)
    })
}

#[tokio::test(start_paused = true)]
async fn group_write_on_secured_ga_is_wrapped() {
    let (bus, mut mock, store) = group_secure_bus();

    bus.group_write(secured_ga(), &[1], GroupValueEncoding::Short).await.expect("group write accepted");

    let frame = mock.recv().await;
    assert_eq!(&frame[6..8], &[0x03, 0xF1], "SecureService APCI on the wire");
    assert_eq!(frame[secure::SCF], 0x10, "group data SCF: A+C, no tool access");

    // The device side verifies with the same group key; a fresh sender
    // is at floor 1 and the timestamp-seeded seq is far above it.
    let (plain, _) = zweidraehte_client::security::group_unwrap(&GROUP_KEY, &frame, 1).expect("frame verifies");
    let msg = KnxMessageBuffer::from_buffer(plain.as_slice());
    assert_eq!(msg.get_apci_code(), ApciCode::GroupValueWrite);

    // The consumed sending seq was persisted (successor of the
    // timestamp-floored counter).
    assert!(store.load_client_seq() > 200_000_000_000, "client seq persisted, got {}", store.load_client_seq());
}

#[tokio::test(start_paused = true)]
async fn group_write_on_plain_ga_stays_plaintext() {
    let (bus, mut mock, _) = group_secure_bus();
    let other_ga = GroupAddress::from_three_level(2, 0, 4);

    bus.group_write(other_ga, &[1], GroupValueEncoding::Short).await.expect("group write accepted");

    let frame = mock.recv().await;
    let msg = KnxMessageBuffer::from_buffer(frame.as_slice());
    assert_eq!(msg.get_apci_code(), ApciCode::GroupValueWrite, "no secure envelope on an unkeyed GA");
}

#[tokio::test(start_paused = true)]
async fn secure_group_indication_is_decrypted_and_replay_dropped() {
    let (bus, mock, store) = group_secure_bus();
    let mut events = bus.group_events();

    // The device sends a secured write with its own sending seq.
    let plain = plain_group_write(device_ia(), secured_ga());
    let wrapped = zweidraehte_client::security::group_wrap(&GROUP_KEY, 500, u16::from_be_bytes(device_ia().0), &plain);
    mock.indicate(&wrapped);

    let telegram = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("decrypted telegram delivered")
        .expect("broadcast channel open");
    assert_eq!(telegram.group, secured_ga());
    assert_eq!(telegram.source, device_ia());
    assert_eq!(telegram.data, vec![1]);
    assert!(telegram.secured, "telegram flagged as secured");

    // The sender's replay floor advanced and was persisted.
    assert_eq!(store.load_sender_seq(device_ia()), 501);

    // The identical frame again is a replay: nothing reaches subscribers.
    mock.indicate(&wrapped);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), events.recv()).await.is_err(),
        "replayed frame must not be delivered"
    );
}

#[tokio::test(start_paused = true)]
async fn plaintext_on_secured_ga_is_dropped() {
    let (bus, mock, _) = group_secure_bus();
    let mut events = bus.group_events();

    // Downgrade attempt: plaintext write on the secured address.
    mock.indicate(&plain_group_write(device_ia(), secured_ga()));
    assert!(
        tokio::time::timeout(Duration::from_secs(5), events.recv()).await.is_err(),
        "plaintext on a secured GA must not be delivered"
    );

    // Plaintext on an unkeyed address still flows, unflagged.
    mock.indicate(&plain_group_write(device_ia(), GroupAddress::from_three_level(2, 0, 4)));
    let telegram = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("plain telegram delivered")
        .expect("broadcast channel open");
    assert!(!telegram.secured);
}
