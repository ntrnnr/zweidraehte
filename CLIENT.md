# zweidraehte-client: KNX client library (Falcon analogue)

## Mission

A PC-side KNX client library, the counterpart to our device stack — what the
KNX Falcon SDK is to the KNX Association's ecosystem. It connects to a bus
through pluggable link connectors (KNX/IP tunneling and USB first; routing,
TPUART, and the secure variants later), issues group traffic without any
device connection, and runs the standardized management procedures from
03/05/02 against remote devices — connected (RCo) over the real TL state
machine and connectionless (RCl).

Later phases add KNX Data Secure, KNX IP Secure, secure commissioning from
FDSK, and full from-zero device configuration (table/blob generation per mask
plus load-state-machine download). The initial architecture must not preclude
any of that.

## Starting point

`crates/zweidraehte-client` already exists: a working tokio tunnel client
(CONNECT handshake, TunnelingFeatureGet MAX_APDU, TunnelingRequest/Ack with
retry, heartbeat) with unconnected and connected management (property,
function property, memory, authorize, restart). Its shortcomings drive the
redesign:

- ad-hoc TL sequence numbering instead of the 03/03/04 §5.4 state machine,
- no `T_ACK` sent for incoming connected data,
- `memory_write`/`restart` don't await the bus confirmation,
- no group-traffic API and no subscriber for unsolicited frames,
- tunneling only — no USB, no routing,
- the caller must spawn the worker task themselves.

## Fixed decisions

- **Sans-io protocol core + thin tokio driver.** All protocol logic (tunnel
  session, TL client connection, management procedure sequencing) is written
  runtime-agnostic: no sockets, no clocks — time and frames are passed in,
  I/O comes out as actions. A tokio front-end drives it.
- **Falcon-like layering**, restructured freely (existing API breaks; the two
  examples get ported).
- **Milestone 1**: tunnel + USB connectors, group traffic, the existing
  management set made spec-correct, NM_* programming-mode + scanning. No
  security yet.
- **Reuse**: `zweidraehte-proto` for all packet build/parse (enhanced where
  its device-role asymmetry bites), the device crate's pure TL state machine.
  Duplicate only where device coupling makes reuse worse than a copy.

## Verified reuse facts

- `crates/zweidraehte-device/src/layers/transport/state_machine.rs`:
  `process_event(conn, event, style)` is a pure, time-free function and
  explicitly symmetric — client events E25/E26 (T_Connect.req /
  T_Disconnect.req), Style 3 `Connecting` state,
  `TlStyle::supports_outgoing_connections()`.
- `connection.rs` takes `embassy_time::Instant` only as parameters (`now`,
  `deadline`); only the device-coupled `TransportLayer` wrapper calls
  `Instant::now()`. The wrapper is not reusable (StackDefinition /
  LayerContext / outbox coupling); the SM and the `Connection` core are.
- USB HID **host** code exists in
  `crates/zweidraehte-device/src/layers/linklayers/usb/`: `async-hid` 0.4
  (workspace dep), `KNOWN_KNX_DEVICES` VID/PID table, report
  framing/fragmentation in `hid.rs` + `protocol.rs` with no embassy deps,
  cEMI-mode negotiation in `transport.rs`. `tools/bus-tools/src/usb_test.rs`
  proves standalone use.
- proto: the KNX/IP connection/tunneling/discovery messages are symmetric
  (builders and parsers); cEMI `CemiLData` / `CemiTransport` /
  `CemiLocalMgmt` all have builders; the crypto primitives for the secure
  phases already exist (`proto/src/crypto/{ccm,scf,ip_secure_ccm,
  session_key}.rs`) as do the 0x09xx secure KNX/IP service types.
- The device knxip link layer has tunneling as a composable `FeatureSet`
  option — a Linux loopback tunnel-server test fixture is feasible.

## Architecture

### Crate layout (single crate, layered modules)

```
crates/zweidraehte-client/src/
  core/            sans-io: no tokio, no sockets, no clocks (time passed in)
    session.rs     KNX/IP tunnel session FSM (Idle→Connecting→Connected→Disconnecting)
    tl_client.rs   TL client core wrapping proto process_event (one outgoing conn)
    procedure.rs   management procedure sequencer (request/response match, timeouts)
    nm.rs          NM_* sequencers (IA read/write, serial-number, scan collection)
    group.rs       group telegram encode/decode
  connector/
    mod.rs         KnxConnector trait + ConnectorInfo
    ip_tunnel.rs   tokio UDP tunneling connector (refactor of tunnel/worker.rs)
    usb.rs         tokio USB HID connector
  api/
    bus.rs         KnxBus (root handle; spawns background task internally)
    device_conn.rs DeviceConnection (RCo)
    network_mgmt.rs NetworkManagement (NM_*)
    group_comm.rs  GroupTelegram + subscription
  driver/
    bus_task.rs    tokio select loop: connector ⇄ core FSMs ⇄ command channel
  error.rs
  lib.rs
```

`core/` uses only `alloc` + proto, so it can later be extracted into a
`zweidraehte-client-core` crate (not over-engineered for now).

### TL state machine reuse: move the pure SM to proto

The runtime-agnostic TL SM moves from the device crate into
`crates/zweidraehte-proto/src/transport/` — it is exactly the "pure protocol
shared with future client implementations" the proto crate exists for:

- `events.rs`: `TlEvent`, `TlAction`, `TlStyle`, `ActionBuffer`,
  `ProcessResult`, `ConnectionState`, `MAX_REPETITIONS` (moved verbatim).
- `core_trait.rs`: new `trait ConnectionCore` — accessors for state,
  remote_addr, seq_no_send/recv, rep_count, `has_queued_incoming()`; the only
  fields `process_event` actually touches.
- `sm.rs`: `process_event<C: ConnectionCore>(conn, event, style)` —
  transition tables unchanged, field access via the trait.

Device crate: `impl ConnectionCore for Connection` in `connection.rs`; the
old `state_machine.rs` becomes `pub use` re-exports. Zero behavior change;
the conformance transport-layer suites are the regression net.

Client side: a small `ClientConnection` struct (state / seqs / rep_count)
implements `ConnectionCore`; ACK and connection deadlines live in the tokio
driver as `tokio::time::Instant` — the sans-io core never reads a clock.

### Sans-io event/action pattern

`core/session.rs` (hosting the TL and procedure cores) is a pure
`step(input) -> outputs` machine:

- Inputs: `PacketReceived(bytes)`, timer expiries (heartbeat / ack /
  connection), user commands (open tunnel, send cEMI and await filtered
  response, open/close TL connection, send group telegram, subscribe,
  disconnect).
- Outputs: `SendPacket(bytes)`, arm/cancel named timers, notifications
  (connected / disconnected / error, group telegram, TL confirm /
  indication).

The driver executes outputs with tokio UDP/USB I/O and `sleep_until`, feeding
expiries and received packets back in. The session FSM carries over the
proven logic from today's `tunnel/worker.rs`: CONNECT handshake, FeatureGet
MAX_APDU (fallback 254), Tunneling Ack + one retry, heartbeat
(ConnectionstateRequest every 60 s, 10 s timeout, one retry),
server-initiated disconnect handling.

Spec-correctness fixes over today's client:

- `T_ACK` is sent for incoming connected data (driven by
  `TlAction::SendAck`).
- RCo timeouts come from the SM: ACK timeout with up to `MAX_REPETITIONS`
  repeats, plus the connection timeout — not one ad-hoc retry.
- `memory_write` waits for L_Data.con; the RCoV variant verifies by
  read-back; restart / master reset get typed handling.
- Unsolicited frames are routed (group → subscribers, TL frames → the open
  connection by source match, the rest logged) instead of discarded.

### Connector abstraction

```rust
trait KnxConnector: Send + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn open(&mut self) -> Result<ConnectorInfo, Self::Error>;  // negotiation incl. local mgmt
    async fn send_cemi(&mut self, cemi: &[u8]) -> Result<(), Self::Error>;
    async fn recv_cemi(&mut self) -> Result<Vec<u8>, Self::Error>;
    async fn close(&mut self) -> Result<(), Self::Error>;
}
struct ConnectorInfo { assigned_address: IndividualAddress, max_apdu: u16 }
```

Connectors transport **raw cEMI frames**; framing (TunnelingRequest
wrap/unwrap, USB HID transfer frames + fragmentation) is internal to each
connector. cEMI↔internal conversion stays in `proto::encoding::cemi` and is
applied in `core/` for APCI inspection and response matching. Local device
management (the USB M_PropRead/Write negotiation; later the KNX/IP
DeviceConfiguration channel) happens inside `open()` / connector-specific
methods, not on the data plane. This is also where an IP Secure session
wrapper will later slot in: a secure connector wrapping the plain one.

### Public API (Falcon-like)

```rust
let bus = KnxBus::connect_ip("192.168.1.10:3671".parse()?).await?;   // or connect_usb(selector) / connect(custom)
bus.group_write(ga, &[1], GroupValueEncoding::SixBit).await?;        // group traffic, no device conn
let mut rx = bus.group_events();                                     // broadcast::Receiver<GroupTelegram>

let mut dev = bus.connect_device("1.1.42".parse()?).await?;          // T_Connect (RCo)
let serial = dev.property_read(0, PID_SERIAL_NUMBER, 1, 1).await?;
dev.memory_write_verify(0x4000, &blob).await?;                       // DMP_MemWrite_RCoV
dev.master_reset(EraseCode::FactoryReset, 0).await?;
dev.close().await?;

let nm = bus.network_management();
nm.write_individual_address("1.1.42".parse()?).await?;               // NM_IndividualAddress_Write (prog mode)
let found = nm.read_individual_addresses(Duration::from_secs(3)).await?;  // prog-mode scan
nm.write_individual_address_by_serial(&serial6, addr).await?;        // NM_..._SerialNumber_Write
bus.disconnect().await?;
```

- `KnxBus` spawns its background task itself; the actor stays an internal
  detail. Explicit `close()` / `disconnect()`, best-effort `Drop`.
- `DeviceConnection` set: property read / write / description, function
  property command / state, memory read / write / write_verify, authorize,
  restart, master_reset(erase_code, channel) returning the device's process
  time, device descriptor read, close. One open `DeviceConnection` at a time
  in milestone 1 (`MAX_OUTGOING = 1`; `Error::ConnectionBusy` otherwise).
- Connectionless (RCl) ops (device descriptor read, property read, …) live on
  the NM surface / bus handle.
- DPT helpers stay decoupled: thin `dpt` re-export; the group API carries raw
  bytes.

## Proto enhancements (milestone 1)

The proto APDU modules were written for the device role, so several types are
parse-only or write-only where a client needs the inverse. Each addition gets
a unit test:

| File | Addition |
|---|---|
| `messages/apdu/device.rs` | `DeviceDescriptorResponse::parse_type0/parse_type2`; `IndividualAddressWrite::write`; `IndividualAddressSerialNumberRead::write`; `IndividualAddressSerialNumberResponse::parse`; `IndividualAddressSerialNumberWrite::write` |
| `messages/apdu/memory.rs` | `MemoryResponse::parse` |
| `messages/apdu/auth.rs` | `AuthorizeResponse::parse` |
| `messages/apdu/restart.rs` | master-reset request builder (`erase_code`, `channel`); `RestartResponse::parse` |
| `messages/knxip/messages/tunneling.rs` | `TunnelingFeatureSetBuilder` |
| `src/transport/` (new) | pure TL SM move (see above) |

Deferred, with room left in the design: AN163 ext-property request builders,
`KeyWrite` builder (DM_SetKey), discovery-driven interface listing.

## USB connector

- Extract the dependency-free framing (`usb/hid.rs` report fragmentation /
  reassembly, `usb/protocol.rs` transfer frames + EMI IDs,
  `KNOWN_KNX_DEVICES`) into `zweidraehte-proto/src/usb_hid/` behind a new
  proto feature `usb-hid`; the device crate keeps thin re-export shims so its
  imports don't change.
- `connector/usb.rs` re-implements the `UsbCemiTransport` sequence
  (enumerate → open → BAS get/set EMI type → activate cEMI → M_PropRead
  MAX_APDU + IA from the device object) on tokio. Try `async-hid` 0.4
  directly first (it is runtime-agnostic); if its Linux backend doesn't
  cooperate with tokio, fall back to a dedicated I/O thread owning the HID
  handle, bridged with channels.

## Work breakdown (reviewable chunks, in order)

Each chunk ends compilable and tested.

- **A. Proto TL SM move** *(done)* — `proto/src/transport/`,
  `ConnectionCore`, generic `process_event`, device-crate re-exports +
  `impl ConnectionCore for Connection`. Verified against the full
  hand-written conformance suite (556/556).
- **B. Proto APDU symmetry** *(done)* — the table above, each addition
  with a round-trip unit test.
- **C. Client skeleton + connector trait** *(done)* — module tree,
  `KnxConnector` (raw cEMI both ways; constructed-open, no `open()`
  method), `connector/ip_tunnel.rs`.
- **D. Session FSM + bus task + group comm** *(done)* —
  `core/session.rs` (pure, unit-tested: handshake, ack retry, heartbeat
  loss, duplicate sequences), `driver/bus_task.rs`, `KnxBus`
  connect/disconnect, group write/read/subscribe.
- **E. TL client + DeviceConnection** *(done)* — `core/tl_client.rs` over
  the proto SM, frame classification into `TlEvent`s, T_ACK sending, the
  full management service set including `memory_write_verify` and
  `master_reset`.
- **F. Network management** *(done)* — `api/network_mgmt.rs`: IA
  read/write (broadcast), serial-number read/write, scan collection,
  connectionless RCl ops (moved from the old `KnxClient`).
- **G. USB connector** *(done, untested on hardware)* — HID framing /
  transfer protocol / Bus Access Server moved to
  `proto/src/usb_hid/` (feature `usb-hid`, device crate re-exports),
  `connector/usb.rs` with the full bring-up (EMI negotiation, comm-mode
  DLL, IA + max-APDU reads), `KnxBus::connect_usb`. async-hid composes
  with tokio directly (its own backend threads) — the dedicated-thread
  fallback was not needed. Needs a smoke test against a physical
  interface.
- **H. Examples + docs** *(done)* — `function_property.rs` and
  `mdt_bootloader.rs` ported; `group_monitor.rs` and `device_scan.rs`
  added; env-var-gated live tests in `tests/live_tunnel.rs`.
  Later additions: `line_scan.rs` sweeps one line for present devices
  (per-address connectionless descriptor-read probe via
  `NetworkManagement::is_device_present`, window-bounded so a full
  line takes ~80 s rather than the 3 s-timeout worst case; a negative
  L2 confirmation counts as "absent", not an error). Both scanners
  also read each found device's serial (PID 11, connectionless), and
  `prog_mode.rs` switches programming mode by serial — resolving the
  IA via `NM_IndividualAddress_SerialNumber_Read`, then flipping bit 0
  of 0060h (System 7 / BCU lineage) or writing PID_PROGMODE (System
  B), chosen by the device's descriptor.
  Outstanding beyond the milestone: hardware smoke tests (tunnel + USB)
  and the loopback fixture (see below).

### Verification / integration-test story

- Unit: the sans-io cores are tested purely — feed inputs including timer
  expiries, assert outputs. That is the point of sans-io.
- Integration: env-var-gated live tests in
  `crates/zweidraehte-client/tests/live_tunnel.rs` (`KNX_TUNNEL_ADDR`,
  optional `KNX_TARGET_IA`) run tunnel connect/disconnect, an NM scan,
  read-only device management, and a System 7 load-state/table
  read-back against real hardware; they skip silently otherwise. The
  ported examples double as smoke tests.
- Real-device hermetic tier: `conformance-configuration` runs the
  client library against the System 7 device stack in-process (see the
  configuration-download section).
- The hermetic loopback fixture moved to the roadmap: plain
  `WithTunneling` is currently wired for the TP1-bridged IP-interface
  role (`IpInterfaceStateFor`, additional-IA plumbing, subnet bridge),
  so a tunnel server whose frames terminate in the *local* stack needs
  its own wiring first. Until then the env-var tier is the milestone
  gate.
- `linux_eth_light_switch` (routing-only) becomes relevant once the routing
  connector lands.

## KNX Data Secure (done)

Roadmap item 1, implemented August 2026. Management (RCo) against
devices with Data Secure active, under the tool key or FDSK.
Hardware-confirmed against the Teststand Mobil installation (secure
connect + wrapped reads under the ETS keyring, August 2026).

- **`src/security/`**: `SecurityStore` (bus-level keyring keyed by IA;
  `SecurityEntry { mode, tool_key, fdsk, serial }` — the *explicit*
  `DeviceSecurityMode` decides whether a connection is wrapped, so a
  known FDSK on a security-disabled device does not force secure
  comms; active key = tool key, else FDSK, mirroring the device's own
  fallback). `SecureChannel` (sans-io wrap/unwrap + the two counters:
  `tool_seq` our sending number, `table_seq` next accepted from the
  device; replay check before MAC, counter advance after).
  `SeqNumberStore` trait keyed by device serial (IAs are reassignable)
  + `MemSeqStore` and the file-backed `JsonSeqStore` (temp-file +
  rename). Unit-tested against the spec Annex C.1.1 vectors.
- **Proto**: `SyncResRef` added to `messages/apdu/secure.rs` (typed
  parser for the tool-received S-A_Sync_Res; tested against C.1.4).
- **Bus task**: outgoing connected frames wrap **once at store time**
  (retransmissions stay byte-identical; re-encrypting would burn a
  sequence number per retry); incoming `SecureService` frames unwrap
  at `IndicateData` before response matching, so `ResponseMatcher`
  and every management parser see plaintext unchanged. `tool_seq`
  persists on `ConfirmData`, `table_seq` after each verified frame.
  MAC failure fails the in-flight procedure and closes the connection;
  plaintext on a secure connection is dropped (downgrade path).
- **S-A_Sync on open**: after T_Connect confirms, the handshake runs
  connectionless (T_Data_Individual — 03/03/07 §5.3.2 allows either)
  with a `getrandom` challenge; both counters adopt the response's
  "next valid SeqNr" values (`table_seq = seq_remote`, **not** +1 —
  the sync service advertises next-valid, unlike a data frame's
  consumed number; `seq_local == 0` ignored, no rewind). One retry
  with a fresh challenge after 1.5 s (device rate-limits sync
  responses to 1/s), then the open fails with `SecuritySyncTimeout`
  and the TL connection is torn down.
- **API**: `KnxBus::set_device_security(ia, entry)`,
  `connect_{ip,usb}_with_security(..., SecurityStore)` /
  `with_connector_and_security`; `connect_device` goes secure
  automatically when the keyring says so.
- **Tests**: `tests/secure_bus.rs` drives the full handshake +
  wrapped-request round-trip against an in-memory connector with the
  test body playing the secure device (paused tokio time). Env-gated
  live test `secure_connect_and_read` in `tests/live_tunnel.rs`
  (`KNX_TOOL_KEY`/`KNX_FDSK` + `KNX_DEVICE_SERIAL` on top of the
  tunnel vars); example `secure_device_info`.
- **`.knxkeys` keyring import** (`security/knxkeys.rs`, August 2026 —
  the roadmap-item-6 keyring half, pulled forward): parses the ETS
  export, verifies the SHA-256 document signature (which doubles as
  the password check), and decrypts everything — device tool keys,
  FDSKs, group keys, backbone key, interface (tunnel) credentials.
  Crypto per the Falcon scheme (PBKDF2-HMAC-SHA256 over salt
  `1.keyring.ets.knx.org`, AES-128-CBC with IV = SHA-256(Created)),
  cross-checked against xknx and Calimero and validated by an inline
  real-ETS-6.4.1 fixture whose dev-provisioned FDSKs decrypt to the
  repo's `DEFAULT_FDSK`. `SecurityStore::import_keyring` fills the
  bus keyring (tool key + FDSK per device, `table_seq` seeded from
  the exported `SequenceNumber + 1`); `Keyring::load(path, password)`
  is the entry point; `secure_device_info --keyring/--keyring-password`
  uses it. Devices exported without a serial get unpersisted counters
  (`SecurityEntry.serial` is now `Option`); group keys and interface
  credentials ride along on the `Keyring` struct for the group-traffic
  and IP Secure phases. `*.knxkeys` is git-ignored.

Known limitations: a crash between send and L_Data.con can reuse one
tool sequence number (persist-on-confirm; the device-side persists
pre-send — tighten later). Unsolicited device-initiated S-A_Sync_Req
is not answered (devices only initiate sync for P2P group traffic,
not toward the tool). Secure commissioning is a later roadmap item.

### Data Secure group traffic (done, August 2026)

Secure group telegrams under the keyring's group keys, transparent to
the existing group API:

- **`SecurityStore` group keys**: `set_group_key(raw_ga, key)` /
  `get_group_key`; `import_keyring` consumes the keyring's
  `group_keys` (already parsed since the keyring import landed). A
  group address with a key is secure in both directions: outgoing
  frames on it are wrapped, incoming plaintext is dropped (downgrade
  protection, the same gate a device applies to secured group
  objects). Secure frames on unkeyed GAs are dropped at debug level
  (nothing to decrypt them with). The keyring interfaces' per-tunnel
  sender lists are not consumed (devices don't enforce sender
  membership either; TODO in `import_keyring`).
- **Wire shape** (`security/channel.rs` `group_wrap`/`group_unwrap`,
  free functions — `SecureChannel`'s tool SCF and per-connection
  counters don't fit group traffic): SCF 0x10 (A+C, never tool
  access — TSSJ §3.2.6 rejects the tool flag on group frames; A-only
  0x00 accepted incoming), CCM over the real GA with `addr_type`
  0x80 authenticated in B0.
- **Sending seq**: one client-wide counter for all outgoing secure
  group frames (03/03/07 keeps one Sequence Number Sending per
  station). Persisted at consume time and floored to milliseconds
  since 2018-01-05T00:00Z (the ETS/xknx convention) so it never
  regresses — receivers keep our last valid number per sender IA and
  no group-addressed sync exists to recover a rewind; the floor also
  covers a tunnel IA previously used by another tool.
- **Replay protection**: per-sender-IA floor (the device-side analog
  is the SIAT slot, shared between its P2P and group receive), moved
  only after the MAC verifies, persisted per verified frame (TODO:
  watermark batching if the per-frame JSON rewrite ever matters).
  Floors seed from the keyring's exported `SequenceNumber + 1` — for
  every device with one, keyed or not.
- **`SeqNumberStore`** gained `load/save_own_seq` and
  `load/save_sender_seq(ia)`; `JsonSeqStore` stores them as two new
  `serde(default)` fields (`own_seq`, `sender_seq` keyed by hex raw
  IA), so pre-group files stay readable.
- **API**: unchanged — `group_write`/`group_read` wrap automatically
  when the GA has a key; `GroupTelegram` gained `secured: bool`
  (always `true` on keyed GAs, since plaintext there never reaches
  subscribers). `group_monitor` takes
  `--keyring/--keyring-password/--seq-file` and tags secured
  telegrams.
- **Tests**: wrap/unwrap unit tests anchor on round-trips through the
  Annex-C-pinned CCM primitives (the spec Annex C has no group
  vector); `tests/secure_bus.rs` covers wrapped sends, decrypted
  delivery, replay drop and the downgrade drop against the mock bus;
  env-gated `secure_group_monitor` / `secure_group_write_live` in
  `tests/live_tunnel.rs` (`KNX_KEYRING`, `KNX_KEYRING_PASSWORD`,
  `KNX_GROUP_GA` / `KNX_GROUP_WRITE_GA` + `_VALUE`).

Limitations: no runtime group-key injection command — load the
keyring into the `SecurityStore` before `connect_*_with_security`
(TODO if a use case appears). Incoming S-A_Sync_Req is still not
answered; with the timestamp-floored sending counter a peer never
needs to sync us.

## Configuration download — layered as ETS layers it (August 2026)

Roadmap items 4 + 5. The download engine takes its inputs from the
same three places ETS does, with the same lifetimes:

| Layer | Source | Per | Carries |
|---|---|---|---|
| **Mask** | `knx_master.xml` | mask version | resource locations, procedure templates |
| **Product** | `.knxprod` / MTXML | product | segments + default data, load procedures, object and parameter layout |
| **Project** | the caller | installation | individual address, group links, parameter values |

```text
  knx_master.xml ──► MaskDb ──┐
                              ├─► assemble() ─► Vec<Instruction> ─┐
  .knxprod/.mtxml ─► ProductData ─┐                               ├─► Downloader
                                  ├─► compile() ─► DeviceImage ───┘        │
  ProjectConfig ──────────────────┘                                        ▼
                                                             DeviceConnection (RCo)
```

**The mask layer is always present and never hardcoded.** There is no
built-in mask table and no cargo feature guarding it: `MaskDb` is
required input. The reasons, in order of weight — MV-07B0 alone
carries 145 load-control instructions across six procedure templates
plus 40 resources, and hand-transcribing that is exactly the drift
that bit the conformance transcriptions; nothing KNX-supplied may be
committed to this repository; and it is what ETS itself does.
`MaskDb::resolve()` tries `KNX_MASTER_DATA`, then (behind the
`master-data-download` feature) the on-disk cache and a download from
`update.knx.org`. A `.knxprod` bundles `knx_master.xml`, so one file
can supply both upper layers.

- **`src/download/`**
  - `mask.rs` — `MaskDb` / `MaskData` keyed by the mask version a
    device reports; `MemoryResources` read out of the mask's resource
    list rather than hardcoded.
  - `product.rs` — `ProductData` from a parsed `ApplicationProgram`:
    segments (with base64 `Data` decoded), load procedures, com-object
    definitions, parameter memory map. Reads the
    `AddressTable`/`AssociationTable` elements that `DeviceInfo`
    ignores.
  - `project.rs` — `ProjectConfig` plus `compile()`, which follows
    ETS's order: seed segments with product defaults, overlay the RT8
    tables built from the project, patch parameter values, then insert
    the data writes ETS performs implicitly (derived from the
    procedure's own segment records).
  - `assemble.rs` — mask template + product fragments → one stream.
    System 7 takes the product's `ProductProcedure` whole; System B
    splices product fragments into the mask template at `LdCtrlMerge`
    points. Merges resolve here, never at run time.
  - `ir.rs` / `interpreter.rs` — unchanged in shape;
    `controls_to_instructions` now takes a `&[LoadControl]` so master
    data and MTXML share one converter.
- **`zweidraehte-knxprod`** gained `.knxprod` archive *reading*
  (`runtime::knxprod`) and a three-way feature split — `packaging`
  (signing + ZIP write), `master-data` (resolver + cache + download),
  `product-files` (ZIP read) — so the client depends on it without
  pulling HTTP, crypto or ZIP into every build.
- **API**: `KnxBus::configure_device(&mask, &product, &project)`.

### Both management models

The engine drives each family the way its mask does:

| | System 7 (0705) | System B (07B0) |
|---|---|---|
| load control | memory-mapped window at 0104h | `PID_LOAD_STATE_CONTROL` on the machine's own interface object |
| load state | status bytes at B6EAh | the same property, read back |
| segments | absolute — the product fixes the address | relative — the client asks for a size, the device answers with a base through `PID_TABLE_REFERENCE` |
| procedure | the product's whole `ProductProcedure` | the mask's Load template with product fragments spliced in at `LdCtrlMerge` |
| tables | RT8 linking tables plus `co_system7`, 1-octet counts, IA inside the address table | RT7 (`addr7`/`asso6`/`co7`), 2-octet counts and identifiers |

`LoadControlPath` selects the path; the IR addresses machines by
*index* rather than a four-variant enum, because System B has five and
on that family the index is also the interface object index.

Two adjustments the compile step makes that neither layer could,
because both depend on the project:

- **Sizing relative allocations.** The mask templates carry a
  placeholder (`Size="2"` for MV-07B0's tables); the real size is the
  content we are about to write.
- **Pruning empty steps.** A product with no parameters still declares
  a segment and a write for its zero-length parameter block; both are
  dropped, which leaves the interpreter free to treat a write with no
  content as the bug it would otherwise be.

### Test tier: `conformance-configuration`

A third conformance runner beside `conformance-runner` and
`conformance-eitt`: it drives the **real client library** against the
System 7 DUT through `harness::client_bridge`. The DUT has no product
file of its own, so the runner **generates one in-process** from the
same constants the DUT stack is built from and reads it straight back
— closing a loop across all three crates:

```text
  system7_stack_config!  ──► knxprod generator ──► MTXML
           │                                         │
           │                              ProductData (client parses)
           ▼                                         ▼
    the running DUT  ◄────── download ◄────────  KnxBus
```

    KNX_MASTER_DATA=/path/to/knx_master.xml \
      cargo run -p zweidraehte-conformance --bin conformance-configuration

Five scenarios, all passing: descriptor smoke read, programming-mode
IA assignment, full download with table read-back **and a live group
telegram on the rewired address**, `Unload all` assembled from the
mask, and the load-state error path.

Three real bugs this tier has caught so far:

- `Table::write_lsm`'s `LoadEnd` computed the MCB CRC over
  `data_ref()[0..requested_memory_size]`, where the length is
  client-supplied and `ApplicationImpl` accepts segments larger than
  its own buffer — a bus-reachable panic, now clamped with a
  regression test.
- The identity guard compared property values for exact equality,
  which no real product file satisfies: they pad the expected value to
  a fixed field width (MDT writes twenty hex characters for the
  six-octet `PID_HARDWARE_TYPE`, and our generator mirrors that).
  `identity_matches` now compares a prefix and requires the remainder
  to be zero padding.
- The conformance System B fixture kept its table base addresses in
  two places — literals in `ConformanceMemoryMap` and computed offsets
  in `CONFORMANCE_MEMORY_LAYOUT` — which had drifted apart. The device
  reported one base through `PID_TABLE_REFERENCE` and served memory at
  another, so writing where it said to write was refused. No existing
  test allocates relatively and then writes at the reported base; a
  real ETS download would have hit it.

Runtime note: the conformance *parent* side is runtime-agnostic and
all three runners are plain `#[tokio::main]` programs; embassy stays
in the DUT child processes, which are the device stack.

## Later phases roadmap

1. ~~**KNX Data Secure**~~ *(done — see above)*
2. **KNX IP Secure**: `IpSecureTunnelingConnector` wrapping the plain tunnel
   connector with the Session handshake + `SecureWrapper` (proto types
   exist).
3. **Secure commissioning**: FDSK-based tool-key write (`A_Key_Write`
   builder), SIAT seeding — from-factory secure setup.
4. ~~**Download procedures**~~ *(done — both the memory-mapped and the
   property path, both families; see above)*. Remaining: the partial
   procedure subtypes (`grp`, `par`, `cfg`, `ap1`) and the tool-side
   scaffolding they need (`LdCtrlMapError`,
   `LdCtrlSetControlVariable`).
5. ~~**From-zero configuration**~~ *(done — driven from a real
   `.knxprod` / MTXML product file and the ETS master data; see
   above)*.
6. **More connectors**: IP routing (multicast, group-only), TPUART serial,
   secure routing; ~~keyring (`.knxkeys`) import for security material~~
   *(done — see the Data Secure section)*.
7. **AN163 ext property services** for managing secure System B devices.
8. **Loopback test fixture**: a host binary running the device stack with
   a tunneling server whose tunnel traffic terminates in the local stack,
   so the client test suite runs hermetically (tunnel connect → group
   exchange → RCo/RCl management round-trips) without hardware.
   *(Partly obsoleted: `conformance-configuration`'s `client_bridge`
   already gives the client a hermetic real-device tier — at cEMI
   level, bypassing the KNX/IP tunnel layer. A loopback fixture is now
   only needed to cover the tunnel protocol itself.)*

## Risks / notes

- The `ConnectionCore` genericization must not change device behavior — the
  conformance TL suites are the gate.
- `async-hid` under tokio is unproven; the dedicated-thread fallback is
  specified.
- Response matching must filter by source IA + APCI (today's filter is
  retained); unsolicited traffic is routed, not discarded.
- Master reset reboots the device; the returned process time lets callers
  wait before reconnecting.
- Broadcast IA write races if several devices are in programming mode — a
  spec-level property, documented on the API.
