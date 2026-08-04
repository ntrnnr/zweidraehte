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
  Outstanding beyond the milestone: hardware smoke tests (tunnel + USB)
  and the loopback fixture (see below).

### Verification / integration-test story

- Unit: the sans-io cores are tested purely — feed inputs including timer
  expiries, assert outputs. That is the point of sans-io.
- Integration: env-var-gated live tests in
  `crates/zweidraehte-client/tests/live_tunnel.rs` (`KNX_TUNNEL_ADDR`,
  optional `KNX_TARGET_IA`) run tunnel connect/disconnect, an NM scan,
  and read-only device management against real hardware; they skip
  silently otherwise. The ported examples double as smoke tests.
- The hermetic loopback fixture moved to the roadmap: plain
  `WithTunneling` is currently wired for the TP1-bridged IP-interface
  role (`IpInterfaceStateFor`, additional-IA plumbing, subnet bridge),
  so a tunnel server whose frames terminate in the *local* stack needs
  its own wiring first. Until then the env-var tier is the milestone
  gate.
- `linux_eth_light_switch` (routing-only) becomes relevant once the routing
  connector lands.

## Later phases roadmap

1. **KNX Data Secure**: security config (tool keys per IA, persistent
   sequence-number store), secure APDU wrap/unwrap on the TL path via the
   existing proto crypto (`ccm.rs`, `scf.rs`), `S-A_Sync` handshake on secure
   connection open.
2. **KNX IP Secure**: `IpSecureTunnelingConnector` wrapping the plain tunnel
   connector with the Session handshake + `SecureWrapper` (proto types
   exist).
3. **Secure commissioning**: FDSK-based tool-key write (`A_Key_Write`
   builder), SIAT seeding — from-factory secure setup.
4. **Download procedures**: load/run-state-machine write/verify (RCo, Mem and
   IO variants), chunked memory download bounded by max_apdu.
5. **From-zero configuration**: generate address / association / GO tables
   and blobs per mask (master-data driven, shared source of truth with
   `zweidraehte-knxprod` / device definitions), drive the full ETS-style
   download using 3 + 4.
6. **More connectors**: IP routing (multicast, group-only), TPUART serial,
   secure routing; keyring (`.knxkeys`) import for security material.
7. **AN163 ext property services** for managing secure System B devices.
8. **Loopback test fixture**: a host binary running the device stack with
   a tunneling server whose tunnel traffic terminates in the local stack,
   so the client test suite runs hermetically (tunnel connect → group
   exchange → RCo/RCl management round-trips) without hardware.

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
