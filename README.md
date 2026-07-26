# zweidraehte

```
 o--.  .--.  .--o
     \/    \/
     /\    /\       z w e i d r a e h t e
 o--'  '--'  '--o
```

A KNX device stack in Rust — *zwei Drähte*, "two wires", after the TP1
twisted pair.

zweidraehte implements the full KNX device side (System B profile) with
a `no_std`, allocation-free core that runs unchanged on bare-metal
microcontrollers and on embedded Linux. Devices are composed at compile
time: layers, medium extensions, interface objects, and storage are all
selected through trait-level composition and monomorphized, no dynamic
dispatch on the hot path, no runtime registries, and features a device
doesn't use contribute zero code.

Alongside the stack, the workspace contains an ETS product-definition
DSL: devices declare their parameters, communication objects, and ETS
UI pages in Rust macros, and a generator emits the matching
MTXML/`.knxprod` files.

This is a work in progress: the core is solid and conformance-tested,
but some parts are implemented without rigorous testing yet, and others
are known gaps. See [Project status](#project-status) for an honest
breakdown of what works, what needs testing, and what is missing.

## Features

**Protocol stack**

- System B device profile (mask versions 07B0 TP1, 27B0 KNX-RF,
  57B0 KNX/IP); the TP1 + Data Secure core is validated by the
  in-repo conformance suite
- Media / link layers: TP1 (TP-UART 1/2, NCN5120, E981.03), KNX-RF
  (SX1211, RF-Ready), KNXnet/IP (routing, tunneling server, discovery,
  device management, remote configuration), USB HID, and a composite
  KNX/IP↔TP1 link layer for building IP-interface products
- KNX Data Secure (Secure Application Layer, tool key management,
  group/P2P keys, sequence-number persistence) and KNX IP Secure
  (secure multicast routing with timer synchronisation)
- Synchronous NL/TL/AL layers driven by one async router loop with a
  compile-time dispatch table; link layers run as async tasks
  (embassy on embedded, std executors on Linux)
- Unified storage layer: region-anchored flash/FRAM layouts with
  wear-levelling, plus JSON file backends for Linux hosts

**Tooling**

- ETS DSL and a KNXPROD/MTXML generator with signing
- Semantic MTXML comparison (`compare_programs`) for verifying
  generated product data against manufacturer references
- TUI viewer for ApplicationProgram MTXML files (very experimental)
- Device provisioning tool (serial numbers, FDSKs) via probe-rs
- KNX/IP tunneling **client** library (`zweidraehte-client`) for
  device management from Linux (experimental)

**Reference firmware** (in `firmware/`, a separate workspace)

- STM32G0: TP1 and KNX-RF light switches (plain and Data Secure), an
  RF retransmitter
- RP2040: KNX/IP light switches over W5500 Ethernet (plain and IP
  Secure), WiFi (Pico W), TP1, and a KNX/IP↔TP1 interface (tunneling
  server bridging Ethernet to the TP1 bus)

## Project status

### Works, conformance-tested

- **TP1 devices incl. KNX Data Secure**: the in-repo conformance
  suite (transport layer, management, load/run state machines, group
  objects, the Data Secure test plan) runs green against the DUT
  binaries.
- **KNX/IP core**: routing, discovery, device management,
  connectionless remote configuration.
- **Storage layer**: region-anchored flash/FRAM layouts,
  wear-levelled key-value store, sequence-number persistence; runs on
  the real hardware targets.
- **ETS product generation**: the demo devices and the module test
  device generate importable `.knxprod` packages; the MDT replication
  matches the reference on communication objects and is verified with
  `compare_programs`.

### Implemented, not rigorously tested yet

- **KNX/IP tunneling (server side)**: implemented and used by the
  demo devices, but not conformance-tested yet.
- **KNX IP Secure**: secure multicast routing with timer sync is
  implemented; coverage so far is unit tests and a first socket-level
  suite, well short of rigorous.
- **KNX-RF**: the codec is spec-verified (CRC/Manchester/framing
  against the standard's worked examples) and live reception from a
  certified transmitter decodes end-to-end; transmit and
  listen-before-talk are wired but the CCA thresholds and Tx-done
  detection still want bench calibration. RF-Ready Standard frames
  only (no LTE, RF Multi, BiBat).
- **USB HID link layer**: functional, exercised by the `usb_test`
  utility rather than a test suite.
- **`zweidraehte-client`**: device management over tunneling works;
  no automatic reconnection, sequential command channel, no layered
  NL/TL/AL separation yet.
- **ip_interface link layer**: the composite KNX/IP↔TP1 bridge behind
  the IP-interface firmware — implemented, but untested so far.

### Known gaps

- **KNX/IP**: tunneling client side of the link layer, discovery with
  multiple service containers, and the secure unicast services
  (0x09xx) are not implemented. Remote Logging (Part 6) and Object
  Server (Part 8) are out of scope.
- **Bus monitor mode is not implemented**: tunneling connections
  requesting the Busmonitor (or Raw) layer are rejected, and the USB
  interface has no busmonitor support either. The standalone `busmon`
  tool works around this by putting a TP-UART chip into monitor mode
  directly.
- **Config persistence** is single-copy erase-then-write — a power cut
  during the save window loses the ETS configuration (A/B two-sector
  scheme planned before real deployments).
- **IP Secure mc_timer** survives power-off via a persisted watermark,
  not an RTC; cold-boot timer authenticity on a lonely segment takes
  up to ~17 s by design.
- **Generator**: KNX Information Model (`Semantics=`) annotations for
  ETS Smart Linking are not emitted yet; the MDT replication still has
  parameter/page-layout differences against the vendor XML.
- **DPT coverage is thin**: only ~two dozen Data Point Types are
  implemented (the ones the demo devices need, e.g. 1.xxx switching,
  3.007 dimming, 5.001 scaling, 9.001 temperature, 17/18 scenes,
  232.600 RGB). Most of the catalogue is still missing.
- **Line couplers / routers** are not implemented yet — no coupler
  network layer with filter tables, and no KNX/IP router acting as a
  backbone/line coupler.
- **Profiles**: no mask other than System B is implemented yet.
- **Embedded platform**: no reusable STM32 `Platform` impl, Pico W
  WiFi credentials lack a provisioning mechanism, TCP on the RP2040
  targets is stubbed.

## Repository layout

```
crates/
  zweidraehte-proto/         Protocol types (messages, encoding, addresses, DPTs)
  zweidraehte-device/        The device stack (layers, objects, BCUs, storage)
  zweidraehte-device-macros/ Proc-macros (interface objects, service registry, extension state)
  zweidraehte-ets/           Proc-macros for ETS parameter/com-object definitions
  zweidraehte-knxprod/       MTXML / .knxprod generator + parser
  zweidraehte-client/        KNX/IP tunneling client
  zweidraehte-platform/      Platform abstraction (serial, sockets, Linux)
  zweidraehte-util/          Small embedded utilities

examples/
  devices/                   Device definitions + demo/generator binaries
  support/                   Host-side demo support (JSON storage, mocks)

conformance/                 KNX conformance test framework + runner

tools/
  knxprod-tui/               TUI viewer for MTXML files
  compare-programs/          Semantic MTXML comparison
  bus-tools/                 busmon, tpuart, usb_test hardware utilities
  knx-provision/             Factory provisioning via probe-rs

firmware/                    Embedded targets (separate cargo workspace)
  common/                    Chip-agnostic crates (incl. the SX1211 KNX-RF driver)
  stm32/                     STM32G0 devices + family HAL glue
  rp2040/                    Raspberry Pi Pico devices + family HAL glue

docs/                        Architecture and reference documentation
```

## Getting started

The workspace pins a nightly toolchain via `rust-toolchain.toml`
(unstable const-trait features; see the comments in that file).
`rustup` picks it up automatically.

```bash
# Run the KNX/IP light switch device (host target). The network interface is
# auto-detected; name it with --interface <name|ip> or KNX_INTERFACE=<name|ip>
# when the host has several.
(cd firmware/linux/eth_light_switch && cargo run)

# Run the KNX conformance suite (long; accepts a name filter)
cargo run --bin conformance-runner [filter]

# Generate MTXML / .knxprod from a device definition
# (--knxprod needs a converter_key.xml — see "Signing key" below)
cargo run --bin gen_mtxml -- --knxprod

# Product database entries for the firmware devices (import into ETS)
cargo run --bin gen_light_switch_mtxml -- --knxprod   # the light-switch firmwares
cargo run --bin gen_ip_interface_mtxml -- --knxprod   # the KNX/IP<->TP1 interface

# Inspect a generated ApplicationProgram in the TUI
cargo run -p knxprod-tui -- out/DerGeraet/M-00FA/ApplicationProgram1.mtxml
```

Do **not** run `cargo build --workspace` from the repo root and expect
it to cover the firmware! `firmware/` is its own workspace. Build
embedded binaries from their project directory so the per-project
`.cargo/config.toml` selects the right target:

```bash
cd firmware/stm32/g0_tp1_light_switch && cargo build
cd firmware/rp2040/wifi_light_switch && WIFI_SSID=x WIFI_PASS=y cargo build
```

### Conformance tests

`conformance/` contains a socket/shared-memory harness that drives
separate DUT executables through KNX conformance test cases (transport
layer, management, group objects, Data Secure, IP Secure, …). The
runner rebuilds nothing itself — `cargo build` first so the DUT
binaries are current. Timing-sensitive waits are compressed ~50× by
default; pass `--realtime` to disable.

### Signing key (`.knxprod` generation)

ETS only imports a `.knxprod` whose application program is signed. KNX
uses two RSA keys: the **certification** key, which signs officially
certified products, and the **converter** key, which ETS uses to sign
*converted legacy product definitions* (older formats migrated into the
current `.knxprod` schema). Our generator emits current-schema programs
and signs them with the converter key — that is what `--knxprod` uses.
The converter key's public modulus/exponent are embedded in the source;
its **private** components are not, and are read at runtime from a
`converter_key.xml` file at the workspace root (falling back to the
current directory).

That file is **not** in this repository. Without it, `--knxprod` fails
with `could not read the converter key file …`; plain MTXML generation
still works. Supply your own `converter_key.xml` in .NET `RSAKeyValue`
format:

```xml
<RSAKeyValue>
  <Modulus>…</Modulus><Exponent>AQAB</Exponent>
  <P>…</P><Q>…</Q><D>…</D>
  <DP>…</DP><DQ>…</DQ><InverseQ>…</InverseQ>
</RSAKeyValue>
```

Only `<P>`, `<Q>`, and `<D>` are read (the public parts are embedded and
the CRT values are recomputed), but a full key from any .NET RSA export
works as-is.

The converter key is not one you invent: it is a fixed key inside ETS's
signing library `Knx.Ets.XmlSigning.dll`, function
`Knx.Ets.XmlSigning.XmlSigning.GetConverterRsaKey()`. How you extract it
from there is left to you. The public modulus embedded in
[`keys.rs`](crates/zweidraehte-knxprod/src/signing/keys.rs) identifies
the correct key — whatever you obtain must match it, or ETS rejects the
signature.

Treat the resulting file like any private key: it stays local and
git-ignored, never committed.

### Working with product data

`gen_mdt_mtxml` + `compare_programs` reproduce a real manufacturer
device (MDT Push Button Lite) and diff the generated program against
its vendor XML. Manufacturer reference XML is licensed material and is
not distributed with this repository — supply your own copy to run the
comparison.

## Documentation

- [`docs/STACK_ARCHITECTURE.md`](docs/STACK_ARCHITECTURE.md) — design
  philosophy, core components, context traits, extensions/augments,
  storage. Read this first when touching stack internals.
- [`docs/DEVICE_DEFINITION.md`](docs/DEVICE_DEFINITION.md) — how to
  define a concrete device and wire it into `main`.
- [`docs/DSL_REFERENCE.md`](docs/DSL_REFERENCE.md) — the ETS DSL
  macros and the KNXPROD generation pipeline.

## FAQ

**Why the name?**

Take one more-or-less public building with a KNX installation, add a
conference full of free-software nerds, and give it a weekend. Of course
somebody found the bus. Of course somebody hooked up to it. Of course the
lights, blinds, and heating had opinions for the rest of the conference.

When a janitor was told what had happened, he looked at the cable and summed
up KNX better than any spec document ever has, in the thickest Eastern
European accent:

"Zwei Drähte!? Ganze Haus spiel verrückt!" ("Two wires!? Whole house goes mad!")

That's where the name comes from.

**Is this affiliated with or certified by the KNX Association?**

No. I am not a member of the KNX Association, and I have no access to the EITT
(the official KNX conformance testing software) - the in-repo conformance
suite is my own implementation of the published test specifications. In the
long run I'd love to get my hands on the EITT and maybe become a member. To
make this possible, I am open to consulting and other business proposals. If
you are interested, please reach out!

**Is this stack compliant with the KNX Standard?**

Kind of — but not officially. Nobody has verified the stack's actual
conformance yet (see the previous question). What exists is the in-repo
conformance runner, which executes a substantial part of the test suites
specified in the standard against the device implementations. A few test
cases have been patched along the way, where the published test description
is incorrect or doesn't apply to this specific implementation; those
deviations are deliberate, not accidental. Treat "conformance-tested" in
this README as "passes my reading of the published test specifications",
not as a certification claim.

**Do you offer services around this stack?**

Yes. Through Netrunner UG I offer development and consulting around the
stack: firmware for your KNX device built on zweidraehte, porting to your
hardware, ETS product definitions and `.knxprod` tooling, and KNX protocol
work in general (including Data Secure and IP Secure). Contact
Netrunner UG <info@netrunner.info>.

And: want to help me get this stack properly conformance-tested, EITT
access, KNX Association contacts, or a certification project to piggyback
on? Let's talk, I'm sure we can make a deal.

**Can I use this for a commercial product?**

Yes, in one of two ways: under the AGPL-3.0 if you can comply with it (its
copyleft covers network interaction, and a device shipping this stack must
offer its users the corresponding source), or under a commercial license
from Netrunner UG without those obligations — see
[LICENSING.md](LICENSING.md). Independently of the software license,
shipping a *certified* KNX device requires KNX Association membership and
certification testing of your product. Building on a stack that is written
against the conformance test specifications should reduce that effort, but
the stack itself is not certified and using it certifies nothing (see the
previous two questions).

**Which hardware do you recommend to get started?**

You don't need any: `cd firmware/linux/eth_light_switch && cargo run` puts a KNX/IP device on
your LAN that ETS can discover and program. The cheapest real hardware after
that is a Raspberry Pi Pico W (or a Pico with a W5500 Ethernet board) running
the KNX/IP firmware: still no KNX transceiver required. For the actual
twisted pair, the reference firmware targets an STM32G0 with a TP-UART-class
transceiver (TP-UART 2, NCN5120, or E981.03), matching
`firmware/stm32/g0_tp1_light_switch`.

Whichever firmware you flash, ETS needs the matching product database
entry: `cargo run --bin gen_light_switch_mtxml -- --knxprod` generates it
for the light-switch firmwares (`gen_ip_interface_mtxml` for the KNX/IP↔TP1
interface); the signed `.knxprod` lands under `out/<Device>/` and imports
straight into ETS.

Apart from that, a development board with replaceable physical-layer
interface modules (TP1, RF, IP) is in the works, but not done yet.

**Does it interoperate with ETS?**

Yes, that's a core goal. The generated `.knxprod` packages import into ETS,
and ETS can discover, commission, and download devices running this stack
(individual address, parameters, group addresses, and diagnostics). The MDT
device replication is developed against real ETS project files to keep the
generator honest.

## License

zweidraehte is dual-licensed, following the same model as Grafana:

- **[AGPL-3.0-only](LICENSE)** for everyone. Keep in mind that the
  AGPL's copyleft extends to network interaction and that devices
  shipping this stack must offer their users the corresponding source.
- **Commercial license** from Netrunner UG for proprietary products
  that cannot comply with the AGPL, contact <info@netrunner.info>.

See [LICENSING.md](LICENSING.md) for details.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
The short version:

- Every contribution requires the [Netrunner UG Contributor License
  Agreement](CLA.md) (Apache-CLA-based; it keeps the dual licensing
  possible while you retain your copyright, and it promises that
  community contributions always stay open source). Accept it in your
  first merge request.
- Discuss non-trivial changes in an issue first.
- Keep the core `no_std`/allocation-free, follow the existing
  compile-time-composition patterns, and keep the conformance suite
  green.
