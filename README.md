# zweidraehte

```
 o--.  .--.  .--o
     \/    \/
     /\    /\       z w e i d r a e h t e
 o--'  '--'  '--o
```

A KNX device stack in Rust — *zwei Drähte*, "two wires", after the TP1
twisted pair.

zweidraehte implements the full KNX device side (System B profile, plus
System 7 on TP1) with a `no_std`, allocation-free core that
runs unchanged on bare-metal microcontrollers and on embedded Linux.
Devices are composed at compile time: layers, medium extensions,
interface objects, and storage are all selected through trait-level
composition and monomorphized, no dynamic dispatch on the hot path, no
runtime registries, and features a device doesn't use contribute zero
code.

There is also `zweidraehte-microdevice`, a separate and much smaller
polling TP1 stack for fixed-map BCU-era hardware: one owner, a
cooperative `poll()` loop, flat EEPROM-backed tables, and no executor,
channels, or interface-object tower. It models BCU1, BCU2, and System 7
families, and shares protocol vocabulary, table codecs, state-machine
logic, ETS metadata, and application behaviour with the full stack while
keeping a deliberately different runtime architecture.

**Treat the micro stack as an experiment.** It exists because it was
interesting to find out how small a KNX device can get and how much of
the "generic" core really is generic. It is young, thinly tested
compared to the full stack, and has no production use behind it. Build
on it only if you are willing to debug it.

Alongside the stack, the workspace contains an ETS product-definition
DSL: devices declare their parameters, communication objects, and ETS
UI pages in Rust macros, and a generator emits the matching
MTXML/`.knxprod` files.

It also contains the other side of the wire: `zweidraehte-client`, a
PC-side management client (the Falcon analogue) that connects over a
KNX/IP tunnel or USB, does group traffic and KNX Data Secure, and
commissions devices with an ETS-style configuration download — reading
the mask facts from `knx_master.xml` and the product layout from a
`.knxprod`, exactly as ETS does.

This is a work in progress: the core is solid and conformance-tested,
but some parts are implemented without rigorous testing yet, and others
are known gaps. See [Project status](#project-status) for an honest
breakdown of what works, what needs testing, and what is missing.

## Features

**Protocol stack**

- Standard full-stack presets for System B TP1/RF/IP/IP-interface and
  their secure variants, plus System 7 TP1 plain/secure. Normal firmware
  implements the small `DeviceDefinition` input trait; advanced users can
  still implement the low-level `StackDefinition` directly.
- System B device profile (mask versions 07B0 TP1, 27B0 KNX-RF,
  57B0 KNX/IP); the TP1 + Data Secure core is validated by the
  in-repo conformance suite
- System 7 device profile, TP1 only (mask version 0705, with Data
  Secure as a composable profile module): compact fixed-map tables, the fixed
  absolute memory map, memory-mapped load controls, 16 authorization
  levels, and the ETS `ProductProcedure` download. **For a new custom
  device you normally want System B** — see "Which profile for a
  custom device?" in the [FAQ](#faq)
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
- Ultra-lightweight no-async TP1 stack for BCU1/BCU2 and fixed-map
  System 7 devices, with EEPROM tables parsed in place and bounded
  `heapless` outputs — **experimental**, see the note above

**Tooling**

- ETS DSL and a KNXPROD/MTXML generator with signing
- Semantic MTXML comparison (`compare_programs`) for verifying
  generated product data against manufacturer references
- TUI viewer for ApplicationProgram MTXML files (very experimental)
- Device provisioning tool (serial numbers, FDSKs) via probe-rs
- KNX **client** library (`zweidraehte-client`) — a Falcon-style
  management client for Linux: KNX/IP tunneling and USB connectors,
  group traffic, connected/connectionless device management, KNX Data
  Secure, and ETS-style **configuration download**, driven the way ETS
  is — from `knx_master.xml` and a product's `.knxprod`/MTXML. Covers
  the System B, System 7 (BIM M112), BCU2 and BCU1 management models,
  including the BCU-era specifics: RT1/RT2 table codings, diffed EEPROM
  writes, relocation under Dynamic Table Management, and the no-load-
  state-machine direct path of mask 0012h. Verified against real
  hardware (an MDT System 7 push button, over USB and tunneling)
- **Project and commissioning tooling** on top of the client: a small,
  human-editable `project.knx` language, separate credential and durable
  sequence/SIAT state stores, `knx-dump` project skeleton generation,
  project-aware `knx-loader` address/program/load/unload/read/sync/recovery operations, and
  `knxproj-tui` as an interactive product/project editor. See
  [`docs/DEVICE_PROGRAMMING.md`](docs/DEVICE_PROGRAMMING.md)

**Reference firmware** (in `firmware/`, a separate workspace)

- STM32G0: TP1 and KNX-RF light switches (plain and Data Secure),
  System 7 TP1 light switches (plain and Data Secure — same hardware
  and device definition as their System B siblings, different
  management model), an RF retransmitter, and — on the experimental
  micro stack — BCU2 and micro-System-7 polling light switches
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
- **System 7 TP1 (0705h) incl. KNX Data Secure**: all seven vendor
  conformance templates (group objects, network layer, transport
  layer, load and run state machines, management, TSSJ data security)
  run against the System 7 DUTs as they do against the System B ones —
  525 cases, all passing. ETS commissions the STM32G0 System 7
  firmware end to end over the `ProductProcedure` download, verified
  on hardware for the non-secure variant; the secure variant exchanges
  secure group telegrams with System B secure devices on real
  hardware, but a full ETS Data Secure download onto the 0705h mask is
  still unverified.
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
- **`zweidraehte-client`**: group traffic, connected/connectionless
  device management, and KNX Data Secure work over tunneling and USB.
  The ETS-style **configuration download** (unload → allocate → write
  tables and parameters → load → restart) runs end to end against both
  the System 7, System B and BCU2 conformance DUTs — the client
  generates each DUT's product file, reads it back, downloads, and
  verifies the device rewired — exercising all three load-control
  paths. On real hardware, **three third-party devices** have been
  configured start to finish so far: an MDT BE-TAL5502.01 push button
  (System 7) over both USB and tunneling, a mask-0012h BCU1 device
  over the direct no-LSM path, and a mask-0020h BCU2 device running
  that same converted BCU1 program (the device-mask-aware path, with
  mask-ROM fixups applied at compile time), including repeated
  re-downloads onto a running application. Every wire detail is
  pinned against the spec and ETS traces of those devices, so expect
  other products to surface surprises — a native BCU2 product has not
  met silicon yet. No automatic reconnection, sequential command
  channel, no layered NL/TL/AL separation yet. Partial-download
  subtypes (`grp`/`par`/`cfg`/`ap1`) are not wired. Secure BCU2 first
  commissioning is covered by the configuration runner; broader secure
  real-device download coverage is still missing.
- **ip_interface link layer**: the composite KNX/IP↔TP1 bridge behind
  the IP-interface firmware — implemented, but untested so far.
- **`zweidraehte-microdevice`** (experimental throughout): BCU2 and
  micro-System-7 DUTs pass a smoke suite, the micro System 7 DUT shares
  the full stack's bus-observable System 7 contracts and runs the vendor
  network, transport, load-state, run-state and management templates. Its
  secure sibling passes all 172 selected cases from the AN158 and AN177 Data
  Security collections. The secure BCU2 composition separately passes 176
  applicable base-profile cases and all 172 selected Data Security cases,
  including `PID_IO_LIST`; the BCU2 DUT also completes client download/unload
  scenarios. That is real coverage, but far short of what the full stack gets:
  Group Objects and AN170 Group Object Diagnostics are not in the micro EITT
  profile, BCU1 has a DUT but no reference firmware, and nothing here has seen
  a certification lab.

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
- **Profiles**: System B (07B0/27B0/57B0) and System 7 TP1 (0705,
  incl. Data Secure) are implemented by the full stack. The micro stack
  implements BCU1 0012h, BCU2 0020h/0021h/0025h, and System 7 0705h on
  TP1; plain and Data Secure BCU2 plus plain and Data Secure micro-System-7
  have reference firmware and DUT coverage. System 7 RF/IP siblings, System
  300, couplers/routers, and USB interface masks are not implemented.
- **Micro-stack maturity**: the micro-System-7 EITT profile does not yet run
  Group Objects or AN170 Group Object Diagnostics, and BCU1 has no firmware
  target. Plain and secure BCU2 plus secure micro-System-7 commissioning and
  application traffic have hardware smoke coverage, but no micro target has
  endurance or certification-lab time. Its
  application-parameter adapter, like the full stack's writable typed
  parameter table, also still relies on downloaded bytes containing
  valid Rust enum discriminants.
- **Embedded platform**: no reusable STM32 `Platform` impl, Pico W
  WiFi credentials lack a provisioning mechanism, TCP on the RP2040
  targets is stubbed.

## Repository layout

```
crates/
  zweidraehte-proto/         Protocol types (messages, encoding, addresses, DPTs)
  zweidraehte-device/        Full async-capable device stack (layers, BCUs, storage)
  zweidraehte-microdevice/   Polling TP1 stack for BCU1/BCU2/System 7 (experimental)
  zweidraehte-device-macros/ Proc-macros (interface objects, service registry, extension state)
  zweidraehte-ets/           Proc-macros for ETS parameter/com-object definitions
  zweidraehte-ets-model/     Stack-neutral ETS metadata emitted by those macros
  zweidraehte-knxprod/       MTXML / .knxprod generator + parser
  zweidraehte-client/        Management client (tunnel/USB, secure, download)
  zweidraehte-project/       Host-only project grammar, keys, and mutable state
  zweidraehte-platform/      Platform abstraction (serial, sockets, Linux)
  zweidraehte-util/          Small embedded utilities

examples/
  devices/                   Stack-neutral device/application definitions
  generators/                MTXML/.knxprod generator binaries
  support/                   Host-side demo support (JSON storage, mocks)

conformance/                 Hand-written, vendor-EITT, and download runners

tools/
  knxproj-tui/               Project/product TUI (parameters, object flags,
                             GA links, affected device programming)
  knx-config/                knx-dump (project skeletons) + project-aware
                             knx-loader (check/status/address/program/load/read/unload,
                             keyring import/export, sync)
  compare-programs/          Semantic MTXML comparison
  bus-tools/                 busmon, tpuart, usb_test hardware utilities
  knx-provision/             Factory provisioning via probe-rs

firmware/                    Embedded targets (separate cargo workspace)
  common/                    Chip-agnostic crates (incl. the SX1211 KNX-RF driver)
  stm32/                     STM32G0 devices + family HAL glue
  rp2040/                    Raspberry Pi Pico devices + family HAL glue
  linux/                     Host-target KNX/IP device shells

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

# Inspect a generated ApplicationProgram in product-only TUI mode
cargo run -p knxproj-tui -- out/DerGeraet/M-00FA/ApplicationProgram1.mtxml

# Create a project, import a product/device, then configure it
# (see docs/DEVICE_PROGRAMMING.md for the full workflow)
cargo run --bin knx-loader -- --project project.knx init
cargo run --bin knx-loader -- --project project.knx add device vendor.knxprod \
  --address 1.1.10
cargo run --bin knx-loader -- --project project.knx --usb address device --program-ia
cargo run --bin knx-loader -- --project project.knx --usb load device
# Data Secure credentials come from keys.toml and/or a read-only ETS keyring.
# Import matching keyring entries once if keys.toml should be self-contained.
cargo run --bin knx-loader -- --project project.knx \
  --keyring project.knxkeys import-keyring
# Export the project credentials and device sequence observations again.
cargo run --bin knx-loader -- --project project.knx \
  --keyring-password "$KNX_KEYRING_PASSWORD" \
  export-keyring --out project-export.knxkeys
# project.knx must set `data_secure enabled` on every secured net member.
cargo run --bin knx-loader -- --project project.knx --usb \
  --keyring project.knxkeys program device --affected
# Omit the device to program only the project-wide affected closure.
cargo run --bin knx-loader -- --project project.knx --usb \
  --keyring project.knxkeys program --affected
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
- [`docs/DEVICE_PROGRAMMING.md`](docs/DEVICE_PROGRAMMING.md) —
  configuring real devices with project/key/state stores, affected batches,
  addressing, sequence recovery, the TUI, and loader.

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

No. I am not a member of the KNX Association and the stack is not certified.
The repository contains both hand-written transcriptions and a runner for
licensed vendor EITT XML templates. Those templates are not redistributed;
the current local template set runs against the System B and System 7 DUTs.
Access to the test material and passing it in our harness are useful evidence,
but neither is KNX Association certification.

**Is this stack compliant with the KNX Standard?**

Kind of — but not officially. The in-repo runners execute the hand-written
suite and the licensed vendor EITT XML templates against separate DUT
processes. Profiles document every not-applicable case and GUID-anchored
harness patch. Treat "conformance-tested" in this README as "passes those
suites in this harness", not as a certification claim.

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

**Which profile for a custom device?**

**System B**, unless something forces your hand. It is the profile this
stack is built around: all three media (TP1, KNX-RF, KNX/IP), KNX Data
Secure and KNX IP Secure, the broadest medium support, and the default
full-stack presets. A new device you design yourself
has no reason to be anything else — the mask a product declares is your
choice as the manufacturer, and nothing in ETS rewards picking the
older family.

**System 7** (mask 0705h, TP1) is in the stack for two reasons: to keep
the core honest about being BCU-agnostic — a second family flushed out
the places where "generic" code had quietly grown System B assumptions
— and to support devices that have to match an existing System 7
installed base or toolchain. Reach for it when that constraint is real,
knowing what you give up here: TP1 only. The full System 7 DUT now runs
the same vendor template set as System B. What you get is a genuinely
different management model — compact fixed-map tables, a fixed absolute memory map, absolute-segment load
procedures, 16 authorization levels — commissioned by ETS through the
`ProductProcedure` download, with KNX Data Secure available as the
same composable profile module System B uses.

Practically, the two are the same amount of work to build a device on:
the STM32G0 System 7 light switch and its System B sibling share their
hardware shell and the identical `devices::light_switch` definition,
and differ only in the selected preset (`system_b::Tp1<Definition>` or
`system_7::Tp1<Definition, COT_ADDRESS>`; secure variants use
`SecureTp1`). One
detail leaks into device definitions: `#[ets(index = N)]` on
communication objects is a 0-based logical index, and the object number
ETS shows is `N` plus the family's start (System 7 numbers from 0,
System B from 1), so a shared definition works on both.

**`zweidraehte-microdevice`** is not a third profile so much as a side
quest: an experiment in how small a KNX device gets when you drop the
executor, the buffer pool and the interface-object tower, and let the
EEPROM image *be* the tables. It covers BCU1, BCU2 and fixed-map System 7
on TP1; plain profiles remain standard-frame-only, while the evidence-backed
secure BCU2 0021h profile opts into APDU-40 extended frames. Device code
owns one `Microdevice<F>` and polls it directly. It is much less tested than
the full stack, so
pick it for actual BCU-era hardware or a genuinely brutal RAM/flash
budget — and expect to get your hands dirty. Do not pick it merely as a
smaller API for a new System B product; it models different hardware and
management constraints.

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
