# zweidraehte

## Mission

We are building a KNX device stack in Rust targeting both embedded
devices in a no_std, no-alloc environment and embedded Linux userspace
systems (and possibly more later).

The stack needs to be conformance compliant and generic enough so that
we can replace different layers and servers in the stack for different
use cases when building devices. It's best to stick to existing
patterns where applicable.

We are also working on a product definition XML generator: device
definitions in Rust macros (parameters, communication objects, dynamic
ETS pages) from which we generate the MTXML/`.knxprod` files that ETS
imports — one source of truth for firmware behaviour and the product
database entry. See "Product definition generator" below.

## Conformance testing

Run the conformance tests with `cargo run --bin conformance-runner`.
Pass a test name, suite name, or a substring of either as the first
argument to run a subset. Do not truncate the output of a test run —
it can be long. The tests take a long while; if you need to inspect
the output, pipe it into a file once and grep that file instead of
re-running the suite. Before running, rebuild the DUT binaries with
`cargo build` — the runner spawns them as separate executables.

## Authoring conformance tests

### Suite-level preparation and teardown

`TestSuite` has two hooks for managing global DUT state around a suite:

- `.with_preparation(vec![...])` — steps run once before any test case
  in the suite. Use for non-trivial setup that all cases depend on
  (e.g. loading Security IO, seeding SIAT entries, initial SyncReq).
  If preparation fails, **all tests in the suite are skipped** — the
  runner reports "Preparation failed - skipping suite tests". A
  cascade of skipped suites usually traces back to a missing or
  misordered preparation step.
- `.with_teardown(vec![...])` — steps run once after all cases finish
  (pass or fail). Use to restore global DUT state so the next suite
  starts from a known baseline. Teardown failures are logged but do
  not affect the suite's pass/fail count.

When a test case mutates global DUT state, you have two choices:

1. **Self-contained**: undo the mutation at the end of the case so
   other cases (and suites) are unaffected. Pattern used in e.g.
   3.8.10.1 restoring the GK table entry.
2. **Suite teardown**: if the mutation can't be cleanly reverted per
   case (factory reset, tool key rotation under multiple branches,
   sync rate-limit consumption) put the restore in `with_teardown`.

Destructive operations that leave the DUT in a state the next suite
can't recover from (wiped address / association / group-key tables,
missing IA, etc.) should use `full_reset(timeout_ms)` in the suite
teardown. `TestStep::FullReset` kills the DUT, rewrites shared memory
with the factory-default snapshot, zeroes the sequence-number tail
region (so the respawned DUT starts with fresh seq counters rather
than inheriting stale ones from the previous run), respawns, and
drains ROI frames. Pair it with `wait(1500)` when the prior test
consumed a `S-A_Sync_Req` slot — the DUT's sync rate-limit timer is
wall-clock and survives the respawn.

### Timing, fast mode, and rate limits

The runner compresses inter-step waits by a default 50× via the
`KNX_TIME_DIVISOR` env var (the `--realtime` flag disables it).
`wait(ms)` calls scale accordingly.

DUT-side timing windows that tests depend on (TL ACK / connection
timeouts, `S-A_Sync_Req` rate limit) are scaled by the same divisor
inside the DUT when built with the `conformance` feature, so logical
ordering is preserved without burning real wall-clock. The sync
rate-limit window is 1 s per spec and scales to ~20 ms in fast mode;
tests between back-to-back syncs park `wait(1500)` which comfortably
clears the window in both fast and realtime runs.

## Product definition generator & MDT replication

To prove the ETS DSL has feature parity with real products, we
replicate an existing MDT device
(`examples/devices/src/mdt_push_button_lite.rs`): the parameters, the
enums, the comm objects, and the dynamic pages that select different
combinations of references and show/hide parameters and/or
communication objects based on the currently selected configuration.
After parity, we optimize the DSL for readability and quality of life.
Module definitions (reusable multi-channel blocks) are replicated
conceptually with a small test device
(`examples/devices/src/module_test_device.rs`).

**The manufacturer reference material is NOT in the repository.** The
vendor XML lives in a git-ignored local directory `manuf_tool_data/`
that only exists on machines with a private copy (licensed vendor
data). If present, the relevant files are:

- `manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml`
  — the MDT Push Button Lite reference that `mdt_push_button_lite.rs`
  replicates.
- `manuf_tool_data/VC-EASY-03_MDT_KP_V35/M-0083/M-0083_A-0070-35-1740.xml`
  — contains the module definitions the module test device mirrors.
- `manuf_tool_data/knx_project.xsd` — XSD schema for validating the
  XML.

If `manuf_tool_data/` is absent on this machine, generation still
works (`gen_mdt_mtxml` etc.); only comparison tasks against the vendor
XML are impossible. Skip them rather than hunting for the files, and
advise the user that — if they want the comparisons — they must create
`manuf_tool_data/` themselves and place the right XML files there
(extracted from the vendor `.knxprod` packages); we cannot deliver
these files as they are copyrighted. The same applies to the KNX
specification PDFs: `spec/` is a git-ignored local directory; consult
it when present, but don't expect it to exist.

Signing `.knxprod` packages needs the converter RSA private key, read
at runtime from a git-ignored `converter_key.xml` at the workspace
root (`.NET RSAKeyValue` format; see
`crates/zweidraehte-knxprod/src/signing/keys.rs`). Never hardcode this
key in source or commit the file. If it is absent, `--knxprod`
generation fails with a "could not read the converter key file" error;
the user must supply their own copy.

## Codebase Structure

### Workspace Overview

The project is organized as a Rust workspace with `crates/` for libraries,
`examples/` for device definitions and demo support code, `tools/` for
standalone applications, and `conformance/` for the conformance test
framework. `firmware/` holds the embedded targets in a separate workspace.

```
crates/
  zweidraehte-proto/         Shared KNX protocol types (messages, encoding, addresses, DPTs)
  zweidraehte-device/        KNX device stack (layers, objects, BCUs)
  zweidraehte-device-macros/ Proc-macros for interface objects, service registries, extension state
  zweidraehte-platform/      Platform abstraction (serial, sockets, network)
  zweidraehte-ets/           Procedural macros for ETS parameter definitions
  zweidraehte-knxprod/       XML generator for KNX product definitions
  zweidraehte-util/          Embedded utility types (button input, etc.)

examples/
  devices/                 Device definitions only (light switch, IP interface,
                           demos-gated demo/replication devices) — no binaries
  generators/              MTXML/.knxprod generator binaries (gen_mtxml,
                           gen_mdt_mtxml, ...), one per device definition
  support/                 Host-side demo/test support (JSON storage,
                           keyboard/mock-context utilities)

conformance/               KNX conformance test framework + runner

tools/
  knxprod-tui/             TUI viewer for MTXML files
  knx-provision/           Device provisioning via probe-rs
  compare-programs/        Semantic MTXML comparison (generated vs. reference)
  bus-tools/               Hardware utilities: busmon, tpuart, usb_test

firmware/                  Device targets (separate workspace)
  common/                  Chip-agnostic: embedded-common, knxrf (SX1211
                           driver), dev-provisioning-build
  stm32/                   stm32/common (HAL glue) + STM32G0 devices
  rp2040/                  rp2040/common (HAL glue) + Pico devices
  linux/                   Host-target device shells (eth_light_switch,
                           eth_secure_light_switch)
```

### Coding style

- Don't assume std or even alloc in the core crates, we need to run on embedded devices
- Try to prevent dynamic dispatch: Rely on compile-time composable and monomorphizable types
- If you see common patterns, implement new features using these patterns in case they fit instead of inventing new ones
- When generating packets, use the existing packet generation infrastructure in `zweidraehte_proto::messages`
- When parsing packets, use the existing packet parsing infrastructure in `zweidraehte_proto::messages`
- When using foreign parts from one of our local crates, add a use statement, don't litter the code with full paths of types

### Crates

#### 1. Protocol Crate (`crates/zweidraehte-proto`)
**Purpose**: Shared KNX protocol types used by both device stacks and (future) client implementations. Pure protocol — no device behavior.

Contains:
- `address.rs` - KNX addressing types (individual and group addresses)
- `dpt.rs` - Data Point Types (DPT) - KNX data encoding/decoding
- `access.rs` - Access control types (authorization levels)
- `config.rs` - Buffer sizing and APDU constants
- `device.rs` - Device identification (MaskVersion, MaskFamily, DeviceDescriptor)
- `properties.rs` - Interface object property definitions and access traits
- `error.rs` - Protocol error types
- `encoding/` - Low-level encoding
  - `cemi.rs` - Common EMI format for KNX messages
  - `tp1.rs` - TP1 physical layer encoding
- `messages/` - Message formatting and building
  - `knx.rs` - KNX message structures and ServiceType
  - `builder.rs` - Message construction utilities
  - `buffers.rs` - Buffer management for messages
  - `apdu/` - Application layer PDU types (property, memory, device, auth, restart)
  - `knxip/` - KNX/IP protocol messages (tunneling, discovery, routing, etc.)
- `util/` - Utility functions
  - `crc.rs` - CRC calculations
  - `packets/` - Packet parsing and buffer utilities
  - `dequeue.rs` - Queue operations

#### 2. Device Stack Crate (`crates/zweidraehte-device`)
**Purpose**: Core KNX device stack implementation. Depends on `zweidraehte-proto` and re-exports its modules for downstream convenience.

Key modules:
- `lib.rs` - Main stack entry point, defines core traits, re-exports proto modules
- `definition.rs` - `StackDefinition` trait (central compile-time "bill of materials")
- `router.rs` - Synchronous `Layer` trait and compile-time dispatch-table router
- `runner.rs` - Stack factory (`new()`) and router event loop
- `composition.rs` - Layer-stack builders (`PlainDeviceBuilder`, `PlainIpDeviceBuilder`, `SecureDeviceBuilder`)
- `context/` - Context-trait surface
  - `traits.rs` - Small single-responsibility context traits (buffer manager, APDU length, outbox, property service, address table, etc.)
  - `layer.rs` - `LayerContext<D>` (persistent shared runtime infrastructure, owned by `StackResources`)
  - `stack.rs` - `StackContext<'a, D>` (transient bundle assembled in `Runner::run`)
- `resources.rs` - `StackResources<D, BUF_SZ, NUM_BUFS>` pre-allocated static storage
- `stack_core.rs` - `StackCore<D>` (pub(crate) owned interior: state, platform, memory map, &layer_context)
- `state.rs` - `StackState`, `HasAuthorization`, `HasPersistence`, `HasExtensionState`, `HasSecurityMode`, `HasDiagnosticsContext`, `DiagnosticsView`, `ReadObjectError`/`UpdateObjectError`
- `storage/` - `DeviceIdentity`, `SecureDeviceIdentity`, `SequenceNumberStorage`, `HasSeqStore`, `ConfigStoreBackend`, `HasConfigStore`, `HasDeviceConfig`, `StorageHooks`; the bounded store handles (`ConfigStorage`, `SecureStorage`, `SecureIpStorage`) and the region-anchored layout vocabulary (`StorageLayout`, `Placed<R, C, L>`, `StoreOf<P>`, `Stored<C>`) in `layout.rs`/`region.rs`; backends in `backends/`; the storage task in `task.rs`
- `prelude.rs` - One-stop re-exports for device authors (derive macros, core traits, common types)
- `memory.rs` - `MemoryMap` trait for `A_Memory_Read/Write` dispatch
- `config.rs` - Device-specific configuration macros (`knx_stack_config!`)
- `ets.rs` - ETS integration, parameter export, derive macro re-exports
- `ip.rs` - IP extension view traits (`IpStateView`, `HasIpExtensionState`, `HasRoutingMulticastRebind`, `HasAdditionalIas`, `IpSecureStateView`, `HasIpSecureView`), platform re-exports
- `actor.rs` - Lightweight request/response primitives (`Request<M, R>`, `ActorRequest`)
- `device_model.rs` - `DeviceModelNotifier` and device-model lifecycle
- `restart.rs` - Restart request types and erase codes
- `access_policy.rs` - Access-control policy helpers

Subdirectories:
- `layers/` - KNX protocol stack layers (all synchronous except link layers)
  - `network.rs` - Network layer (routing, hop count)
  - `transport/` - Transport layer connection management
    - `mod.rs` - `TransportLayer` (TL state machine per 03/03/04 §5.4)
    - `connection.rs` - Individual connections
    - `state_machine.rs` - Connection state tracking
    - `cemi.rs` - `CemiTransportLayer` wrapper (used by KNX/IP stacks as `(NL, CemiTL<TL>, AL)`)
  - `application/` - Application layer (`mod.rs` dispatches APCI codes)
  - `secure_application/` - Secure Application Layer wrapper (KNX Data Secure; wraps plain AL, decrypts/encrypts Secure Service APDUs)
  - `linklayers/` - Physical layer implementations (each runs as a separate async task, connected to the router via req/ind/conf channels)
    - `tpuart/` - TP-UART serial interface (bus access, state machine, busmon)
    - `knxip/` - KNX/IP routing, tunneling, discovery, device management
    - `usb/` - USB HID interface support
    - `ip_interface.rs` - Composite KNX/IP↔TP1 link layer for IP-interface products: tunneling server bridged to a TPUART bus (feature `ip-interface`)
    - `mock.rs` - Mock link layer for testing
- `objects/` - KNX interface objects
  - `comm.rs` - Communication objects (group objects), `ComObjects` trait
  - `interface/` - Interface object traits, `PropertyServiceHandler`, `InterfaceObjectAugment<D>`, standard objects
  - `tables/` - Standard KNX tables (address table, app table, association table, CO table) with `Has*` accessor traits
- `bcus/` - Bus Control Units (BCU) device implementations
  - `system_b/` - System B BCU implementation (mask versions 07B0 / 57B0)
    - `mod.rs` - module wiring + the `forward_to_field!` macro (forwards a trait to a named field — `extension_state` on `SystemBDeviceState`, `inner` on wrapper extensions) + `forward_system_b_state_traits!` (emits the standard 14-trait pure-delegation set for state newtypes; `StackState`/`DeviceModelNotifier` stay hand-written)
    - `device_state/` - `SystemBDeviceState`
    - `extensions/` - TP1, RF (+ retransmitter), IP, Security, OperationMode extensions and their augments; leaf extensions use `#[derive(ExtensionState)]`, each pairs a plain `*State` struct with a borrowing `*Augment<'a>`
    - `objects/` - `SystemBObjects` container
    - `storage.rs` - `DeviceConfig`, `ExtensionConfig`, `ExtensionState`, `Extension` vocabulary (and the `ExtensionState` derive re-export)
    - `memory_map.rs` - `SystemBMemoryMap`
    - `definition.rs` - `SystemBStackDefinition` convenience supertrait; `system_b_standard_stack!` macro generating the always-identical half of a device's `StackDefinition` impl (optional `resources:` slot for `SecureResources` and `augments: { bundle, create }` slot for custom augment bundles — all firmware devices use it). `#[macro_export]`ed, so it is invoked as `zweidraehte_device::system_b_standard_stack!` (crate root), not via the `bcus::system_b` path

#### 3. Platform Crate (`crates/zweidraehte-platform`)
**Purpose**: Platform abstraction layer for different operating systems and hardware

Key modules:
- `lib.rs` - Platform abstraction interface
- `serialport.rs` - Serial port abstraction

Subdirectories:
- `address/` - Network address utilities
- `linux/` - Linux-specific implementations
  - Async serial port handling
  - UDP multicast socket handling (for KNX/IP routing)
  - Network interface address resolution

#### 4. Conformance Testing Crate (`conformance/`)
**Purpose**: KNX conformance test framework for validating stack compliance

Run with: `cargo run --bin conformance-runner [test_name_filter]`

When running the conformance tests, make sure the two DUTs that are separate
executables are rebuilt with `cargo build`!

Key modules:
- `lib.rs` - Test framework definition and data structures
- `bin/runner.rs` - Test runner executable
- `telegram.rs` - Telegram parsing and matching
- `logger.rs` - Test logging utilities

Subdirectories:
- `harness/` - Test harness implementations
  - `mock.rs` - Mock link layer for injection/capture
  - `stack.rs` - Stack instance for testing
- `tests/` - Actual test suites
  - `group_objects.rs` - Group object communication tests
  - `network_layer.rs` - Network layer conformance
  - `transport_layer_*.rs` - Transport layer tests (general, state machine, timing)
  - `load_state_machines.rs` - Application state loading
  - `run_state_machines.rs` - Application state execution
  - `management.rs` - Management operations

#### 5. ETS Macros Crate (`crates/zweidraehte-ets`)
**Purpose**: Procedural macros for generating ETS parameter definitions

Macros provided:
- `#[derive(EtsParams)]` - For parameter structs
  - Generates ETS_PARAMS and ETS_PARAMS_EXT constants
  - Supports enums, bitfields, unions
  - Attributes: `display`, `suffix`, `bits`, `bit_offset`, `enum_variants`, `union`, `hidden`
- `#[derive(EtsUnion)]` - For union parameter types (`#[repr(C, u8)]` enums)
  - Generates ETS_UNION_INFO and ETS_SELECTOR_VARIANTS
  - Creates discriminant enum for type-safe access
- `#[derive(EtsEnum)]` - For simple enums (`#[repr(u8)]`)
  - Generates ETS_VARIANTS constant for dropdown parameters
- `#[derive(EtsComObjects)]` - For communication object definitions
  - Generates Index enum, ETS_COMM_OBJECTS array
  - Supports multi-DPT objects with selector-based typed access
  - Attributes: `index`, `display`, `function`, `flags`, `selector_enum`,
    `initial` (non-default seed value in the generated `new()`)
  - Struct attrs: `bus_hook` (derived dispatch + hand-written
    `ComObjectBusHook`), `manual_impl` (hand-write both)

#### 5b. Device Macros Crate (`crates/zweidraehte-device-macros`)
**Purpose**: Proc-macros for KNX interface-object metadata, service-registry
wiring, and extension-state generation. Re-exported through `zweidraehte-device`
(e.g. `interface_object_augment` via `objects::interface`, `ServiceRegistry`
and the `ExtensionState` derive via `service` / `bcus::system_b`).

Macros provided:
- `#[interface_object(object_type = ...)]` - Rewrites a struct into an
  `InterfaceObject` impl with a `const PROPERTY_DESCRIPTORS` table, from
  per-field `#[io(...)]` annotations.
- `#[interface_object_augment(target_objects | additional_objects = [...])]` -
  Same DSL for `Augment<D>` impls; `target_objects` + `intercepts` adds PIDs to
  an existing object, `additional_objects` provides a new object. Supports
  `where_bounds(...)`.
- `#[derive(ServiceRegistry)]` - Derives `LayerRegistry<D>` / `Augment<D>` for a
  device's services struct by walking `#[service(handler | augment | flatten |
  lifecycle | channel)]` fields.
- `#[derive(ExtensionState)]` - Generates the persisted `*Config` mirror struct
  (`Cell`/`RefCell` fields unwrapped) plus its `Default`/`ExtensionConfig` impls
  and the `ExtensionState` impl (`from_config`/`to_config`/`on_erase`) from a
  runtime `*State` struct, plus an inherent `apply_config(&self, Config)`
  (in-place reset through interior mutability; used by `on_erase = manual`
  impls). Struct attr `#[extension_state(config = ...,
  resources = ..., on_erase = manual, default = manual)]`; field attrs
  `#[runtime_only]`, `#[config(ty = ..., from = ..., to = ..., serde_default =
  ...)]`, `#[erase(default = ...)]`.

#### 6. KNXPROD Generator Crate (`crates/zweidraehte-knxprod`)
**Purpose**: XML generator for KNX product definitions (MTXML format)

Key modules:
- `lib.rs` - Main library interface and documentation
- `schema.rs` - Typed Rust structs matching KNX XSD schema
  - ApplicationProgram, Hardware, Catalog structures
  - All XML serialization types
- `generator.rs` - Main MTXML generation engine
  - KnxprodBuilder - Unified builder API (preferred entry point)
  - MtxmlGenerator - Creates ApplicationProgram XML (used internally by builder)
  - HardwareGenerator - Hardware definitions (used internally by builder)
  - CatalogGenerator - Product catalog XML (used internally by builder)
  - Parameter reference generation
  - Communication object mapping
- `page_layout.rs` - ETS parameter page layout DSL
  - EtsPageLayout trait
  - PageStructure, PageBlock, PageItem
  - Conditional visibility logic
  - Parameter grouping and sections

#### 7. Device Definitions Crate (`examples/devices`, package `zweidraehte-devices`)
**Purpose**: Device definitions only — no binaries. The no_std definitions are
consumed by the firmware targets; the demo/replication definitions (feature
`demos`) by the generators and the Linux demo target. The library is named
`devices` so all consumers write `use devices::...`.

Modules:
- `light_switch/`, `ip_interface/` - no_std device definitions used by firmware
- `mdt_push_button_lite.rs` - MDT Push Button Lite 55 replication (feature `demos`)
- `module_test_device.rs` - Module test device, 4-channel dimmer (feature `demos`)
- `system_b_demo.rs` - Demo System B device (feature `demos`)

Features: `demos` is a **default feature** so `cargo test -p
zweidraehte-devices` covers the demo definitions; firmware consumers use
`default-features = false` and stay no_std/lean.

#### 7b. Generators Crate (`examples/generators`, package `zweidraehte-generators`)
**Purpose**: MTXML/.knxprod generator binaries — thin glue between a device
definition and `KnxprodBuilder`. One binary per device, all in `src/bin/`.

Binaries (run with `cargo run --bin <name>`):
- `gen_mtxml` - Generate MTXML from the demo System B device definition
- `gen_light_switch_mtxml` / `gen_ip_interface_mtxml` - Firmware device MTXML
- `gen_mdt_mtxml` - Generate MDT device MTXML
- `gen_module_mtxml` - Generate module test device MTXML

#### 7c. Demo Support Crate (`examples/support`, package `zweidraehte-support`)
**Purpose**: Host-side (std/Linux) support code shared by the demo binaries
and hardware tools. The library is named `support`.

- `storage/` - State persistence backends (JSON-based): `JsonStorage`, `FileIdentity`
- `util/` - Helper utilities (keyboard input polling, mock stack context)

#### 7d. Hardware Tools Crate (`tools/bus-tools`)
Binaries (run with `cargo run --bin <name>`):
- `busmon` - Bus monitor utility
- `tpuart` - TPUART interface test
- `usb_test` - USB interface testing

#### 8. Firmware Workspace (`firmware/`)
**Purpose**: Device targets (separate workspace) — embedded MCU families plus
`linux/` for host-target device shells

**IMPORTANT**: The `firmware/` directory is a separate Cargo workspace. To
build embedded binaries, you must `cd` into the specific project directory
first. Each project has its own `.cargo/config.toml` that sets the correct
target (e.g., `thumbv6m-none-eabi` for the Pico W). Building with `-p <name>`
from the parent workspace or the `firmware/` directory will use the wrong
target and fail with confusing errors (e.g., missing `#[panic_handler]`,
invalid registers).

```bash
# Correct:
cd firmware/rp2040/wifi_light_switch && cargo build

# Wrong — uses host target, not thumbv6m-none-eabi:
cd firmware && cargo build -p pico_wifi_light_switch
```

Layout: `common/` holds chip-agnostic crates (`embedded-common`, the `knxrf`
SX1211 driver, `dev-provisioning-build`); `stm32/` and `rp2040/` each hold a
family `common/` HAL-glue crate plus the device projects. Directory names
drop the chip prefix (`stm32/g0_blink`, `rp2040/eth_light_switch`), package names keep it
(`stm32g0_blink`, `pico_eth_light_switch`). `linux/` holds host-target device
shells following the same `<medium>[_secure]_<role>` naming (package prefix
`linux_`); these build with a plain `cargo build` in the project directory —
no target override.

Notable devices:
- `linux/eth_light_switch/` (package `linux_eth_light_switch`) - Linux-hosted
  KNX/IP light switch
  - Runs the shared `devices::light_switch` definition over the read-only
    `LinuxIpPlatform` (UDP + TCP, routing + remote config, no tunnelling —
    feature set `KnxIpDeviceTcp`) with JSON state persistence and keyboard
    interaction
  - Run with: `cd firmware/linux/eth_light_switch && cargo run`
- `linux/eth_secure_light_switch/` (package `linux_eth_secure_light_switch`) -
  the secure sibling: same light switch with KNX IP Secure (secure multicast
  routing) + KNX Data Secure. Adds `GetrandomRng`, a `StaticSecureIdentity`
  carrying the FDSK, and the file-backed sequence/SIAT store
  `support::storage::LinuxSecureSeqStorage` (the host equivalent of the
  embedded flash seq store — `SecureIpDeviceBuilder` needs `HasSeqStore`).
  - Run with: `cd firmware/linux/eth_secure_light_switch && cargo run`
- `rp2040/wifi_light_switch/` (package `pico_wifi_light_switch`) - KNX/IP
  light switch device on Raspberry Pi Pico W
  - RP2040 + CYW43 WiFi, embassy async runtime
  - Uses `devices::light_switch` device definition
  - Build with: `cd firmware/rp2040/wifi_light_switch && WIFI_SSID=x WIFI_PASS=y cargo build`

### Documentation (`/docs`)

- `STACK_ARCHITECTURE.md` - Full reference for the device stack's design
  philosophy, core components, and the context-trait surface. Covers
  `StackDefinition`, router + `Layer` trait, `LayerContext` vs.
  `StackContext`, `Config`/`State`/`Resources`/`StateInit` vocabulary,
  extensions and augments, link layers, and a dispatch walk-through.
  Read this first when touching stack internals.
- `DEVICE_DEFINITION.md` - How to define a concrete device and wire it
  into `main`.
- `DSL_REFERENCE.md` - Comprehensive reference for the ETS DSL macros:
  - `#[derive(EtsParams)]` - Parameter struct definitions
  - `#[derive(EtsEnum)]` - Simple enum dropdowns
  - `#[derive(EtsUnion)]` - Tagged union/variant parameters
  - `#[derive(EtsComObjects)]` - Communication object definitions
  - `ets_pages!` - Page layout macro for ETS UI structure
  - `define_module!` - Reusable module definitions for multi-channel devices
  - Conditional visibility (`when`/`choose` blocks)
  - Text templates (`{{0}}`, `{{ArgName}}`)

### Architecture Layers

NL, TL, and AL are **synchronous** `Layer` implementations dispatched by
a single async router loop via a compile-time dispatch table keyed on
`ServiceType`. The link layer runs as a separate async task connected
to the router via three channels (req/ind/conf). KNX/IP stacks insert
a `CemiTransportLayer` wrapper between TL and the link layer. KNX Data
Secure swaps `ApplicationLayer` for `SecureApplicationLayer` (a wrapper
that decrypts incoming Secure Service APDUs and encrypts responses).

```
User code  ←─(ApplicationLayerService, ComObject events, restart)→  Application Layer
                                                                  (or SecureApplicationLayer wrapper)
                                      ↓ (Outbox + DispatchTable)
                                  Transport Layer
                                      ↓
                           (CemiTransportLayer wrapper — KNX/IP only)
                                      ↓
                                  Network Layer
                                      ↓ (req / ind / conf channels)
            Link Layer (async task: TPUART, KNX/IP, USB, ip_interface, Mock)
                                      ↓
                                  KNX wire
```

See `docs/STACK_ARCHITECTURE.md` for the full component / context-trait
reference.

### Crate Dependency Graph

```
zweidraehte-proto          (no_std, pure protocol types)
  ├── zweidraehte-device   (no_std, device stack — re-exports proto)
  │     ├── conformance/
  │     ├── examples/devices
  │     ├── examples/support
  │     ├── tools/bus-tools
  │     └── firmware/*
  └── zweidraehte-client

zweidraehte-ets            (proc-macro, no runtime deps)
  └── zweidraehte-device

zweidraehte-device-macros  (proc-macro, no runtime deps)
  └── zweidraehte-device

zweidraehte-knxprod        (std, XML generation)
  ├── examples/devices     (feature "knxprod"/"demos")
  ├── examples/generators
  ├── tools/knxprod-tui
  └── tools/compare-programs

zweidraehte-platform       (platform abstraction)
  ├── zweidraehte-proto
  └── zweidraehte-device
```

### ETS Integration Pipeline

```
Device Definition (macros)
    ↓
Parameter Metadata (EtsParams)
    ↓
Communication Objects (EtsComObjects)
    ↓
Page Layout Definition (EtsPageLayout)
    ↓
XML Generation (KnxprodBuilder)
    ↓
MTXML/KNXPROD Files
```

### Key Design Patterns

- **Trait-Based Abstraction**: `Layer` trait for protocol layers, `ComObjects` trait for comm object access, `MemoryMap` trait for device memory, `LinkLayerBuilder` for pluggable link layers
- **State / Augment split**: every extension pairs a plain runtime `*State` struct with a separate borrowing `*Augment<'a>` (the augment holds `&'a State`, so writes reach the state's authoritative `Cell`/`RefCell`). TP1, RF, IP all follow this one shape.
- **Config derived from State**: `#[derive(ExtensionState)]` generates the persisted `*Config` mirror and the `from_config`/`to_config`/`on_erase` glue from the runtime state's `Cell`/`RefCell` fields — the state is the single source of truth.
- **Macro-collapsed boilerplate**: `system_b_standard_stack!` generates the always-identical half of a device's `StackDefinition` impl; `forward_to_field!` generates trait-forwarding to a struct field. Both are opt-in; hand-writing still works.
- **Platform Abstraction**: Platform crate abstracts OS-specific operations with features to enable/disable platform support
- **no_std Compatible**: Core stack works in both no_std embedded and std Linux environments
- **Proto/Device Split**: Pure protocol types in `zweidraehte-proto` can be shared with future client implementations without pulling in device stack logic

## KNXPROD Parser & Viewer

### Purpose
Parse existing KNX ApplicationProgram MTXML files (like the MDT reference device) and render them in a TUI or web interface. This enables:
1. Verification of DSL-generated XML against real manufacturer XML
2. Interactive exploration of device configurations
3. Memory content generation matching ETS behavior

### Architecture

**Parser (`crates/zweidraehte-knxprod/src/parser.rs`)**:
- Uses existing schema.rs types (already have serde Deserialize)
- Simple wrapper functions for parsing XML strings and files

**Device Model (`crates/zweidraehte-knxprod/src/model.rs`)**:
- Runtime state: parameter values, object bindings, visibility
- Condition evaluation engine for choose/when blocks
- Visibility recomputation on parameter changes

**TUI Application (knxprod-tui crate)**:
- Built with ratatui and crossterm
- Tab navigation between channels
- Collapsible parameter blocks
- Custom widgets for enum dropdowns, number inputs
- Communication objects table view

**HTML Server (knxprod-html crate)** (future):
- axum web server with tera templates
- SSE for live visibility updates
- Form-based parameter editing

### Key Files
- `crates/zweidraehte-knxprod/src/parser.rs` - XML parsing functions
- `crates/zweidraehte-knxprod/src/model.rs` - Device model and condition evaluation
- `tools/knxprod-tui/src/` - TUI application
- `knxprod-html/src/` - HTML server (future)

## Commands Reference

### Testing & Validation

**Run KNX Conformance Tests**
```bash
cargo run --bin conformance-runner [test_filter]
```
Runs KNX protocol conformance tests. Takes a long while to run. Prevent running them multiple times. If you need output, write it to a file to grep through later for what you are looking. Also pass an optional filter to run specific tests or test suites (e.g., `transport` to run only transport layer tests).

**Compare MTXML Programs**
```bash
cargo run --bin compare_programs -- --reference <ref.xml> --generated <gen.xml> [OPTIONS]
```
Compares two KNX ApplicationProgram XML files for semantic equivalence. Used to verify DSL-generated XML against manufacturer reference XML.

Options:
- `--strict` - Enable strict mode (compare ordering and ID structure)
- `--compare-ordering` - Compare element ordering
- `--compare-ids` - Compare ID correspondence structure
- `--no-text` - Skip text comparison
- `--warn-missing` - Treat missing entities as warnings instead of errors

Example (needs the local `manuf_tool_data/` vendor files — see
"Product definition generator & MDT replication" above):
```bash
cargo run --bin compare_programs -- \
  --reference manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml \
  --generated MdtApplicationProgram1.mtxml
```

### XML Generation

**Generate Demo Device MTXML**
```bash
cargo run --bin gen_mtxml [--knxprod]
```
Generates MTXML files (ApplicationProgram1.mtxml, Hardware1.mtxml, Catalog1.mtxml) from the demo System B device definition. Use `--knxprod` to also generate a signed `.knxprod` package.

**Generate MDT Push Button Lite MTXML**
```bash
cargo run --bin gen_mdt_mtxml
```
Generates MTXML files from the MDT Push Button Lite device definition (`examples/devices/src/mdt_push_button_lite.rs`). Used for comparing against the real MDT reference XML.

**Generate Module Test Device MTXML**
```bash
cargo run --bin gen_module_mtxml
```
Generates MTXML files from the module test device definition (`examples/devices/src/module_test_device.rs`). Demonstrates KNX module support with a 4-channel dimmer device.

### Device Demos & Testing

**Run Light Switch Device (Linux host target)**
```bash
cd firmware/linux/eth_light_switch && cargo run          # plain KNX/IP
cd firmware/linux/eth_secure_light_switch && cargo run   # IP Secure + Data Secure
```
Runs the shared `light_switch` device stack on the host (firmware workspace).

The network interface is resolved at startup by
`support::util::resolve_knx_interface` (policy in
`zweidraehte_platform::InterfaceSelector`): `--interface <name|ip>` /
`KNX_INTERFACE=<name|ip>` if given, otherwise the only live,
multicast-capable, non-loopback interface, otherwise whichever one the
kernel routes `224.0.23.12` through. Several candidates and no route ⇒ a
listing and exit 1, never a panic. Both binaries print the choice and why.

**Run TPUART Interface Test**
```bash
cargo run --bin tpuart
```
Tests the TP-UART serial interface.

**Run Bus Monitor**
```bash
cargo run --bin busmon
```
Monitors KNX bus traffic.

**Run USB Interface Test**
```bash
cargo run --bin usb_test
```
Tests USB HID interface support.

### TUI Viewer

**Run KNXPROD TUI Viewer**
```bash
cargo run -p knxprod-tui -- <mtxml-file>
```
Interactive TUI for viewing and exploring KNX ApplicationProgram MTXML files. Navigate parameters, view communication objects, and explore device configurations.
