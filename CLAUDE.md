We are building a KNX device stack. We can run a bunch of conformance tests by running `cargo run --bin conformance-runner`. You can pass test names or subset of names as a parameter to only run specific tests. Make sure to not truncate the output of a test run as it is possibly long. The conformance tests take a long while to run. If you need different output, pipe it into a file and then grep through it for what you need without running them over and over again. You can also give it a test suite name or part of it as the first argument to only run specific tests or test suites.

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

The goal is to write a KNX device stack (and possibly more later) in Rust targeting both embedded devices in a no_std and no alloc environment and embedded Linux userspace systems.

The stack needs to be conformance compliant and generic enough so that we can replace different layers and servers in the stack for different use cases when building devices. It's best to stick to existing patterns where applicable.

We are also working on a product definition XML generator. We are generating XML files based on rust macro code that defines the device, its parameters and communication objects as well as dynamic pages that are presented to the user when configuring the device in the ETS.
We try to replicate a real existing MDT device that is defined in `manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml` using this framework in `examples/testutil/src/devices/mdt_push_button_lite.rs`.
We aim for an accurate replication by using our own DSL to ensure feature parity - the parameters, the enums, the comm objects and the dynamic pages that select different combinations of references and show/hide parameters and/or communication objects based on the currently selected configuration. After that we will start optimizing everything and ensure some quality of life improvements when defining all these structures in our DSL to make it easier to understand.
The file in `manuf_tool_data/VC-EASY-03_MDT_KP_V35/M-0083/M-0083_A-0070-35-1740.xml` contains so-called module definitions that we still need to replicate conceptually with a small test device.
For all these XML files, an XSD schema is available at `manuf_tool_data/knx_project.xsd` for reference and checking of correctness.

## Codebase Structure

### Workspace Overview

The project is organized as a Rust workspace with three top-level directories:
`crates/` for libraries, `examples/` for testing and demo code, and `tools/`
for standalone applications.

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
  conformance/             KNX conformance test framework
  devices/                 Device definitions (light switch, IP interface)
  testutil/                Test helpers, demo binaries, MTXML generators

tools/
  knxprod-tui/             TUI viewer for MTXML files

cross/                     Embedded targets (separate workspace)
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
- `composition.rs` - Layer-stack builders (`InsecureDeviceBuilder`, `InsecureIpDeviceBuilder`, `SecureDeviceBuilder`)
- `context/` - Context-trait surface
  - `traits.rs` - Small single-responsibility context traits (buffer manager, APDU length, outbox, property service, address table, etc.)
  - `layer.rs` - `LayerContext<D>` (persistent shared runtime infrastructure, owned by `StackResources`)
  - `stack.rs` - `StackContext<'a, D>` (transient bundle assembled in `Runner::run`)
- `resources.rs` - `StackResources<D, BUF_SZ, NUM_BUFS>` pre-allocated static storage
- `inner.rs` - `Inner<D>` (owned core: state, platform, memory map, &layer_context)
- `state.rs` - `StackState`, `HasAuthorization`, `HasSecureIdentity`, `HasPersistence`, `CoreDeviceState`
- `storage.rs` - `DeviceIdentity`, `SecureDeviceIdentity`, `DeviceStorage`, `SequenceNumberStorage`, `HasSequenceStorage`
- `memory.rs` - `MemoryMap` trait for `A_Memory_Read/Write` dispatch
- `config.rs` - Device-specific configuration macros (`knx_stack_config!`)
- `ets.rs` - ETS integration, parameter export, derive macro re-exports
- `ip.rs` - `IpStackState`, `IpPlatformState` (IP extension state traits), platform re-exports
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
    - `ip_interface/` - External KNXnet/IP interface client (feature `ip-interface`)
    - `mock.rs` - Mock link layer for testing
- `objects/` - KNX interface objects
  - `comm.rs` - Communication objects (group objects), `ComObjects` trait
  - `interface/` - Interface object traits, `PropertyServiceHandler`, `InterfaceObjectAugment<D>`, standard objects
  - `tables/` - Standard KNX tables (address table, app table, association table, CO table) with `Has*` accessor traits
- `bcus/` - Bus Control Units (BCU) device implementations
  - `system_b/` - System B BCU implementation (mask versions 07B0 / 57B0)
    - `mod.rs` - module wiring + the `forward_to_field!` macro (forwards a trait to a named field — `extension_state` on `SystemBDeviceState`, `inner` on wrapper extensions)
    - `device_state/` - `SystemBDeviceState`
    - `extensions/` - TP1, RF (+ retransmitter), IP, Security, OperationMode extensions and their augments; leaf extensions use `#[derive(ExtensionState)]`, each pairs a plain `*State` struct with a borrowing `*Augment<'a>`
    - `objects/` - `SystemBObjects` container
    - `storage.rs` - `DeviceConfig`, `ExtensionConfig`, `ExtensionState`, `Extension` vocabulary (and the `ExtensionState` derive re-export)
    - `memory_map.rs` - `SystemBMemoryMap`
    - `definition.rs` - `SystemBStackDefinition` convenience supertrait; `system_b_standard_stack!` macro generating the always-identical half of a device's `StackDefinition` impl

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

#### 4. Conformance Testing Crate (`examples/conformance`)
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
  - Attributes: `index`, `display`, `function`, `flags`, `selector_enum`

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
  runtime `*State` struct. Struct attr `#[extension_state(config = ...,
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

#### 7. Test Utilities Crate (`examples/testutil`)
**Purpose**: Device definitions, test helpers, and demonstration tools

Key modules:
- `lib.rs` - Library documentation and module exports

Subdirectories:
- `devices/` - Device implementations
  - `mdt_push_button_lite.rs` - MDT Push Button Lite 55 replication
  - `system_b_demo.rs` - Demo System B device
- `mock_platform.rs` - Shared `MockIpPlatform` (mock `IpPlatform`) for KNX/IP device demos and tests
- `storage/` - State persistence backends (JSON-based)
- `util/` - Helper utilities (keyboard input polling, mock context)

Binaries (run with `cargo run --bin <name>`):
- `stack_system_b` - System B device demo
- `stack_knxip` - Full KNX/IP stack demo
- `gen_mtxml` - Generate MTXML from device definitions
- `gen_mdt_mtxml` - Generate MDT device MTXML
- `gen_module_mtxml` - Generate module test device MTXML
- `tpuart` - TPUART interface test
- `knxip` - KNX/IP protocol test
- `busmon` - Bus monitor utility
- `usb_test` - USB interface testing

#### 8. Cross-Compilation Crate (`cross/`)
**Purpose**: Embedded cross-compilation support (separate workspace)

**IMPORTANT**: The `cross/` directory is a separate Cargo workspace. To build
embedded binaries, you must `cd` into the specific project directory first.
Each project has its own `.cargo/config.toml` that sets the correct target
(e.g., `thumbv6m-none-eabi` for the Pico W). Building with `-p picow` from
the parent workspace or the `cross/` directory will use the wrong target and
fail with confusing errors (e.g., missing `#[panic_handler]`, invalid
registers).

```bash
# Correct:
cd cross/picow && cargo build

# Wrong — uses host target, not thumbv6m-none-eabi:
cd cross && cargo build -p picow
```

Contains:
- `tpuart_bridge/` - TP-UART to other protocol bridges
  - Embedded firmware for STM32
  - Uses embassy async runtime, defmt logging, embassy-stm32 HAL
- `picow/` - KNX/IP light switch device on Raspberry Pi Pico W
  - RP2040 + CYW43 WiFi, embassy async runtime
  - Uses `devices::light_switch` device definition
  - Build with: `cd cross/picow && WIFI_SSID=x WIFI_PASS=y cargo build`

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
  │     ├── examples/conformance
  │     ├── examples/testutil
  │     ├── examples/devices
  │     └── cross/*
  └── (future: zweidraehte-client)

zweidraehte-ets            (proc-macro, no runtime deps)
  └── zweidraehte-device

zweidraehte-device-macros  (proc-macro, no runtime deps)
  └── zweidraehte-device

zweidraehte-knxprod        (std, XML generation)
  ├── examples/testutil
  ├── examples/devices
  └── tools/knxprod-tui

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

Example:
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
Generates MTXML files from the MDT Push Button Lite device definition (`examples/testutil/src/devices/mdt_push_button_lite.rs`). Used for comparing against the real MDT reference XML.

**Generate Module Test Device MTXML**
```bash
cargo run --bin gen_module_mtxml
```
Generates MTXML files from the module test device definition (`examples/testutil/src/devices/module_test_device.rs`). Demonstrates KNX module support with a 4-channel dimmer device.

### Device Demos & Testing

**Run System B Demo Device**
```bash
cargo run --bin stack_system_b
```
Runs a demo System B device stack.

**Run KNX/IP Stack Demo**
```bash
cargo run --bin stack_knxip
```
Runs a full KNX/IP stack demo with routing and tunneling support.

**Run TPUART Interface Test**
```bash
cargo run --bin tpuart
```
Tests the TP-UART serial interface.

**Run KNX/IP Protocol Test**
```bash
cargo run --bin knxip
```
Tests KNX/IP protocol functionality.

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

**Run Sequence Number Test**
```bash
cargo run --bin seqno_test
```
Tests sequence number handling.

### TUI Viewer

**Run KNXPROD TUI Viewer**
```bash
cargo run -p knxprod-tui -- <mtxml-file>
```
Interactive TUI for viewing and exploring KNX ApplicationProgram MTXML files. Navigate parameters, view communication objects, and explore device configurations.
