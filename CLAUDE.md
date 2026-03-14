We are building a KNX device stack. We can run a bunch of conformance tests by running `cargo run --bin conformance-runner`. You can pass test names or subset of names as a parameter to only run specific tests. Make sure to not truncate the output of a test run as it is possibly long. The conformance tests take a long while to run. If you need different output, pipe it into a file and then grep through it for what you need without running them over and over again. You can also give it a test suite name or part of it as the first argument to only run specific tests or test suites.

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
  zweidraehte-proto/       Shared KNX protocol types (messages, encoding, addresses, DPTs)
  zweidraehte-device/      KNX device stack (layers, objects, BCUs)
  zweidraehte-platform/    Platform abstraction (serial, sockets, network)
  zweidraehte-ets/         Procedural macros for ETS parameter definitions
  zweidraehte-knxprod/     XML generator for KNX product definitions
  zweidraehte-util/        Embedded utility types (button input, etc.)

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
- If you see common patterns, implement new features using these patterns in case they fit instead of inventing new ones
- When generating packets, use the existing packet generation infrastructure in `zweidraehte_device::messages`
- When parsing packets, use the existing packet parsing infrastructure in `zweidraehte_device::messages`

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
- `config.rs` - Device-specific configuration macros (`knx_stack_config!`)
- `context.rs` - Runtime context for buffer management
- `ets.rs` - ETS integration, parameter export, derive macro re-exports
- `memory.rs` - Memory management for embedded/no_std environments
- `router.rs` - Table-driven message router and `Layer` trait
- `definition.rs` - `StackDefinition` trait

Subdirectories:
- `layers/` - KNX protocol stack layers
  - `application.rs` - Application layer (handles app-level services)
  - `network.rs` - Network layer routing
  - `transport/` - Transport layer connection management
    - `connection.rs` - Individual connections
    - `state_machine.rs` - Connection state tracking
  - `linklayers/` - Physical layer implementations
    - `tpuart/` - TP-UART serial interface (bus access, state machine, busmon)
    - `knxip/` - KNX/IP routing and tunneling over IP
    - `usb/` - USB HID interface support
    - `mock.rs` - Mock link layer for testing
- `objects/` - KNX interface objects
  - `comm.rs` - Communication objects (group objects)
  - `interface/` - Interface object traits and standard objects
  - `tables/` - Standard KNX tables (address table, app table, association table, CO table)
- `bcus/` - Bus Control Units (BCU) device implementations
  - `system_b/` - System B BCU implementation

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
- `storage/` - State persistence backends (JSON-based)
- `util/` - Helper utilities (keyboard input polling)

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

```
Application Layer (handlers for services)
    ↓
Transport Layer (connection management)
    ↓
Network Layer (routing)
    ↓
Link Layers (physical: TPUART, KNX/IP, USB, Mock)
```

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
Runs KNX protocol conformance tests. Takes a long while to run. Pass an optional filter to run specific tests or test suites (e.g., `transport` to run only transport layer tests). Pipe output to a file if you need to grep through results.

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
