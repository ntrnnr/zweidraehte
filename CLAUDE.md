We are building a KNX device stack. We can run a bunch of conformance tests by running `cargo run --bin conformance-runner`. You can pass test names or subset of names as a parameter to only run specific tests. Make sure to not truncate the output of a test run as it is possibly long. The conformance tests take a long while to run. If you need different output, pipe it into a file and then grep through it for what you need without running them over and over again. You can also give it a test suite name or part of it as the first argument to only run specific tests or test suites.

The goal is to write a KNX device stack (and possibly more later) in Rust targeting both embedded devices in a no_std and no alloc environment and embedded Linux userspace systems.

The stack needs to be conformance compliant and generic enough so that we can replace different layers and servers in the stack for different use cases when building devices. It's best to stick to existing patterns where applicable.

We are also working on a product definition XML generator. We are generating XML files based on rust macro code that defines the device, its parameters and communication objects as well as dynamic pages that are presented to the user when configuring the device in the ETS.
We try to replicate a real existing MDT device that is defined in `manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml` using this framework in `testutil/src/devices/mdt_push_button_lite.rs`.
We aim for an accurate replication by using our own DSL to ensure feature parity - the parameters, the enums, the comm objects and the dynamic pages that select different combinations of references and show/hide parameters and/or communication objects based on the currently selected configuration. After that we will start optimizing everything and ensure some quality of life improvements when defining all these structures in our DSL to make it easier to understand.

## Codebase Structure

### Workspace Overview

The project is organized as a Rust workspace with 6 main crates targeting both embedded devices (no_std) and Linux userspace systems.

### Crates

#### 1. Stack Crate (`/stack`)
**Purpose**: Core KNX device stack implementation (the main library)

Key modules:
- `lib.rs` - Main stack entry point, defines core traits and state management
- `address.rs` - KNX addressing types (individual and group addresses)
- `dpt.rs` - Data Point Types (DPT) - KNX data encoding/decoding
- `config.rs` - Device configuration and parameter management
- `context.rs` - Runtime context for buffer management
- `ets.rs` - ETS (Engineering Tool Software) integration and parameter export
- `memory.rs` - Memory management for embedded/no_std environments
- `macros.rs` - Helper macros for DSL definitions
- `fmt.rs` - Formatting helpers

Subdirectories:
- `encoding/` - Low-level encoding
  - `cemi.rs` - Common EMI format for KNX messages
  - `tp1.rs` - TP1 physical layer encoding
- `layers/` - KNX protocol stack layers
  - `application.rs` - Application layer (handles app-level services)
  - `network.rs` - Network layer routing
  - `transport/` - Transport layer connection management
    - `connection.rs` - Individual connections
    - `state_machine.rs` - Connection state tracking
  - `linklayers/` - Physical layer implementations
    - `tpuart/` - TP-UART serial interface (bus access, state machine, busmon)
    - `knxip/` - KNX/IP routing and tunneling over IP
      - `servers/` - Discovery, routing, remote config, tunneling servers
    - `usb/` - USB HID interface support
    - `mock.rs` - Mock link layer for testing
- `messages/` - Message formatting and building
  - `knx.rs` - KNX message structures
  - `builder.rs` - Message construction utilities
  - `buffers.rs` - Buffer management for messages
  - `knxip/` - KNX/IP protocol messages
- `objects/` - KNX interface objects
  - `comm.rs` - Communication objects (group objects)
  - `interface/` - Interface object properties and standard objects
  - `tables/` - Standard KNX tables (address table, app table, association table, CO table)
- `bcus/` - Bus Control Units (BCU) device implementations
  - `system_b/` - System B BCU implementation
    - `device_state.rs` - Runtime state persistence
    - `memory_map.rs` - Memory layout
    - `objects.rs` - Object management
    - `storage.rs` - State storage backends
  - `x7b0.rs` - X7B0 model support
- `util/` - Utility functions
  - `crc.rs` - CRC calculations
  - `packets/` - Packet parsing and buffer utilities
  - `dequeue.rs` - Queue operations
- `test_util/` - Testing utilities (when feature enabled)

#### 2. Platform Crate (`/platform`)
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

#### 3. Conformance Testing Crate (`/conformance`)
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

#### 4. ETS Macros Crate (`/ets-macros`)
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

#### 5. KNXPROD Generator Crate (`/knxprod`)
**Purpose**: XML generator for KNX product definitions (MTXML format)

Key modules:
- `lib.rs` - Main library interface and documentation
- `schema.rs` - Typed Rust structs matching KNX XSD schema
  - ApplicationProgram, Hardware, Catalog structures
  - All XML serialization types
- `generator.rs` - Main MTXML generation engine
  - MtxmlGenerator - Creates ApplicationProgram XML
  - HardwareGenerator - Hardware definitions
  - CatalogGenerator - Product catalog XML
  - Parameter reference generation
  - Communication object mapping
- `page_layout.rs` - ETS parameter page layout DSL
  - EtsPageLayout trait
  - PageStructure, PageBlock, PageItem
  - Conditional visibility logic
  - Parameter grouping and sections

#### 6. Test Utilities Crate (`/testutil`)
**Purpose**: Device definitions, test helpers, and demonstration tools

Key modules:
- `lib.rs` - Library documentation and module exports

Subdirectories:
- `devices/` - Device implementations
  - `mdt_push_button_lite.rs` - MDT Push Button Lite 55 replication
  - `system_b_demo.rs` - Demo System B device
- `storage/` - State persistence backends (JSON-based)
- `util/` - Helper utilities (keyboard input polling)
- `mtxml_gen/` - MTXML generation utilities

Binaries (run with `cargo run --bin <name>`):
- `stack_system_b` - System B device demo
- `stack_knxip` - Full KNX/IP stack demo
- `gen_mtxml` - Generate MTXML from device definitions
- `gen_mdt_mtxml` - Generate MDT device MTXML
- `tpuart` - TPUART interface test
- `knxip` - KNX/IP protocol test
- `busmon` - Bus monitor utility
- `usb_test` - USB interface testing

#### 7. Cross-Compilation Crate (`/cross`)
**Purpose**: Embedded STM32 cross-compilation support (separate workspace)

Contains:
- `tpuart_bridge/` - TP-UART to other protocol bridges
  - Embedded firmware for STM32
  - Uses embassy async runtime, defmt logging, embassy-stm32 HAL

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
XML Generation (MtxmlGenerator)
    ↓
MTXML/KNXPROD Files
```

### Key Design Patterns

- **Trait-Based Abstraction**: `Layer` trait for protocol layers, `ComObjects` trait for comm object access, `MemoryMap` trait for device memory, `LinkLayerBuilder` for pluggable link layers
- **Platform Abstraction**: Platform crate abstracts OS-specific operations with features to enable/disable platform support
- **no_std Compatible**: Core stack works in both no_std embedded and std Linux environments

## KNXPROD Parser & Viewer

### Purpose
Parse existing KNX ApplicationProgram MTXML files (like the MDT reference device) and render them in a TUI or web interface. This enables:
1. Verification of DSL-generated XML against real manufacturer XML
2. Interactive exploration of device configurations
3. Memory content generation matching ETS behavior

### Architecture

**Parser (knxprod/src/parser.rs)**:
- Uses existing schema.rs types (already have serde Deserialize)
- Simple wrapper functions for parsing XML strings and files

**Device Model (knxprod/src/model.rs)**:
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
- `knxprod/src/parser.rs` - XML parsing functions
- `knxprod/src/model.rs` - Device model and condition evaluation
- `knxprod-tui/src/` - TUI application
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
cargo run --bin gen_mtxml
```
Generates MTXML files (ApplicationProgram1.mtxml, Hardware1.mtxml, Catalog1.mtxml) from the demo System B device definition.

**Generate MDT Push Button Lite MTXML**
```bash
cargo run --bin gen_mdt_mtxml
```
Generates MTXML files from the MDT Push Button Lite device definition (`testutil/src/devices/mdt_push_button_lite.rs`). Used for comparing against the real MDT reference XML.

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
