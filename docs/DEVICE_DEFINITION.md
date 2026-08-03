# Device Definition Guide

This document explains how to define, configure, and run a KNX device
using the zweidraehte stack. It covers the state model, extension state,
augments, persistence, and the full startup sequence.

## Overview

A device definition brings together:

1. **Device descriptor** — hardware identity, table capacities, mask version
2. **Application parameters** — ETS-configurable values (`#[derive(EtsParams)]`)
3. **Communication objects** — group object definitions (`#[derive(EtsComObjects)]`)
4. **Extension** — medium-specific state + augmentation (IP config, retry count, etc.)
5. **Link layer** — physical transport (TPUART, KNX/IP, USB)

All of these are composed at compile time through the `StackDefinition`
trait, which acts as the "bill of materials" for the device.

## State Model

### SystemBDeviceState

All runtime device state lives in a single struct:

```rust
pub struct SystemBDeviceState<
    const ADT_SIZE: usize,      // Address table byte size
    const AST_SIZE: usize,      // Association table byte size
    const COT_SIZE: usize,      // Comm object table byte size
    D: StackDefinition,         // Stack definition (provides P, CO, Mutex)
    ES: ExtensionState = (),    // Extension state (IP config, augment state)
    const MAX_CONN: usize = 1,  // Max concurrent transport connections
> {
    // Runtime (volatile)
    individual_address: Cell<IndividualAddress>,
    programming_mode: Cell<bool>,

    // Factory-programmed identity (serial number; FDSK for Data Secure).
    // Serial number is read through `DeviceIdentity::serial_number()`.
    identity: D::Identity,

    // ETS-loaded tables (persisted)
    adt: RefCell<Table<AddrTab7Impl<ADT_SIZE>>>,
    ast: RefCell<Table<AssoTab6Impl<AST_SIZE>>>,
    cot: RefCell<Table<CoTab7Impl<COT_SIZE>>>,
    app: RefCell<Application<D::P>>,

    // Communication objects (runtime-only, not persisted)
    comm_objs: RefCell<D::CO>,

    // Extension state (persisted)
    extension_state: ES,

    // Dirty tracking
    dirty: Cell<bool>,
    // ...
}
```

The `D: StackDefinition` parameter provides `D::P` (parameters) and
`D::CO` (communication objects) as associated types, eliminating the
need for separate `P` and `CO` generic parameters.

The const generics for table sizes are derived from the `DeviceDescriptor`:

```rust
const DEVICE_DESCRIPTOR: DeviceDescriptor = DeviceDescriptor {
    mask_version: MaskVersion::SystemBKnxIp,
    manufacturer_id: 0x00FA,
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    application_id: 0x0100,
    application_version: 0x01,
    max_address_table_entries: 16,
    max_association_table_entries: 16,
    max_comm_objects: 8,
    pei_type: 0,
};

const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();
```

### Type Aliases

For convenience, type aliases fill in the extension state automatically.

**KNX/IP devices** — use `IpDeviceState` parameterized on a `FeatureSet`
type (the same `F` used for the link layer builder). Tunneling capacity
and device capabilities (PID 68) are derived from `F` at compile time:

```rust
// Routing device (KnxIpDeviceUdp → no tunneling, routing + remote config)
type MyState = IpDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyStack, KnxIpDeviceUdp>;

// Tunneling interface (KnxIpInterfaceUdp<4> → 4 tunneling slots)
type MyState = IpDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyStack, KnxIpInterfaceUdp<4>>;
```

**TP1 devices:**

```rust
type MyState = Tp1SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyStack>;
```

Under the hood, `IpDeviceState` uses `IpExtensionFor<F>` as the extension
state, a type alias for `IpExtensionState<CAPS>` with the capability
bits derived from `F`:

```rust
pub type IpExtensionFor<F: FeatureSet> =
    IpExtensionState<{ F::KNXNETIP_DEVICE_CAPABILITIES }>;  // CAPS (PID 68)

pub type IpDeviceState<..., D: StackDefinition, F: FeatureSet> =
    SystemBDeviceState<..., D, IpExtensionFor<F>>;
```

Tunneling capacity is not part of `IpExtensionState`: devices that
serve tunneling connections compose `IpInterfaceExtension<N, CAPS>`
instead, which pairs `IpExtensionState<CAPS>` with a
`TunnellingExtension<N>` (the additional individual addresses live on
the latter). The low-level aliases `IpExtensionState<CAPS>` and
`IpSystemBDeviceState<..., CAPS>` still exist for cases where you need
explicit control over the const generics.

## Extensions

An extension contributes both **persistent state** and **interface
object augmentation** to the device. The `Extension<Platform>` trait
combines an `ExtensionState` (the persisted/runtime state) with a
recipe for producing the `Augment<D>` impl that exposes that state
on the wire.

### The Extension Trait

```rust
pub trait Extension<Platform = ()>: ExtensionState {
    /// The augment type this extension creates.
    type Augment<'a, D: StackDefinition>: Augment<D>
    where Self: 'a, Platform: 'a;

    /// Create the augment from this extension state and the platform.
    fn create_augment<'a, D: StackDefinition>(
        &'a self, platform: &'a Platform,
    ) -> Self::Augment<'a, D>
    where Platform: 'a;
}
```

Each extension declares what platform type it needs. `Platform` flows
from `StackDefinition::Platform` — the stack ensures compatibility.

### The ExtensionState / ExtensionConfig Traits

`Extension` is a supertrait of `ExtensionState`, which handles persistence:

```rust
/// Serializable form (for persistence)
pub trait ExtensionConfig: Default + Serialize + Deserialize {}

/// Runtime form (with interior mutability)
pub trait ExtensionState: Sized {
    type Config: ExtensionConfig;
    /// Non-serialisable construction inputs (FDSK copy, sequence
    /// storage handle, …). Use `()` if the extension needs none.
    type Resources;
    fn from_config(config: Self::Config, resources: Self::Resources) -> Self;
    fn to_config(&self) -> Self::Config;
    /// Handle a master-reset erase code. Each extension decides per
    /// code what to clear (see [`EraseCode`](crate::restart::EraseCode)).
    /// Called from `SystemBDeviceState::factory_reset()` and
    /// `execute_reset()`.
    fn on_erase(&self, code: EraseCode);
}
```

`ExtensionConfig` is what gets serialized to storage (JSON, flash).
`ExtensionState` is the runtime representation with `Cell`/`RefCell`
fields for interior mutability. `Resources` is the non-serialisable
construction-time bundle — typically `()`, but secure extensions use
it to receive a sequence-number storage handle and the FDSK copy.

### Built-in Extensions

**`()` — no extension.** Only useful for test/mock scenarios.
Implements `Extension<()>` with `Augment = ()`.

**`Tp1ExtensionState`** — TP1 retry count (PID 52).
Implements `Extension<()>`; `create_augment` returns a separate
[`Tp1Augment<'a>`] that borrows `&'a Tp1ExtensionState`. Adds
PID\_MAX\_RETRY\_COUNT to the Device Object.

```rust
pub struct Tp1ExtensionState {
    max_retry_count: Cell<u8>, // 0x33 = 3 busy, 3 NAK retries
}
```

**`IpExtensionState<CAPS>`** — full IP configuration.
Implements `Extension<P>` for any `P: IpPlatform`. Creates an
`IpAugment<'a, P, CAPS>` that combines the persisted config with the
platform reference for IP property dispatch.

```rust
pub struct IpExtensionState<const CAPS: u16 = 0> {
    friendly_name: Cell<[u8; 30]>,        // PID 76
    configured_ip: Cell<Ipv4Addr>,        // PID 60
    configured_subnet: Cell<Ipv4Addr>,    // PID 61
    configured_gateway: Cell<Ipv4Addr>,   // PID 62
    ip_assignment_method: Cell<u8>,       // PID 55
    routing_multicast: Cell<Ipv4Addr>,    // PID 66
    ttl: Cell<u8>,                        // PID 67
    project_installation_id: Cell<u16>,   // PID 51
    // + runtime-only rebind channel for live IGMP re-joins
}
```

- `CAPS` — KNXnet/IP device capabilities bitfield (PID 68), compile-time
  constant derived from the link layer's `FeatureSet`

Tunneling state is separate: devices that serve tunneling connections
compose **`IpInterfaceExtension<N, CAPS>`**, which pairs
`IpExtensionState<CAPS>` with a `TunnellingExtension<N>` holding the
additional individual addresses (`N` = tunneling slot count).

You typically don't specify `CAPS` directly. Use `IpExtensionFor<F>`
(or `IpInterfaceExtensionFor<F>` for tunneling devices), which derives
it from a `FeatureSet` type. `IpAugmentFor<'a, P, F>` does the same
for the augment type (needed when spelling out `InterfaceObjects` for
devices with extra augments):

```rust
// These are equivalent:
type ES = IpExtensionFor<KnxIpDeviceUdp>;
type ES = IpExtensionState<0x0015>;  // CAPS=routing+devmgmt+remoteconfig
```

### One Extension State Per Device

Each device has exactly one extension state type. There is no tuple
composition for extension states — if a device needs multiple concerns
(e.g., IP config + custom persistent data), define a single struct that
contains both and implements `ExtensionState` + `Extension` directly:

```rust
pub struct MyBridgeState {
    ip: IpFields,
    custom: Cell<u32>,
}

impl ExtensionState for MyBridgeState {
    type Config = MyBridgeConfig;
    // ... implement from_config, to_config, on_erase
}

impl<P: IpPlatform> Extension<P> for MyBridgeState {
    type Augment<'a, D: StackDefinition> = MyBridgeAugment<'a, P>
    where Self: 'a, P: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, platform: &'a P) -> Self::Augment<'a, D>
    where P: 'a {
        MyBridgeAugment { state: self, platform }
    }
}
```

## Augments

Augments extend the device's interface objects. They can do two things:

1. **Add properties to existing objects** — e.g., add PID 52 (retry count)
   to the Device Object
2. **Provide entirely new interface objects** — e.g., provide the IP
   Parameter Object (Type 11) at index 6

### The Augment trait

```rust
//! crates/zweidraehte-device/src/service/traits.rs

pub trait Augment<D: StackDefinition> {
    fn additional_object_count(&self) -> u16 { 0 }
    fn additional_object_type_at(&self, _index: u16) -> Option<InterfaceObjectType> { None }
    fn get_property_descriptor(&self, _ot: InterfaceObjectType, _pid: u16) -> Option<PropertyDescriptor> { None }
    fn property_description_read(&self, _ctx: &ServiceCtx<'_, D>, …) -> Option<…> { None }
    fn property_value_read   (&self, _ctx: &ServiceCtx<'_, D>, …) -> Option<…> { None }
    fn property_value_write  (&self, _ctx: &ServiceCtx<'_, D>, …) -> Option<…> { None }
    fn function_property_command   (&self, _ctx: &ServiceCtx<'_, D>, …) -> Option<…> { None }
    fn function_property_state_read(&self, _ctx: &ServiceCtx<'_, D>, …) -> Option<…> { None }
}
```

All hook methods return `Option<…>` — returning `None` delegates to
the next augment in the chain or the base object.

### How Augments Relate to Extensions

For built-in mediums, the `Extension` trait handles augment creation
automatically. You don't construct medium-specific augments manually:

- **TP1**: `Tp1ExtensionState::create_augment` returns a `Tp1Augment<'a>`
  that holds `state: &'a Tp1ExtensionState`. Writes to property storage
  (e.g. PID 52 retry count) reach the same `Cell<u8>` the device state
  owns, via that borrow.
- **IP**: `IpExtensionState` produces an `IpAugment<'a, P, CAPS>`
  wrapper that bundles state + platform.

Both follow the same shape — a small augment struct borrowing the state
(and the platform, for IP).

For ergonomics, devices spell their `D::Augments<'a>` either as a
direct projection or as a `#[derive(ServiceRegistry)]` struct
(see "The Augment chain — `D::Augments<'a>`" below).

### Stateless extra augments

Stateless augments (no persistent state, no resources) just
implement `Augment<D>`:

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct EasterEggAugment;

impl<D: StackDefinition> Augment<D> for EasterEggAugment {
    fn function_property_command(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if object_type != InterfaceObjectType::Device || req.prop_id != 255 {
            return None;
        }
        Some(match req.service_data {
            b"knock knock" => FunctionPropertyResult::success_with_data(
                b"Who's there? ...a lost packet. Wrong subnet.",
            ),
            _ => FunctionPropertyResult::not_supported(),
        })
    }
}
```

For descriptor-table-driven augments (the common case where the
augment exposes a fixed list of PIDs), use the
`#[interface_object_augment]` attribute macro — it auto-generates
the `Augment<D>` impl from a small DSL.

### The Augment chain — `D::Augments<'a>`

Each device's complete augment set lives behind the
`D::Augments<'a>` GAT on `StackDefinition`. The IO container
borrows `&'a D::Augments<'a>` and routes every property hook
through the `Augment<D>` trait. There are three idiomatic
ways to spell `D::Augments<'a>`:

#### 1. Bare projection (no extras)

When the device only has the medium extension's augment:

```rust
type Augments<'a> = <Self::ES as Extension<Self::Platform>>::Augment<'a, Self>;

fn create_augments<'a>(state, platform, _lctx) -> Self::Augments<'a> {
    state.extension_state().create_augment::<Self>(platform)
}
```

#### 2. `#[derive(ServiceRegistry)]` struct

When the device adds extra augments alongside the medium's, give
each one a name and let the macro build the `Augment<D>`
impl:

```rust
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct PicoTp1Augments<'a> {
    #[service(augment)] tp1:    Tp1Augment<'a>,
    #[service(augment)] easter: EasterEggAugment,
}

type Augments<'a> = PicoTp1Augments<'a>;

fn create_augments<'a>(state, platform, _lctx) -> Self::Augments<'a> {
    PicoTp1Augments {
        tp1:    state.extension_state().create_augment::<Self>(platform),
        easter: EasterEggAugment,
    }
}
```

The macro emits `Augment<D>` walking the fields
left-to-right: hooks chain via `or_else()` (first `Some` claims),
IO list counts sum, lifecycle delegates to each augment.

#### 3. `#[service(flatten)]` for nested composition

Useful when one chain wants to inherit another wholesale — for
example, sharing a "conformance extras" bundle across stacks:

```rust
#[derive(ServiceRegistry)]
pub struct ConformanceExtras<'a> {
    #[service(augment)] cert: CertificationObjectAugment,
    #[service(augment)] diag: DiagnosticsAugment<'a>,
}

#[derive(ServiceRegistry)]
pub struct SecureConformanceAugments<'a> {
    #[service(augment)] sec:    SecAugment<'a>,
    #[service(flatten)] extras: ConformanceExtras<'a>,
}
```

The outer `Augment<D>` impl walks `sec` first, then
delegates the rest of the chain into `extras`. `flatten` is
**augment-only** — it cannot be combined with `#[service(handler)]`
on the same struct because the const dispatch table can't route
through a flattened sub-table. The macro emits a clear
compile-time error if you try.

#### Composing legacy tuple shapes

The `()`, `(Head, Tail)`, and `&A` shapes also implement
`Augment<D>` directly (see
`crates/zweidraehte-device/src/service/registry.rs`), so legacy
tuple augment chains and the `<D::ES as Extension<…>>::Augment<'a,
D>` projection types all work without per-device migration to the
derive. Mix and match as suits the device.

## Persistence

### How State is Saved and Restored

The persistence system has three layers:

```
SystemBDeviceState<..., ES>          (runtime, interior mutability)
        |
        | HasDeviceConfig::to_config()        SystemBDeviceState::from_init(StateInit)
        v                                              ^
DeviceConfig<..., ES::Config>        (serializable snapshot, serde)
        |                                              |
        | ConfigStoreBackend::save / load               |
        v                                              |
Storage backend (JSON file, flash, ...)  ─────────────┘
                                          (loaded snapshot reaches state via SystemBStateInit)
```

**`HasDeviceConfig`** is the trait that bridges runtime state to its
serializable form:

```rust
pub trait HasDeviceConfig: Sized {
    type Config: Serialize + for<'de> Deserialize<'de>;
    /// Export current runtime state to a serializable config.
    fn to_config(&self) -> Self::Config;
}
```

`SystemBDeviceState` implements `HasDeviceConfig` with
`type Config = DeviceConfig<..., ES::Config>`. The struct holds
individual address, auth keys, routing count, the four ETS-loaded
tables, the application program, the program version, and the
embedded extension config — i.e. exactly the state that survives a
power cycle.

**Reverse direction.** There is no `from_config` trait method.
Restoration goes through `D::StateInit` (the envelope passed to
`StackDefinition::create_state`), which for System B devices is
`SystemBStateInit<Identity, DeviceConfig, ExtensionResources>`:

```rust
pub struct SystemBStateInit<I, C, R = ()> {
    pub identity: I,
    /// `Some(snapshot)` from a previous boot, or `None` for factory-fresh.
    pub loaded_config: Option<C>,
    /// Non-serialisable construction inputs for the extension state.
    pub resources: R,
}
```

`SystemBDeviceState::from_init(init)` consumes the envelope: if
`loaded_config` is `Some`, it rebuilds the runtime state from it
(calling `ExtensionState::from_config(extension_config, resources)`
on the embedded extension config); if `None`, it constructs
factory-fresh defaults.

### Dirty Tracking

`SystemBDeviceState` tracks whether unsaved changes exist via
inherent methods (these live on the state, **not** on the stores):

```rust
state.is_dirty()    // Check if there are unsaved changes
state.mark_dirty()  // Called automatically by property writes (HasPersistence)
state.clear_dirty() // Called after successful save
```

On embedded targets the generic storage task (spawned via the
`storage_task!` macro) polls `is_dirty()` and saves through
`HasConfigStore::save_config`; a std binary without that task polls
it in its own loop.

### Storage Backends

**`JsonStorage`** (for Linux userspace, in `examples/support`):
```rust
use support::storage::{FileIdentity, JsonStorage};

let identity = FileIdentity::load_or_provision("device_identity.json", SERIAL)?;
let mut storage: JsonStorage<MyState, _> =
    JsonStorage::new("device_state.json", identity);

// Load (returns Option<DeviceConfig>; None on first boot)
let loaded_config = storage.load_config()?;

// Hand the optional snapshot into D::StateInit; the runner builds
// the runtime state via D::create_state(state_init). The stored
// identity's serial number seeds the compile-time Identity type.
let state_init =
    SystemBStateInit::new(StaticIdentity::new(*storage.identity().serial_number()), loaded_config);

// Periodic save loop
if stack.state().is_dirty() {
    storage.save(stack.state())?;
    stack.state().clear_dirty();
}
```

Backends call `state.to_config()` internally inside their save;
`load_config()` returns the deserialised `DeviceConfig` for the
binary to slot into `SystemBStateInit`.

**Embedded backends** (RP2040 / STM32 flash, FRAM) implement the
storage-layer backend traits (`ConfigStoreBackend`,
`SequenceNumberStorage`, …) over the `SectorIo` / `ByteIo` medium
seams. A device declares each durable region once as a
`Placed<Region, Chip, Layout>` alias; the store type and its `open()`
derive from that declaration, and the live stores group in one of the
bounded stores structs (`ConfigStorage` / `SecureStorage` /
`SecureIpStorage`) referenced as `&'static` from
`StackDefinition::Storage`:

```rust
pub struct StorageMap;
type Cfg = Placed<StmConfigRegion<MyState>, StmFlash, StorageMap>;
type Seq = Placed<StmSiatRegion<SIAT_SIZE>, FramChip, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC, Seq::SPEC];
}
// main(): STORAGE.init(SecureStorage::new(Cfg::open(io)?, Seq::open(fram_io)?))
```

The firmware family commons provide the chip pieces: the `Chip`
markers (`StmFlash`, `RpFlash`), the `Io` handles (`StmFlashIo`,
`RpFlashIo`, FRAM), and chip-sized region aliases
(`StmConfigRegion<S>`, `RpConfigRegion<S>`, `StmSiatRegion<SLOTS>`)
over the core `ConfigRegion` / `FlashSiatRegion` / `FramSiatRegion`
markers — see `docs/STACK_ARCHITECTURE.md` §3.14 for the full
vocabulary.

## Defining a New Device

### Step 0: Pick a BCU family

**Use System B.** It carries all three media (TP1, KNX-RF, KNX/IP),
KNX Data Secure and KNX IP Secure, and the deepest conformance
coverage; everything below this line is written for it.

The stack also implements **System 7 on TP1** (mask 0705h) *without*
Data Secure. Choose it only when a device has to match an existing
System 7 installed base or toolchain — the mask a product declares is
the manufacturer's choice, and nothing in ETS rewards the older
family. Building on it costs no extra effort (swap
`system_b_standard_stack!` for `system_7_standard_stack!` plus its
`cot_address:` slot, and `Tp1StateFor` for `Tp1StateFor7`; see
[`firmware/stm32/g0_tp1_system7_light_switch`](../firmware/stm32/g0_tp1_system7_light_switch/)
next to its System B sibling, both running the same
`devices::light_switch` definition), but you give up Data Secure, RF
and KNX/IP. The family differences are catalogued in
[`STACK_ARCHITECTURE.md` §3.11](STACK_ARCHITECTURE.md#311-bcus--system_b-and-system_7).

One difference reaches the device definition either way:
`#[ets(index = N)]` on a communication object is a **0-based logical
index**, and the object number ETS shows is `N + FIRST_ASAP` — 0 on
System 7, 1 on System B, whose CO table cannot express ASAP 0. Write
definitions from 0 and a shared one works on both families.

### Step 1: Device Descriptor

```rust
pub const DEVICE_DESCRIPTOR: DeviceDescriptor = DeviceDescriptor {
    mask_version: MaskVersion::SystemBKnxIp,  // or SystemBTp1
    manufacturer_id: 0x00FA,
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    application_id: 0x0100,
    application_version: 0x01,
    max_address_table_entries: 16,
    max_association_table_entries: 16,
    max_comm_objects: 8,
    pei_type: 0,
};
```

### Step 2: Parameters and Communication Objects

```rust
#[derive(EtsParams, Clone, Default, Serialize, Deserialize)]
pub struct MyParams {
    #[ets(display = "Brightness")]
    pub brightness: u8,
}

#[derive(EtsComObjects)]
pub struct MyComObjects {
    #[ets(index = 0, display = "Switch", function = "Switching", flags = C | W | T | U)]
    pub switch: ComObject<DPT_Switch>,
}
```

### Step 3: State Type

Choose the state type alias based on your medium. For KNX/IP devices,
pass the same `FeatureSet` type used for the link layer builder —
tunneling capacity and device capabilities are derived automatically.
The `IpStateFor<D, Proto>` alias projects the table sizes directly from
`D::DEVICE` so you do not need to state them by hand:

```rust
// KNX/IP routing device
type MyState = IpStateFor<MyDevice, KnxIpDeviceUdp>;

// KNX/IP tunneling interface with 4 slots
type MyState = IpStateFor<MyDevice, KnxIpInterfaceUdp<4>>;

// TP1 device
type MyState = Tp1StateFor<MyDevice>;
```

The lower-level aliases that take explicit `ADT_SIZE`/`AST_SIZE`/`COT_SIZE`
const generics (`Tp1SystemBDeviceState`, `IpDeviceState`, …) still exist for
cases where you need explicit control, but the `*StateFor<D, …>` forms are
preferred for new code.

### Step 4: StackDefinition

A standard System B device's `StackDefinition` impl is half device-specific
bill-of-materials and half always-identical shell (the `StateInit`/`Mem`
types, the one-line `create_state`, the `InterfaceObjects`/`Augments` GATs,
and the two `create_*` method bodies — Rust can't inherit those from the
`SystemBStackDefinition` supertrait). The `system_b_standard_stack!` macro
generates the shell so you write only the BOM.

For KNX/IP devices, `IpExtensionFor<F>` derives both the tunneling
capacity and the PID 68 capabilities bitfield from the same `FeatureSet`
type used for the link layer builder:

**KNX/IP device:**

```rust
#[derive(Debug, Clone, Copy)]
struct MyDevice;

// IP link-layer bill of materials.
impl KnxNetIpDefinition for MyDevice {
    type Transport = LinuxIpTransport;
    type Features = KnxIpDeviceUdp;
}

zweidraehte_device::system_b_standard_stack! {
    stack:              MyDevice,
    device:             &DEVICE_DESCRIPTOR,
    tl_style:           TlStyle::Style3,
    params:             MyParams,
    com_objects:        MyComObjects,
    link_layer_builder: KnxNetIpBuilder<MyDevice>,
    platform:           MyPlatform,
    extension_state:    IpExtensionFor<KnxIpDeviceUdp>,
    state:              MyState,
    al_extensions:      (SystemBAlServices, DomainAddressService),
    layer_builder:      PlainIpDeviceBuilder,
}
```

The macro generates the empty `impl SystemBStackDefinition for MyDevice {}`,
the `type Mem`/`type StateInit` (deriving the config type automatically as
`<MyState as HasDeviceConfig>::Config`), `fn create_state`
(`MyState::from_init(init)`), the `InterfaceObjects`/`Augments` GATs, and the
`create_interface_objects` / `create_augments` bodies. Note how `KnxIpDeviceUdp`
appears in both `link_layer_builder` (via `KnxNetIpDefinition::Features`) and
`extension_state` — the single source of truth for the device's IP feature
set.

Three optional slots cover the common deviations:

- `resources: <type>` — construction-time resources threaded into
  `StateInit` (e.g. `SecureResources<…>` carrying the FDSK);
- `augments: { bundle: …, create: |state, platform, lctx| … }` — a custom
  augment bundle (next subsection);
- `extra { … }` — verbatim items pasted into the `impl StackDefinition`
  block to override remaining defaults (`type Identity`, `type Rng`,
  `type Mutex`, `const MAX_APDU_LENGTH`, …).

**TP1 device:**

The same macro, with `extension_state: Tp1ExtensionState` and the TP1 link
layer builder — the `Extension` trait abstracts the medium, so nothing else
changes.

**With extra augments (e.g., EasterEggAugment):**

When the device chains extra augments alongside the medium extension, spell
`D::Augments<'a>` as a `#[derive(ServiceRegistry)]` struct and hand it to
`system_b_standard_stack!` through its `augments:` slot (`IpAugmentFor<'a,
P, F>` derives the augment's const generics from the `FeatureSet`):

```rust
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct MyDeviceAugments<'a> {
    #[service(augment)] ip:     IpAugmentFor<'a, MyPlatform, KnxIpDeviceUdp>,
    #[service(augment)] easter: EasterEggAugment,
}

zweidraehte_device::system_b_standard_stack! {
    stack: MyDevice,
    // ... bill of materials items ...
    augments: {
        bundle: MyDeviceAugments,
        create: |state, platform, _lctx| MyDeviceAugments {
            ip:     state.extension_state().create_augment::<Self>(platform),
            easter: EasterEggAugment,
        },
    },
}
```

The macro emits `type Augments<'a> = MyDeviceAugments<'a>` and
`create_augments()` from the slot; the `#[derive(ServiceRegistry)]` macro
emits the `Augment<D>` impl for the bundle, which the IO container calls
into for property dispatch and IO list contributions. A fully hand-written
`impl StackDefinition` remains the path only for devices with a
non-standard `InterfaceObjects` wrapper, a custom `Mem`, or a custom
`StateInit` shape (the conformance DUTs do this for their
`ConformanceMemoryMap`). See the "Augments" section above for the full
story including `#[service(flatten)]` for nested composition.

### Step 5: Startup

The runner takes ownership of the stack resources, link-layer
builder, the `D::StateInit` envelope, the platform, and the memory
map — five arguments to `zweidraehte_device::new()`. The runtime
state is **not** built by the binary; the runner constructs it
internally via `D::create_state(state_init)` so it can hand the
freshly built state a reference to the `LayerContext` from birth (no
two-phase init).

```rust
use zweidraehte_device::{
    StackResources, StackDefinition,
    bcus::system_b::SystemBStateInit,
};

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // 1. Load device identity (factory-fixed: serial number, optional FDSK).
    let identity = FileIdentity::load_or_provision("identity.json", SERIAL)?;

    // 2. Open storage and load the persisted DeviceConfig (None on first boot).
    let mut storage = JsonStorage::<MyState, _>::new("state.json", identity);
    let loaded_config = storage.load_config()?;

    // 3. Build the StateInit envelope. The runner consumes it inside
    //    D::create_state. For System B, SystemBStateInit::new() handles
    //    the no-resources case (resources defaulted to ()).
    let state_init = SystemBStateInit::new(
        StaticIdentity::new(*storage.identity().serial_number()),
        loaded_config,
    );

    // 4. Create link layer builder.
    //    Features, transport type, and sizing knobs all flow from MyDevice's
    //    KnxNetIpDefinition impl — no explicit const generics at the call site.
    let link_layer_builder = KnxNetIpBuilder::<MyDevice>::new(
        "eth0", local_addr, control_endpoint, (),
    );

    // 5. Allocate static stack resources.
    const BUF_SZ: usize = zweidraehte_device::config::buffer_size_for_apdu(
        <MyDevice as StackDefinition>::MAX_APDU_LENGTH,
    );
    static RESOURCES: StaticCell<StackResources<MyDevice, BUF_SZ>> = StaticCell::new();

    // 6. Create the stack. Six args, in this order. The last is the
    //    device's storage handle (a `&'static` stores struct such as
    //    `ConfigStorage`); only a stack with no storage at all
    //    passes `()`.
    let (stack, runner) = zweidraehte_device::new(
        RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        MyDevice::memory_map(),
        (),
    );

    // 7. Spawn the stack runner.
    spawner.spawn(run_stack(runner)).unwrap();

    // 8. Application loop — read/write COs via `stack`, persist on dirty.
    loop {
        if stack.state().is_dirty() {
            storage.save(stack.state())?;
            stack.state().clear_dirty();
        }
        // ... user logic ...
    }
}
```

Note what is **not** an argument: there is no `MyComObjects::new()`
parameter and no separate "hook context". The CO container is part
of `D::State` (built inside `create_state`), and any per-device
context the layers need is reached through `D::Augments<'a>` and
`D::AlExtensions`.

## Architecture Diagram

```
                    StackDefinition
                    (compile-time bill of materials)
                           |
          +----------------+----------------+
          |                |                |
    DeviceDescriptor  Parameters    CommObjects
          |
          v
    SystemBDeviceState<..., ES>
     +-- individual_address
     +-- tables (ADT, AST, COT, APP)
     +-- extension_state: ES
     |    +-- IpExtensionFor<F> (KNX/IP — N and CAPS from FeatureSet)
     |    +-- Tp1ExtensionState (TP1 devices)
     |    +-- () (test/mock only)
     |
     +-- Extension<Platform>::create_augment()
     |    +-- IpAugment<'a, P, CAPS> (borrows config + platform)
     |    +-- Tp1Augment<'a> (borrows the Tp1ExtensionState)
     |    +-- () (no augment)
     |
     v
    PersistedState -----> Storage Backend (JSON / Flash)
     |
     v
    SystemBObjects<..., Augment>
     +-- Device Object (index 0)
     +-- Address Table Object (index 1)
     +-- Association Table Object (index 2)
     +-- Group Object Table Object (index 3)
     +-- Application Program Object (index 4)
     +-- PEI Program Object (index 5)
     +-- [augment-provided objects] (index 6+)
     |    +-- IP Parameter Object (from IpAugment)
     |
     v
    Protocol Layers
     +-- Application Layer
     +-- Transport Layer
     +-- Network Layer
     +-- Link Layer (TPUART / KNX/IP / USB)
```

## Writing a Custom Extension with Persistent State

To create an extension that owns persistent state and provides augmentation:

### 1. Define the runtime state and derive its config

`#[derive(ExtensionState)]` treats the runtime `*State` struct as the
source of truth and generates the persisted `*Config` mirror (the
`Cell`/`RefCell` fields unwrapped), its `Default`/`ExtensionConfig` impls,
and the `ExtensionState` impl (`from_config`/`to_config`/`on_erase`):

```rust
#[derive(ExtensionState)]
#[extension_state(config = MyConfig)]
pub struct MyExtension {
    // Generated config field: `pub counter: u32`. `#[erase(default = …)]`
    // is the value a factory reset restores (defaults to `Default`).
    #[erase(default = 0)]
    counter: Cell<u32>,
}
```

This generates `pub struct MyConfig { pub counter: u32 }` (with
`Serialize`/`Deserialize`/`Default`/`ExtensionConfig`) plus the
`ExtensionState` impl. Field/struct attributes cover the cases the plain
`Cell<T>` → `T` unwrap can't:

- `#[config(ty = U, from = |c| …, to = |s| …)]` — wire type differs from the
  runtime type (e.g. an `Ipv4Addr` field persisted as `[u8; 4]`).
- `#[config(serde_default = "path")]` — emit `#[serde(default = "path")]` on
  the config field.
- `#[runtime_only]` — a field that is never persisted (rebuilt in
  `from_config`; `#[runtime_only(init = expr)]` for a non-`Default` init).
- struct-level `resources = <type>` — sets `ExtensionState::Resources`
  (defaults to `()`); the value arrives as `from_config`'s second argument.
- struct-level `on_erase = manual` / `default = manual` — hand-write those
  two pieces when a field reset needs a side-effect, or the factory defaults
  aren't per-field. The derive also emits an inherent
  `apply_config(&self, Config)` (in-place reset through interior
  mutability) that `on_erase = manual` impls typically call. (The composing
  `SecureExtensionState` and the tuple-config retransmitter hand-write the
  whole impl — the derive is for flat leaf extensions.)

### 2. Define the augment

The augment is a *separate* struct that borrows the state. For a fixed list
of PIDs, `#[interface_object_augment]` generates the `Augment<D>` impl from
the `#[io(…)]` field DSL — the read/write closures reach the state through
`this.state`:

```rust
#[interface_object_augment(target_objects = [InterfaceObjectType::Device])]
pub struct MyAugment<'a> {
    pub state: &'a MyExtension,

    #[io(pid = MY_PID, pdt = PDT_UnsignedLong, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3, intercepts,
         read  = |this: &Self| this.state.counter.get().to_be_bytes(),
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             this.state.counter.set(u32::from_be_bytes(data[..4].try_into().unwrap()));
             Ok(WriteResponse::Echo)
         })]
    _counter_io: (),
}
```

Use `target_objects` + `intercepts` to add PIDs to an existing object (as
above, on the Device Object), or `additional_objects = [X]` to provide a new
object — the latter needs a PID 1 `OBJECT_TYPE` entry. (Augments needing
hand-written dispatch can `impl Augment<D>` directly instead.)

### 3. Implement Extension

Since this extension needs no platform, use `Extension<()>`; `create_augment`
returns the augment borrowing the state:

```rust
impl Extension<()> for MyExtension {
    type Augment<'a, D: StackDefinition> = MyAugment<'a> where Self: 'a;

    fn create_augment<'a, D: StackDefinition>(
        &'a self, _platform: &'a (),
    ) -> Self::Augment<'a, D> where (): 'a {
        MyAugment { state: self }
    }
}
```

### 4. Wire it into the device

```rust
type MyState = SystemBDeviceState<ADT, AST, COT, MyDevice, MyExtension>;

zweidraehte_device::system_b_standard_stack! {
    stack: MyDevice, device: &DEVICE_DESCRIPTOR, tl_style: TlStyle::Style3,
    params: Params, com_objects: MyComObjects,
    link_layer_builder: …, platform: (),
    extension_state: MyExtension, state: MyState,
    al_extensions: (SystemBAlServices, DomainAddressService),
    layer_builder: PlainDeviceBuilder,
}
```

The counter is automatically persisted and restored across power
cycles because the derived `ExtensionState::to_config()` / `from_config()`
captures it.

To compose this extension's augment with one or more extra augments
(e.g. `EasterEggAugment`), wrap them in a `#[derive(ServiceRegistry)]`
struct and hand it to the macro's `augments: { bundle, create }` slot,
as shown in the "Augments" section earlier.
