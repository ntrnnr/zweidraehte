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
    serial_number: [u8; 6],
    programming_mode: Cell<bool>,

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

Under the hood, `IpDeviceState` uses `IpExtension<F>` as the extension
state, which is a type alias for `IpExtensionState<N, CAPS>` with both
const generics derived from `F`:

```rust
pub type IpExtension<F: FeatureSet> = IpExtensionState<
    { <F::Tunneling as TunnelingFeature>::CAPACITY },  // N
    { F::KNXNETIP_DEVICE_CAPABILITIES },               // CAPS (PID 68)
>;

pub type IpDeviceState<..., D: StackDefinition, F: FeatureSet> =
    SystemBDeviceState<..., D, IpExtension<F>>;
```

The low-level aliases `IpExtensionState<N, CAPS>` and
`IpSystemBDeviceState<..., N, CAPS>` still exist for cases where you
need explicit control over the const generics.

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
    fn from_config(config: Self::Config) -> Self;
    fn to_config(&self) -> Self::Config;
    fn factory_reset(&self);
}
```

`ExtensionConfig` is what gets serialized to storage (JSON, flash).
`ExtensionState` is the runtime representation with `Cell`/`RefCell`
fields for interior mutability.

### Built-in Extensions

**`()` — no extension.** Only useful for test/mock scenarios.
Implements `Extension<()>` with `Augment = ()`.

**`Tp1ExtensionState`** — TP1 retry count (PID 52).
Implements `Extension<()>` — self-contained, IS its own augment
(`Augment = &'a Tp1ExtensionState`). Adds PID\_MAX\_RETRY\_COUNT to the
Device Object.

```rust
pub struct Tp1ExtensionState {
    max_retry_count: Cell<u8>, // 0x33 = 3 busy, 3 NAK retries
}
```

**`IpExtensionState<N, CAPS>`** — full IP configuration.
Implements `Extension<P>` for any `P: IpPlatform`. Creates an
`IpAugment<'a, P, N, CAPS>` that combines the persisted config with the
platform reference for IP property dispatch.

```rust
pub struct IpExtensionState<const N: usize = 0, const CAPS: u16 = 0> {
    friendly_name: Cell<[u8; 30]>,        // PID 70
    configured_ip: Cell<Ipv4Addr>,        // PID 62
    configured_subnet: Cell<Ipv4Addr>,    // PID 63
    configured_gateway: Cell<Ipv4Addr>,   // PID 64
    ip_assignment_method: Cell<u8>,       // PID 57
    routing_multicast: Cell<Ipv4Addr>,    // PID 67
    ttl: Cell<u8>,                        // PID 68
    project_installation_id: Cell<u16>,   // PID 54
    additional_individual_addresses: RefCell<heapless::Vec<IndividualAddress, N>>,
}
```

- `N` — maximum tunneling slot count (0 for non-tunneling devices)
- `CAPS` — KNXnet/IP device capabilities bitfield (PID 68), compile-time
  constant derived from the link layer's `FeatureSet`

You typically don't specify `N` or `CAPS` directly. Use
`IpExtension<F>` which derives both from a `FeatureSet` type.
`IpAugmentFor<'a, P, F>` does the same for the augment type (needed
when spelling out `InterfaceObjects` for devices with extra augments):

```rust
// These are equivalent:
type ES = IpExtension<KnxIpDeviceUdp>;
type ES = IpExtensionState<0, 0x0015>;  // N=0, CAPS=routing+devmgmt+remoteconfig
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
    // ... implement from_config, to_config, factory_reset
}

impl<P: IpPlatform> Extension<P> for MyBridgeState {
    type Augment<'a, S: StackState> = MyBridgeAugment<'a, P>
    where Self: 'a, P: 'a;

    fn create_augment<'a, S: StackState>(&'a self, platform: &'a P) -> Self::Augment<'a, S>
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
    fn next_deadline(&self) -> Option<Instant> { None }
    fn poll(&mut self, _ctx: &ServiceCtx<'_, D>) {}
}
```

All hook methods return `Option<…>` — returning `None` delegates to
the next augment in the chain or the base object. `next_deadline` /
`poll` are opt-in lifecycle hooks for augments with temporal
behaviour (Diagnostics auto-revert, Security rekey timers).

### How Augments Relate to Extensions

For built-in mediums, the `Extension` trait handles augment creation
automatically. You don't construct medium-specific augments manually:

- **TP1**: `Tp1ExtensionState` IS its own augment, accessed by
  reference. `create_augment` returns `&self`. The augment chain
  ends up holding `&'a Tp1ExtensionState` so writes to property
  storage (e.g. PID 52 retry count) reach the same `Cell<u8>` the
  device state owns.
- **IP**: `IpExtensionState` produces an `IpAugment<'a, P, N, CAPS>`
  wrapper that bundles state + platform.

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
    #[service(augment)] tp1:    &'a Tp1ExtensionState,
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
SystemBDeviceState (runtime, interior mutability)
        |
        | to_persisted() / from_persisted()
        v
PersistedState (serializable snapshot, serde)
        |
        | serialize / deserialize
        v
Storage backend (JSON file, flash, etc.)
```

**`HasPersistedState`** converts between runtime and serializable form:
```rust
pub trait HasPersistedState: Sized {
    type Persisted: Serialize + Deserialize;
    fn to_persisted(&self) -> Self::Persisted;
    fn from_persisted(identity: &impl DeviceIdentity, persisted: Self::Persisted) -> Self;
}
```

**`PersistedState`** is the serializable snapshot:
```rust
pub struct PersistedState<..., E: ExtensionConfig = ()> {
    pub version: u8,
    pub individual_address: IndividualAddress,
    pub auth_keys: [[u8; 4]; 3],
    pub routing_count: u8,
    pub address_table: Table<...>,
    pub association_table: Table<...>,
    pub group_object_table: Table<...>,
    pub application: Application<P>,
    pub program_version: [u8; 5],
    pub extension_config: E,  // Extension state serialized here
}
```

Extension state is serialized as part of the `PersistedState` via
`extension_state.to_config()`.

### Dirty Tracking

`SystemBDeviceState` tracks whether unsaved changes exist:

```rust
state.is_dirty()    // Check if there are unsaved changes
state.mark_dirty()  // Called automatically by property writes
state.clear_dirty() // Called after successful save
```

The binary is responsible for checking `is_dirty()` and calling the
storage backend to save when needed.

### Storage Backends

**`JsonStorage`** (for Linux userspace, in `examples/testutil`):
```rust
let identity = FileIdentity::load_or_provision("device_identity.json", serial)?;
let mut storage = JsonStorage::<MyState, _>::new("device_state.json", identity);

// Load
let state = match storage.load()? {
    Some(state) => state,
    None => MyState::new(storage.identity()), // Factory defaults
};

// Save (periodic or on dirty)
if state.is_dirty() {
    storage.save(&state)?;
    state.clear_dirty();
}
```

**`RpFlashStorage`** (for embedded RP2040, in `cross/rp-common`):
Same trait interface, writes to flash sectors instead of files.

## Defining a New Device

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
    #[display("Brightness")]
    pub brightness: u8,
}

#[derive(EtsComObjects)]
pub struct MyComObjects {
    #[index(0)]
    #[display("Switch")]
    #[function("Switching")]
    #[flags(C, W, T, U)]
    pub switch: GroupObject<DPT_Switch>,
}
```

### Step 3: State Type

Choose the state type alias based on your medium. For KNX/IP devices,
pass the same `FeatureSet` type used for the link layer builder —
tunneling capacity and device capabilities are derived automatically:

```rust
const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();

// KNX/IP routing device
type MyState = IpDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyParams, KnxIpDeviceUdp>;

// KNX/IP tunneling interface with 4 slots
type MyState = IpDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyParams, KnxIpInterfaceUdp<4>>;

// TP1 device
type MyState = Tp1SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyParams>;
```

### Step 4: StackDefinition

The `Extension` trait and helper functions eliminate most of the
boilerplate. For System B devices, `type ES` determines the augment type
automatically, and `SystemBInterfaceObjectsFor` derives the
`InterfaceObjects` type from it.

For KNX/IP devices, `IpExtension<F>` derives both the tunneling
capacity and the PID 68 capabilities bitfield from the same `FeatureSet`
type used for the link layer builder:

**KNX/IP device:**

```rust
#[derive(Debug, Clone, Copy)]
struct MyDevice;

impl SystemBStackDefinition for MyDevice {}

impl StackDefinition for MyDevice {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = MyParams;
    type CO = MyComObjects;
    type LLB = KnxNetIpBuilder<LinuxIpTransport, KnxIpDeviceUdp, 2>;
    type Platform = MyPlatform;
    type ES = IpExtension<KnxIpDeviceUdp>;
    type State = MyState;
    type Mem = SystemBMemoryMap;

    type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;

    // No extras: D::Augments is just the medium extension's augment.
    type Augments<'a> = <Self::ES as Extension<Self::Platform>>::Augment<'a, Self>;

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        create_system_b_objects::<Self, _>(state, layer_ctx, &Self::memory_layout(), augments)
    }

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        _layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        state.extension_state().create_augment::<Self>(platform)
    }

    type AlExtensions = (SystemBAlServices, DomainAddressService);
    type LayerBuilder = InsecureIpDeviceBuilder;
}
```

Note how `KnxIpDeviceUdp` appears in both `type LLB` and `type ES` —
this is the single source of truth for the device's IP feature set.

**TP1 device:**

The same shape, with `type ES = Tp1ExtensionState`. `create_augments`
and `create_interface_objects` are byte-for-byte identical to the
KNX/IP example — the `Extension` trait abstracts the medium.

**With extra augments (e.g., EasterEggAugment):**

When the device chains extra augments alongside the medium extension,
spell `D::Augments<'a>` as a `#[derive(ServiceRegistry)]` struct so
each augment has a name:

```rust
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct MyDeviceAugments<'a> {
    #[service(augment)] ip:     IpAugmentFor<'a, MyPlatform, KnxIpDeviceUdp>,
    #[service(augment)] easter: EasterEggAugment,
}

impl StackDefinition for MyDevice {
    // …
    type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>;
    type Augments<'a> = MyDeviceAugments<'a>;

    fn create_interface_objects<'a>(
        state, _platform, layer_ctx, augments,
    ) -> Self::InterfaceObjects<'a> where … {
        create_system_b_objects::<Self, _>(state, layer_ctx, &Self::memory_layout(), augments)
    }

    fn create_augments<'a>(state, platform, _lctx) -> Self::Augments<'a> where … {
        MyDeviceAugments {
            ip:     state.extension_state().create_augment::<Self>(platform),
            easter: EasterEggAugment,
        }
    }
}
```

The macro emits the `Augment<D>` impl for the struct, which
the IO container calls into for property dispatch and IO list
contributions. See the "Augments" section above for the full story
including `#[service(flatten)]` for nested composition.

### Step 5: Startup

```rust
#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // 1. Load device identity
    let identity = FileIdentity::load_or_provision("identity.json", SERIAL)?;

    // 2. Load or create device state
    let mut storage = JsonStorage::<MyState, _>::new("state.json", identity);
    let state = match storage.load()? {
        Some(state) => state,
        None => MyState::new(storage.identity()),
    };

    // 3. Create link layer builder
    let link_layer_builder = KnxNetIpBuilder::new(
        "eth0", local_addr, control_endpoint, (),
    );

    // 4. Allocate resources and create the stack
    static RESOURCES: StaticCell<StackResources<MyDevice, { buffer_size }>> = StaticCell::new();

    let (stack, runner) = zweidraehte_device::new(
        RESOURCES.init(StackResources::new()),
        MyComObjects::new(),
        (),                          // hook context
        link_layer_builder,
        state,
        platform,
        MyDevice::memory_map(),
    );

    // 5. Run the stack
    spawner.spawn(run_stack(runner)).unwrap();

    // 6. Application loop
    loop {
        // Read/write communication objects via `stack`
        // Periodically save state if dirty
        if stack.state().is_dirty() {
            storage.save(stack.state()).unwrap();
            stack.state().clear_dirty();
        }
    }
}
```

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
     |    +-- IpExtension<F> (KNX/IP — N and CAPS from FeatureSet)
     |    +-- Tp1ExtensionState (TP1 devices)
     |    +-- () (test/mock only)
     |
     +-- Extension<Platform>::create_augment()
     |    +-- IpAugment (combines config + platform + capabilities)
     |    +-- &Tp1ExtensionState (is its own augment)
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

### 1. Define the config (serializable) and state (runtime)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyConfig {
    pub counter: u32,
}

impl Default for MyConfig {
    fn default() -> Self { Self { counter: 0 } }
}

impl ExtensionConfig for MyConfig {}

pub struct MyExtension {
    counter: Cell<u32>,
}

impl ExtensionState for MyExtension {
    type Config = MyConfig;
    fn from_config(config: MyConfig) -> Self {
        Self { counter: Cell::new(config.counter) }
    }
    fn to_config(&self) -> MyConfig {
        MyConfig { counter: self.counter.get() }
    }
    fn factory_reset(&self) { self.counter.set(0); }
}
```

### 2. Implement Augment

`Augment<D>` is generic over the *device*, not the state. The
extension reaches into its own fields directly via `&self`:

```rust
impl<D: StackDefinition> Augment<D> for MyExtension {
    fn property_value_read(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        if object_type != InterfaceObjectType::Device || req.pid != MY_PID {
            return None;
        }
        let val = self.counter.get().to_be_bytes();
        buf[..4].copy_from_slice(&val);
        Some(Ok(4))
    }

    fn property_value_write(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        if object_type != InterfaceObjectType::Device || req.pid != MY_PID {
            return None;
        }
        let val = u32::from_be_bytes(req.data[..4].try_into().unwrap());
        self.counter.set(val);
        Some(Ok(WriteResponse::Echo))
    }
}
```

For augments that just expose a fixed list of PIDs, the
`#[interface_object_augment]` attribute macro saves the boilerplate.
It generates the `Augment<D>` impl from a small DSL.

### 3. Implement Extension

Since this extension needs no platform, use `Extension<()>`. The
extension state IS its own augment, accessed by reference:

```rust
impl Extension<()> for MyExtension {
    type Augment<'a, D: StackDefinition> = &'a MyExtension where Self: 'a;

    fn create_augment<'a, D: StackDefinition>(
        &'a self, _platform: &'a (),
    ) -> Self::Augment<'a, D> where (): 'a {
        self
    }
}
```

### 4. Wire it into the device

```rust
type MyState = SystemBDeviceState<ADT, AST, COT, Params, MyExtension>;

impl StackDefinition for MyDevice {
    type ES = MyExtension;
    type State = MyState;

    type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
    type Augments<'a> = <Self::ES as Extension<Self::Platform>>::Augment<'a, Self>;

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        create_system_b_objects::<Self, _>(state, layer_ctx, &Self::memory_layout(), augments)
    }

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        _layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        state.extension_state().create_augment::<Self>(platform)
    }
    // ...
}
```

The counter is automatically persisted and restored across power
cycles because `ExtensionState::to_config()` / `from_config()`
captures it.

To compose this extension's augment with one or more extra augments
(e.g. `EasterEggAugment`), wrap them in a
`#[derive(ServiceRegistry)]` struct as shown in the "Augments"
section earlier.
