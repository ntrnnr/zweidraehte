# Device Definition Guide

This document explains how to define, configure, and run a KNX device
using the zweidraehte stack. It covers the state model, extension state,
augments, persistence, and the full startup sequence.

## Overview

A device definition brings together:

1. **Device descriptor** — hardware identity, table capacities, mask version
2. **Application parameters** — ETS-configurable values (`#[derive(EtsParams)]`)
3. **Communication objects** — group object definitions (`#[derive(EtsComObjects)]`)
4. **Extension state** — link-layer config and/or augment state (IP config, retry count, etc.)
5. **Augments** — extend interface objects with extra properties or provide entirely new ones
6. **Link layer** — physical transport (TPUART, KNX/IP, USB)

All of these are composed at compile time through the `StackDefinition`
trait, which acts as the "bill of materials" for the device.

## State Model

### SystemBDeviceState

All runtime device state lives in a single struct:

```rust
pub struct SystemBDeviceState<
    const ADT_SIZE: usize,   // Address table byte size
    const AST_SIZE: usize,   // Association table byte size
    const COT_SIZE: usize,   // Comm object table byte size
    P: ConstDefault,          // Application parameters type
    ES: ExtensionState = (), // Extension state (IP config, augment state)
    const MAX_CONN: usize = 1, // Max concurrent transport connections
> {
    // Runtime (volatile)
    individual_address: Cell<IndividualAddress>,
    serial_number: [u8; 6],
    programming_mode: Cell<bool>,

    // ETS-loaded tables (persisted)
    adt: RefCell<Table<AddrTab7Impl<ADT_SIZE>>>,
    ast: RefCell<Table<AssoTab6Impl<AST_SIZE>>>,
    cot: RefCell<Table<CoTab7Impl<COT_SIZE>>>,
    app: RefCell<Application<P>>,

    // Extension state (persisted)
    extension_state: ES,

    // Dirty tracking
    dirty: Cell<bool>,
    // ...
}
```

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

For convenience, there are type aliases that fill in common patterns:

```rust
// KNX/IP device (extension state = IpExtensionState)
type MyState = IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyParams, MyPlatform>;

// TP1 device with retry count (extension state = Tp1ExtensionState)
type MyState = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyParams, Tp1ExtensionState>;

// Plain TP1 device (no extension state)
type MyState = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyParams>;
```

`IpSystemBDeviceState` is just a type alias:
```rust
pub type IpSystemBDeviceState<..., P, Plat, const N: usize = 0> =
    SystemBDeviceState<..., P, IpExtensionState<Plat, N>>;
```

## Extension State

Extension state holds persistent data that doesn't fit in the core device
state — link-layer configuration, augment-specific properties, or any
device-specific values that need to survive power cycles.

### The ExtensionState / ExtensionConfig Traits

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

The key idea: `ExtensionConfig` is what gets serialized to storage (JSON,
flash). `ExtensionState` is the runtime representation with `Cell`/`RefCell`
fields for interior mutability.

### Built-in Extension States

**`()` — no extension state.** Used by plain TP1 devices.

**`Tp1ExtensionState`** — TP1 retry count (PID 52):
```rust
pub struct Tp1ExtensionState {
    max_retry_count: Cell<u8>, // 0x33 = 3 busy, 3 NAK retries
}
```

**`IpExtensionState<P, N>`** — full IP configuration:
```rust
pub struct IpExtensionState<P: IpPlatform + IpPlatformConfig, const N: usize = 0> {
    platform: P,                          // Network queries
    friendly_name: Cell<[u8; 30]>,        // PID 76
    configured_ip: Cell<Ipv4Addr>,        // PID 60
    configured_subnet: Cell<Ipv4Addr>,    // PID 61
    configured_gateway: Cell<Ipv4Addr>,   // PID 62
    ip_assignment_method: Cell<u8>,       // PID 55
    routing_multicast: Cell<Ipv4Addr>,    // PID 66
    ttl: Cell<u8>,                        // PID 67
    project_installation_id: Cell<u16>,   // PID 51
    additional_individual_addresses: RefCell<heapless::Vec<IndividualAddress, N>>, // PID 53
}
```

The const generic `N` is the maximum tunneling slot count. Non-tunneling
devices use the default `N = 0`, paying zero storage.

### One Extension State Per Device

Each device has exactly one extension state type. There is no tuple
composition for extension states — if a device needs multiple concerns
(e.g., IP config + custom persistent data), define a single struct that
contains both and implements `ExtensionState` directly:

```rust
pub struct MyBridgeState {
    ip: IpFields,
    custom: Cell<u32>,
}

impl ExtensionState for MyBridgeState {
    type Config = MyBridgeConfig;
    // ... implement from_config, to_config, factory_reset
}
```

This avoids the complexity of tuple delegation and keeps trait bounds
straightforward — the extension state type is always a single concrete
struct, never a nested tuple.

## Augments

Augments extend the device's interface objects. They can do two things:

1. **Add properties to existing objects** — e.g., add PID 52 (retry count)
   to the Device Object
2. **Provide entirely new interface objects** — e.g., provide the IP
   Parameter Object (Type 11) at index 6

### The InterfaceObjectAugment Trait

```rust
pub trait InterfaceObjectAugment<S: StackState> {
    /// Intercept property description requests.
    /// Return `Some(result)` to handle, `None` to delegate.
    fn property_description_read(&self, state: &S, object_type: InterfaceObjectType,
        object_idx: u16, lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> { None }

    /// Intercept property read requests.
    fn property_value_read(&self, state: &S, object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest, buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> { None }

    /// Intercept property write requests.
    fn property_value_write(&self, state: &S, object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> { None }

    /// Intercept function property commands.
    fn function_property_command(&self, state: &S, object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> { None }

    /// Intercept function property state reads.
    fn function_property_state_read(&self, state: &S, object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> { None }

    /// Number of additional interface objects this augment provides.
    fn additional_object_count(&self) -> u16 { 0 }

    /// Object type for an augment-provided interface object (0-based index).
    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType> { None }
}
```

All methods return `Option` — returning `None` delegates to the next
augment in the chain or the base object.

### Three Kinds of Augments

#### 1. Stateless augments (owned values)

These are simple unit structs that add behavior without needing persistent
state. They're passed directly as values.

```rust
#[derive(Debug, Clone, Copy)]
pub struct EasterEggAugment;

impl<S: StackState> InterfaceObjectAugment<S> for EasterEggAugment {
    fn function_property_command(
        &self, _state: &S, object_type: InterfaceObjectType,
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

Usage:
```rust
create_system_b_objects::<Self, _, _>(state, &layout, EasterEggAugment)
```

#### 2. Extension-state augments (borrowed from state)

These combine persistent state with augment behavior. The extension state
struct implements both `ExtensionState` (for persistence) and
`InterfaceObjectAugment` (for property handling). It's borrowed from
`state.extension_state()` and passed as a reference.

**Example: `Tp1ExtensionState`** — adds PID 52 to the Device Object:

```rust
// Persistent state
pub struct Tp1ExtensionState {
    max_retry_count: Cell<u8>,
}

impl ExtensionState for Tp1ExtensionState {
    type Config = Tp1ExtensionConfig;
    fn from_config(config: Tp1ExtensionConfig) -> Self {
        Self { max_retry_count: Cell::new(config.max_retry_count) }
    }
    fn to_config(&self) -> Tp1ExtensionConfig {
        Tp1ExtensionConfig { max_retry_count: self.max_retry_count.get() }
    }
    fn factory_reset(&self) { self.max_retry_count.set(0x33); }
}

// Augment behavior — adds PID 52 to the Device Object
impl<S: StackState> InterfaceObjectAugment<S> for Tp1ExtensionState {
    fn property_value_read(&self, _state: &S, object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest, buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        if object_type != InterfaceObjectType::Device || req.pid != pid::MAX_RETRY_COUNT {
            return None;
        }
        // Read directly from &self — no trait indirection needed.
        buf[0] = self.max_retry_count.get();
        Some(Ok(1))
    }
    // ... write, description
}
```

Usage:
```rust
// State type includes the extension state
type MyState = SystemBDeviceState<ADT, AST, COT, Params, Tp1ExtensionState>;

// Borrow extension state as the augment
fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a> {
    create_system_b_objects::<Self, _, _>(state, &layout, state.extension_state())
}
```

#### 3. Object-providing augments (new interface objects)

These declare additional interface objects beyond the base 6. The
container routes property requests at indices >= 6 to the augment.

**Example: `IpExtensionState`** — provides the IP Parameter Object (Type 11):

```rust
impl<S: StackState, P: IpPlatform + IpPlatformConfig, const N: usize>
    InterfaceObjectAugment<S> for IpExtensionState<P, N>
{
    fn additional_object_count(&self) -> u16 { 1 }

    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType> {
        match index {
            0 => Some(InterfaceObjectType::IPParameter),
            _ => None,
        }
    }

    fn property_value_read(&self, state: &S, object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest, buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        if object_type != InterfaceObjectType::IPParameter { return None; }
        // Handle all IP PIDs directly via &self field access
        self.read_ip_property(state, req, buf)
    }
    // ... description, write, tunneling PIDs
}
```

Usage:
```rust
type MyState = IpSystemBDeviceState<ADT, AST, COT, Params, MyPlatform>;

fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a> {
    create_system_b_objects::<Self, _, _>(state, &layout, state.extension_state())
}
```

### Composing Multiple Augments

Augments compose via tuples. The `(Head, Tail)` impl chains both:

- Property methods: try head first, then tail (via `or_else`)
- Additional objects: head's objects come first, then tail's
- The blanket `InterfaceObjectAugment for &A` impl enables references

```rust
// KNX/IP device with custom augment:
//   - IpExtensionState provides the IP Parameter Object (index 6)
//   - EasterEggAugment adds a function property to the Device Object (index 0)
type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<
    'a, MyState, (&'a IpExtensionState<MyPlatform>, EasterEggAugment),
>;

fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a> {
    create_system_b_objects::<Self, _, _>(
        state,
        &Self::memory_layout(),
        (state.extension_state(), EasterEggAugment),
    )
}
```

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

Choose the extension state based on your device type:

```rust
// KNX/IP device
type MyState = IpSystemBDeviceState<
    { DEVICE_DESCRIPTOR.address_table_size() },
    { DEVICE_DESCRIPTOR.association_table_size() },
    { DEVICE_DESCRIPTOR.comm_object_table_size() },
    MyParams,
    MyPlatform,
>;

// TP1 device with retry count
type MyState = SystemBDeviceState<
    { DEVICE_DESCRIPTOR.address_table_size() },
    { DEVICE_DESCRIPTOR.association_table_size() },
    { DEVICE_DESCRIPTOR.comm_object_table_size() },
    MyParams,
    Tp1ExtensionState,
>;
```

### Step 4: StackDefinition

```rust
#[derive(Debug, Clone, Copy)]
struct MyDevice;

impl StackDefinition for MyDevice {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = MyParams;
    type CO = MyComObjects;
    type LLB = KnxNetIpBuilder<LinuxIpTransport, KnxIpDeviceUdp, 2>;
    type State = MyState;
    type Mem = SystemBMemoryMap;

    // Augment = extension state (borrowed) providing IP Parameter Object
    type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<
        'a, MyState, &'a IpExtensionState<MyPlatform>,
    >;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where Self::State: 'a {
        create_system_b_objects::<Self, _, _>(
            state, &Self::memory_layout(), state.extension_state(),
        )
    }

    type LayerBuilder = InsecureIpDeviceBuilder;
}
```

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
     |    +-- IpExtensionState (KNX/IP devices)
     |    +-- Tp1ExtensionState (TP1 devices)
     |    +-- () (test/mock only)
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
     |    +-- IP Parameter Object (from IpExtensionState)
     |
     v
    Protocol Layers
     +-- Application Layer
     +-- Transport Layer
     +-- Network Layer
     +-- Link Layer (TPUART / KNX/IP / USB)
```

## Writing a Custom Augment with Persistent State

To create an augment that owns persistent state:

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

pub struct MyAugmentState {
    counter: Cell<u32>,
}

impl ExtensionState for MyAugmentState {
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

### 2. Implement InterfaceObjectAugment

```rust
impl<S: StackState> InterfaceObjectAugment<S> for MyAugmentState {
    fn property_value_read(&self, _state: &S, object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest, buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        if object_type != InterfaceObjectType::Device || req.pid != MY_PID {
            return None;
        }
        let val = self.counter.get().to_be_bytes();
        buf[..4].copy_from_slice(&val);
        Some(Ok(4))
    }

    fn property_value_write(&self, _state: &S, object_type: InterfaceObjectType,
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

### 3. Wire it into the device

Use `MyAugmentState` as the extension state, and borrow it as the augment:

```rust
type MyState = SystemBDeviceState<ADT, AST, COT, Params, MyAugmentState>;

type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<
    'a, MyState, &'a MyAugmentState,
>;

fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a> {
    create_system_b_objects::<Self, _, _>(
        state, &Self::memory_layout(), state.extension_state(),
    )
}
```

If you also need IP support, create a combined extension state struct:

```rust
pub struct MyIpAugmentState<P: IpPlatform + IpPlatformConfig> {
    ip: IpExtensionState<P>,
    counter: Cell<u32>,
}

// Implement ExtensionState, InterfaceObjectAugment, and IpStackState
// on the combined struct, delegating IP methods to self.ip.
```

The counter is automatically persisted and restored across power cycles
because `ExtensionState::to_config()`/`from_config()` captures it.
