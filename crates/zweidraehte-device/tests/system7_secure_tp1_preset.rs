//! The secure System 7 preset exposes its state without making persistent
//! storage project through the stack definition it is helping define.

use zweidraehte_device::bcus::system_7::{SecureTp1, SecureTp1State, System7StateInit};
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::NoComObjects;
use zweidraehte_device::security::SecureResources;
use zweidraehte_device::storage::kv::KeyValueStore;
use zweidraehte_device::storage::views::SiatStore;
use zweidraehte_device::storage::{ConfigStoreBackend, HasDeviceConfig, SecureStorage, StaticSecureIdentity};
use zweidraehte_device::{DeviceDefinition, LayerStackBuilder, NoParams, Rng, SecureRng, StackDefinition};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

const DEVICE: DeviceDescriptor =
    DeviceDescriptor::new(MaskVersion::System7Tp1, 0x00FA, [0; 6], 0xF003, 0x01, 4, 4, 4, 0);

struct TestDefinition;

type TestState = SecureTp1State<TestDefinition, 0x4200>;
type TestStack = SecureTp1<TestDefinition, 0x4200>;

// The config backend names `TestState`, while `TestDefinition::Storage` below
// names the backend. This is the cycle that a `StackDefinition::State`
// projection cannot resolve.
struct NoConfigStore;

impl ConfigStoreBackend for NoConfigStore {
    type State = TestState;
    type Config = <TestState as HasDeviceConfig>::Config;

    fn save(&mut self, _state: &Self::State) {}

    fn load(&mut self) -> Option<Self::Config> {
        None
    }
}

struct NoKv;

impl KeyValueStore for NoKv {
    type Error = core::convert::Infallible;

    fn get(&self, _namespace: u8, _key: &[u8], _buffer: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }

    fn put(&mut self, _namespace: u8, _key: &[u8], _value: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn remove(&mut self, _namespace: u8, _key: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn for_each(&self, _namespace: u8, _visitor: &mut dyn FnMut(&[u8], &[u8])) {}
}

type SequenceStore = SiatStore<NoKv, 4, 0>;
type TestStorage = SecureStorage<NoConfigStore, SequenceStore>;

struct TestRng;

impl Rng for TestRng {
    fn fill(buffer: &mut [u8]) {
        buffer.fill(0xA5);
    }
}

impl SecureRng for TestRng {}

impl DeviceDefinition for TestDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE;

    type Rng = TestRng;
    type Params = NoParams;
    type ComObjects = NoComObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
    type Identity = StaticSecureIdentity;
    type Storage = &'static TestStorage;
}

fn assert_runnable<D>()
where
    D: StackDefinition,
    D::LayerBuilder: LayerStackBuilder<D>,
{
}

#[test]
fn companion_state_alias_breaks_the_storage_definition_cycle() {
    assert_runnable::<TestStack>();

    let state: TestState = TestStack::create_state(System7StateInit {
        identity: StaticSecureIdentity::new([0; 6], [0xAA; 16]),
        loaded_config: None,
        resources: SecureResources::simple([0xAA; 16]),
    });

    assert_eq!(state.extension_state().security.tool_key(), [0xAA; 16]);
}
