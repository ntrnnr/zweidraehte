//! The secure System 7 preset's state alias names the state the preset
//! builds, and the preset assembles over secure storage.

use zweidraehte_device::bcus::system_7::{SecureTp1, SecureTp1State, System7StateInit};
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::NoComObjects;
use zweidraehte_device::security::SecureResources;
use zweidraehte_device::storage::kv::KeyValueStore;
use zweidraehte_device::storage::views::SiatStore;
use zweidraehte_device::storage::{SecureStorage, StaticSecureIdentity};
use zweidraehte_device::{DeviceDefinition, LayerStackBuilder, NoParams, Rng, StackDefinition};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

const DEVICE: DeviceDescriptor =
    DeviceDescriptor::new(MaskVersion::System7Tp1, 0x00FA, [0; 6], 0xF003, 0x01, 4, 4, 4, 0);

struct TestDefinition;

type TestState = SecureTp1State<TestDefinition, 0x4200>;
type TestStack = SecureTp1<TestDefinition, 0x4200>;

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
// No config store: the device never persists its configuration.
type TestStorage = SecureStorage<(), SequenceStore>;

struct TestRng;

impl Rng for TestRng {
    fn fill(buffer: &mut [u8]) {
        buffer.fill(0xA5);
    }
}

impl DeviceDefinition for TestDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE;

    type Rng = TestRng;
    type Params = NoParams;
    type ComObjects = NoComObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
    type Identity = StaticSecureIdentity;
    type Storage = TestStorage;
}

fn assert_runnable<D>()
where
    D: StackDefinition,
    D::LayerBuilder: LayerStackBuilder<D>,
{
}

#[test]
fn the_state_alias_names_the_preset_state() {
    assert_runnable::<TestStack>();

    let state: TestState = TestStack::create_state(System7StateInit {
        identity: StaticSecureIdentity::new([0; 6], [0xAA; 16]),
        boot_image: None,
        resources: SecureResources::simple([0xAA; 16]),
    });

    assert_eq!(state.extension_state().security.tool_key(), [0xAA; 16]);
}
