//! The standard presets under test, each built as firmware builds it.
//!
//! Every stack is assembled from a minimal [`DeviceDefinition`]: no
//! application augments, no communication objects, a mock link layer. What
//! remains is exactly the interface-object surface the preset itself
//! composes, which is what the access-control checks walk.

use core::marker::PhantomData;

use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::NoComObjects;
use zweidraehte_device::storage::kv::KeyValueStore;
use zweidraehte_device::storage::views::SiatStore;
use zweidraehte_device::storage::{ConfigStoreBackend, HasDeviceConfig, SecureStorage, StaticSecureIdentity};
use zweidraehte_device::{DeviceDefinition, NoParams, Rng};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

// ============================================================================
// Shared test doubles
// ============================================================================

/// A key-value backend that stores nothing; the checks never persist.
pub struct NoKv;

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

/// A config store that never persists, for any device state `S`.
pub struct NoConfigStore<S>(PhantomData<fn() -> S>);

impl<S> NoConfigStore<S> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<S: HasDeviceConfig> ConfigStoreBackend for NoConfigStore<S> {
    type State = S;
    type Config = S::Config;
    type Error = core::convert::Infallible;

    fn snapshot(&self, state: &Self::State) -> Self::Config {
        state.to_config()
    }

    fn save(&mut self, _config: &Self::Config) -> Result<(), Self::Error> {
        Ok(())
    }

    fn load(&mut self) -> Option<Self::Config> {
        None
    }
}

pub type SequenceStore = SiatStore<NoKv, 4, 0>;

/// Deterministic stand-in for the platform RNG; secure stacks refuse `NoRng`.
pub struct TestRng;

impl Rng for TestRng {
    fn fill(buffer: &mut [u8]) {
        buffer.fill(0xA5);
    }
}

pub const FDSK: [u8; 16] = [0xAA; 16];

pub fn secure_identity() -> StaticSecureIdentity {
    StaticSecureIdentity::new([0x00, 0xFA, 0x01, 0x02, 0x03, 0x04], FDSK)
}

const fn descriptor(mask: MaskVersion) -> DeviceDescriptor {
    DeviceDescriptor::new(mask, 0x00FA, [0; 6], 0xF003, 0x01, 4, 4, 4, 0)
}

// ============================================================================
// Definitions
// ============================================================================

/// A plain definition for `mask`.
macro_rules! plain_definition {
    ($name:ident, $mask:expr) => {
        pub struct $name;

        impl DeviceDefinition for $name {
            const DEVICE: &'static DeviceDescriptor = &descriptor($mask);
            type Params = NoParams;
            type ComObjects = NoComObjects;
            type LinkLayer = MockLinkLayerBuilder<1>;
        }
    };
}

/// A Data Secure definition for `mask`, whose storage names `$state`.
macro_rules! secure_definition {
    ($name:ident, $mask:expr, $storage:ident, $state:ty) => {
        pub struct $name;

        pub type $storage = SecureStorage<NoConfigStore<$state>, SequenceStore>;

        impl DeviceDefinition for $name {
            const DEVICE: &'static DeviceDescriptor = &descriptor($mask);
            type Rng = TestRng;
            type Params = NoParams;
            type ComObjects = NoComObjects;
            type LinkLayer = MockLinkLayerBuilder<1>;
            type Identity = StaticSecureIdentity;
            type Storage = &'static $storage;
        }
    };
}

pub mod system_b {
    use super::*;
    use zweidraehte_device::bcus::system_b::{
        Rf, RfExtensionState, RfRetransmitterExtension, SecureRf, SecureRfRetransmitter, SecureTp1, SystemBDeviceState,
        Tp1, Tp1ExtensionState,
    };
    use zweidraehte_device::security::SecureExtensionState;

    // The secure states are spelled out with literal table sizes. The
    // `Secure*StateFor<Stack, _>` aliases project the sizes through the
    // stack, and naming that from the storage type the definition itself
    // declares closes a const-evaluation cycle. The literal sizes equal
    // what the presets derive from the same descriptor, so the types are
    // identical.
    const ADT: usize = descriptor(MaskVersion::SystemBTp1).address_table_size();
    const AST: usize = descriptor(MaskVersion::SystemBTp1).association_table_size();
    const COT: usize = descriptor(MaskVersion::SystemBTp1).comm_object_table_size();
    type SecureState<Stack, Inner> = SystemBDeviceState<ADT, AST, COT, Stack, SecureExtensionState<Inner, 4, 0, 4>>;

    plain_definition!(Tp1Definition, MaskVersion::SystemBTp1);
    pub type Tp1Stack = Tp1<Tp1Definition>;

    plain_definition!(RfDefinition, MaskVersion::SystemBRf);
    pub type RfStack = Rf<RfDefinition>;

    secure_definition!(
        SecureTp1Definition,
        MaskVersion::SystemBTp1,
        SecureTp1Storage,
        SecureState<SecureTp1Stack, Tp1ExtensionState>
    );
    pub type SecureTp1Stack = SecureTp1<SecureTp1Definition>;

    secure_definition!(
        SecureRfDefinition,
        MaskVersion::SystemBRf,
        SecureRfStorage,
        SecureState<SecureRfStack, RfExtensionState>
    );
    pub type SecureRfStack = SecureRf<SecureRfDefinition>;

    secure_definition!(
        SecureRfRetransmitterDefinition,
        MaskVersion::SystemBRf,
        SecureRfRetransmitterStorage,
        SecureState<SecureRfRetransmitterStack, RfRetransmitterExtension>
    );
    pub type SecureRfRetransmitterStack = SecureRfRetransmitter<SecureRfRetransmitterDefinition>;
}

pub mod system_7 {
    use super::*;
    use zweidraehte_device::bcus::system_7::{SecureTp1, SecureTp1State, Tp1};

    pub const COT_ADDRESS: u16 = 0x4200;

    plain_definition!(Tp1Definition, MaskVersion::System7Tp1);
    pub type Tp1Stack = Tp1<Tp1Definition, COT_ADDRESS>;

    secure_definition!(
        SecureTp1Definition,
        MaskVersion::System7Tp1,
        SecureTp1Storage,
        SecureTp1State<SecureTp1Definition, COT_ADDRESS>
    );
    pub type SecureTp1Stack = SecureTp1<SecureTp1Definition, COT_ADDRESS>;
}
