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

// ============================================================================
// KNXnet/IP
// ============================================================================

/// The IP presets, with a transport and a platform that are never used:
/// the checks build the interface objects and never start the link layer.
#[cfg(feature = "knxip")]
pub mod knxip {
    use core::net::{Ipv4Addr, SocketAddrV4};

    use super::*;
    use zweidraehte_device::bcus::system_b::{Ip, IpInterface};
    use zweidraehte_device::layers::linklayers::knxip::KnxNetIpDefinition;
    use zweidraehte_device::layers::linklayers::knxip::features::{KnxIpDeviceTcp, KnxIpInterfaceTcp};
    use zweidraehte_platform::{
        AsyncUdpSocket, IpConfig, IpTransport, NetworkConfig, NetworkInfo, NeverTcpListener, NeverTcpStream,
        UdpSocketOptions,
    };

    /// A UDP socket that cannot be bound.
    pub struct NoUdpSocket;

    impl AsyncUdpSocket for NoUdpSocket {
        type Error = core::convert::Infallible;
        type Context = ();

        fn bind(_ctx: &(), _options: UdpSocketOptions) -> Result<Self, Self::Error> {
            unreachable!("the access-control checks never start the link layer")
        }

        fn join_multicast(&self, _group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
            Ok(())
        }

        fn leave_multicast(&self, _group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
            Ok(())
        }

        fn set_broadcast(&self, _broadcast: bool) -> Result<(), Self::Error> {
            Ok(())
        }

        fn local_endpoint(&self) -> SocketAddrV4 {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddrV4, Option<Ipv4Addr>), Self::Error> {
            core::future::pending().await
        }

        async fn send_to(&self, _buf: &[u8], _addr: SocketAddrV4) -> Result<usize, Self::Error> {
            unreachable!("the access-control checks never start the link layer")
        }
    }

    #[derive(Clone, Copy)]
    pub struct NoTransport;

    impl IpTransport for NoTransport {
        type UdpSocket = NoUdpSocket;
        type TcpListener = NeverTcpListener;
        type TcpStream = NeverTcpStream;
    }

    /// The network state the IP augments read; all unspecified.
    pub struct StubPlatform;

    impl NetworkInfo for StubPlatform {
        fn current_ip_address(&self) -> Ipv4Addr {
            Ipv4Addr::UNSPECIFIED
        }
        fn current_subnet_mask(&self) -> Ipv4Addr {
            Ipv4Addr::UNSPECIFIED
        }
        fn current_default_gateway(&self) -> Ipv4Addr {
            Ipv4Addr::UNSPECIFIED
        }
        fn mac_address(&self) -> [u8; 6] {
            [0; 6]
        }
        fn current_ip_assignment_method(&self) -> u8 {
            0
        }
        fn ip_capabilities(&self) -> u8 {
            0
        }
    }

    impl NetworkConfig for StubPlatform {
        type Error = core::convert::Infallible;

        fn apply_ip_config(&self, _config: &IpConfig) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// A plain definition for `mask` on the stub IP platform.
    macro_rules! ip_definition {
        ($name:ident, $mask:expr, $features:ty) => {
            #[derive(Clone, Copy)]
            pub struct $name;

            impl KnxNetIpDefinition for $name {
                type Transport = NoTransport;
                type Features = $features;
            }

            impl DeviceDefinition for $name {
                const DEVICE: &'static DeviceDescriptor = &descriptor($mask);
                type Platform = StubPlatform;
                type Params = NoParams;
                type ComObjects = NoComObjects;
                type LinkLayer = MockLinkLayerBuilder<1>;
            }
        };
    }

    ip_definition!(IpDefinition, MaskVersion::SystemBKnxIp, KnxIpDeviceTcp);
    pub type IpStack = Ip<IpDefinition>;

    ip_definition!(IpInterfaceDefinition, MaskVersion::SystemBTp1, KnxIpInterfaceTcp<2>);
    pub type IpInterfaceStack = IpInterface<IpInterfaceDefinition>;

    /// A KNX IP Secure tunnelling interface with Data Secure: two
    /// password slots and two tunnelling users, so every IP Secure
    /// property is served.
    #[cfg(feature = "ip-secure")]
    pub mod secure {
        use super::*;
        use zweidraehte_device::bcus::system_b::{IpSecureInterfaceExtensionFor, SecureIp, SystemBDeviceState};
        use zweidraehte_device::layers::linklayers::knxip::features::KnxIpSecureInterfaceTcp;
        use zweidraehte_device::layers::secure_application::NoP2p;
        use zweidraehte_device::security::SecureExtensionState;

        pub type Features = KnxIpSecureInterfaceTcp<2>;

        #[derive(Clone, Copy)]
        pub struct SecureIpDefinition;

        pub type SecureIpStack = SecureIp<SecureIpDefinition, NoP2p, 0, 2, 2>;

        // Spelled with literal sizes for the reason the System B secure
        // states are (see `system_b` above).
        const ADT: usize = descriptor(MaskVersion::SystemBKnxIp).address_table_size();
        const AST: usize = descriptor(MaskVersion::SystemBKnxIp).association_table_size();
        const COT: usize = descriptor(MaskVersion::SystemBKnxIp).comm_object_table_size();
        type State = SystemBDeviceState<
            ADT,
            AST,
            COT,
            SecureIpStack,
            SecureExtensionState<IpSecureInterfaceExtensionFor<Features, 2, 2>, 4, 0, 4>,
        >;
        pub type SecureIpStorage = SecureStorage<NoConfigStore<State>, SequenceStore>;

        impl KnxNetIpDefinition for SecureIpDefinition {
            type Transport = NoTransport;
            type Features = Features;
        }

        impl DeviceDefinition for SecureIpDefinition {
            const DEVICE: &'static DeviceDescriptor = &descriptor(MaskVersion::SystemBKnxIp);
            type Rng = TestRng;
            type Platform = StubPlatform;
            type Params = NoParams;
            type ComObjects = NoComObjects;
            type LinkLayer = MockLinkLayerBuilder<1>;
            type Identity = StaticSecureIdentity;
            type Storage = &'static SecureIpStorage;
        }
    }
}
