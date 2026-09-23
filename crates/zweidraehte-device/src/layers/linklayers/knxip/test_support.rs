//! Concrete device context shared by KNX/IP service tests.

use super::context::{
    DeviceInfoContext, IpAdditionalIndividualAddressContext, IpConfigWriteContext, IpDiagnosticsContext,
    IpSecureConfigContext, RemoteRestartContext, RoutingMulticastRebindContext,
};
use crate::HasRoutingMulticastRebind;
use crate::bcus::system_b::{ExtensionState, IpExtensionConfig, IpExtensionState};
use crate::context::{
    AddressTableContext, ApduLengthContext, BufferManagerContext, IndividualAddressContext, PropertyServiceContext,
};
use crate::ip::IpStateView;
use crate::layers::linklayers::address_check::tests::TestAddressContext;
use crate::restart::RestartRequest;
use crate::rng::NoRng;
use core::cell::{Cell, RefCell};
use core::net::Ipv4Addr;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use zweidraehte_platform::address::EthernetAddress;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};
use zweidraehte_proto::messages::knxip::substructs::{
    DeviceInformation, DeviceStatus, ExtendedDeviceInformation, IpConfig, KNXMedium,
};

/// One concrete device context, shared by the read, write and reset paths.
pub(super) struct TestContext {
    prog_mode: bool,
    mac: EthernetAddress,
    pub(super) addresses: TestAddressContext,
    pub(super) state: IpExtensionState,
    pub(super) dirty: Cell<bool>,
    pub(super) restart: RefCell<Option<RestartRequest>>,
    buffers: &'static DynBufferManager<'static>,
    max_apdu: Cell<u16>,
}

impl TestContext {
    pub(super) fn new(prog_mode: bool, mac: EthernetAddress) -> Self {
        Self {
            prog_mode,
            mac,
            addresses: TestAddressContext::new(IndividualAddress::new(1, 1, 1)),
            // Start with cleared fields so each successful write is observable.
            state: IpExtensionState::from_config(
                IpExtensionConfig { configured_subnet: [0; 4], ip_assignment_method: 0, ..Default::default() },
                (),
            ),
            dirty: Cell::new(false),
            restart: RefCell::new(None),
            buffers: leaked_buffer_manager::<2, 256>(),
            max_apdu: Cell::new(15),
        }
    }
}

impl DeviceInfoContext for TestContext {
    fn device_information(&self) -> DeviceInformation {
        DeviceInformation {
            medium: KNXMedium::KNXIP,
            device_status: if self.prog_mode { DeviceStatus::ProgrammingMode } else { DeviceStatus::None },
            individual_address: self.individual_address(),
            project_installation_identifier: 0,
            knx_serial_number: [0; 6],
            routing_multicast_address: Ipv4Addr::new(224, 0, 23, 12),
            mac_address: self.mac,
            friendly_name: [0; 30],
        }
    }

    fn extended_device_information(&self) -> ExtendedDeviceInformation {
        ExtendedDeviceInformation { medium_status: 0, max_local_apdu_len: 15, device_descriptor_type0: 0x07b0 }
    }

    fn manufacturer_code(&self) -> u16 {
        0x0083
    }
}

impl IndividualAddressContext for TestContext {
    fn individual_address(&self) -> IndividualAddress {
        self.addresses.individual_address()
    }
}

impl AddressTableContext for TestContext {
    type ADT = <TestAddressContext as AddressTableContext>::ADT;
    fn address_table(&self) -> &RefCell<Self::ADT> {
        self.addresses.address_table()
    }
}

impl BufferManagerContext for TestContext {
    fn buffer_manager(&self) -> &DynBufferManager<'static> {
        self.buffers
    }
}

impl ApduLengthContext for TestContext {
    fn max_apdu_length(&self) -> u16 {
        self.max_apdu.get()
    }
    fn set_max_apdu_length(&self, length: u16) {
        self.max_apdu.set(length);
    }
}

impl PropertyServiceContext for TestContext {
    type Handler = ();
    fn property_handler(&self) -> &Self::Handler {
        &()
    }
}

impl IpAdditionalIndividualAddressContext for TestContext {
    fn write_additional_individual_addresses(&self, _buf: &mut [IndividualAddress]) -> usize {
        0
    }
    fn contains_additional_individual_address(&self, _addr: IndividualAddress) -> bool {
        false
    }
}

impl IpSecureConfigContext for TestContext {
    type Rng = NoRng;
    type SecureState = core::convert::Infallible;
    fn ip_secure_view(&self) -> Option<&Self::SecureState> {
        None
    }
    fn knx_serial_number(&self) -> [u8; 6] {
        [0; 6]
    }
}

impl RoutingMulticastRebindContext for TestContext {
    fn routing_multicast_rebind_channel(&self) -> &Channel<NoopRawMutex, Ipv4Addr, 2> {
        self.state.routing_multicast_rebind_channel()
    }
}

impl IpConfigWriteContext for TestContext {
    type IpState = IpExtensionState;
    fn ip_state_mut(&self) -> &Self::IpState {
        &self.state
    }
    fn mark_config_dirty(&self) {
        self.dirty.set(true);
    }
}

impl IpDiagnosticsContext for TestContext {
    fn ip_config(&self) -> IpConfig {
        IpConfig {
            ip_address: self.state.configured_ip_address(),
            subnet_mask: self.state.configured_subnet_mask(),
            default_gateway: self.state.configured_default_gateway(),
            ip_capabilities: 0,
            ip_assignment_method: self.state.ip_assignment_method(),
        }
    }
    fn ip_current_config(&self) -> zweidraehte_proto::messages::knxip::substructs::IpCurrentConfig {
        zweidraehte_proto::messages::knxip::substructs::IpCurrentConfig {
            ip_address: self.state.configured_ip_address(),
            subnet_mask: self.state.configured_subnet_mask(),
            default_gateway: self.state.configured_default_gateway(),
            dhcp_server: Ipv4Addr::UNSPECIFIED,
            ip_assignment_method: self.state.ip_assignment_method(),
        }
    }
}

impl RemoteRestartContext for TestContext {
    fn request_restart(&self, request: RestartRequest) -> bool {
        *self.restart.borrow_mut() = Some(request);
        true
    }
}

/// Build a `'static` buffer manager. `ServerContext` requires
/// `DynBufferManager<'static>` (its buffers escape into `Buffer<'static>`),
/// so the backing pool must outlive the test — we leak it. Tests are
/// short-lived processes, so the leak is harmless.
fn leaked_buffer_manager<const N: usize, const SZ: usize>() -> &'static DynBufferManager<'static> {
    let pool: &'static mut [[u8; SZ]; N] = Box::leak(Box::new([[0u8; SZ]; N]));
    let mgr: &'static BufferManager<N> = Box::leak(Box::new(unsafe { BufferManager::new(pool) }));
    Box::leak(Box::new(mgr.dyn_buffer_manager()))
}
