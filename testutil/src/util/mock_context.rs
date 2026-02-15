//! Mock context for testing link layers in isolation.

use core::cell::{Cell, RefCell};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, DynamicSender};

use zweidraehte::context::{
    ApplicationLayerContext, BufferManagerContext, DeviceInfoContext, IpDiagnosticsContext,
    KnxAddressContext, PropertyServiceContext,
};
use zweidraehte::layers::LayerOp;
use zweidraehte::messages::buffers::{Buffer, DynBufferManager};
use zweidraehte::messages::knxip::substructs::DeviceInformation;
use zweidraehte::objects::interface::PropertyServiceHandler;

/// Mock context for testing link layers.
///
/// This provides a minimal implementation of the required context traits
/// for testing link layers in isolation.
pub struct MockContext {
    buffer_manager: RefCell<DynBufferManager<'static>>,
    max_apdu_length: Cell<u16>,
    device_info: Cell<Option<DeviceInformation>>,
    /// Dummy AL channel for ApplicationLayerContext. Messages sent here are dropped.
    al_channel: Channel<NoopRawMutex, LayerOp<Buffer<'static>>, 1>,
}

impl MockContext {
    /// Create a new mock context with the provided buffer manager.
    pub fn new(buffer_manager: DynBufferManager<'static>) -> Self {
        Self {
            buffer_manager: RefCell::new(buffer_manager),
            max_apdu_length: Cell::new(zweidraehte::config::MAX_APDU_LENGTH_EXTENDED),
            device_info: Cell::new(None),
            al_channel: Channel::new(),
        }
    }

    /// Create a new mock context with a custom max APDU length.
    pub fn with_max_apdu_length(buffer_manager: DynBufferManager<'static>, max_apdu_length: u16) -> Self {
        Self {
            buffer_manager: RefCell::new(buffer_manager),
            max_apdu_length: Cell::new(max_apdu_length),
            device_info: Cell::new(None),
            al_channel: Channel::new(),
        }
    }

    /// Set the device information returned by `DeviceInfoContext`.
    pub fn set_device_info(&self, info: DeviceInformation) {
        self.device_info.set(Some(info));
    }
}

impl BufferManagerContext for &MockContext {
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
        &self.buffer_manager
    }

    fn max_apdu_length(&self) -> u16 {
        self.max_apdu_length.get()
    }

    fn set_max_apdu_length(&self, length: u16) {
        self.max_apdu_length.set(length);
    }
}

// PropertyServiceContext is needed for link layers that require it (e.g., KNX/IP).
// Link layers that don't need it (mock, USB) simply won't constrain on this trait.
impl PropertyServiceContext for &MockContext {
    fn property_handler(&self) -> &dyn PropertyServiceHandler {
        &()
    }
}

impl PropertyServiceContext for &mut MockContext {
    fn property_handler(&self) -> &dyn PropertyServiceHandler {
        &()
    }
}

impl BufferManagerContext for &mut MockContext {
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
        &self.buffer_manager
    }

    fn max_apdu_length(&self) -> u16 {
        self.max_apdu_length.get()
    }

    fn set_max_apdu_length(&self, length: u16) {
        self.max_apdu_length.set(length);
    }
}

impl DeviceInfoContext for &MockContext {
    fn device_information(&self) -> DeviceInformation {
        self.device_info.get().expect("MockContext: device_info not set")
    }

    fn extended_device_information(&self) -> zweidraehte::messages::knxip::substructs::ExtendedDeviceInformation {
        zweidraehte::messages::knxip::substructs::ExtendedDeviceInformation {
            medium_status: 0x00,
            max_local_apdu_len: self.max_apdu_length.get(),
            device_descriptor_type0: 0x091A, // System B TP1
        }
    }
}

impl DeviceInfoContext for &mut MockContext {
    fn device_information(&self) -> DeviceInformation {
        self.device_info.get().expect("MockContext: device_info not set")
    }

    fn extended_device_information(&self) -> zweidraehte::messages::knxip::substructs::ExtendedDeviceInformation {
        zweidraehte::messages::knxip::substructs::ExtendedDeviceInformation {
            medium_status: 0x00,
            max_local_apdu_len: self.max_apdu_length.get(),
            device_descriptor_type0: 0x091A, // System B TP1
        }
    }
}

impl IpDiagnosticsContext for &MockContext {
    fn ip_config(&self) -> zweidraehte::messages::knxip::substructs::IpConfig {
        use core::net::Ipv4Addr;
        zweidraehte::messages::knxip::substructs::IpConfig {
            ip_address: Ipv4Addr::UNSPECIFIED,
            subnet_mask: Ipv4Addr::UNSPECIFIED,
            default_gateway: Ipv4Addr::UNSPECIFIED,
            ip_capabilities: 0,
            ip_assignment_method: 0,
        }
    }

    fn ip_current_config(&self) -> zweidraehte::messages::knxip::substructs::IpCurrentConfig {
        use core::net::Ipv4Addr;
        zweidraehte::messages::knxip::substructs::IpCurrentConfig {
            ip_address: Ipv4Addr::UNSPECIFIED,
            subnet_mask: Ipv4Addr::UNSPECIFIED,
            default_gateway: Ipv4Addr::UNSPECIFIED,
            dhcp_server: Ipv4Addr::UNSPECIFIED,
            ip_assignment_method: 0,
        }
    }
}

impl IpDiagnosticsContext for &mut MockContext {
    fn ip_config(&self) -> zweidraehte::messages::knxip::substructs::IpConfig {
        use core::net::Ipv4Addr;
        zweidraehte::messages::knxip::substructs::IpConfig {
            ip_address: Ipv4Addr::UNSPECIFIED,
            subnet_mask: Ipv4Addr::UNSPECIFIED,
            default_gateway: Ipv4Addr::UNSPECIFIED,
            ip_capabilities: 0,
            ip_assignment_method: 0,
        }
    }

    fn ip_current_config(&self) -> zweidraehte::messages::knxip::substructs::IpCurrentConfig {
        use core::net::Ipv4Addr;
        zweidraehte::messages::knxip::substructs::IpCurrentConfig {
            ip_address: Ipv4Addr::UNSPECIFIED,
            subnet_mask: Ipv4Addr::UNSPECIFIED,
            default_gateway: Ipv4Addr::UNSPECIFIED,
            dhcp_server: Ipv4Addr::UNSPECIFIED,
            ip_assignment_method: 0,
        }
    }
}

impl KnxAddressContext for &MockContext {
    fn individual_address(&self) -> zweidraehte::address::IndividualAddress {
        zweidraehte::address::IndividualAddress::new(0, 0, 0)
    }
}

impl KnxAddressContext for &mut MockContext {
    fn individual_address(&self) -> zweidraehte::address::IndividualAddress {
        zweidraehte::address::IndividualAddress::new(0, 0, 0)
    }
}

impl ApplicationLayerContext for &MockContext {
    fn application_layer_sender(&self) -> DynamicSender<'_, LayerOp<Buffer<'static>>> {
        self.al_channel.sender().into()
    }
}

impl ApplicationLayerContext for &mut MockContext {
    fn application_layer_sender(&self) -> DynamicSender<'_, LayerOp<Buffer<'static>>> {
        self.al_channel.sender().into()
    }
}
