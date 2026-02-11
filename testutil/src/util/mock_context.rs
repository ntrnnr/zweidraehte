//! Mock context for testing link layers in isolation.

use core::cell::{Cell, RefCell};

use zweidraehte::context::{BufferManagerContext, DeviceInfoContext, PropertyServiceContext};
use zweidraehte::messages::buffers::DynBufferManager;
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
}

impl MockContext {
    /// Create a new mock context with the provided buffer manager.
    pub fn new(buffer_manager: DynBufferManager<'static>) -> Self {
        Self {
            buffer_manager: RefCell::new(buffer_manager),
            max_apdu_length: Cell::new(zweidraehte::config::MAX_APDU_LENGTH_EXTENDED),
            device_info: Cell::new(None),
        }
    }

    /// Create a new mock context with a custom max APDU length.
    pub fn with_max_apdu_length(buffer_manager: DynBufferManager<'static>, max_apdu_length: u16) -> Self {
        Self {
            buffer_manager: RefCell::new(buffer_manager),
            max_apdu_length: Cell::new(max_apdu_length),
            device_info: Cell::new(None),
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
}

impl DeviceInfoContext for &mut MockContext {
    fn device_information(&self) -> DeviceInformation {
        self.device_info.get().expect("MockContext: device_info not set")
    }
}
