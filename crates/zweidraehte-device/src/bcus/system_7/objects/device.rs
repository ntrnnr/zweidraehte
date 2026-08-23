//! Device Object (Object Type 0) for System 7 devices.
//!
//! Same property surface as the System B `DeviceObject`, but with the
//! 16-level access levels of 06 Profiles v02.02.01 Annex A.2.3's
//! 0705h column. The mask has 16 authorization levels, but Annex A assigns
//! these management properties controller level 3 rather than its free
//! runtime level 15.

use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    DeviceControl, InterfaceObjectType, KNXVersion, PDT_Generic06, PDT_Generic10, PDT_UnsignedChar, PDT_UnsignedInt,
    PDT_Version, ProgrammingMode, RoutingCount,
};
use zweidraehte_proto::properties::PropertyError;

use crate::StackState;
use crate::objects::interface::{WriteResponse, interface_object, pid};
use zweidraehte_proto::device::DeviceDescriptor;

#[interface_object(object_type = InterfaceObjectType::Device, levels = 16, object_type_rl = Controller)]
pub struct System7DeviceObject<'a, S: StackState> {
    /// Stack state backing the virtual properties (programming mode,
    /// serial number, individual address, max APDU length).
    pub state: &'a S,

    #[io(pid = pid::DEVICE_CONTROL, pdt = DeviceControl, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller)]
    pub device_control: DeviceControl,

    #[io(pid = pid::ORDER_INFO, pdt = PDT_Generic10, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer)]
    pub order_info: PDT_Generic10,

    #[io(pid = pid::VERSION, pdt = PDT_Version, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer)]
    pub version: PDT_Version,

    #[io(pid = pid::device::HARDWARE_TYPE, pdt = PDT_Generic06, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = ProductManufacturer)]
    pub hardware_type: PDT_Generic06,

    #[io(pid = pid::device::DEVICE_DESCRIPTOR, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer)]
    pub device_descriptor: PDT_UnsignedInt,

    #[io(pid = pid::device::ROUTING_COUNT, pdt = RoutingCount, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller)]
    pub routing_count: RoutingCount,

    // ----- Virtual properties -----

    // One flag with the memory byte at 0060h; both views go through
    // `StackState`.
    #[io(pid = pid::device::PROGMODE, pdt = ProgrammingMode, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller,
         read = |this: &Self| [if this.state.is_programming_mode() { 0x01u8 } else { 0x00u8 }],
         write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let &[byte] = data else { return Err(PropertyError::BufferTooSmall); };
             this.state.set_programming_mode(byte != 0);
             Ok(WriteResponse::Echo)
         })]
    progmode: (),

    #[io(pid = pid::SERIAL_NUMBER, pdt = PDT_Generic06, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer,
         read = |this: &Self| *this.state.serial_number())]
    serial_number: (),

    #[io(pid = pid::MANUFACTURER_ID, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer,
         read = |this: &Self| { let sn = this.state.serial_number(); [sn[0], sn[1]] })]
    manufacturer_id: (),

    // OPEN rather than the default policy for the same reason as the
    // System B object: ETS reads this plaintext to negotiate APDU size.
    #[io(pid = pid::device::MAX_APDU_LENGTH, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::OPEN, rl = Controller, wl = SystemManufacturer,
         read = |this: &Self| this.state.max_apdu_length().to_be_bytes())]
    max_apdu_length: (),

    #[io(pid = pid::device::SUBNET_ADDRESS, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::OPEN_OFF_TOOL_ON, rl = Controller, wl = SystemManufacturer,
         read = |this: &Self| {
             let addr = this.state.individual_address();
             [(addr.area() << 4) | addr.line()]
         })]
    subnet_address: (),

    #[io(pid = pid::device::DEVICE_ADDRESS, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::OPEN_OFF_TOOL_ON, rl = Controller, wl = SystemManufacturer,
         read = |this: &Self| [this.state.individual_address().device()])]
    device_address: (),
}

impl<'a, S: StackState> System7DeviceObject<'a, S> {
    /// Create a fresh device object backed by the given `state`.
    pub fn new(state: &'a S) -> Self {
        Self {
            state,
            device_control: DeviceControl::default(),
            order_info: PDT_Generic10::default(),
            version: PDT_Version::default(),
            hardware_type: PDT_Generic06::default(),
            device_descriptor: PDT_UnsignedInt::default(),
            routing_count: RoutingCount::default(),
        }
    }

    /// Create a device object from a [`DeviceDescriptor`].
    pub fn from_descriptor(state: &'a S, desc: &DeviceDescriptor) -> Self {
        let mut obj = Self::new(state);
        obj.hardware_type = PDT_Generic06::with_value(desc.hardware_type);
        obj.version = PDT_Version::with_value(KNXVersion::from_triplet(0, 0, 1));
        obj.device_descriptor = PDT_UnsignedInt::with_value(desc.mask_version.as_u16());
        obj
    }
}
