//! Full Stack Test Harness
//!
//! This module provides the infrastructure to run the complete KNX stack
//! with a MockLinkLayer for conformance testing.
//!
//! Unlike the network layer harness, this tests the entire stack end-to-end:
//! - Application Layer
//! - Transport Layer
//! - Network Layer
//! - MockLinkLayer (for injection/capture)
//!
//! This is required for EITT tests that expect full device responses
//! (e.g., GroupValue_Read → GroupValue_Response).
//!
//! ## BCU1-Style Group Object Tests
//!
//! The Group Object conformance tests (1.4.1.x) require a BCU1-style application
//! where shadow objects (GO1, GO2, GO3) provide access to GO0's internal state:
//!
//! - **GO1 (ASAP 2)**: Communication flags - reading/writing controls GO0's transmission state
//! - **GO2 (ASAP 3)**: Configuration flags - reading/writing modifies GO0's COT flags
//! - **GO3 (ASAP 4)**: Value access - direct read/write of GO0's value without flag changes

use core::cell::RefCell;
use std::net::Ipv4Addr;

use const_default::ConstDefault;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use static_cell::StaticCell;

use zweidraehte::{
    memory::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable},
    messages::buffers::{Buffer, BufferManager, DynBufferManager, MessageBuffer},
    messages::knx::{KnxMessageBuffer, ServiceType},
    objects::comm::{ComObjectStatus, ComObjects},
    objects::interface::{
        AddressTableObject, ApplicationProgramObject, AssociationTableObject, DeviceInfo, DeviceObject,
        GroupObjectTableObject, InterfaceObject, IpParameterObject, PropertyDescriptionResponse,
        PropertyError, PropertyServiceHandler, WriteResponse,
    },
    objects::tables::{app::Application, HasLoadStateMachine},
    IpPlatform, IpStackState, Runner, StackDefinition, StackResources,
};

use super::mock::{CapturedLinkLayerMessage, MockLinkLayerBuilder, MockLinkLayerHandle};

// ============================================================================
// Communication Objects (BCU1-style with shadow objects)
// ============================================================================
//
// The conformance tests use a BCU1-style setup where shadow objects provide
// access to the main object's internal state:
//
// - GO0 (ASAP 1): Main 1-bit group object
// - GO1 (ASAP 2): Exposes GO0's communication flags (4-bit)
// - GO2 (ASAP 3): Exposes GO0's configuration flags from COT (8-bit)
// - GO3 (ASAP 4): Exposes GO0's value as 8-bit
// - GO4 (ASAP 5): For Read on Init testing
//
// Writing to GO1/GO2/GO3 modifies the internal state of GO0.
// This is achieved through the prepare_read and handle_write hooks.

pub mod comm_objs {
    use zweidraehte::dpt::{DPT_Switch, DPT_Value_1_Ucount, DPT_Value_3_Ucount};
    use zweidraehte::ets::EtsComObjects;
    use zweidraehte::objects::comm::ComObject;
    #[allow(unused_imports)]
    use zweidraehte::objects::comm::{ComObjectIndex, ComObjectInfo, ComObjectInfoMut, ComObjects};

    // Use #[ets(manual_impl)] to provide our own ComObjects implementation with hooks
    #[derive(EtsComObjects)]
    #[ets(manual_impl)]
    pub struct ConformanceComObjects {
        // ================================================================
        // GO0-GO3: 1-bit main object and shadow objects (ASAP 1-4)
        // ================================================================
        /// GO0: Main 1-bit object (UINT1)
        /// This is the primary test object whose flags/value are accessed via GO1-GO3
        #[ets(index = 1)]
        pub go_0: ComObject<DPT_Switch>,

        /// GO1: Communication flags (4-bit / UINT4)
        /// Bit 0: Read request pending
        /// Bit 1: Write/Transmission request pending
        /// Bit 2: Error flag (0=OK, 1=Error)
        /// Bit 3: Update flag
        #[ets(index = 2)]
        pub go_1_comm_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO2: Configuration flags (8-bit / UINT8)
        /// Bits 0-1: Priority (0=System, 1=High, 2=Alarm, 3=Low)
        /// Bit 2: Communication Enable
        /// Bit 3: Read Enable
        /// Bit 4: Write Enable
        /// Bit 5: Read on Init
        /// Bit 6: Transmission Enable
        /// Bit 7: Update Enable (Read Response Update)
        #[ets(index = 3)]
        pub go_2_config_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO3: Value of GO0 as 8-bit (for reading/writing without affecting flags)
        #[ets(index = 4)]
        pub go_3_value: ComObject<DPT_Value_1_Ucount>,

        // ================================================================
        // GO0_BYTE3-GO3_BYTE3: 3-byte main object and shadow objects (ASAP 5-8)
        // For invalid data length tests (1.4.1.4a)
        // ================================================================
        /// GO0_BYTE3: 3-byte version of GO0 for invalid data length tests
        #[ets(index = 5)]
        pub go_0_byte3: ComObject<DPT_Value_3_Ucount>,

        /// GO1_BYTE3: Communication flags for GO0_BYTE3
        #[ets(index = 6)]
        pub go_1_byte3_comm_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO2_BYTE3: Configuration flags for GO0_BYTE3
        #[ets(index = 7)]
        pub go_2_byte3_config_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO3_BYTE3: Value of GO0_BYTE3 as 3-byte (for reading/writing without affecting flags)
        #[ets(index = 8)]
        pub go_3_byte3_value: ComObject<DPT_Value_3_Ucount>,

        // ================================================================
        // Additional test objects (ASAP 9-11)
        // ================================================================
        /// GO4: For Read on Init testing
        #[ets(index = 9)]
        pub go_4: ComObject<DPT_Value_1_Ucount>,

        /// GO5: 8-bit object for network layer test 3.1 (long format response)
        #[ets(index = 10)]
        pub go_5_network_test: ComObject<DPT_Value_1_Ucount>,

        /// GO6: 1-bit object for transport layer test 2.1
        #[ets(index = 11)]
        pub go_6_transport_test: ComObject<DPT_Switch>,
    }
}

// Manual ComObjects implementation with custom hooks for shadow objects
use comm_objs::{ConformanceComObjects, Index as CoIndex};
use core::cell::UnsafeCell;
use zweidraehte::dpt::{DPT_Switch, DPT_Value_1_Ucount, DPT_Value_3_Ucount};
use zweidraehte::objects::comm::{ComObject, ComObjectIndex, ComObjectInfo, ComObjectInfoMut};
use zweidraehte::objects::tables::{ComObjectFlags, CommunicationObjectTable};

/// Hook context for conformance tests that provides access to the COT.
///
/// This struct uses interior mutability to allow setting the COT reference
/// after stack initialization.
///
/// # Safety
///
/// The COT pointer is initialized to null and must be set via `set_cot()`
/// before any hooks are called. The pointer must remain valid for the
/// lifetime of the stack.
pub struct ConformanceHookContext {
    /// Pointer to the COT, set after stack initialization.
    /// Using UnsafeCell because we need to mutate this after creation.
    cot: UnsafeCell<*const RefCell<conformance_config::CoTab>>,
}

impl ConformanceHookContext {
    /// Create a new hook context with no COT reference.
    pub const fn new() -> Self {
        Self { cot: UnsafeCell::new(core::ptr::null()) }
    }

    /// Set the COT reference. Must be called after stack initialization.
    ///
    /// # Safety
    ///
    /// The caller must ensure the COT reference remains valid for the
    /// lifetime of the stack.
    pub unsafe fn set_cot(&self, cot: &RefCell<conformance_config::CoTab>) {
        *self.cot.get() = cot as *const _;
    }

    /// Get a reference to the COT if it has been set.
    fn cot(&self) -> Option<&RefCell<conformance_config::CoTab>> {
        // SAFETY: We only read the pointer, and if non-null, it was set
        // to a valid reference by set_cot().
        unsafe {
            let ptr = *self.cot.get();
            if ptr.is_null() {
                None
            } else {
                Some(&*ptr)
            }
        }
    }
}

// SAFETY: The UnsafeCell is only accessed from single-threaded embassy context
unsafe impl Send for ConformanceHookContext {}
unsafe impl Sync for ConformanceHookContext {}

impl ComObjects for ConformanceComObjects {
    type Index = CoIndex;
    type HookContext = ConformanceHookContext;

    fn new() -> Self {
        Self {
            // GO0-GO3: 1-bit main object and shadow objects
            go_0: ComObject::new(DPT_Switch::from(false)),
            go_1_comm_flags: ComObject::new(DPT_Value_1_Ucount::from(0u8)),
            go_2_config_flags: ComObject::new(DPT_Value_1_Ucount::from(0xDFu8)),
            go_3_value: ComObject::new(DPT_Value_1_Ucount::from(0u8)),
            // GO0_BYTE3-GO3_BYTE3: 3-byte main object and shadow objects
            go_0_byte3: ComObject::new(DPT_Value_3_Ucount::default()),
            go_1_byte3_comm_flags: ComObject::new(DPT_Value_1_Ucount::from(0u8)),
            go_2_byte3_config_flags: ComObject::new(DPT_Value_1_Ucount::from(0xDFu8)),
            go_3_byte3_value: ComObject::new(DPT_Value_3_Ucount::default()),
            // Additional test objects
            go_4: ComObject::new(DPT_Value_1_Ucount::from(0u8)),
            go_5_network_test: ComObject::new(DPT_Value_1_Ucount::from(0u8)),
            go_6_transport_test: ComObject::new(DPT_Switch::from(false)),
        }
    }

    fn info(&self, idx: u16) -> ComObjectInfo<'_> {
        match CoIndex::from_index(idx).expect("invalid index") {
            // GO0-GO3: 1-bit main object and shadow objects
            CoIndex::Go0 => ComObjectInfo { status: &self.go_0.status, value: self.go_0.value.as_ref() },
            CoIndex::Go1CommFlags => {
                ComObjectInfo { status: &self.go_1_comm_flags.status, value: self.go_1_comm_flags.value.as_ref() }
            }
            CoIndex::Go2ConfigFlags => {
                ComObjectInfo { status: &self.go_2_config_flags.status, value: self.go_2_config_flags.value.as_ref() }
            }
            CoIndex::Go3Value => {
                ComObjectInfo { status: &self.go_3_value.status, value: self.go_3_value.value.as_ref() }
            }
            // GO0_BYTE3-GO3_BYTE3: 3-byte main object and shadow objects
            CoIndex::Go0Byte3 => {
                ComObjectInfo { status: &self.go_0_byte3.status, value: self.go_0_byte3.value.as_ref() }
            }
            CoIndex::Go1Byte3CommFlags => ComObjectInfo {
                status: &self.go_1_byte3_comm_flags.status,
                value: self.go_1_byte3_comm_flags.value.as_ref(),
            },
            CoIndex::Go2Byte3ConfigFlags => ComObjectInfo {
                status: &self.go_2_byte3_config_flags.status,
                value: self.go_2_byte3_config_flags.value.as_ref(),
            },
            CoIndex::Go3Byte3Value => {
                ComObjectInfo { status: &self.go_3_byte3_value.status, value: self.go_3_byte3_value.value.as_ref() }
            }
            // Additional test objects
            CoIndex::Go4 => ComObjectInfo { status: &self.go_4.status, value: self.go_4.value.as_ref() },
            CoIndex::Go5NetworkTest => {
                ComObjectInfo { status: &self.go_5_network_test.status, value: self.go_5_network_test.value.as_ref() }
            }
            CoIndex::Go6TransportTest => ComObjectInfo {
                status: &self.go_6_transport_test.status,
                value: self.go_6_transport_test.value.as_ref(),
            },
        }
    }

    fn info_mut(&mut self, idx: u16) -> ComObjectInfoMut<'_> {
        match CoIndex::from_index(idx).expect("invalid index") {
            // GO0-GO3: 1-bit main object and shadow objects
            CoIndex::Go0 => ComObjectInfoMut { status: &mut self.go_0.status, value: self.go_0.value.as_mut() },
            CoIndex::Go1CommFlags => ComObjectInfoMut {
                status: &mut self.go_1_comm_flags.status,
                value: self.go_1_comm_flags.value.as_mut(),
            },
            CoIndex::Go2ConfigFlags => ComObjectInfoMut {
                status: &mut self.go_2_config_flags.status,
                value: self.go_2_config_flags.value.as_mut(),
            },
            CoIndex::Go3Value => {
                ComObjectInfoMut { status: &mut self.go_3_value.status, value: self.go_3_value.value.as_mut() }
            }
            // GO0_BYTE3-GO3_BYTE3: 3-byte main object and shadow objects
            CoIndex::Go0Byte3 => {
                ComObjectInfoMut { status: &mut self.go_0_byte3.status, value: self.go_0_byte3.value.as_mut() }
            }
            CoIndex::Go1Byte3CommFlags => ComObjectInfoMut {
                status: &mut self.go_1_byte3_comm_flags.status,
                value: self.go_1_byte3_comm_flags.value.as_mut(),
            },
            CoIndex::Go2Byte3ConfigFlags => ComObjectInfoMut {
                status: &mut self.go_2_byte3_config_flags.status,
                value: self.go_2_byte3_config_flags.value.as_mut(),
            },
            CoIndex::Go3Byte3Value => ComObjectInfoMut {
                status: &mut self.go_3_byte3_value.status,
                value: self.go_3_byte3_value.value.as_mut(),
            },
            // Additional test objects
            CoIndex::Go4 => ComObjectInfoMut { status: &mut self.go_4.status, value: self.go_4.value.as_mut() },
            CoIndex::Go5NetworkTest => ComObjectInfoMut {
                status: &mut self.go_5_network_test.status,
                value: self.go_5_network_test.value.as_mut(),
            },
            CoIndex::Go6TransportTest => ComObjectInfoMut {
                status: &mut self.go_6_transport_test.status,
                value: self.go_6_transport_test.value.as_mut(),
            },
        }
    }

    fn prepare_read(&mut self, idx: u16, ctx: &Self::HookContext) {
        match CoIndex::from_index(idx) {
            Some(CoIndex::Go1CommFlags) => {
                // GO1 reads GO0's communication status
                let flags = self.go_0.status.to_flags_byte();
                self.go_1_comm_flags.value.as_mut()[0] = flags;
            }
            Some(CoIndex::Go2ConfigFlags) => {
                // GO2 reads GO0's configuration flags from the COT
                // GO0 is at ASAP 1 (index 1 in the COT)
                if let Some(cot) = ctx.cot() {
                    if let Some(flags) = cot.borrow().object_flags(1) {
                        self.go_2_config_flags.value.as_mut()[0] = flags.to_byte();
                    }
                }
            }
            Some(CoIndex::Go3Value) => {
                // GO3 reads GO0's value
                let go0_value = self.go_0.value.as_ref()[0];
                self.go_3_value.value.as_mut()[0] = go0_value;
            }
            // BYTE3 shadow objects
            Some(CoIndex::Go1Byte3CommFlags) => {
                // GO1_BYTE3 reads GO0_BYTE3's communication status
                let flags = self.go_0_byte3.status.to_flags_byte();
                self.go_1_byte3_comm_flags.value.as_mut()[0] = flags;
            }
            Some(CoIndex::Go2Byte3ConfigFlags) => {
                // GO2_BYTE3 reads GO0_BYTE3's configuration flags from the COT
                // GO0_BYTE3 is at ASAP 5 (index 5 in the COT)
                if let Some(cot) = ctx.cot() {
                    if let Some(flags) = cot.borrow().object_flags(5) {
                        self.go_2_byte3_config_flags.value.as_mut()[0] = flags.to_byte();
                    }
                }
            }
            Some(CoIndex::Go3Byte3Value) => {
                // GO3_BYTE3 reads GO0_BYTE3's value (3 bytes)
                let go0_value = self.go_0_byte3.value.as_ref();
                self.go_3_byte3_value.value.as_mut().copy_from_slice(go0_value);
            }
            _ => {}
        }
    }

    fn handle_write(&mut self, idx: u16, ctx: &Self::HookContext) {
        match CoIndex::from_index(idx) {
            Some(CoIndex::Go1CommFlags) => {
                // GO1 write sets GO0's communication flags directly
                // The value written becomes GO0's new comm flags
                let flags = self.go_1_comm_flags.value.as_ref()[0];
                self.go_0.status = ComObjectStatus::from_flags_byte(flags);
            }
            Some(CoIndex::Go2ConfigFlags) => {
                // GO2 write modifies GO0's configuration flags in the COT
                // GO0 is at ASAP 1 (index 1 in the COT)
                if let Some(cot) = ctx.cot() {
                    let new_flags = ComObjectFlags::from_byte(self.go_2_config_flags.value.as_ref()[0]);
                    cot.borrow_mut().set_object_flags(1, new_flags);
                }
            }
            Some(CoIndex::Go3Value) => {
                // GO3 write modifies GO0's value directly
                let new_value = self.go_3_value.value.as_ref()[0];
                self.go_0.value.as_mut()[0] = new_value;
            }
            // BYTE3 shadow objects
            Some(CoIndex::Go1Byte3CommFlags) => {
                // GO1_BYTE3 write sets GO0_BYTE3's communication flags directly
                let flags = self.go_1_byte3_comm_flags.value.as_ref()[0];
                self.go_0_byte3.status = ComObjectStatus::from_flags_byte(flags);
            }
            Some(CoIndex::Go2Byte3ConfigFlags) => {
                // GO2_BYTE3 write modifies GO0_BYTE3's configuration flags in the COT
                // GO0_BYTE3 is at ASAP 5 (index 5 in the COT)
                if let Some(cot) = ctx.cot() {
                    let new_flags = ComObjectFlags::from_byte(self.go_2_byte3_config_flags.value.as_ref()[0]);
                    cot.borrow_mut().set_object_flags(5, new_flags);
                }
            }
            Some(CoIndex::Go3Byte3Value) => {
                // GO3_BYTE3 write modifies GO0_BYTE3's value directly (3 bytes)
                let new_value = self.go_3_byte3_value.value.as_ref();
                self.go_0_byte3.value.as_mut().copy_from_slice(new_value);
            }
            _ => {}
        }
    }
}

// ============================================================================
// Test Stack Configuration
// ============================================================================
//
// Address layout for conformance tests (MUST be sorted by encoded group address):
// - TSAP 1: 0x0801 (1/0/1) → CO 10 (GO5, 8-bit for network layer test 3.1)
// - TSAP 2: 0x1000 (2/0/0) → CO 1 (GO0, main 1-bit object)
// - TSAP 3: 0x1001 (2/0/1) → CO 2 (GO1, comm flags)
// - TSAP 4: 0x1002 (2/0/2) → CO 3 (GO2, config flags)
// - TSAP 5: 0x1003 (2/0/3) → CO 4 (GO3, value)
// - TSAP 6: 0x1005 (2/0/5) → CO 9 (GO4, read on init)
// - TSAP 7: 0x1100 (2/1/0) → CO 5 (GO0_BYTE3, 3-byte main object for test 1.4.1.4a)
// - TSAP 8: 0x1101 (2/1/1) → CO 6 (GO1_BYTE3, comm flags for GO0_BYTE3)
// - TSAP 9: 0x1102 (2/1/2) → CO 7 (GO2_BYTE3, config flags for GO0_BYTE3)
// - TSAP 10: 0x1103 (2/1/3) → CO 8 (GO3_BYTE3, value for GO0_BYTE3)
// - TSAP 11: 0x2D05 (5/5/5) → CO 11 (GO6, 1-bit for transport layer test 2.1)

mod conformance_config {
    use zweidraehte::config::{CE, RE, ROI, TE, UE, WE};
    use zweidraehte::knx_stack_config;

    knx_stack_config! {
        name: ConformanceTestConfig,
        individual_address: "1.0.1",  // BDUT = 1.0.1 = 0x1001

        // NOTE: Group addresses MUST be sorted by their encoded value for binary search!
        // Address encoding (3-level): ((main & 0x1F) << 11) | ((middle & 0x07) << 8) | sub
        group_addresses: {
            // Sorted order by encoded value:
            1 => "1/0/1",  // 0x0801 - for network layer test 3.1 (8-bit, long format)
            2 => "2/0/0",  // 0x1000 (main object GO0)
            3 => "2/0/1",  // 0x1001 (comm flags GO1)
            4 => "2/0/2",  // 0x1002 (config flags GO2)
            5 => "2/0/3",  // 0x1003 (value GO3)
            6 => "2/0/5",  // 0x1005 (read on init GO4)
            7 => "2/1/0",  // 0x1100 (3-byte main object GO0_BYTE3 for test 1.4.1.4a)
            8 => "2/1/1",  // 0x1101 (comm flags GO1_BYTE3)
            9 => "2/1/2",  // 0x1102 (config flags GO2_BYTE3)
            10 => "2/1/3", // 0x1103 (value GO3_BYTE3)
            11 => "5/5/5", // 0x2D05 - for transport layer test 2.1 (1-bit)
        },

        comm_objects: {
            // ================================================================
            // GO0-GO3: 1-bit main object and shadow objects (ASAP 1-4)
            // ================================================================
            // GO0: Main 1-bit object (UINT1) - all flags enabled by default
            1 => (1, CE | TE | RE | WE | UE),
            // GO1: Communication flags (4-bit) - for accessing GO0's comm flags
            2 => (4, CE | TE | RE | WE | UE),
            // GO2: Configuration flags (8-bit) - for accessing GO0's config flags
            3 => (7, CE | TE | RE | WE | UE),
            // GO3: Value (8-bit) - for accessing GO0's value without flag modification
            4 => (7, CE | TE | RE | WE | UE),

            // ================================================================
            // GO0_BYTE3-GO3_BYTE3: 3-byte main object and shadow objects (ASAP 5-8)
            // ================================================================
            // GO0_BYTE3: 3-byte main object for invalid data length test 1.4.1.4a
            5 => (9, CE | TE | RE | WE | UE),   // 9 = Byte3 (3 bytes)
            // GO1_BYTE3: Communication flags for GO0_BYTE3 (4-bit like original GO1)
            6 => (4, CE | TE | RE | WE | UE),   // 4 = 4-bit for short format response
            // GO2_BYTE3: Configuration flags for GO0_BYTE3
            7 => (7, CE | TE | RE | WE | UE),
            // GO3_BYTE3: Value for GO0_BYTE3 (3 bytes)
            8 => (9, CE | TE | RE | WE | UE),   // 9 = Byte3 (3 bytes)

            // ================================================================
            // Additional test objects (ASAP 9-11)
            // ================================================================
            // GO4: Read on Init test object - has ROI flag set
            9 => (7, CE | TE | RE | WE | UE | ROI),
            // GO5: 8-bit object for network layer test 3.1 (long format response)
            10 => (7, CE | TE | RE | WE | UE),
            // GO6: 1-bit object for transport layer test 2.1
            11 => (1, CE | TE | RE | WE | UE),
        },

        associations: {
            // Note: TSAPs are assigned based on sorted group address positions
            1 => [10],  // TSAP 1 (1/0/1) → CO 10 (GO5, 8-bit for network layer test)
            2 => [1],   // TSAP 2 (2/0/0) → CO 1 (GO0, 1-bit main object)
            3 => [2],   // TSAP 3 (2/0/1) → CO 2 (GO1, comm flags)
            4 => [3],   // TSAP 4 (2/0/2) → CO 3 (GO2, config flags)
            5 => [4],   // TSAP 5 (2/0/3) → CO 4 (GO3, value)
            6 => [9],   // TSAP 6 (2/0/5) → CO 9 (GO4, read on init)
            7 => [5],   // TSAP 7 (2/1/0) → CO 5 (GO0_BYTE3, 3-byte main object)
            8 => [6],   // TSAP 8 (2/1/1) → CO 6 (GO1_BYTE3, comm flags)
            9 => [7],   // TSAP 9 (2/1/2) → CO 7 (GO2_BYTE3, config flags)
            10 => [8],  // TSAP 10 (2/1/3) → CO 8 (GO3_BYTE3, value)
            11 => [11], // TSAP 11 (5/5/5) → CO 11 (GO6, 1-bit for transport layer)
        },
    }
}

// ============================================================================
// Mock IP Platform
// ============================================================================

/// Mock platform for testing that provides static IP configuration.
#[derive(Debug, Clone)]
pub struct MockIpPlatform {
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mac_address: [u8; 6],
}

impl Default for MockIpPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl MockIpPlatform {
    pub fn new() -> Self {
        Self {
            ip_address: Ipv4Addr::new(192, 168, 1, 100),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            mac_address: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        }
    }
}

impl IpPlatform for MockIpPlatform {
    fn current_ip_address(&self) -> Ipv4Addr {
        self.ip_address
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.subnet_mask
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    fn current_ip_assignment_method(&self) -> u8 {
        0x02 // Manual
    }

    fn ip_capabilities(&self) -> u8 {
        0x07 // BootP, DHCP, Manual supported
    }

    fn knxnetip_device_capabilities(&self) -> u16 {
        0x003F // Supports routing, tunneling, etc.
    }
}

// ============================================================================
// Device Information
// ============================================================================

/// Device-specific constants for Interface Objects
pub mod device_info {
    use zweidraehte::config::{buffer_size_for_apdu, MAX_APDU_LENGTH_EXTENDED};
    use zweidraehte::ets::DeviceDescriptor;

    /// The device descriptor for conformance testing.
    ///
    /// This is the single source of truth for all device/application metadata.
    pub const DEVICE: DeviceDescriptor = DeviceDescriptor {
        mask_version: 0x57B0, // System B KNX/IP device
        manufacturer_id: 0x00FA,
        hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        application_id: 0x0100,
        application_version: 0x01,
        max_address_table_entries: 254,
        max_association_table_entries: 254,
        max_com_objects: 254,
    };

    /// Device serial number (6 bytes)
    /// Must match BDUT_SERIAL_NUMBER in test variables (management.rs)
    /// NOTE: This is stored in runtime state, not the device descriptor
    pub const SERIAL_NUMBER: [u8; 6] = [0x30, 0x30, 0x30, 0x30, 0x30, 0x30];

    /// Hardware type identifier (6 bytes)
    pub const HARDWARE_TYPE: [u8; 6] = DEVICE.hardware_type;

    /// Application program version (5 bytes: manufacturer, app_id, version)
    pub const PROGRAM_VERSION: [u8; 5] = DEVICE.program_version();

    /// PEI type (0 = no PEI)
    pub const PEI_TYPE: u8 = 0x00;

    /// Maximum APDU length for this device.
    ///
    /// Uses the extended format (255 bytes) which is supported by KNX/IP
    /// and modern TP1 devices with Extended Frame Format.
    pub const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;

    /// Device descriptor (mask version)
    /// 0x57B0 = System B KNX/IP device
    pub const DEVICE_DESCRIPTOR: u16 = DEVICE.mask_version;

    /// Buffer size for message buffers.
    ///
    /// Calculated from the maximum APDU length plus frame overhead and headroom.
    pub const BUFFER_SIZE: usize = buffer_size_for_apdu(MAX_APDU_LENGTH);
}

// ============================================================================
// KNX/IP Interface Objects
// ============================================================================

/// Interface Objects container for a KNXnet/IP device
///
/// This struct holds all the interface objects required for a standard
/// KNXnet/IP device. It implements `PropertyServiceHandler` to dispatch
/// property requests to the correct object by index:
///
/// - Index 0: Device Object
/// - Index 1: Address Table Object
/// - Index 2: Association Table Object
/// - Index 3: Application Program Object
/// - Index 4: Group Object Table Object
/// - Index 5: IP Parameter Object
pub struct KnxIpInterfaceObjects<'a> {
    pub device: RefCell<DeviceObject<'a, ConformanceState>>,
    pub addr_table: RefCell<AddressTableObject<'a, conformance_config::AddrTab>>,
    pub asso_table: RefCell<AssociationTableObject<'a, conformance_config::AssoTab>>,
    pub app_program: RefCell<ApplicationProgramObject<'a, Application<()>>>,
    pub group_object_table: RefCell<GroupObjectTableObject<'a, conformance_config::CoTab>>,
    pub ip_parameter: RefCell<IpParameterObject<'a, ConformanceState>>,
}

impl<'a> KnxIpInterfaceObjects<'a> {
    /// Create new interface objects wrapping the provided state
    pub fn new(state: &'a ConformanceState) -> Self {
        // Create Device Object with device information
        let device = DeviceObject::with_info(state, &DeviceInfo {
            order_info: [0; 10],
            hardware_type: device_info::HARDWARE_TYPE,
            version: [0x00, 0x01], // Version 0.0.1
            device_descriptor: device_info::DEVICE_DESCRIPTOR,
        });

        // Create Application Program Object wrapping the application table
        // APP doesn't have a fixed memory address in conformance tests
        let mut app_program = ApplicationProgramObject::new(&state.app, 0);
        app_program.set_program_version(device_info::PROGRAM_VERSION.into());
        app_program.set_pei_type(device_info::PEI_TYPE.into());

        // Create IP Parameter Object
        let ip_parameter = IpParameterObject::with_state(state);

        // Use ConformanceMemoryMap addresses for tables
        Self {
            device: RefCell::new(device),
            addr_table: RefCell::new(AddressTableObject::new(&state.adt, ConformanceMemoryMap::ADT_BASE as u32)),
            asso_table: RefCell::new(AssociationTableObject::new(&state.ast, ConformanceMemoryMap::AST_BASE as u32)),
            app_program: RefCell::new(app_program),
            group_object_table: RefCell::new(GroupObjectTableObject::new(
                &state.cot,
                ConformanceMemoryMap::COT_BASE as u32,
            )),
            ip_parameter: RefCell::new(ip_parameter),
        }
    }
}

impl<'a> PropertyServiceHandler for KnxIpInterfaceObjects<'a> {
    fn object_count(&self) -> u16 {
        6 // Device, AddrTable, AssoTable, AppProgram, GroupObjectTable, IpParameter
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        match object_idx {
            0 => self.device.borrow().property_description(object_idx, prop_id, prop_idx),
            1 => self.addr_table.borrow().property_description(object_idx, prop_id, prop_idx),
            2 => self.asso_table.borrow().property_description(object_idx, prop_id, prop_idx),
            3 => self.app_program.borrow().property_description(object_idx, prop_id, prop_idx),
            4 => self.group_object_table.borrow().property_description(object_idx, prop_id, prop_idx),
            5 => self.ip_parameter.borrow().property_description(object_idx, prop_id, prop_idx),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
        access_level: u8,
    ) -> Result<usize, PropertyError> {
        // Check access level first (in separate scope to release borrow)
        {
            let desc = match object_idx {
                0 => self.device.borrow().property_descriptor_by_id(prop_id),
                1 => self.addr_table.borrow().property_descriptor_by_id(prop_id),
                2 => self.asso_table.borrow().property_descriptor_by_id(prop_id),
                3 => self.app_program.borrow().property_descriptor_by_id(prop_id),
                4 => self.group_object_table.borrow().property_descriptor_by_id(prop_id),
                5 => self.ip_parameter.borrow().property_descriptor_by_id(prop_id),
                _ => return Err(PropertyError::InvalidObjectIndex),
            };
            if let Some((_, desc)) = desc {
                if !desc.can_read(access_level) {
                    return Err(PropertyError::AccessDenied);
                }
            }
        }

        match object_idx {
            0 => self.device.borrow().read_property(prop_id, start_idx, count, buf),
            1 => self.addr_table.borrow().read_property(prop_id, start_idx, count, buf),
            2 => self.asso_table.borrow().read_property(prop_id, start_idx, count, buf),
            3 => self.app_program.borrow().read_property(prop_id, start_idx, count, buf),
            4 => self.group_object_table.borrow().read_property(prop_id, start_idx, count, buf),
            5 => self.ip_parameter.borrow().read_property(prop_id, start_idx, count, buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        data: &[u8],
        access_level: u8,
    ) -> Result<WriteResponse, PropertyError> {
        // Check access level first (in separate scope to release borrow)
        {
            let desc = match object_idx {
                0 => self.device.borrow().property_descriptor_by_id(prop_id),
                1 => self.addr_table.borrow().property_descriptor_by_id(prop_id),
                2 => self.asso_table.borrow().property_descriptor_by_id(prop_id),
                3 => self.app_program.borrow().property_descriptor_by_id(prop_id),
                4 => self.group_object_table.borrow().property_descriptor_by_id(prop_id),
                5 => self.ip_parameter.borrow().property_descriptor_by_id(prop_id),
                _ => return Err(PropertyError::InvalidObjectIndex),
            };
            if let Some((_, desc)) = desc {
                if !desc.can_write(access_level) {
                    return Err(PropertyError::AccessDenied);
                }
            }
        }

        match object_idx {
            0 => self.device.borrow_mut().write_property(prop_id, start_idx, data),
            1 => self.addr_table.borrow_mut().write_property(prop_id, start_idx, data),
            2 => self.asso_table.borrow_mut().write_property(prop_id, start_idx, data),
            3 => self.app_program.borrow_mut().write_property(prop_id, start_idx, data),
            4 => self.group_object_table.borrow_mut().write_property(prop_id, start_idx, data),
            5 => self.ip_parameter.borrow_mut().write_property(prop_id, start_idx, data),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }
}

impl<'a> zweidraehte::objects::interface::HasDeviceObject for KnxIpInterfaceObjects<'a> {
    fn device_control(&self) -> zweidraehte::dpt::DeviceControl {
        self.device.borrow().device_control
    }

    fn set_device_control(&self, value: zweidraehte::dpt::DeviceControl) {
        self.device.borrow_mut().device_control = value;
    }

    fn programming_mode(&self) -> zweidraehte::dpt::ProgrammingMode {
        self.device.borrow().programming_mode
    }

    fn set_programming_mode(&self, value: zweidraehte::dpt::ProgrammingMode) {
        self.device.borrow_mut().programming_mode = value;
    }

    fn routing_count(&self) -> zweidraehte::dpt::RoutingCount {
        self.device.borrow().routing_count
    }

    fn set_routing_count(&self, value: zweidraehte::dpt::RoutingCount) {
        self.device.borrow_mut().routing_count = value;
    }
}

// ============================================================================
// Interface Objects Builder
// ============================================================================

/// Create KNX/IP interface objects for conformance testing.
pub fn create_conformance_interface_objects<'a>(state: &'a ConformanceState) -> KnxIpInterfaceObjects<'a> {
    KnxIpInterfaceObjects::new(state)
}

// ============================================================================
// Test Parameters
// ============================================================================

#[derive(Debug)]
pub struct TestParameters;

impl ConstDefault for TestParameters {
    const DEFAULT: Self = TestParameters;
}

// ============================================================================
// Stack Definition
// ============================================================================

/// Stack definition for conformance testing
#[derive(Debug, Clone, Copy)]
pub struct ConformanceTestStack;

/// Size of linear memory region (0x0200-0x02FF) - freely accessible
pub const LINEAR_MEMORY_SIZE: usize = 256;
/// Size of level 2 memory block (0x0300-0x03FF) - requires access level <= 2
pub const LEVEL2_MEMORY_SIZE: usize = 256;
/// Size of level 1 memory block (0x0400-0x04FF) - requires access level <= 1
pub const LEVEL1_MEMORY_SIZE: usize = 256;
/// Size of user memory region (0x7FF0-0x7FFF) - for A_UserMemory_Read/Write tests
pub const USER_MEMORY_SIZE: usize = 16;

/// Unified state for conformance tests.
///
/// Combines runtime state (individual address, auth keys, IP config) with
/// ETS-loaded tables (ADT, AST, COT, APP) and test memory regions.
///
/// This implements both `StackState`/`IpStackState` for runtime configuration
/// and `Has*Table` traits for table access.
pub struct ConformanceState {
    // ========================================================================
    // Runtime State
    // ========================================================================
    individual_address: core::cell::Cell<zweidraehte::address::IndividualAddress>,
    auth_keys: RefCell<[[u8; 4]; 3]>,

    // ========================================================================
    // IP State
    // ========================================================================
    platform: MockIpPlatform,
    configured_ip: RefCell<Ipv4Addr>,
    configured_subnet: RefCell<Ipv4Addr>,
    configured_gateway: RefCell<Ipv4Addr>,
    ip_assignment_method: RefCell<u8>,
    routing_multicast: RefCell<Ipv4Addr>,
    ttl: RefCell<u8>,
    friendly_name: RefCell<[u8; 30]>,
    friendly_name_len: RefCell<usize>,
    project_installation_id: RefCell<u16>,

    // ========================================================================
    // Tables (ADT, AST, COT, APP)
    // ========================================================================
    pub adt: RefCell<conformance_config::AddrTab>,
    pub ast: RefCell<conformance_config::AssoTab>,
    pub cot: RefCell<conformance_config::CoTab>,
    /// Application program table (holds both load and run state machines)
    pub app: RefCell<Application<()>>,

    // ========================================================================
    // Test Memory Regions
    // ========================================================================
    /// Linear memory region for A_Memory_Read/Write tests (0x0200-0x02FF)
    /// This is freely accessible (no access level restriction) for M-2.6/M-2.7 tests.
    pub linear_memory: RefCell<[u8; LINEAR_MEMORY_SIZE]>,
    /// Level 2 memory block for authorization tests (0x0300-0x03FF)
    /// Requires access level <= 2. Used by M-2.6 as "protected" and M-2.11 as level 2 block.
    pub level2_memory: RefCell<[u8; LEVEL2_MEMORY_SIZE]>,
    /// Level 1 memory block for M-2.11 authorization tests (0x0400-0x04FF)
    /// Requires access level <= 1.
    pub level1_memory: RefCell<[u8; LEVEL1_MEMORY_SIZE]>,
    /// User memory region for A_UserMemory_Read/Write tests (0x7FF0-0x7FFF)
    /// Used by M-2.31/M-2.32 tests.
    pub user_memory: RefCell<[u8; USER_MEMORY_SIZE]>,
}

impl ConformanceState {
    /// Create new conformance state with test defaults.
    pub fn new(
        addr_tab: conformance_config::AddrTab,
        asso_tab: conformance_config::AssoTab,
        co_tab: conformance_config::CoTab,
        app_table: Application<()>,
        platform: MockIpPlatform,
    ) -> Self {
        Self {
            individual_address: core::cell::Cell::new(zweidraehte::address::IndividualAddress::new(1, 0, 1)),
            auth_keys: RefCell::new([[0xFF; 4]; 3]),
            platform,
            configured_ip: RefCell::new(Ipv4Addr::new(0, 0, 0, 0)),
            configured_subnet: RefCell::new(Ipv4Addr::new(0, 0, 0, 0)),
            configured_gateway: RefCell::new(Ipv4Addr::new(0, 0, 0, 0)),
            ip_assignment_method: RefCell::new(0x04), // DHCP
            routing_multicast: RefCell::new(zweidraehte::DEFAULT_MULTICAST_ADDR),
            ttl: RefCell::new(16),
            friendly_name: RefCell::new([0; 30]),
            friendly_name_len: RefCell::new(0),
            project_installation_id: RefCell::new(0),
            adt: RefCell::new(addr_tab),
            ast: RefCell::new(asso_tab),
            cot: RefCell::new(co_tab),
            app: RefCell::new(app_table),
            linear_memory: RefCell::new([0x0F; LINEAR_MEMORY_SIZE]),
            level2_memory: RefCell::new([0xAA; LEVEL2_MEMORY_SIZE]),
            level1_memory: RefCell::new([0xFF; LEVEL1_MEMORY_SIZE]),
            user_memory: RefCell::new([0xFF; USER_MEMORY_SIZE]),
        }
    }
}

// ============================================================================
// StackState Implementation for ConformanceState
// ============================================================================

impl Default for ConformanceState {
    fn default() -> Self {
        use zweidraehte::objects::tables::Table;
        Self::new(Table::new(), Table::new(), Table::new(), Application::new(), MockIpPlatform::new())
    }
}

impl zweidraehte::StackState for ConformanceState {
    fn individual_address(&self) -> zweidraehte::address::IndividualAddress {
        self.individual_address.get()
    }

    fn set_individual_address(&self, addr: zweidraehte::address::IndividualAddress) {
        self.individual_address.set(addr);
    }

    fn serial_number(&self) -> &[u8; 6] {
        &device_info::SERIAL_NUMBER
    }

    fn max_apdu_length(&self) -> u16 {
        device_info::MAX_APDU_LENGTH
    }

    fn max_access_levels(&self) -> u8 {
        4
    }

    fn default_access_level(&self) -> u8 {
        self.authorize(&[0xFF, 0xFF, 0xFF, 0xFF])
    }

    fn authorize(&self, key: &[u8; 4]) -> u8 {
        let keys = self.auth_keys.borrow();
        for level in 0..3 {
            if &keys[level] == key {
                return level as u8;
            }
        }
        3 // Minimum access
    }

    fn key_write(&self, level: u8, key: &[u8; 4], current_access_level: u8) -> u8 {
        if level >= 3 {
            return 0xFF;
        }
        if current_access_level > level {
            return 0xFF;
        }
        self.auth_keys.borrow_mut()[level as usize] = *key;
        level
    }
}

impl IpStackState for ConformanceState {
    fn current_ip_address(&self) -> Ipv4Addr {
        self.platform.current_ip_address()
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.platform.current_subnet_mask()
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        self.platform.current_default_gateway()
    }

    fn mac_address(&self) -> [u8; 6] {
        self.platform.mac_address()
    }

    fn current_ip_assignment_method(&self) -> u8 {
        self.platform.current_ip_assignment_method()
    }

    fn ip_capabilities(&self) -> u8 {
        self.platform.ip_capabilities()
    }

    fn knxnetip_device_capabilities(&self) -> u16 {
        self.platform.knxnetip_device_capabilities()
    }

    fn configured_ip_address(&self) -> Ipv4Addr {
        *self.configured_ip.borrow()
    }

    fn set_configured_ip_address(&self, addr: Ipv4Addr) {
        *self.configured_ip.borrow_mut() = addr;
    }

    fn configured_subnet_mask(&self) -> Ipv4Addr {
        *self.configured_subnet.borrow()
    }

    fn set_configured_subnet_mask(&self, mask: Ipv4Addr) {
        *self.configured_subnet.borrow_mut() = mask;
    }

    fn configured_default_gateway(&self) -> Ipv4Addr {
        *self.configured_gateway.borrow()
    }

    fn set_configured_default_gateway(&self, gateway: Ipv4Addr) {
        *self.configured_gateway.borrow_mut() = gateway;
    }

    fn ip_assignment_method(&self) -> u8 {
        *self.ip_assignment_method.borrow()
    }

    fn set_ip_assignment_method(&self, method: u8) {
        *self.ip_assignment_method.borrow_mut() = method;
    }

    fn routing_multicast_address(&self) -> Ipv4Addr {
        *self.routing_multicast.borrow()
    }

    fn set_routing_multicast_address(&self, addr: Ipv4Addr) {
        *self.routing_multicast.borrow_mut() = addr;
    }

    fn ttl(&self) -> u8 {
        *self.ttl.borrow()
    }

    fn set_ttl(&self, ttl: u8) {
        *self.ttl.borrow_mut() = ttl;
    }

    fn friendly_name_len(&self) -> usize {
        *self.friendly_name_len.borrow()
    }

    fn friendly_name(&self, buf: &mut [u8]) -> usize {
        let name = self.friendly_name.borrow();
        let len = self.friendly_name_len().min(buf.len());
        buf[..len].copy_from_slice(&name[..len]);
        len
    }

    fn set_friendly_name(&self, name: &[u8]) {
        let mut fname = self.friendly_name.borrow_mut();
        let len = name.len().min(30);
        fname[..len].copy_from_slice(&name[..len]);
        fname[len..].fill(0);
        *self.friendly_name_len.borrow_mut() = len;
    }

    fn project_installation_id(&self) -> u16 {
        *self.project_installation_id.borrow()
    }

    fn set_project_installation_id(&self, id: u16) {
        *self.project_installation_id.borrow_mut() = id;
    }
}

// ============================================================================
// Table Accessor Trait Implementations for ConformanceState
// ============================================================================

impl HasAddressTable for ConformanceState {
    type ADT = conformance_config::AddrTab;
    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl HasAssociationTable for ConformanceState {
    type AST = conformance_config::AssoTab;
    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl HasCommunicationObjectTable for ConformanceState {
    type COT = conformance_config::CoTab;
    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

impl HasApplication for ConformanceState {
    type APP = Application<()>;
    fn app(&self) -> &RefCell<Self::APP> {
        &self.app
    }
}

/// Memory map for conformance tests.
///
/// Memory layout:
/// - 0x0100-0x0115: Address Table (ADT) - 22 bytes max (11 entries * 2 bytes)
/// - 0x0116-0x014F: Association Table (AST) - 48 bytes max (11 entries * 4 bytes + 4 header)
/// - 0x0150-0x019F: Communication Object Table (COT) - 24 bytes max (11 entries * 2 bytes + 2 header)
/// - 0x0200-0x02FF: Linear memory (256 bytes) - freely accessible (no restriction)
/// - 0x0300-0x03FF: Level 2 block (256 bytes) - requires access level <= 2
/// - 0x0400-0x04FF: Level 1 block (256 bytes) - requires access level <= 1
///
/// This layout matches what the conformance tests expect:
/// - M-2.6/M-2.7: MEMPOS = 0x0200 (accessible), MEMPOS_PROTECTED = 0x0300 (protected for level 3)
/// - M-2.11: MEM_START_BLOCK_LEVEL_1 = 0x0400, MEM_START_BLOCK_LEVEL_2 = 0x0300
#[derive(Debug, Default, Clone, Copy)]
pub struct ConformanceMemoryMap;

impl ConformanceMemoryMap {
    /// Base address for Address Table
    pub const ADT_BASE: u16 = 0x0100;
    /// Base address for Association Table
    pub const AST_BASE: u16 = 0x0116;
    /// Base address for Communication Object Table
    pub const COT_BASE: u16 = 0x0150;
    /// Base address for linear memory region (freely accessible)
    pub const LINEAR_MEMORY_BASE: u16 = 0x0200;
    /// Base address for level 2 memory block (requires access level <= 2)
    pub const LEVEL2_MEMORY_BASE: u16 = 0x0300;
    /// Base address for level 1 memory block (requires access level <= 1)
    pub const LEVEL1_MEMORY_BASE: u16 = 0x0400;
    /// Base address for user memory region (for A_UserMemory_* tests)
    pub const USER_MEMORY_BASE: u16 = 0x7FF0;
}

impl zweidraehte::memory::MemoryMap<ConformanceState> for ConformanceMemoryMap {
    fn read(
        &self,
        tables: &ConformanceState,
        address: u16,
        data: &mut [u8],
        access_level: u8,
    ) -> Result<usize, zweidraehte::memory::MemoryError> {
        use zweidraehte::memory::MemoryError;
        use zweidraehte::objects::tables::TableMemory;

        let end_address = address.saturating_add(data.len() as u16);

        // Address Table (ADT): 0x0100 - 0x0115
        let adt = tables.adt.borrow();
        let adt_data = adt.data_ref();
        let adt_end = Self::ADT_BASE + adt_data.len() as u16;
        if address >= Self::ADT_BASE && end_address <= adt_end {
            let offset = (address - Self::ADT_BASE) as usize;
            data.copy_from_slice(&adt_data[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Association Table (AST): 0x0116 - 0x014F
        let ast = tables.ast.borrow();
        let ast_data = ast.data_ref();
        let ast_end = Self::AST_BASE + ast_data.len() as u16;
        if address >= Self::AST_BASE && end_address <= ast_end {
            let offset = (address - Self::AST_BASE) as usize;
            data.copy_from_slice(&ast_data[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Communication Object Table (COT): 0x0150 - 0x019F
        let cot = tables.cot.borrow();
        let cot_data = cot.data_ref();
        let cot_end = Self::COT_BASE + cot_data.len() as u16;
        if address >= Self::COT_BASE && end_address <= cot_end {
            let offset = (address - Self::COT_BASE) as usize;
            data.copy_from_slice(&cot_data[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Linear memory: 0x0200 - 0x02FF (256 bytes)
        // Freely accessible - no access level restriction.
        // Used by M-2.6/M-2.7 tests as "accessible" memory.
        if address >= Self::LINEAR_MEMORY_BASE && end_address <= Self::LINEAR_MEMORY_BASE + LINEAR_MEMORY_SIZE as u16 {
            let offset = (address - Self::LINEAR_MEMORY_BASE) as usize;
            let mem = tables.linear_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Level 2 memory block: 0x0300 - 0x03FF (256 bytes)
        // Requires access level <= 2 (levels 0, 1, or 2).
        // For M-2.6 tests: "protected" (level 3 = no access).
        // For M-2.11 tests: "level 2 block" accessible with default key.
        if address >= Self::LEVEL2_MEMORY_BASE && end_address <= Self::LEVEL2_MEMORY_BASE + LEVEL2_MEMORY_SIZE as u16 {
            if access_level > 2 {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL2_MEMORY_BASE) as usize;
            let mem = tables.level2_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Level 1 memory block: 0x0400 - 0x04FF (256 bytes)
        // Requires access level <= 1 (levels 0 or 1 only).
        // Used by M-2.11 tests as "level 1 block".
        if address >= Self::LEVEL1_MEMORY_BASE && end_address <= Self::LEVEL1_MEMORY_BASE + LEVEL1_MEMORY_SIZE as u16 {
            if access_level > 1 {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL1_MEMORY_BASE) as usize;
            let mem = tables.level1_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // User memory region: 0x7FF0 - 0x7FFF (16 bytes)
        // Freely accessible for A_UserMemory_Read/Write tests (M-2.31/M-2.32).
        if address >= Self::USER_MEMORY_BASE && end_address <= Self::USER_MEMORY_BASE + USER_MEMORY_SIZE as u16 {
            let offset = (address - Self::USER_MEMORY_BASE) as usize;
            let mem = tables.user_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Address is outside accessible range
        Err(MemoryError::NotAccessible)
    }

    fn write(
        &self,
        tables: &ConformanceState,
        address: u16,
        data: &[u8],
        access_level: u8,
    ) -> Result<usize, zweidraehte::memory::MemoryError> {
        use zweidraehte::memory::MemoryError;
        use zweidraehte::objects::tables::TableMemory;

        let end_address = address.saturating_add(data.len() as u16);

        // Address Table (ADT): 0x0100 - 0x0115
        {
            let adt = tables.adt.borrow();
            let adt_end = Self::ADT_BASE + adt.data_ref().len() as u16;
            if address >= Self::ADT_BASE && end_address <= adt_end {
                drop(adt);
                let mut adt = tables.adt.borrow_mut();
                let offset = (address - Self::ADT_BASE) as usize;
                adt.data_ref_mut()[offset..offset + data.len()].copy_from_slice(data);
                return Ok(data.len());
            }
        }

        // Association Table (AST): 0x0116 - 0x014F
        {
            let ast = tables.ast.borrow();
            let ast_end = Self::AST_BASE + ast.data_ref().len() as u16;
            if address >= Self::AST_BASE && end_address <= ast_end {
                drop(ast);
                let mut ast = tables.ast.borrow_mut();
                let offset = (address - Self::AST_BASE) as usize;
                ast.data_ref_mut()[offset..offset + data.len()].copy_from_slice(data);
                return Ok(data.len());
            }
        }

        // Communication Object Table (COT): 0x0150 - 0x019F
        {
            let cot = tables.cot.borrow();
            let cot_end = Self::COT_BASE + cot.data_ref().len() as u16;
            if address >= Self::COT_BASE && end_address <= cot_end {
                drop(cot);
                let mut cot = tables.cot.borrow_mut();
                let offset = (address - Self::COT_BASE) as usize;
                cot.data_ref_mut()[offset..offset + data.len()].copy_from_slice(data);
                return Ok(data.len());
            }
        }

        // Linear memory: 0x0200 - 0x02FF (256 bytes)
        // Freely accessible - no access level restriction.
        // Used by M-2.6/M-2.7 tests as "accessible" memory.
        if address >= Self::LINEAR_MEMORY_BASE && end_address <= Self::LINEAR_MEMORY_BASE + LINEAR_MEMORY_SIZE as u16 {
            let offset = (address - Self::LINEAR_MEMORY_BASE) as usize;
            let mut mem = tables.linear_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Level 2 memory block: 0x0300 - 0x03FF (256 bytes)
        // Requires access level <= 2 (levels 0, 1, or 2).
        // For M-2.6 tests: "protected" (level 3 = no access).
        // For M-2.11 tests: "level 2 block" accessible with default key.
        if address >= Self::LEVEL2_MEMORY_BASE && end_address <= Self::LEVEL2_MEMORY_BASE + LEVEL2_MEMORY_SIZE as u16 {
            if access_level > 2 {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL2_MEMORY_BASE) as usize;
            let mut mem = tables.level2_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Level 1 memory block: 0x0400 - 0x04FF (256 bytes)
        // Requires access level <= 1 (levels 0 or 1 only).
        // Used by M-2.11 tests as "level 1 block".
        if address >= Self::LEVEL1_MEMORY_BASE && end_address <= Self::LEVEL1_MEMORY_BASE + LEVEL1_MEMORY_SIZE as u16 {
            if access_level > 1 {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL1_MEMORY_BASE) as usize;
            let mut mem = tables.level1_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // User memory region: 0x7FF0 - 0x7FFF (16 bytes)
        // Freely accessible for A_UserMemory_Read/Write tests (M-2.31/M-2.32).
        if address >= Self::USER_MEMORY_BASE && end_address <= Self::USER_MEMORY_BASE + USER_MEMORY_SIZE as u16 {
            let offset = (address - Self::USER_MEMORY_BASE) as usize;
            let mut mem = tables.user_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Address is outside accessible range
        Err(MemoryError::NotAccessible)
    }
}

/// Device descriptor type 2 (DD2) data for conformance tests.
///
/// This must match the DD2_RESPONSE variable in the conformance test suite.
/// Format:
/// - Bytes 0-1: Application manufacturer code (0x0001)
/// - Bytes 2-3: Manufacturer-specific device type (0x0203)
/// - Byte 4: Version (0x04)
/// - Byte 5: Link management support (bit 7=0) + Logical tag base (0x05)
/// - Bytes 6-13: Channel information (4 channels)
pub const CONFORMANCE_DD2: [u8; 14] =
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E];

/// User Manufacturer Info for conformance tests.
///
/// This must match the expected response in the conformance test suite.
/// Format: Manufacturer ID (2 bytes) + Device Type (1 byte)
pub const CONFORMANCE_USER_MANUFACTURER_INFO: [u8; 3] = [0x00, 0x00, 0x00];

impl StackDefinition for ConformanceTestStack {
    const DEVICE: &'static zweidraehte::ets::DeviceDescriptor = &device_info::DEVICE;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = Some(&CONFORMANCE_DD2);
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = Some(&CONFORMANCE_USER_MANUFACTURER_INFO);
    const MAX_APDU_LENGTH: u16 = device_info::MAX_APDU_LENGTH;
    type P = TestParameters;
    type CO = ConformanceComObjects;
    type LLB = MockLinkLayerBuilder<16, 16>;
    type State = ConformanceState;
    type Mem = ConformanceMemoryMap;

    type InterfaceObjects<'a> = KnxIpInterfaceObjects<'a>;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_conformance_interface_objects(state)
    }
}

// ============================================================================
// Static Resources
// ============================================================================

// Injection channel for sending messages into the stack
static INJECTION_CHANNEL: StaticCell<Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, 16>> = StaticCell::new();

// Capture channel for receiving messages from the stack
static CAPTURE_CHANNEL: StaticCell<Channel<NoopRawMutex, CapturedLinkLayerMessage, 16>> = StaticCell::new();

// Stack resources - buffer size calculated from MAX_APDU_LENGTH
static STACK_RESOURCES: StaticCell<StackResources<ConformanceTestStack, { device_info::BUFFER_SIZE }, 4>> =
    StaticCell::new();

// Buffer manager for test injections - use BUFFER_SIZE from device_info
static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();

// ============================================================================
// Full Stack Harness
// ============================================================================

/// Full stack test harness with MockLinkLayer
///
/// This harness runs the complete KNX stack and provides methods to:
/// - Inject telegrams (simulating incoming messages from the bus)
/// - Capture outgoing telegrams (messages the stack sends to the bus)
/// - Control device state (programming mode, etc.)
pub struct FullStackHarness {
    handle: MockLinkLayerHandle<16, 16>,
    buffer_manager: DynBufferManager<'static>,
    stack: zweidraehte::Stack<'static, ConformanceTestStack>,
}

impl FullStackHarness {
    /// Create a new full stack harness
    ///
    /// Returns the harness and a runner that must be spawned as a task.
    pub fn new() -> (Self, Runner<'static, ConformanceTestStack>) {
        // Initialize static channels
        let injection_channel = INJECTION_CHANNEL.init(Channel::new());
        let capture_channel = CAPTURE_CHANNEL.init(Channel::new());

        // Initialize buffer manager for test injections
        let buffers = INJECTION_BUFFERS.init([[0u8; device_info::BUFFER_SIZE]; 16]);
        // SAFETY: We're initializing the buffer manager with our static buffers
        let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
        let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
        // SAFETY: We're transmuting to 'static because the buffer manager lives for the entire program
        let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

        // Create MockLinkLayerBuilder with capture support
        let (link_layer_builder, handle) =
            MockLinkLayerBuilder::<16, 16>::with_capture(injection_channel, capture_channel);

        // Create tables from configuration with their memory-mapped base addresses
        let (addr_tab, asso_tab, co_tab) = conformance_config::ConformanceTestConfig::create_tables(
            ConformanceMemoryMap::ADT_BASE as u32,
            ConformanceMemoryMap::AST_BASE as u32,
            ConformanceMemoryMap::COT_BASE as u32,
        );

        // Create application table - starts loaded and running for conformance tests
        use zweidraehte::objects::tables::LoadEvent;
        let mut app_table = Application::<()>::new();
        // Load the application (using None for alloc_address since these are
        // simple state transitions without RelativeData allocation)
        // The app automatically transitions HALTED -> READY -> RUNNING when loading completes
        app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Create unified conformance state (combines tables + runtime state)
        let state = ConformanceState::new(addr_tab, asso_tab, co_tab, app_table, MockIpPlatform::new());

        // Create stack resources
        let resources = STACK_RESOURCES.init(StackResources::new());

        // Create hook context (initially with null COT pointer)
        let hook_context = ConformanceHookContext::new();

        // Create stack
        let (stack, runner) = zweidraehte::new(
            resources,
            ConformanceComObjects::new(),
            hook_context,
            link_layer_builder,
            state,
            ConformanceMemoryMap,
        );

        // Patch the hook context with the COT reference
        // SAFETY: The COT lives in Inner which is stored in STACK_RESOURCES,
        // so it has 'static lifetime. The stack is single-threaded (embassy).
        unsafe {
            stack.hook_context().set_cot(stack.communication_object_table());
        }

        let harness = Self { handle, buffer_manager: dyn_buffer_manager, stack };
        (harness, runner)
    }

    /// Allocate a buffer and create a KnxMessageBuffer from raw bytes
    pub async fn create_message(&self, data: &[u8], service_type: ServiceType) -> KnxMessageBuffer<Buffer<'static>> {
        let mut buffer = self.buffer_manager.alloc().await;
        buffer.fill_from_slice(data);
        KnxMessageBuffer::new(buffer, service_type)
    }

    /// Inject a telegram into the stack (simulating incoming message from bus)
    pub async fn inject(&self, msg: KnxMessageBuffer<Buffer<'static>>) {
        self.handle.inject(msg).await;
    }

    /// Wait for and receive a captured outgoing telegram
    pub async fn receive_captured(&self) -> Option<CapturedLinkLayerMessage> {
        self.handle.receive_captured().await
    }

    /// Try to receive a captured telegram without blocking
    pub fn try_receive_captured(&self) -> Option<CapturedLinkLayerMessage> {
        self.handle.try_receive_captured()
    }

    /// Set the programming mode flag on the DUT
    ///
    /// When enabled, the device responds to A_IndividualAddress_Read broadcasts.
    pub fn set_programming_mode(&self, enabled: bool) {
        use zweidraehte::objects::interface::HasDeviceObject;
        self.stack.interface_objects().set_programming_mode_enabled(enabled);
    }

    /// Drain all pending captured messages from the channel
    ///
    /// This is useful for clearing leftover messages between tests.
    /// Returns the number of messages drained.
    pub fn drain_captured(&self) -> usize {
        self.handle.drain_captured()
    }

    /// Get access to the stack for direct manipulation
    pub fn stack(&self) -> &zweidraehte::Stack<'static, ConformanceTestStack> {
        &self.stack
    }
}
