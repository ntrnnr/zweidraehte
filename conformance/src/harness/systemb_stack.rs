//! Conformance Test Stack Configuration
//!
//! Defines the device configuration, communication objects, memory map,
//! and state types used by both the DUT child process and the multi-process
//! harness.
//!
//! ## BCU1-Style Group Object Tests
//!
//! The Group Object conformance tests (1.4.1.x) require a BCU1-style application
//! where shadow objects (GO1, GO2, GO3) provide access to GO0's internal state:
//!
//! - **GO1 (ASAP 2)**: Communication flags - reading/writing controls GO0's transmission state
//! - **GO2 (ASAP 3)**: Configuration flags - reading/writing modifies GO0's COT flags
//! - **GO3 (ASAP 4)**: Value access - direct read/write of GO0's value without flag changes

// FIXME: We should replace DPT_Colour_RGB with PDT_Generic03

use core::cell::RefCell;

use super::fixture_common::{CONFORMANCE_DD2, CONFORMANCE_USER_MANUFACTURER_INFO, TestParameters};
use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    bcus::system_b::{
        ExtensionAugmentFor, MemoryLayout, SystemBDeviceModel, SystemBInterfaceObjectsFor, Tp1ExtensionState,
        Tp1SystemBDeviceState, create_system_b_objects,
    },
    context::layer::LayerContext,
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    objects::tables::Application,
    restart::EraseCode,
    storage::StaticIdentity,
};
use zweidraehte_proto::AccessContext;

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
    use zweidraehte_device::ets::EtsComObjects;
    use zweidraehte_device::objects::comm::ComObject;
    use zweidraehte_proto::dpt::{DPT_Colour_RGB, DPT_Switch, DPT_Value_1_Ucount};

    // `bus_hook` keeps the derive-generated `ComObjects` dispatch but lets
    // us write the `ComObjectBusHook` impl (the shadow-object mirroring)
    // ourselves — see the hook impl below the module.
    #[derive(EtsComObjects)]
    #[ets(bus_hook)]
    pub struct ConformanceComObjects {
        // ================================================================
        // GO0-GO3: 1-bit main object and shadow objects (ASAP 1-4)
        // ================================================================
        /// GO0: Main 1-bit object (UINT1)
        /// This is the primary test object whose flags/value are accessed via GO1-GO3
        #[ets(index = 0)]
        pub go_0: ComObject<DPT_Switch>,

        /// GO1: Communication flags (4-bit / UINT4)
        /// Bit 0: Read request pending
        /// Bit 1: Write/Transmission request pending
        /// Bit 2: Error flag (0=OK, 1=Error)
        /// Bit 3: Update flag
        #[ets(index = 1)]
        pub go_1_comm_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO2: Configuration flags (8-bit / UINT8)
        /// Bits 0-1: Priority (0=System, 1=High, 2=Alarm, 3=Low)
        /// Bit 2: Communication Enable
        /// Bit 3: Read Enable
        /// Bit 4: Write Enable
        /// Bit 5: Read on Init
        /// Bit 6: Transmission Enable
        /// Bit 7: Update Enable (Read Response Update)
        ///
        /// Seeded with GO0's default flags byte so the shadow value is
        /// sensible even before the first `prepare_read` recomputes it
        /// from the live CoTab.
        #[ets(index = 2, initial = DPT_Value_1_Ucount::from(0xDFu8))]
        pub go_2_config_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO3: Value of GO0 as 8-bit (for reading/writing without affecting flags)
        #[ets(index = 3)]
        pub go_3_value: ComObject<DPT_Value_1_Ucount>,

        // ================================================================
        // GO0_BYTE3-GO3_BYTE3: 3-byte main object and shadow objects (ASAP 5-8)
        // For invalid data length tests (1.4.1.4a)
        // ================================================================
        /// GO0_BYTE3: 3-byte version of GO0 for invalid data length tests
        #[ets(index = 4)]
        pub go_0_byte3: ComObject<DPT_Colour_RGB>,

        /// GO1_BYTE3: Communication flags for GO0_BYTE3
        #[ets(index = 5)]
        pub go_1_byte3_comm_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO2_BYTE3: Configuration flags for GO0_BYTE3 (same default
        /// seed rationale as GO2).
        #[ets(index = 6, initial = DPT_Value_1_Ucount::from(0xDFu8))]
        pub go_2_byte3_config_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO3_BYTE3: Value of GO0_BYTE3 as 3-byte (for reading/writing without affecting flags)
        #[ets(index = 7)]
        pub go_3_byte3_value: ComObject<DPT_Colour_RGB>,

        // ================================================================
        // Additional test objects (ASAP 9-11)
        // ================================================================
        /// GO4: For Read on Init testing
        #[ets(index = 8)]
        pub go_4: ComObject<DPT_Value_1_Ucount>,

        /// GO5: 8-bit object for network layer test 3.1 (long format response)
        #[ets(index = 9)]
        pub go_5_network_test: ComObject<DPT_Value_1_Ucount>,

        /// GO6: 1-bit object for transport layer test 2.1 + security GO test
        #[ets(index = 10)]
        pub go_6_transport_test: ComObject<DPT_Switch>,

        // ================================================================
        // Security GO test objects (ASAP 12-13) — for section 3.8.17
        // ================================================================
        /// GO_SEC_0: 1-bit object for security GO flag testing.
        /// Receives on 1/1/1 (TSAP 2), transmits on 2/2/2 (TSAP 12).
        #[ets(index = 11)]
        pub go_sec_0: ComObject<DPT_Switch>,

        /// GO_SEC_1: 1-bit object for security GO flag testing.
        /// Receives on 3/3/3 (TSAP 15), transmits on 4/4/4 (TSAP 16).
        #[ets(index = 12)]
        pub go_sec_1: ComObject<DPT_Switch>,

        /// GO_SEC_3: 1-bit object for security GO flag testing (C-only).
        /// Receives on 6/6/6 (TSAP 18).
        #[ets(index = 13)]
        pub go_sec_3: ComObject<DPT_Switch>,

        // ================================================================
        // Diagnostic test objects (ASAP 15-17) — for Section 6.2
        // ================================================================
        /// GO_DIAG_NO_C: 1-byte object WITHOUT communication enable flag.
        /// Used by 6.2.6 and 6.2.14 for config flags error tests.
        #[ets(index = 14)]
        pub go_diag_no_c: ComObject<DPT_Value_1_Ucount>,

        /// GO_DIAG_NO_W: 1-byte object WITHOUT write enable flag.
        /// Used by 6.2.6 for "W-flag not set" test.
        #[ets(index = 15)]
        pub go_diag_no_w: ComObject<DPT_Value_1_Ucount>,

        /// GO_DIAG_NO_T: 1-byte object WITHOUT transmission enable flag.
        /// Used by 6.2.14 for "T-flag not set" test.
        #[ets(index = 16)]
        pub go_diag_no_t: ComObject<DPT_Value_1_Ucount>,
    }
}

// Custom bus hooks for the shadow objects (`#[ets(bus_hook)]` above).
use comm_objs::{ConformanceComObjects, Index as CoIndex};
use std::sync::atomic::{AtomicPtr, Ordering};
use zweidraehte_device::objects::comm::ComObjectBusHook;
use zweidraehte_device::objects::tables::CommunicationObjectTable;

// ============================================================================
// CoTab pointer for the ComObjectBusHook shadow objects
// ============================================================================
//
// The 1.4.1 group-object tests synthesise BCU1-style "shadow" GOs
// (GO1/GO2/GO3) that mirror GO0's status + configured CoTab flags +
// value. `GO2 ← bus-write` mutates the live CoTab (to toggle ROI),
// which means `ComObjectBusHook::handle_write` needs a reference to
// the CoTab from `&mut self` alone. Rather than fight the
// `#[derive(EtsComObjects)]` macro — which requires every struct
// field to be a ComObject with an index — we park the CoTab pointer
// in a process-global static set once from each DUT binary's startup.
// Same pattern as `harness::ipc::PRIMARY_SOCKET_FD`. This keeps all
// the unsafety localised to the conformance crate, off the library's
// public traits.

static COT_PTR: AtomicPtr<RefCell<conformance_config::CoTab>> = AtomicPtr::new(core::ptr::null_mut());

/// Publish the COT reference used by the shadow-object hook.
///
/// Call once from each DUT binary's `main` after stack construction.
/// The reference must outlive the hook's use of it — the conformance
/// DUT keeps the stack + its tables alive for the entire process, so
/// any reference from the stack's `communication_object_table()`
/// satisfies that.
///
/// # Safety
/// The caller guarantees that `cot` remains a valid reference for
/// the duration of the process.
pub unsafe fn set_conformance_cot(cot: &RefCell<conformance_config::CoTab>) {
    COT_PTR.store(cot as *const _ as *mut _, Ordering::Release);
}

fn conformance_cot() -> Option<&'static RefCell<conformance_config::CoTab>> {
    let ptr = COT_PTR.load(Ordering::Acquire);
    // SAFETY: if non-null, the pointer was installed by `set_conformance_cot`
    // with the caller's guarantee that the referent outlives the process.
    unsafe { ptr.as_ref() }
}

// `ComObjects` (the per-index dispatch) is derive-generated —
// `#[ets(bus_hook)]` only leaves the `ComObjectBusHook` impl below to us.

// ============================================================================
// BCU1-style shadow-object hook
// ============================================================================
//
// GO1/GO2/GO3 (and their BYTE3 siblings) are synthesised objects that
// mirror GO0's runtime state for the 1.4.1 group-object conformance
// tests. The AL calls `prepare_read` before emitting a
// `GroupValue_Response` and `handle_write` after accepting a
// `GroupValue_Write`, giving us a synchronous place to wire the
// mirroring logic. The CoTab pointer used by GO2's runtime-flag
// mutation comes from the static installed by `set_conformance_cot`.

impl ComObjectBusHook for ConformanceComObjects {
    fn prepare_read(&mut self, idx: u16) {
        match CoIndex::from_index(idx) {
            Some(CoIndex::Go1CommFlags) => {
                // GO1 reads GO0's communication status
                let flags = self.go_0.status.to_flags_byte();
                self.go_1_comm_flags.value.as_mut()[0] = flags;
            }
            Some(CoIndex::Go2ConfigFlags) => {
                // GO2 reads GO0's configuration flags from the COT
                // GO0 is at ASAP 1 (index 1 in the COT)
                if let Some(cot) = conformance_cot()
                    && let Some(flags) = cot.borrow().object_flags(1)
                {
                    self.go_2_config_flags.value.as_mut()[0] = flags.to_byte();
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
                if let Some(cot) = conformance_cot()
                    && let Some(flags) = cot.borrow().object_flags(5)
                {
                    self.go_2_byte3_config_flags.value.as_mut()[0] = flags.to_byte();
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

    fn handle_write(&mut self, idx: u16) {
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
                if let Some(cot) = conformance_cot() {
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
                if let Some(cot) = conformance_cot() {
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
// - TSAP 1:  0x0801 (1/0/1) → CO 10 (GO5, 8-bit for network layer test 3.1)
// - TSAP 2:  0x0901 (1/1/1) → CO 12 (GO_SEC_0, security test receive)
// - TSAP 3:  0x1000 (2/0/0) → CO 1  (GO0, main 1-bit object)
// - TSAP 4:  0x1001 (2/0/1) → CO 2  (GO1, comm flags)
// - TSAP 5:  0x1002 (2/0/2) → CO 3  (GO2, config flags)
// - TSAP 6:  0x1003 (2/0/3) → CO 4  (GO3, value)
// - TSAP 7:  0x1005 (2/0/5) → CO 9  (GO4, read on init)
// - TSAP 8:  0x1100 (2/1/0) → CO 5  (GO0_BYTE3, 3-byte main object for test 1.4.1.4a)
// - TSAP 9:  0x1101 (2/1/1) → CO 6  (GO1_BYTE3, comm flags for GO0_BYTE3)
// - TSAP 10: 0x1102 (2/1/2) → CO 7  (GO2_BYTE3, config flags for GO0_BYTE3)
// - TSAP 11: 0x1103 (2/1/3) → CO 8  (GO3_BYTE3, value for GO0_BYTE3)
// - TSAP 12: 0x1202 (2/2/2) → CO 12 (GO_SEC_0, security test SEND)
// - TSAP 13: 0x1906 (3/1/6) → CO 7  (GO2_BYTE3, Section 6.2 GO diagnostics, secure)
// - TSAP 14: 0x1907 (3/1/7) → CO 7  (GO2_BYTE3, Section 6.2 GO diagnostics, plain)
// - TSAP 15: 0x1B03 (3/3/3) → CO 13 (GO_SEC_1, security test receive)
// - TSAP 16: 0x2404 (4/4/4) → CO 13 (GO_SEC_1, security test SEND)
// - TSAP 17: 0x2D05 (5/5/5) → CO 11 (GO6, transport + security GO_SEC_2)
// - TSAP 18: 0x3606 (6/6/6) → CO 14 (GO_SEC_3, C-only flag test)

pub(crate) mod conformance_config {
    use zweidraehte_device::config::{CE, RE, ROI, TE, UE, WE};
    use zweidraehte_device::knx_stack_config;
    use zweidraehte_device::objects::tables::ComObjectType;

    knx_stack_config! {
        name: ConformanceTestConfig,
        individual_address: "1.0.1",  // BDUT = 1.0.1 = 0x1001

        // NOTE: Group addresses MUST be sorted by their encoded value for binary search!
        // Address encoding (3-level): ((main & 0x1F) << 11) | ((middle & 0x07) << 8) | sub
        group_addresses: {
            // Sorted order by encoded value:
            1 => "1/0/1",  // 0x0801 - for network layer test 3.1 (8-bit, long format)
            2 => "1/1/1",  // 0x0901 - security GO test (GO_SEC_0 receive)
            3 => "2/0/0",  // 0x1000 (main object GO0)
            4 => "2/0/1",  // 0x1001 (comm flags GO1)
            5 => "2/0/2",  // 0x1002 (config flags GO2)
            6 => "2/0/3",  // 0x1003 (value GO3)
            7 => "2/0/5",  // 0x1005 (read on init GO4)
            8 => "2/1/0",  // 0x1100 (3-byte main object GO0_BYTE3 for test 1.4.1.4a)
            9 => "2/1/1",  // 0x1101 (comm flags GO1_BYTE3)
            10 => "2/1/2", // 0x1102 (config flags GO2_BYTE3)
            11 => "2/1/3", // 0x1103 (value GO3_BYTE3)
            12 => "2/2/2", // 0x1202 - security GO test (GO_SEC_0 transmit)
            13 => "3/1/6", // 0x1906 - Section 6.2 GO diagnostics (secure, GK6)
            14 => "3/1/7", // 0x1907 - Section 6.2 GO diagnostics (plain)
            15 => "3/3/3", // 0x1B03 - security GO test (GO_SEC_1 receive)
            16 => "4/4/4", // 0x2404 - security GO test (GO_SEC_1 transmit)
            17 => "5/5/5", // 0x2D05 - for transport layer test 2.1 + security GO test (GO_SEC_2)
            18 => "6/6/6", // 0x3606 - security GO test (GO_SEC_3, C-only flag)
        },

        comm_objects: {
            // ================================================================
            // GO0-GO3: 1-bit main object and shadow objects (ASAP 1-4)
            // ================================================================
            // GO0: Main 1-bit object (UINT1) - all flags enabled by default
            1 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            // GO1: Communication flags (4-bit) - for accessing GO0's comm flags
            2 => (ComObjectType::Uint4 as u8, CE | TE | RE | WE | UE),
            // GO2: Configuration flags (8-bit) - for accessing GO0's config flags
            3 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE),
            // GO3: Value (8-bit) - for accessing GO0's value without flag modification
            // ROI flag is set for test 1.4.1.6 (Read-on-Init verification).
            4 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE | ROI),

            // ================================================================
            // GO0_BYTE3-GO3_BYTE3: 3-byte main object and shadow objects (ASAP 5-8)
            // ================================================================
            // No test drives these any more — EITT dropped the BYTE3 form of
            // 1.4.1.4a in 2024 and both it and 1.4.1.7 now run on the 1-bit
            // GO0. They stay because every later ASAP (GO4's read-on-init at
            // 9, the security GOs at 12-14) is referenced by number from the
            // association table and from the security suites, and renumbering
            // buys nothing.
            // GO0_BYTE3: 3-byte main object
            5 => (ComObjectType::Byte3 as u8, CE | TE | RE | WE | UE),
            // GO1_BYTE3: Communication flags for GO0_BYTE3 (4-bit like original GO1)
            6 => (ComObjectType::Uint4 as u8, CE | TE | RE | WE | UE),   // Uint4 = 4-bit, short format
            // GO2_BYTE3: Configuration flags for GO0_BYTE3
            7 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE),
            // GO3_BYTE3: Value for GO0_BYTE3 (3 bytes)
            8 => (ComObjectType::Byte3 as u8, CE | TE | RE | WE | UE),

            // ================================================================
            // Additional test objects (ASAP 9-11)
            // ================================================================
            // GO4: Read on Init test object - has ROI flag set
            9 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE | ROI),
            // GO5: 8-bit object for network layer test 3.1 (long format response)
            10 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE),
            // GO6: 1-bit object for transport layer test 2.1 + security GO test
            11 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),

            // ================================================================
            // Security GO test objects (ASAP 12-13) — for section 3.8.17
            // ================================================================
            // GO_SEC_0: 1-bit object, receives on 1/1/1, transmits on 2/2/2
            12 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            // GO_SEC_1: 1-bit object, receives on 3/3/3, transmits on 4/4/4
            13 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            // GO_SEC_3: 1-bit object, receives on 6/6/6 (C-only flag test)
            14 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),

            // ================================================================
            // Diagnostic test objects (ASAP 15-17) — for Section 6.2
            // ================================================================
            // GO_DIAG_NO_C: 1-byte object, C flag NOT set (no communication)
            15 => (ComObjectType::Byte1 as u8, TE | RE | WE | UE),
            // GO_DIAG_NO_W: 1-byte object, W flag NOT set (no write)
            16 => (ComObjectType::Byte1 as u8, CE | TE | RE | UE),
            // GO_DIAG_NO_T: 1-byte object, T flag NOT set (no transmit)
            17 => (ComObjectType::Byte1 as u8, CE | RE | WE | UE),
        },

        associations: {
            // Note: TSAPs are assigned based on sorted group address positions.
            // TSAP numbers match the GA index in the sorted address table.
            //
            // IMPORTANT: For COs with separate receive/send GAs, the SENDING
            // TSAP must come FIRST because sending_tsap() returns the
            // first match for a given ASAP. This means the sending association
            // (12→CO12, 16→CO13) must appear before the receiving association
            // (2→CO12, 15→CO13).
            1 => [10],   // TSAP 1  (1/0/1) → CO 10 (GO5, 8-bit for network layer test)
            12 => [12],  // TSAP 12 (2/2/2) → CO 12 (GO_SEC_0, security test SEND)
            2 => [12],   // TSAP 2  (1/1/1) → CO 12 (GO_SEC_0, security test receive)
            3 => [1],    // TSAP 3  (2/0/0) → CO 1  (GO0, 1-bit main object)
            4 => [2],    // TSAP 4  (2/0/1) → CO 2  (GO1, comm flags)
            5 => [3],    // TSAP 5  (2/0/2) → CO 3  (GO2, config flags)
            6 => [4],    // TSAP 6  (2/0/3) → CO 4  (GO3, value)
            7 => [9],    // TSAP 7  (2/0/5) → CO 9  (GO4, read on init)
            8 => [5],    // TSAP 8  (2/1/0) → CO 5  (GO0_BYTE3, 3-byte main object)
            9 => [6],    // TSAP 9  (2/1/1) → CO 6  (GO1_BYTE3, comm flags)
            // GO2_BYTE3 (CO 7): SENDING TSAP is 14 (3/1/7), must come first.
            // Also receives on 10 (2/1/2) and 13 (3/1/6).
            14 => [7],   // TSAP 14 (3/1/7) → CO 7  (GO2_BYTE3, Section 6.2 GO diagnostics SEND)
            10 => [7],   // TSAP 10 (2/1/2) → CO 7  (GO2_BYTE3, config flags receive)
            13 => [7],   // TSAP 13 (3/1/6) → CO 7  (GO2_BYTE3, Section 6.2 GO diagnostics secure receive)
            11 => [8],   // TSAP 11 (2/1/3) → CO 8  (GO3_BYTE3, value)
            16 => [13],  // TSAP 16 (4/4/4) → CO 13 (GO_SEC_1, security test SEND)
            15 => [13],  // TSAP 15 (3/3/3) → CO 13 (GO_SEC_1, security test receive)
            17 => [11],  // TSAP 17 (5/5/5) → CO 11 (GO6, transport + security GO_SEC_2)
            18 => [14],  // TSAP 18 (6/6/6) → CO 14 (GO_SEC_3, C-only flag test)
        },

        // Security configuration for Data Secure conformance tests.
        security: {
            p2p_key_capacity: 8,
            siat_capacity: 8,
            tool_key: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01",

            // Group keys: TSAP → 16-byte key.
            // Sorted by TSAP for binary search in the S-AL.
            //
            // Values are the ones in the data-security template's own
            // Security Configuration Table (supportfiles/TSSJ_SCT.csv),
            // because that template provisions keys by value; see the
            // note in tests::security::variables.
            group_keys: {
                2  => "AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA",  // TSAP 2  (1/1/1) → GK1
                12 => "BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB",  // TSAP 12 (2/2/2) → GK2
                13 => "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",  // TSAP 13 (3/1/6) → GK6
                15 => "CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC",  // TSAP 15 (3/3/3) → GK3
                16 => "DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD",  // TSAP 16 (4/4/4) → GK4
                18 => "EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE",  // TSAP 18 (6/6/6) → GK5
            },

            // GO security flags of the AN158 sample application ("2.3.1"
            // in the data-security template: GO0 A-only, GO1 A+C, GO2
            // plain, GO3 C-only). The boot image is the bench operator's
            // loaded sample app, and the EITT run restores it via
            // `full_reset` after the template preparation's factory
            // reset — with all-zero flags every secured 3.2 read died on
            // the receive-side flag check. The hand-written 3.2 suite
            // writes the same values itself in its preparation, so this
            // seed changes nothing for suites that provision explicitly.
            go_flags: {
                12 => 0x01,  // GO_SEC_0 (1/1/1 recv, 2/2/2 send): A only
                13 => 0x03,  // GO_SEC_1 (3/3/3 recv, 4/4/4 send): A+C
                14 => 0x02,  // GO_SEC_3 (6/6/6): C only
            },
        },
    }
}

// ============================================================================
// Device Information
// ============================================================================

/// Device-specific constants for Interface Objects
pub mod device_info {
    use super::*;
    use zweidraehte_device::config::{MAX_APDU_LENGTH_EXTENDED, buffer_size_for_apdu};

    /// The device descriptor for conformance testing.
    ///
    /// This is the single source of truth for all device/application metadata.
    pub const DEVICE: DeviceDescriptor = DeviceDescriptor {
        mask_version: MaskVersion::SystemBTp1,
        manufacturer_id: 0x00FA,
        hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        application_id: 0x0100,
        application_version: 0x01,
        max_address_table_entries: 254,
        max_association_table_entries: 254,
        max_com_objects: 254,
        pei_type: 0,
    };

    /// Device serial number (6 bytes)
    /// Must match BDUT_SERIAL_NUMBER in test variables (management.rs)
    /// NOTE: This is stored in runtime state, not the device descriptor
    pub const SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE];

    /// Maximum APDU length for this device.
    ///
    /// Uses the extended format (254 bytes) which is supported by KNX/IP
    /// and modern TP1 devices with Extended Frame Format.
    pub const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;

    /// Buffer size for message buffers.
    ///
    /// Calculated from the maximum APDU length plus frame overhead and headroom.
    pub const BUFFER_SIZE: usize = buffer_size_for_apdu(MAX_APDU_LENGTH);
}

// ============================================================================
// Memory Layout
// ============================================================================

/// Memory layout for interface objects.
///
/// The conformance tests use a custom memory map with table addresses at
/// fixed positions. This layout tells `create_knxip_objects` where the
/// tables live in address space (for PID_TABLE_REFERENCE responses).
pub(crate) const CONFORMANCE_MEMORY_LAYOUT: MemoryLayout = MemoryLayout::calculate(
    ConformanceMemoryMap::ADT_BASE,
    // Use the conformance test's actual table entry counts.
    conformance_config::ConformanceTestConfig::NUM_GROUP_ADDRS,
    conformance_config::ConformanceTestConfig::NUM_ASSOCIATIONS,
    conformance_config::ConformanceTestConfig::NUM_COMM_OBJECTS,
    // Application data size — not meaningful for conformance tests
    // since memory is accessed through the custom memory map.
    0,
);

// ============================================================================
// Stack Definition
// ============================================================================

/// Size of linear memory region (0x0200-0x02FF) - freely accessible
pub const LINEAR_MEMORY_SIZE: usize = 256;
/// Size of level 2 memory block (0x0320-0x03FF) - requires access level <= 2.
/// Shorter than a full page: the read-only and write-only regions sit in
/// front of it, directly behind the linear block (see `ConformanceMemoryMap`).
pub const LEVEL2_MEMORY_SIZE: usize = 224;
/// Size of level 1 memory block (0x0400-0x04FF) - requires access level <= 1
pub const LEVEL1_MEMORY_SIZE: usize = 256;
/// Size of user memory region (0x7FF0-0x7FFF) - for A_UserMemory_Read/Write tests
pub const USER_MEMORY_SIZE: usize = 16;

/// Table sizes for `SystemBDeviceState` const generics.
///
/// These match both the `ASSO6_SIZE` / `ADDR7_SIZE` / `CO7_SIZE` constants
/// from `knx_stack_config!` and the `Table<*Impl<SIZE>>` type aliases.
pub(crate) mod table_sizes {
    use super::conformance_config::ConformanceTestConfig;

    pub const ADT: usize = ConformanceTestConfig::ADDR7_SIZE;
    pub const AST: usize = ConformanceTestConfig::ASSO6_SIZE;
    pub const COT: usize = ConformanceTestConfig::CO7_SIZE;

    /// Entry counts (not byte sizes) — capacity parameters for the
    /// Data Secure tables (`GRP` = one key slot per group address,
    /// `GO` = one flag byte per communication object).
    pub const ADT_ENTRIES: usize = ConformanceTestConfig::NUM_GROUP_ADDRS;
    pub const COT_ENTRIES: usize = ConformanceTestConfig::NUM_COMM_OBJECTS;
}

/// The inner device state type used by the conformance wrapper.
///
/// The inner System B device state for conformance testing.
type InnerState =
    Tp1SystemBDeviceState<{ table_sizes::ADT }, { table_sizes::AST }, { table_sizes::COT }, IpcConformanceTestStack>;

/// Configuration for constructing a [`ConformanceState`].
///
/// Passed to [`IpcConformanceTestStack::create_state`] to produce the full state.
pub enum ConformanceStateInit {
    /// Build fresh state from pre-built tables and application.
    Fresh {
        addr_tab: conformance_config::AddrTab,
        asso_tab: conformance_config::AssoTab,
        co_tab: conformance_config::CoTab,
        app_table: Application<TestParameters>,
    },
    /// Restore from a previously-persisted config snapshot.
    Loaded(SystemBDutConfig),
}

/// Unified state for conformance tests.
///
/// Wraps [`Tp1SystemBDeviceState`] and adds test memory regions needed
/// by the conformance memory map tests.
///
/// All standard trait impls (`StackState`, `Has*Table`,
/// `HasPeiApplication`, `HasRoutingCount`) are thin forwarding impls that
/// delegate to the inner state.
pub struct ConformanceState {
    /// Base device state (runtime + tables + TP1 config).
    inner: InnerState,

    // ========================================================================
    // Test Memory Regions
    // ========================================================================
    /// Linear memory region for A_Memory_Read/Write tests (0x0200-0x02FF)
    /// This is freely accessible (no access level restriction) for M-2.6/M-2.7 tests.
    pub linear_memory: RefCell<[u8; LINEAR_MEMORY_SIZE]>,
    /// Level 2 memory block for authorization tests (0x0320-0x03FF)
    /// Requires access level <= 2. Used by M-2.6 as "protected" and M-2.11 as level 2 block.
    pub level2_memory: RefCell<[u8; LEVEL2_MEMORY_SIZE]>,
    /// Level 1 memory block for M-2.11 authorization tests (0x0400-0x04FF)
    /// Requires access level <= 1.
    pub level1_memory: RefCell<[u8; LEVEL1_MEMORY_SIZE]>,
    /// User memory region for A_UserMemory_Read/Write tests (0x7FF0-0x7FFF)
    /// Used by M-2.31/M-2.32 tests.
    pub user_memory: RefCell<[u8; USER_MEMORY_SIZE]>,

    /// DeviceModel notification slot
    dm_slot: DmNotificationSlot,
}

impl ConformanceState {
    /// Create new conformance state with pre-built tables.
    pub fn new(
        addr_tab: conformance_config::AddrTab,
        asso_tab: conformance_config::AssoTab,
        co_tab: conformance_config::CoTab,
        app_table: Application<TestParameters>,
    ) -> Self {
        let identity = StaticIdentity::new(device_info::SERIAL_NUMBER);
        let inner = InnerState::new(identity, ConformanceComObjects::new(), ());

        // Set the conformance test individual address (1.0.1).
        inner.set_individual_address(IndividualAddress::new(1, 0, 1));

        // Load the pre-built tables into the inner state.
        *inner.adt.borrow_mut() = addr_tab;
        *inner.ast.borrow_mut() = asso_tab;
        *inner.cot.borrow_mut() = co_tab;
        *inner.app.borrow_mut() = app_table;

        Self {
            inner,
            linear_memory: RefCell::new([0x0F; LINEAR_MEMORY_SIZE]),
            level2_memory: RefCell::new([0xAA; LEVEL2_MEMORY_SIZE]),
            level1_memory: RefCell::new([0xFF; LEVEL1_MEMORY_SIZE]),
            user_memory: RefCell::new([0xFF; USER_MEMORY_SIZE]),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    /// Access the inner device state directly.
    pub fn inner(&self) -> &InnerState {
        &self.inner
    }
}

// ============================================================================
// Trait Forwarding — StackState
// ============================================================================

impl StackState for ConformanceState {
    type Identity = <InnerState as StackState>::Identity;

    fn individual_address(&self) -> IndividualAddress {
        self.inner.individual_address()
    }

    fn set_individual_address(&self, addr: IndividualAddress) {
        self.inner.set_individual_address(addr);
    }

    fn identity(&self) -> &Self::Identity {
        self.inner.identity()
    }

    fn max_apdu_length(&self) -> u16 {
        device_info::MAX_APDU_LENGTH
    }

    fn set_max_apdu_length(&self, _length: u16) {
        // The conformance harness reports a fixed compile-time
        // `MAX_APDU_LENGTH` and the IPC link layer has no
        // hardware-detection step that would call this setter.
        // Intentionally inert.
    }

    fn is_programming_mode(&self) -> bool {
        self.inner.is_programming_mode()
    }

    fn set_programming_mode(&self, enabled: bool) {
        self.inner.set_programming_mode(enabled);
    }
}

// All pure-delegation trait impls (`HasSecurityMode`, `HasPersistence`,
// `HasAuthorization`, `HasExtensionState`, the table accessors,
// `HasCommObjects`, `HasGoSecurityView`, `HasDiagnosticsContext`,
// `HasRoutingCount`, `HasConnectionAuth`) come from the bundle macro.
// `StackState` (fixed APDU length) and `DeviceModelNotifier` (dm_slot)
// are the two genuinely customised traits and stay hand-written.
zweidraehte_device::forward_system_b_state_traits!(impl ConformanceState => self.inner: InnerState);

// ============================================================================
// DeviceModelNotifier Implementation
// ============================================================================

impl DeviceModelNotifier for ConformanceState {
    fn notify(&self, event: DeviceModelEvent) {
        self.dm_slot.notify(event);
    }
    fn take_event(&self) -> Option<DeviceModelEvent> {
        self.dm_slot.take_event()
    }
}

/// Memory map for conformance tests.
///
/// Memory layout:
/// - 0x0100-0x0115: Address Table (ADT) - 22 bytes max (11 entries * 2 bytes)
/// - 0x0116-0x014F: Association Table (AST) - 46 bytes max (2 header + 11 entries * 4 bytes)
/// - 0x0150-0x019F: Communication Object Table (COT) - 24 bytes max (11 entries * 2 bytes + 2 header)
/// - 0x0200-0x02FF: Linear memory (256 bytes) - freely accessible (no restriction)
/// - 0x0300-0x030F: Read-only region (16 bytes)
/// - 0x0310-0x031F: Write-only region (16 bytes)
/// - 0x0320-0x03FF: Level 2 block (224 bytes) - requires access level <= 2
/// - 0x0400-0x04FF: Level 1 block (256 bytes) - requires access level <= 1
/// - 0x7FF0-0x7FFF: User memory (16 bytes)
///
/// The read-only and write-only regions sit between the linear block and
/// the level-2 block deliberately: TSS J 5.1.5 and 5.2.4 start an access
/// on a region's last octet and run into the next one, so each protected
/// region must be reachable by overrunning the region in front of it.
///
/// This layout matches what the conformance tests expect:
/// - M-2.6/M-2.7: MEMPOS = 0x0200 (accessible), MEMPOS_PROTECTED = 0x1000 (outside the map)
/// - M-2.11: MEM_START_BLOCK_LEVEL_1 = 0x0400, MEM_START_BLOCK_LEVEL_2 = 0x0320
#[derive(Debug, Default, Clone, Copy)]
pub struct ConformanceMemoryMap;

impl ConformanceMemoryMap {
    /// Base address for Address Table — the anchor the whole layout
    /// is computed from.
    pub const ADT_BASE: u16 = 0x0100;
    /// Base address for Association Table.
    ///
    /// Derived from [`CONFORMANCE_MEMORY_LAYOUT`] rather than written
    /// out, because two things must agree and used not to: this map
    /// serves the memory, while the layout is what the interface
    /// objects report through `PID_TABLE_REFERENCE` *and* what they
    /// assign during a relative allocation. When the literals here
    /// drifted behind the fixture's growing table counts, a download
    /// that allocated and then wrote at the reported base was refused
    /// — which is exactly what a real ETS download does, and what the
    /// configuration runner's System B scenario caught.
    pub const AST_BASE: u16 = CONFORMANCE_MEMORY_LAYOUT.ast_address();
    /// Base address for Communication Object Table; see [`Self::AST_BASE`].
    pub const COT_BASE: u16 = CONFORMANCE_MEMORY_LAYOUT.cot_address();
    // The protected regions sit directly behind the freely writable
    // linear block, and behind each other:
    //
    //   0200h-02FFh  linear, read/write     (READWRITE_MEM_START/END)
    //   0300h-030Fh  read-only              (READONLY_MEM_START/END)
    //   0310h-031Fh  write-only             (WRITEONLY_MEM_START)
    //   0320h-03FFh  level-2 block
    //   0400h-04FFh  level-1 block
    //
    // Adjacency is the point, not an accident of allocation. TSS J 5.1.5
    // ("partly read only memory") writes six octets starting on the last
    // read/write octet and 5.2.4 reads six starting on the last read-only
    // octet; both need the *next* region to be the protected one, or the
    // access straddles into something with no protection to report and
    // the case tests nothing. A device that keeps its protected memory
    // somewhere unreachable from a write cannot answer these at all.

    /// Base address for linear memory region (freely accessible)
    pub const LINEAR_MEMORY_BASE: u16 = 0x0200;
    /// Base address for the read-only memory region — directly behind the
    /// linear block. Reads return a fixed pattern; writes always fail
    /// with `MemoryError::WriteProtected`, which the application layer
    /// maps to return code 0xFB (`E_READ_ONLY`). Used by Data Security
    /// conformance tests 5.1.4, 5.1.5 and 5.2.3.
    pub const READONLY_MEMORY_BASE: u16 = 0x0300;
    /// Size of the read-only region (16 bytes; the tests address one
    /// 6-byte write and a few short reads).
    pub const READONLY_MEMORY_SIZE: u16 = 0x10;
    /// Base address for the write-only memory region — directly behind
    /// the read-only one. Reads always fail with
    /// `MemoryError::WriteProtected` (mapped by the AL to return code
    /// 0xFA on the read path); writes succeed but the data is dropped.
    pub const WRITEONLY_MEMORY_BASE: u16 = 0x0310;
    /// Size of the write-only region (16 bytes).
    pub const WRITEONLY_MEMORY_SIZE: u16 = 0x10;
    /// Base address for level 2 memory block (requires access level <= 2).
    /// Starts behind the two protected regions and still covers the
    /// 03D0h/03E0h the management template's access-policy cases use.
    pub const LEVEL2_MEMORY_BASE: u16 = 0x0320;
    /// Base address for level 1 memory block (requires access level <= 1)
    pub const LEVEL1_MEMORY_BASE: u16 = 0x0400;
    /// Base address for user memory region (for A_UserMemory_* tests)
    pub const USER_MEMORY_BASE: u16 = 0x7FF0;

    /// Whether `[address, end_address)` starts inside a region and runs
    /// past its end — a *partly protected* access.
    ///
    /// The extended memory services answer with the protection they meet
    /// rather than "address void": the address is not void, part of what
    /// was asked for simply cannot be served. TSS J 5.1.5 writes six
    /// octets starting on the last read-only octet and expects FBh
    /// (E_READ_ONLY); 5.2.4 reads the same range and expects FAh
    /// (E_ACCESS_WRITE_ONLY). Both answer for the region the access
    /// *starts* in.
    pub(crate) fn straddles(address: u16, end_address: u16, base: u16, size: u16) -> bool {
        address >= base && address < base + size && end_address > base + size
    }

    /// Whether `octet` falls inside `[base, base + size)`.
    fn within(octet: u16, base: u16, size: u16) -> bool {
        octet >= base && octet < base + size
    }

    /// The error a partly protected access must report, or `None` when it
    /// straddles no boundary this map knows.
    ///
    /// The protection can come from either end. A write starting on the
    /// last read/write octet runs *into* read-only memory (TSS J 5.1.5's
    /// first case), while a write starting on the last read-only octet is
    /// refused by the region it starts in (5.1.5's second) — so both the
    /// head and the tail are asked, head first. A straddle with no
    /// protection at either end still fails, because the map serves one
    /// region per access, and reports `AccessDenied` → FCh
    /// (E_ILLEGAL_COMMAND).
    pub(crate) fn partly_protected(address: u16, end_address: u16, writing: bool) -> Option<MemoryError> {
        const REGIONS: [(u16, u16); 6] = [
            (ConformanceMemoryMap::LINEAR_MEMORY_BASE, LINEAR_MEMORY_SIZE as u16),
            (ConformanceMemoryMap::READONLY_MEMORY_BASE, ConformanceMemoryMap::READONLY_MEMORY_SIZE),
            (ConformanceMemoryMap::WRITEONLY_MEMORY_BASE, ConformanceMemoryMap::WRITEONLY_MEMORY_SIZE),
            (ConformanceMemoryMap::LEVEL2_MEMORY_BASE, LEVEL2_MEMORY_SIZE as u16),
            (ConformanceMemoryMap::LEVEL1_MEMORY_BASE, LEVEL1_MEMORY_SIZE as u16),
            (ConformanceMemoryMap::USER_MEMORY_BASE, USER_MEMORY_SIZE as u16),
        ];

        if !REGIONS.iter().any(|&(base, size)| Self::straddles(address, end_address, base, size)) {
            return None;
        }

        // The octets at each end of the access, head first: an access is
        // refused by the region it starts in before the one it reaches.
        let tail = end_address.saturating_sub(1);
        for octet in [address, tail] {
            if writing && Self::within(octet, Self::READONLY_MEMORY_BASE, Self::READONLY_MEMORY_SIZE) {
                return Some(MemoryError::WriteProtected);
            }
            if !writing && Self::within(octet, Self::WRITEONLY_MEMORY_BASE, Self::WRITEONLY_MEMORY_SIZE) {
                // The read path renders `WriteProtected` as FAh
                // (E_ACCESS_WRITE_ONLY).
                return Some(MemoryError::WriteProtected);
            }
        }
        Some(MemoryError::AccessDenied)
    }
}

impl MemoryMap<ConformanceState> for ConformanceMemoryMap {
    fn read(
        &self,
        tables: &ConformanceState,
        address: u16,
        data: &mut [u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        let end_address = address.saturating_add(data.len() as u16);

        // Address Table (ADT): 0x0100 - 0x0115
        let adt = tables.adt().borrow();
        let adt_data = adt.data_ref();
        let adt_end = Self::ADT_BASE + adt_data.len() as u16;
        if address >= Self::ADT_BASE && end_address <= adt_end {
            let offset = (address - Self::ADT_BASE) as usize;
            data.copy_from_slice(&adt_data[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Association Table (AST): 0x0116 - 0x014F
        let ast = tables.ast().borrow();
        let ast_data = ast.data_ref();
        let ast_end = Self::AST_BASE + ast_data.len() as u16;
        if address >= Self::AST_BASE && end_address <= ast_end {
            let offset = (address - Self::AST_BASE) as usize;
            data.copy_from_slice(&ast_data[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Communication Object Table (COT): 0x0150 - 0x019F
        let cot = tables.cot().borrow();
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
            if !ctx.has_level(2) {
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
            if !ctx.has_level(1) {
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

        // Read-only memory: 0x0500 - 0x050F (16 bytes).
        if address >= Self::READONLY_MEMORY_BASE
            && end_address <= Self::READONLY_MEMORY_BASE + Self::READONLY_MEMORY_SIZE
        {
            let offset = (address - Self::READONLY_MEMORY_BASE) as usize;
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = (offset + i) as u8;
            }
            return Ok(data.len());
        }

        // Write-only memory: 0x0510 - 0x051F (16 bytes). Reads always
        // reject; writes succeed silently.
        if address >= Self::WRITEONLY_MEMORY_BASE
            && end_address <= Self::WRITEONLY_MEMORY_BASE + Self::WRITEONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        // A partly protected access reports the protection it met.
        if let Some(e) = Self::partly_protected(address, end_address, false) {
            return Err(e);
        }

        // Address is outside accessible range
        Err(MemoryError::NotAccessible)
    }

    fn write(
        &self,
        tables: &ConformanceState,
        address: u16,
        data: &[u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        let end_address = address.saturating_add(data.len() as u16);

        // Address Table (ADT): 0x0100 - 0x0115
        {
            let adt = tables.adt().borrow();
            let adt_end = Self::ADT_BASE + adt.data_ref().len() as u16;
            if address >= Self::ADT_BASE && end_address <= adt_end {
                drop(adt);
                let mut adt = tables.adt().borrow_mut();
                let offset = (address - Self::ADT_BASE) as usize;
                adt.data_ref_mut()[offset..offset + data.len()].copy_from_slice(data);
                return Ok(data.len());
            }
        }

        // Association Table (AST): 0x0116 - 0x014F
        {
            let ast = tables.ast().borrow();
            let ast_end = Self::AST_BASE + ast.data_ref().len() as u16;
            if address >= Self::AST_BASE && end_address <= ast_end {
                drop(ast);
                let mut ast = tables.ast().borrow_mut();
                let offset = (address - Self::AST_BASE) as usize;
                ast.data_ref_mut()[offset..offset + data.len()].copy_from_slice(data);
                return Ok(data.len());
            }
        }

        // Communication Object Table (COT): 0x0150 - 0x019F
        {
            let cot = tables.cot().borrow();
            let cot_end = Self::COT_BASE + cot.data_ref().len() as u16;
            if address >= Self::COT_BASE && end_address <= cot_end {
                drop(cot);
                let mut cot = tables.cot().borrow_mut();
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
            if !ctx.has_level(2) {
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
            if !ctx.has_level(1) {
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

        // Read-only memory region: writes always fail.
        if address >= Self::READONLY_MEMORY_BASE
            && end_address <= Self::READONLY_MEMORY_BASE + Self::READONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        // Write-only memory region: writes succeed silently.
        if address >= Self::WRITEONLY_MEMORY_BASE
            && end_address <= Self::WRITEONLY_MEMORY_BASE + Self::WRITEONLY_MEMORY_SIZE
        {
            return Ok(data.len());
        }

        // A partly protected access reports the protection it met.
        if let Some(e) = Self::partly_protected(address, end_address, true) {
            return Err(e);
        }

        // Address is outside accessible range
        Err(MemoryError::NotAccessible)
    }
}

// ============================================================================
// Stack Definition (for conformance-dut-systemb child process)
// ============================================================================

/// Stack definition for the conformance DUT child process.
///
/// Uses `IpcLinkLayerBuilder` for communication over a Unix socket with the
/// parent (conformance-runner) process.
#[derive(Debug, Clone, Copy)]
pub struct IpcConformanceTestStack;

impl StackDefinition for IpcConformanceTestStack {
    const DEVICE: &'static DeviceDescriptor = &device_info::DEVICE;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = Some(&CONFORMANCE_DD2);
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = Some(&CONFORMANCE_USER_MANUFACTURER_INFO);
    const MAX_APDU_LENGTH: u16 = device_info::MAX_APDU_LENGTH;
    const TL_STYLE: TlStyle = TlStyle::Style3;
    const FIRST_ASAP: u16 = 1;
    type P = TestParameters;
    type CO = ConformanceComObjects;
    type LLB = super::ipc::IpcLinkLayerBuilder;
    type ES = Tp1ExtensionState;
    type State = ConformanceState;
    type StateInit = ConformanceStateInit;
    type Mem = ConformanceMemoryMap;

    fn create_state(init: Self::StateInit) -> Self::State {
        match init {
            ConformanceStateInit::Fresh { addr_tab, asso_tab, co_tab, app_table } => {
                ConformanceState::new(addr_tab, asso_tab, co_tab, app_table)
            }
            ConformanceStateInit::Loaded(snapshot) => ConformanceState::from_device_config(snapshot),
        }
    }

    type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
    type Augments<'a> = ExtensionAugmentFor<'a, Self>;

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        create_system_b_objects::<Self, _>(state, layer_ctx, &CONFORMANCE_MEMORY_LAYOUT, augments)
    }

    type DeviceModel<'a> = SystemBDeviceModel<'a, Self>;

    fn create_device_model<'a>(
        state: &'a Self::State,
        layer_context: &'a LayerContext<Self>,
        interface_objects: &'a Self::InterfaceObjects<'static>,
    ) -> Self::DeviceModel<'a>
    where
        Self::State: 'a,
    {
        SystemBDeviceModel::new(state, layer_context, interface_objects)
    }

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        _layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        use zweidraehte_device::HasExtensionState;
        use zweidraehte_device::bcus::system_b::Extension;
        state.extension_state().create_augment::<Self>(platform)
    }

    type AlExtensions = StandardAlServices;
    type LayerBuilder = PlainDeviceBuilder;
}

// ============================================================================
// ConformanceStack Integration
// ============================================================================
//
// Wires the plain stack into the generic DUT helpers in
// `crate::dut_common`, specifying how to snapshot state into the shared
// memory region and how to apply erase codes.

impl crate::dut_common::ConformanceStack for IpcConformanceTestStack {
    type DeviceConfig = SystemBDutConfig;

    fn to_device_config(state: &Self::State) -> Self::DeviceConfig {
        state.to_device_config()
    }

    fn apply_erase_code(state: &Self::State, code: EraseCode) {
        crate::dut_common::apply_erase_code_to_system_b(state.inner(), code);
    }
}

// ============================================================================
// Shared Memory Integration
// ============================================================================
//
// The shared memory stores a `SystemBDutConfig` serialized with
// postcard. This wraps the stack's own `DeviceConfig` (which handles
// auth keys, tables, load/run state, etc.) plus the test memory regions
// that the conformance harness needs across restarts.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zweidraehte_device::bcus::system_b::{DeviceConfig, Tp1ExtensionConfig};
use zweidraehte_device::layers::application::services::StandardAlServices;
use zweidraehte_device::storage::HasDeviceConfig;

/// The persisted state type for the inner `Tp1SystemBDeviceState`.
type InnerDeviceConfig =
    DeviceConfig<{ table_sizes::ADT }, { table_sizes::AST }, { table_sizes::COT }, TestParameters, Tp1ExtensionConfig>;

/// Full snapshot of conformance test state for shared memory.
///
/// Combines the stack's own `DeviceConfig` (device address, auth keys,
/// tables, load/run state, IP config) with the test memory regions that
/// the conformance harness uses.
///
/// Uses `serde_as(Bytes)` for the test memory arrays since serde's
/// built-in array support only covers sizes up to 32.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SystemBDutConfig {
    /// Core device state — serialized via the stack's `to_config()` /
    /// `from_config()` pattern, which correctly handles private fields
    /// like auth keys.
    pub inner: InnerDeviceConfig,

    /// Test memory regions used by conformance memory map tests.
    #[serde_as(as = "[_; LINEAR_MEMORY_SIZE]")]
    pub linear_memory: [u8; LINEAR_MEMORY_SIZE],
    #[serde_as(as = "[_; LEVEL2_MEMORY_SIZE]")]
    pub level2_memory: [u8; LEVEL2_MEMORY_SIZE],
    #[serde_as(as = "[_; LEVEL1_MEMORY_SIZE]")]
    pub level1_memory: [u8; LEVEL1_MEMORY_SIZE],
    #[serde_as(as = "[_; USER_MEMORY_SIZE]")]
    pub user_memory: [u8; USER_MEMORY_SIZE],
}

impl SystemBDutConfig {
    /// Build a default persisted snapshot without needing runtime state.
    ///
    /// Used by the multiprocess harness to initialize shared memory.
    pub fn default_snapshot() -> Self {
        use conformance_config::ConformanceTestConfig;

        let (addr_tab, asso_tab, co_tab) = ConformanceTestConfig::create_tables(
            ConformanceMemoryMap::ADT_BASE as u32,
            ConformanceMemoryMap::AST_BASE as u32,
            ConformanceMemoryMap::COT_BASE as u32,
        );
        let mut app_table = Application::<TestParameters>::new();
        app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        let mut inner = InnerDeviceConfig::factory_default();
        inner.individual_address = IndividualAddress::new(1, 0, 1);
        inner.address_table = addr_tab;
        inner.association_table = asso_tab;
        inner.group_object_table = co_tab;
        inner.application = app_table;

        Self {
            inner,
            linear_memory: [0x0F; LINEAR_MEMORY_SIZE],
            level2_memory: [0xAA; LEVEL2_MEMORY_SIZE],
            level1_memory: [0xFF; LEVEL1_MEMORY_SIZE],
            user_memory: [0xFF; USER_MEMORY_SIZE],
        }
    }
}

impl ConformanceState {
    /// Reconstruct `ConformanceState` from a persisted snapshot.
    ///
    /// Uses the stack's `from_config()` to reconstruct the inner
    /// device state (including auth keys, tables, load/run states),
    /// then restores the test memory regions.
    pub fn from_device_config(snapshot: SystemBDutConfig) -> Self {
        let identity = StaticIdentity::new(device_info::SERIAL_NUMBER);
        let inner = InnerState::from_config(identity, snapshot.inner, ());

        Self {
            inner,
            linear_memory: RefCell::new(snapshot.linear_memory),
            level2_memory: RefCell::new(snapshot.level2_memory),
            level1_memory: RefCell::new(snapshot.level1_memory),
            user_memory: RefCell::new(snapshot.user_memory),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    /// Create a snapshot of the current state for persistence.
    ///
    /// Called by the child's restart handler right before exiting.
    /// The snapshot is then written to shared memory via postcard.
    pub fn to_device_config(&self) -> SystemBDutConfig {
        SystemBDutConfig {
            inner: self.inner.to_config(),
            linear_memory: *self.linear_memory.borrow(),
            level2_memory: *self.level2_memory.borrow(),
            level1_memory: *self.level1_memory.borrow(),
            user_memory: *self.user_memory.borrow(),
        }
    }
}
