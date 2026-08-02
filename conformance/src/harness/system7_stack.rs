//! System 7 DUT stack definition for conformance tests.
//!
//! Mirrors the plain [`IpcConformanceTestStack`] but on the System 7
//! family (mask 0705h): RT8 tables with the individual address inside
//! the address-table blob, `System7MemoryMap`'s absolute address space
//! (progmode byte at 0060h, OptionReg at 0100h, load-control window at
//! 0104h / B6EAh, GA table fixed at 4000h), the five-object interface
//! roster, and 16 authorization levels.
//!
//! Deliberately leaner than the System B DUT: no shadow-object hook, no
//! extra test memory regions — the smoke suite exercises the family's
//! own memory map instead. The state is the plain
//! [`Tp1StateFor7`] with no wrapper, so the whole stack definition comes
//! from `system_7_standard_stack!`.
//!
//! [`IpcConformanceTestStack`]: super::stack::IpcConformanceTestStack

use zweidraehte_device::PlainDeviceBuilder;
use zweidraehte_device::bcus::system_7::{System7DeviceConfig, System7StateInit, Tp1ExtensionConfig, Tp1StateFor7};
use zweidraehte_device::layers::application::services::StandardAlServices;
use zweidraehte_device::layers::transport::TlStyle;
use zweidraehte_device::objects::tables::{Application, HasLoadStateMachine, LoadEvent};
use zweidraehte_device::restart::EraseCode;
use zweidraehte_device::storage::{HasDeviceConfig, StaticIdentity};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

// ============================================================================
// Communication objects — one switch pair, no shadow-object machinery
// ============================================================================

pub mod comm_objs {
    use zweidraehte_device::ets::EtsComObjects;
    use zweidraehte_device::objects::comm::ComObject;
    use zweidraehte_proto::dpt::DPT_Switch;

    /// Minimal group objects for the System 7 smoke suite: a writable
    /// switch (ASAP 1) and a second one for independence checks (ASAP 2).
    #[derive(EtsComObjects)]
    pub struct System7ComObjects {
        #[ets(index = 1)]
        pub switch: ComObject<DPT_Switch>,

        #[ets(index = 2)]
        pub status: ComObject<DPT_Switch>,
    }
}

// ============================================================================
// Compile-time configuration (RT8 tables)
// ============================================================================

pub mod system7_config {
    use zweidraehte_device::config::{CE, RE, TE, UE, WE};
    use zweidraehte_device::system7_stack_config;

    system7_stack_config! {
        name: System7TestConfig,
        individual_address: "1.0.1", // BDUT = 1.0.1 = 0x1001, same as the plain DUT

        // RT8 mandates ascending group addresses (compile-time checked).
        group_addresses: {
            1 => "0/0/1", // 0x0001
            2 => "0/0/2", // 0x0002
        },

        comm_objects: {
            1 => (1, CE | TE | RE | WE | UE),
            2 => (1, CE | TE | RE | WE | UE),
        },

        associations: {
            1 => [1],
            2 => [2],
        },
    }
}

/// Where the movable tables live in the DUT's absolute address space.
/// The GA table is fixed at 4000h by the profile; these two are our
/// product-database choice.
pub const AST_ADDRESS: u32 = 0x4100;
pub const COT_ADDRESS: u32 = 0x4200;

// ============================================================================
// Device identity
// ============================================================================

pub mod device_info {
    use super::*;
    use zweidraehte_device::config::{MAX_APDU_LENGTH_EXTENDED, buffer_size_for_apdu};

    /// The System 7 DUT's device descriptor.
    pub const DEVICE: DeviceDescriptor = DeviceDescriptor {
        mask_version: MaskVersion::System7Tp1,
        manufacturer_id: 0x00FA,
        hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x07],
        application_id: 0x0700,
        application_version: 0x01,
        max_address_table_entries: system7_config::System7TestConfig::NUM_GROUP_ADDRS as u16,
        max_association_table_entries: system7_config::System7TestConfig::NUM_ASSOCIATIONS as u16,
        max_com_objects: system7_config::System7TestConfig::NUM_COMM_OBJECTS as u16,
        pei_type: 0,
    };

    /// Device serial number (6 bytes). Distinct from the System B DUT so
    /// a mixed log is attributable.
    pub const SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0x07, 0x05, 0xCA, 0xFE];

    /// Support extended frames like the System B DUT does.
    pub const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;

    /// Buffer size fitting a full extended frame.
    pub const BUFFER_SIZE: usize = buffer_size_for_apdu(MAX_APDU_LENGTH);
}

// ============================================================================
// Stack definition
// ============================================================================

/// Stack definition for the System 7 conformance DUT child process.
#[derive(Debug, Clone, Copy)]
pub struct IpcSystem7TestStack;

zweidraehte_device::system_7_standard_stack! {
    stack: IpcSystem7TestStack,
    device: &device_info::DEVICE,
    tl_style: TlStyle::Style3,
    params: super::stack::TestParameters,
    com_objects: comm_objs::System7ComObjects,
    link_layer_builder: super::ipc::IpcLinkLayerBuilder,
    platform: (),
    extension_state: zweidraehte_device::bcus::system_7::Tp1ExtensionState,
    state: Tp1StateFor7<IpcSystem7TestStack>,
    al_extensions: StandardAlServices,
    layer_builder: PlainDeviceBuilder,
    extra {
        const MAX_APDU_LENGTH: u16 = device_info::MAX_APDU_LENGTH;
    },
}

// ============================================================================
// Shared-memory snapshot + ConformanceStack wiring
// ============================================================================

/// The persisted snapshot type for the System 7 DUT.
pub type System7DutConfig = System7DeviceConfig<
    { <IpcSystem7TestStack as zweidraehte_device::bcus::system_7::System7StackDefinition>::ADT_SIZE },
    { <IpcSystem7TestStack as zweidraehte_device::bcus::system_7::System7StackDefinition>::AST_SIZE },
    { <IpcSystem7TestStack as zweidraehte_device::bcus::system_7::System7StackDefinition>::COT_SIZE },
    super::stack::TestParameters,
    Tp1ExtensionConfig,
>;

/// Build the factory boot image the parent writes into shared memory
/// before spawning the child: IA 1.0.1 (inside the RT8 address-table
/// blob), pre-loaded tables, application loaded so the device model
/// starts it on boot.
pub fn default_snapshot() -> System7DutConfig {
    use system7_config::System7TestConfig;

    let (addr_tab, asso_tab, co_tab) = System7TestConfig::create_tables(AST_ADDRESS, COT_ADDRESS);

    let mut app_table = Application::new();
    app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
    app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

    let mut config = System7DutConfig::factory_default();
    config.address_table = addr_tab;
    config.association_table = asso_tab;
    config.group_object_table = co_tab;
    config.application = app_table;
    config
}

/// The `StateInit` value the DUT builds from a shared-memory snapshot.
pub fn state_init_from_snapshot(snapshot: System7DutConfig) -> System7StateInit<StaticIdentity, System7DutConfig> {
    System7StateInit::new(StaticIdentity::new(device_info::SERIAL_NUMBER), Some(snapshot))
}

impl crate::dut_common::ConformanceStack for IpcSystem7TestStack {
    type DeviceConfig = System7DutConfig;

    fn to_device_config(state: &Self::State) -> Self::DeviceConfig {
        state.to_config()
    }

    fn apply_erase_code(state: &Self::State, code: EraseCode) {
        if matches!(code, EraseCode::Other(_)) {
            log::warn!("apply_erase_code: unsupported {:?}", code);
        }
        state.apply_erase_code(code);
    }
}
