//! Every persistent field of a device state survives a reboot.
//!
//! Each case changes one field of a factory-fresh state through the path
//! the stack uses (a setter, a key write, a table write), flushes it into a
//! store, boots another factory state from the same medium, and reads the
//! field back. Records are found by the store comparing them with its
//! durable copy and Images by their own dirty ranges, so a field without a
//! section, or a write that does not mark its range, fails here. Every case
//! runs on a byte medium and on flash.
//!
//! The extensions' fields have the same tests next to each extension; this
//! file covers the device core of both families.

use core::fmt::Debug;

use const_default::ConstDefault;
use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_device::DeviceDefinition;
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::{ComObjects, NoComObjects};
use zweidraehte_device::objects::interface::HasRoutingCount;
use zweidraehte_device::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine,
    HasPeiApplication, LoadControlPolicy, LoadEvent, LoadState, Table, TableMemory,
};
use zweidraehte_device::sections::PersistentSections;
use zweidraehte_device::storage::StaticIdentity;
use zweidraehte_device::{HasAuthorization, StackState};
use zweidraehte_nv::mock::Backing;
use zweidraehte_nv::{ByteNv, FlashLog, Flusher, LogGeometry, NvStore};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

// ============================================================================
// Harness
// ============================================================================

fn round_trip<S: PersistentSections, N: NvStore<Error = ()>, T: PartialEq + Debug>(
    open: impl Fn() -> N,
    fresh: &impl Fn() -> S,
    mutate: &impl Fn(&S),
    read: &impl Fn(&S) -> T,
) {
    let state = fresh();
    let mut store = open();
    store.load(&state).expect("format with the factory state");
    let factory = read(&state);

    mutate(&state);
    let changed = read(&state);
    assert_ne!(changed, factory, "the mutation must change the field away from its factory value");
    Flusher::new().flush(&state, &mut store).expect("flush");
    drop(store);

    let rebooted = fresh();
    open().load(&rebooted).expect("reboot");
    assert_eq!(read(&rebooted), changed, "the field did not survive a reboot");
}

/// Change one field of a factory state, flush, reboot, and require the
/// change back, on a byte medium and on flash.
fn assert_field_persists<S: PersistentSections, T: PartialEq + Debug>(
    fresh: impl Fn() -> S,
    mutate: impl Fn(&S),
    read: impl Fn(&S) -> T,
) {
    let bytes = Backing::new(4096, 1);
    round_trip(|| ByteNv::new(bytes.open_bytes(), 0, 4096), &fresh, &mutate, &read);

    let flash = Backing::new(4096, 2048);
    let geometry = LogGeometry { offset: 0, sector_size: 2048, sectors_per_bank: 1, banks: 2 };
    round_trip(|| FlashLog::<_, 264>::new(flash.open_aligned::<8>(), geometry), &fresh, &mutate, &read);
}

/// Change every control field of a table away from a factory table's, the
/// way the stack does: a load that fails on an undefined segment type
/// leaves the load state `Err` with its error code, and the MCB and table
/// reference take what an allocation would write.
fn change_control<T: TableMemory, P: LoadControlPolicy>(table: &mut Table<T, P>, seed: u8) {
    table.write_lsm(&[LoadEvent::StartLoading.into()], None);
    table.write_lsm(&[LoadEvent::AdditionalLoadControls.into(), 0xEE, 0, 0, 0, 0, 0, 0, 0, 0, 0], None);
    assert_eq!(table.load_state(), LoadState::Err, "an undefined segment type fails the load");
    table.set_table_reference(0x4000 + u32::from(seed));
    table.mcb_bytes_mut().copy_from_slice(&[seed; 8]);
}

/// The control fields: load state, error code, table reference, MCB.
fn control<T: TableMemory, P: LoadControlPolicy>(table: &Table<T, P>) -> (LoadState, u8, u32, Vec<u8>) {
    (table.load_state(), table.last_error_code(), table.table_reference(), table.mcb_bytes().to_vec())
}

/// A key no level holds yet, so `authorize` finds only the level it is
/// written to.
fn key(level: u8) -> [u8; 4] {
    [0x10 + level, 0x20, 0x30, 0x40]
}

/// Non-empty application parameters, so the parameter section has bytes.
#[derive(Clone, Copy, Debug, PartialEq, ConstDefault, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
struct TestParams {
    bytes: [u8; 24],
}

/// The checks both families share: tables, application programs and
/// versions, through the family-neutral table and application traits.
macro_rules! common_fields {
    ($fresh:expr) => {
        #[test]
        fn routing_count() {
            assert_field_persists($fresh, |s| s.set_routing_count(s.routing_count() ^ 0x03), |s| s.routing_count());
        }

        #[test]
        fn individual_address() {
            assert_field_persists(
                $fresh,
                |s| s.set_individual_address(IndividualAddress::new(3, 4, 5)),
                |s| s.individual_address(),
            );
        }

        #[test]
        fn address_table_data() {
            // Past the System 7 IA slot (bytes 1-2), which has its own case.
            assert_field_persists(
                $fresh,
                |s| s.adt().borrow_mut().write(3, &[0x0A, 0x0B]),
                |s| s.adt().borrow().data_image().to_vec(),
            );
        }

        #[test]
        fn association_table_data() {
            assert_field_persists(
                $fresh,
                |s| s.ast().borrow_mut().write(1, &[0x21, 0x22]),
                |s| s.ast().borrow().data_image().to_vec(),
            );
        }

        #[test]
        fn group_object_table_data() {
            assert_field_persists(
                $fresh,
                |s| s.cot().borrow_mut().write(1, &[0x31, 0x32]),
                |s| s.cot().borrow().data_image().to_vec(),
            );
        }

        #[test]
        fn application_parameters() {
            assert_field_persists(
                $fresh,
                |s| s.app().borrow_mut().params_mut().bytes[5] = 0x55,
                |s| *s.app().borrow().params(),
            );
        }

        #[test]
        fn address_table_control() {
            assert_field_persists(
                $fresh,
                |s| change_control(&mut s.adt().borrow_mut(), 0x03),
                |s| control(&s.adt().borrow()),
            );
        }

        #[test]
        fn association_table_control() {
            assert_field_persists(
                $fresh,
                |s| change_control(&mut s.ast().borrow_mut(), 0x04),
                |s| control(&s.ast().borrow()),
            );
        }

        #[test]
        fn group_object_table_control() {
            assert_field_persists(
                $fresh,
                |s| change_control(&mut s.cot().borrow_mut(), 0x05),
                |s| control(&s.cot().borrow()),
            );
        }

        #[test]
        fn application_control() {
            assert_field_persists(
                $fresh,
                |s| change_control(s.app().borrow_mut().inner_mut(), 0x06),
                |s| control(s.app().borrow().inner()),
            );
        }

        #[test]
        fn application2_control() {
            assert_field_persists(
                $fresh,
                |s| change_control(s.pei().borrow_mut().inner_mut(), 0x07),
                |s| control(s.pei().borrow().inner()),
            );
        }

        #[test]
        fn program_version() {
            assert_field_persists(
                $fresh,
                |s| *s.program_version().borrow_mut() = [9, 8, 7, 6, 5],
                |s| *s.program_version().borrow(),
            );
        }

        #[test]
        fn pei_type() {
            assert_field_persists(
                $fresh,
                |s| s.program_pei_type().set(s.program_pei_type().get() ^ 0x14),
                |s| s.program_pei_type().get(),
            );
        }

        #[test]
        fn program2_version() {
            assert_field_persists(
                $fresh,
                |s| *s.pei_program_version().borrow_mut() = [1, 2, 3, 4, 5],
                |s| *s.pei_program_version().borrow(),
            );
        }
    };
}

// ============================================================================
// System B
// ============================================================================

mod system_b {
    use super::*;
    use zweidraehte_device::bcus::system_b::{SystemBDeviceState, Tp1, Tp1ExtensionState};
    use zweidraehte_proto::NUM_AUTH_KEYS;

    const DEVICE: DeviceDescriptor =
        DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00FA, [0; 6], 0xF001, 0x01, 3, 5, 7, 0);

    #[derive(Clone, Copy)]
    struct TestDefinition;

    impl DeviceDefinition for TestDefinition {
        const DEVICE: &'static DeviceDescriptor = &DEVICE;

        type Params = TestParams;
        type ComObjects = NoComObjects;
        type LinkLayer = MockLinkLayerBuilder<1>;
    }

    type State = SystemBDeviceState<
        { DEVICE.address_table_size() },
        { DEVICE.association_table_size() },
        { DEVICE.comm_object_table_size() },
        Tp1<TestDefinition>,
        Tp1ExtensionState,
    >;

    fn fresh() -> State {
        State::new(StaticIdentity::new([0; 6]), NoComObjects::new(), ())
    }

    common_fields!(fresh);

    #[test]
    fn auth_keys() {
        for level in 0..NUM_AUTH_KEYS as u8 {
            assert_field_persists(
                fresh,
                |s| assert_eq!(s.key_write(level, &key(level), AccessContext::MAX_ACCESS), level),
                |s| s.authorize(&key(level)),
            );
        }
    }
}

// ============================================================================
// System 7
// ============================================================================

mod system_7 {
    use super::*;
    use zweidraehte_device::bcus::system_7::{SYSTEM7_NUM_AUTH_KEYS, System7DeviceState, Tp1, Tp1ExtensionState};

    const DEVICE: DeviceDescriptor =
        DeviceDescriptor::new(MaskVersion::System7Tp1, 0x00FA, [0; 6], 0xF003, 0x01, 3, 5, 7, 0);

    #[derive(Clone, Copy)]
    struct TestDefinition;

    impl DeviceDefinition for TestDefinition {
        const DEVICE: &'static DeviceDescriptor = &DEVICE;

        type Params = TestParams;
        type ComObjects = NoComObjects;
        type LinkLayer = MockLinkLayerBuilder<1>;
    }

    const ADT: usize = 3 + DEVICE.max_address_table_entries as usize * 2;
    const AST: usize = 1 + DEVICE.max_association_table_entries as usize * 2;
    const COT: usize = 3 + DEVICE.max_com_objects as usize * 4;

    type State = System7DeviceState<ADT, AST, COT, Tp1<TestDefinition, 0x4200>, Tp1ExtensionState>;

    fn fresh() -> State {
        State::new(StaticIdentity::new([0; 6]), NoComObjects::new(), ())
    }

    common_fields!(fresh);

    #[test]
    fn option_reg() {
        assert_field_persists(fresh, |s| s.set_option_reg(s.option_reg() ^ 0x42), |s| s.option_reg());
    }

    #[test]
    fn auth_keys() {
        for level in 0..SYSTEM7_NUM_AUTH_KEYS as u8 {
            assert_field_persists(
                fresh,
                |s| assert_eq!(s.key_write(level, &key(level), AccessContext::MAX_ACCESS), level),
                |s| s.authorize(&key(level)),
            );
        }
    }
}
