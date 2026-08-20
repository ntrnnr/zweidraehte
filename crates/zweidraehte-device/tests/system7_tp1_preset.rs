//! The standard System 7 preset owns the family's fixed composition and
//! derives its compact table capacities from the product descriptor.

use zweidraehte_device::bcus::system_7::{
    System7DeviceState, System7ProductLayout, System7StateInit, Tp1, Tp1ExtensionState,
};
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::NoComObjects;
use zweidraehte_device::objects::tables::CommunicationObjectTable;
use zweidraehte_device::storage::StaticIdentity;
use zweidraehte_device::{DeviceDefinition, LayerStackBuilder, NoParams, StackDefinition};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};
use zweidraehte_proto::transport::TlStyle;

const DEVICE: DeviceDescriptor =
    DeviceDescriptor::new(MaskVersion::System7Tp1, 0x00FA, [0; 6], 0xF003, 0x01, 3, 5, 7, 0);

#[derive(Clone, Copy)]
struct TestDefinition;

impl DeviceDefinition for TestDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE;

    type Params = NoParams;
    type ComObjects = NoComObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
}

type TestStack = Tp1<TestDefinition, 0x4200>;

fn assert_runnable<D>()
where
    D: StackDefinition,
    D::LayerBuilder: LayerStackBuilder<D>,
{
}

#[test]
fn preset_resolves_the_complete_plain_tp1_stack() {
    assert_runnable::<TestStack>();

    assert_eq!(TestStack::FIRST_ASAP, 0);
    assert_eq!(TestStack::TL_STYLE, TlStyle::Style3);
    assert_eq!(<TestStack as System7ProductLayout>::COT_ADDRESS, 0x4200);

    let state = TestStack::create_state(System7StateInit::new(StaticIdentity::new([0; 6]), None));
    let _: &System7DeviceState<
        { 3 + DEVICE.max_address_table_entries as usize * 2 },
        { 1 + DEVICE.max_association_table_entries as usize * 2 },
        { 3 + DEVICE.max_com_objects as usize * 4 },
        TestStack,
        Tp1ExtensionState,
    > = &state;

    assert_eq!(state.cot.borrow().max_entries(), DEVICE.max_com_objects as usize);
    let _ = TestStack::memory_map();
}

#[test]
#[should_panic(expected = "communication-object capacity differs from DEVICE")]
fn preset_rejects_a_manual_table_capacity_override() {
    type InvalidStack = Tp1<
        TestDefinition,
        0x4200,
        { 3 + DEVICE.max_address_table_entries as usize * 2 },
        { 1 + DEVICE.max_association_table_entries as usize * 2 },
        { 3 + (DEVICE.max_com_objects as usize + 1) * 4 },
    >;

    InvalidStack::create_state(System7StateInit::new(StaticIdentity::new([0; 6]), None));
}
