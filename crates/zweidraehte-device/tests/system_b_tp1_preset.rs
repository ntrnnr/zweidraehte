//! The standard System B TP1 preset resolves descriptor-derived types without
//! asking firmware to restate the stack's internal bill of materials.

use zweidraehte_device::bcus::system_b::{
    Rf, RfExtensionState, SystemBDeviceState, SystemBStateInit, Tp1, Tp1ExtensionState,
};
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::NoComObjects;
use zweidraehte_device::service::{Augment, AugmentChain};
use zweidraehte_device::storage::StaticIdentity;
use zweidraehte_device::{DeviceDefinition, LayerStackBuilder, NoParams, StackDefinition};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::transport::TlStyle;

const DEVICE: DeviceDescriptor =
    DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00FA, [0; 6], 0xF001, 0x01, 3, 5, 7, 0);

const RF_DEVICE: DeviceDescriptor =
    DeviceDescriptor::new(MaskVersion::SystemBRf, 0x00FA, [0; 6], 0xF002, 0x01, 4, 6, 8, 0);

#[derive(Clone, Copy)]
struct TestDefinition;

impl DeviceDefinition for TestDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE;

    type Params = NoParams;
    type ComObjects = NoComObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
}

type TestStack = Tp1<TestDefinition>;

#[derive(Clone, Copy)]
struct RfDefinition;

impl DeviceDefinition for RfDefinition {
    const DEVICE: &'static DeviceDescriptor = &RF_DEVICE;

    type Params = NoParams;
    type ComObjects = NoComObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
}

type RfTestStack = Rf<RfDefinition>;

struct FirstAugment;

impl Augment<TestStack> for FirstAugment {
    fn additional_object_count(&self) -> u16 {
        1
    }

    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType> {
        (index == 0).then_some(InterfaceObjectType::Security)
    }

    fn descriptor_count_for(&self, object_type: InterfaceObjectType) -> u16 {
        (object_type == InterfaceObjectType::Device) as u16
    }
}

struct SecondAugment;

impl Augment<TestStack> for SecondAugment {
    fn additional_object_count(&self) -> u16 {
        2
    }

    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType> {
        match index {
            0 => Some(InterfaceObjectType::IPParameter),
            1 => Some(InterfaceObjectType::RFMedium),
            _ => None,
        }
    }

    fn descriptor_count_for(&self, object_type: InterfaceObjectType) -> u16 {
        2 * (object_type == InterfaceObjectType::Device) as u16
    }
}

fn assert_runnable<D>()
where
    D: StackDefinition,
    D::LayerBuilder: LayerStackBuilder<D>,
{
}

#[test]
fn preset_resolves_the_complete_plain_tp1_stack() {
    assert_runnable::<TestStack>();

    assert_eq!(TestStack::FIRST_ASAP, 1);
    assert_eq!(TestStack::TL_STYLE, TlStyle::Style3);

    let state = TestStack::create_state(SystemBStateInit::new(StaticIdentity::new([0; 6]), None));
    let _: &SystemBDeviceState<
        { DEVICE.address_table_size() },
        { DEVICE.association_table_size() },
        { DEVICE.comm_object_table_size() },
        TestStack,
        Tp1ExtensionState,
    > = &state;

    let memory_map = TestStack::memory_map();
    assert_eq!(memory_map.layout().adt_size, DEVICE.address_table_size());
    assert_eq!(memory_map.layout().ast_size, DEVICE.association_table_size());
    assert_eq!(memory_map.layout().cot_size, DEVICE.comm_object_table_size());
}

#[test]
fn rf_preset_resolves_the_medium_specific_state() {
    assert_runnable::<RfTestStack>();

    assert_eq!(RfTestStack::FIRST_ASAP, 1);
    assert_eq!(RfTestStack::TL_STYLE, TlStyle::Style3);

    let state = RfTestStack::create_state(SystemBStateInit::new(StaticIdentity::new([0; 6]), None));
    let _: &SystemBDeviceState<
        { RF_DEVICE.address_table_size() },
        { RF_DEVICE.association_table_size() },
        { RF_DEVICE.comm_object_table_size() },
        RfTestStack,
        RfExtensionState,
    > = &state;

    let memory_map = RfTestStack::memory_map();
    assert_eq!(memory_map.layout().adt_size, RF_DEVICE.address_table_size());
    assert_eq!(memory_map.layout().ast_size, RF_DEVICE.association_table_size());
    assert_eq!(memory_map.layout().cot_size, RF_DEVICE.comm_object_table_size());
}

#[test]
#[should_panic(expected = "TP1 preset requires a 07B0 descriptor")]
fn tp1_preset_rejects_an_rf_descriptor() {
    type InvalidStack = Tp1<RfDefinition>;

    InvalidStack::create_state(SystemBStateInit::new(StaticIdentity::new([0; 6]), None));
}

#[test]
#[should_panic(expected = "address-table capacity differs from DEVICE")]
fn preset_rejects_a_manual_table_capacity_override() {
    type InvalidStack = Tp1<TestDefinition, { DEVICE.address_table_size() + 1 }>;

    InvalidStack::create_state(SystemBStateInit::new(StaticIdentity::new([0; 6]), None));
}

#[test]
fn augment_chain_preserves_profile_then_device_order() {
    let chain = AugmentChain::new(FirstAugment, SecondAugment);

    assert_eq!(chain.additional_object_count(), 3);
    assert_eq!(chain.additional_object_type_at(0), Some(InterfaceObjectType::Security));
    assert_eq!(chain.additional_object_type_at(1), Some(InterfaceObjectType::IPParameter));
    assert_eq!(chain.additional_object_type_at(2), Some(InterfaceObjectType::RFMedium));
    assert_eq!(chain.descriptor_count_for(InterfaceObjectType::Device), 3);
}
