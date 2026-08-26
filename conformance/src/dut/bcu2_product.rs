//! The BCU2 DUT's product file, generated in-process.
//!
//! Same round-trip idea as [`super::system7_product`]: the product
//! layer the client's download engine consumes is generated from the
//! very definition the DUT boots from, so generator, parser, and
//! device cannot drift apart.
//!
//! The builder renders the vendor BCU-era shape (`LoadProcedureStyle=
//! "DefaultProcedure"`): one absolute EEPROM segment covering the
//! table page at 0100h whose default `<Data>` **is** the corresponding
//! prefix of the DUT's boot image, and the three tables pointing into it
//! at the offsets the definition computed. The MV-0020 mask template then
//! supplies the whole procedure — LSM cycling over the property path, task
//! records, and the explicit verify-mode memory phase.
//!
//! `DynamicTableManagement="true"` so the download loop exercises the
//! client's table relocation (association table packed behind the
//! actual-size address table, AssocTabPtr repointed, TSAP FEh
//! placeholders) against a DUT that resolves the tables through the
//! pointer bytes, the way real BCU silicon does.
//!
use std::sync::OnceLock;

use zweidraehte_ets_model::{EtsCommObjectDef, EtsCommObjectRefDef};
use zweidraehte_knxprod::{ApplicationProgramDef, Bcu2MemoryLayout, KnxprodBuilder, SingleDeviceDef};
use zweidraehte_microdevice::families::bcu2::BCU2_EEPROM_SIZE;
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

use super::{bcu2_secure_stack, bcu2_stack};

/// The application-owned table page downloaded by this synthetic product.
///
/// The rest of BCU2 EEPROM is not application content here. Including the
/// whole address space made the synthetic image overwrite the adjacent
/// direction-protected AN177 conformance windows on the secure DUT. The real
/// light-switch product declares its parameter segment separately.
const SEGMENT_ADDRESS: u32 = 0x0100;
const SEGMENT_SIZE: usize = 0x0100;

// The RT2 descriptors supply sizes and flags, but no datapoint metadata.
// Neutral DPTs make those same wire shapes expressible in MTXML; the tests
// below keep this ETS layer synchronized with the concrete device definition.
const COM_OBJECTS: &[EtsCommObjectDef] = &[
    com_object(0, "GO0", 1, 1, 1, 0xDF),
    com_object(1, "GO1", 5, 10, 8, 0xDF),
    com_object(2, "GO2", 232, 600, 24, 0xDF),
    com_object(3, "GO3", 1, 1, 1, 0x4F),
];

const COM_OBJECT_REFS: &[EtsCommObjectRefDef] = &[];

const fn com_object(
    index: u16,
    name: &'static str,
    dpt_main: u16,
    dpt_sub: u16,
    size_bits: u8,
    default_flags: u8,
) -> EtsCommObjectDef {
    EtsCommObjectDef {
        index,
        name,
        display_name: name,
        function_text: "conformance",
        dpt_main,
        dpt_sub,
        size_bits,
        default_flags,
        object_size_override: None,
        text_template: None,
    }
}

/// Generate the DUT's application program as MTXML.
pub fn generate_mtxml() -> Result<String, String> {
    generate(ProductVariant::Plain0020)
}

/// Generate a plain application for the mask-0021 DUT.
///
/// Data Security is a composable Profile Module, not a property of the mask
/// number. This product deliberately leaves `IsSecureEnabled` unset while
/// targeting the same 0021h device that also runs the secure fixture.
pub fn generate_plain_0021_mtxml() -> Result<String, String> {
    generate(ProductVariant::Plain0021)
}

/// Generate the mask-0021 secure DUT's application program as MTXML.
pub fn generate_secure_mtxml() -> Result<String, String> {
    generate(ProductVariant::Secure0021)
}

#[derive(Clone, Copy)]
enum ProductVariant {
    Plain0020,
    Plain0021,
    Secure0021,
}

impl ProductVariant {
    fn definition(self) -> zweidraehte_microdevice::Bcu2DeviceDefinition {
        match self {
            Self::Plain0020 => bcu2_stack::definition(),
            Self::Plain0021 | Self::Secure0021 => bcu2_secure_stack::definition(),
        }
    }

    fn mask_version(self) -> MaskVersion {
        match self {
            Self::Plain0020 => MaskVersion::Other(0x0020),
            Self::Plain0021 | Self::Secure0021 => MaskVersion::Bcu2Tp1,
        }
    }

    fn app_name(self) -> &'static str {
        match self {
            Self::Plain0020 => "BCU2 Conformance DUT",
            Self::Plain0021 => "BCU2 0021 Conformance DUT",
            Self::Secure0021 => "Secure BCU2 Conformance DUT",
        }
    }

    fn application_hash(self) -> Option<&'static str> {
        matches!(self, Self::Secure0021).then_some("0001")
    }

    fn eeprom(self) -> [u8; BCU2_EEPROM_SIZE] {
        let definition = self.definition();
        match self {
            Self::Plain0020 => definition.build_eeprom(),
            Self::Plain0021 | Self::Secure0021 => definition.build_eeprom_for_mask(0x0021),
        }
    }

    fn tables_data(self) -> &'static [u8] {
        static PLAIN_0020: OnceLock<[u8; SEGMENT_SIZE]> = OnceLock::new();
        static PLAIN_0021: OnceLock<[u8; SEGMENT_SIZE]> = OnceLock::new();
        static SECURE_0021: OnceLock<[u8; SEGMENT_SIZE]> = OnceLock::new();

        let slot = match self {
            Self::Plain0020 => &PLAIN_0020,
            Self::Plain0021 => &PLAIN_0021,
            Self::Secure0021 => &SECURE_0021,
        };

        slot.get_or_init(|| self.eeprom()[..SEGMENT_SIZE].try_into().expect("the table page has a fixed size"))
    }
}

fn generate(variant: ProductVariant) -> Result<String, String> {
    let def = variant.definition();
    if matches!(variant, ProductVariant::Secure0021) {
        ensure_secure_capacities(&def)?;
    }

    let descriptor = DeviceDescriptor::new(
        variant.mask_version(),
        def.app_manufacturer_id,
        [0; 6],
        def.device_type,
        def.version,
        def.max_group_addresses.into(),
        def.max_associations.into(),
        def.comm_objects.len().try_into().map_err(|_| "too many communication objects".to_string())?,
        def.pei_type,
    );
    let app = ApplicationProgramDef {
        name: variant.app_name(),
        device: &descriptor,
        params: &[],
        virtual_params: None,
        param_defaults: &[],
        comm_objects: COM_OBJECTS,
        comm_object_refs: COM_OBJECT_REFS,
        union_fields: None,
        channel_name: "Conformance",
        absolute_segment_address: None,
        system7_layout: None,
        bcu2_layout: Some(Bcu2MemoryLayout {
            tables_address: SEGMENT_ADDRESS,
            tables_data: variant.tables_data(),
            addr_table_offset: def.addr_table_offset() as u32,
            assoc_table_offset: def.assoc_table_offset() as u32,
            cot_offset: def.cot_offset() as u32,
            params_address: SEGMENT_ADDRESS + SEGMENT_SIZE as u32,
        }),
        application_hash: variant.application_hash(),
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: None,
        modules: None,
        baggages: None,
        translations: None,
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: matches!(variant, ProductVariant::Secure0021).then_some(true),
        max_user_entries: None,
        max_tunneling_user_entries: None,
        max_security_individual_address_entries: matches!(variant, ProductVariant::Secure0021)
            .then_some(bcu2_secure_stack::SIAT_CAPACITY as u16),
        max_security_group_key_table_entries: matches!(variant, ProductVariant::Secure0021)
            .then_some(bcu2_secure_stack::GROUP_KEY_CAPACITY as u16),
        max_security_p2p_key_table_entries: matches!(variant, ProductVariant::Secure0021)
            .then_some(bcu2_secure_stack::P2P_KEY_CAPACITY as u16),
    };

    let output = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: descriptor.hardware_type,
        hardware_version: 1,
        hardware_name: variant.app_name(),
        product_name: variant.app_name(),
        order_number: match variant {
            ProductVariant::Plain0020 => "BCU2-DUT-0020",
            ProductVariant::Plain0021 => "BCU2-DUT-0021",
            ProductVariant::Secure0021 => "BCU2-DUT-0021-SEC",
        },
        is_rail_mounted: false,
        catalog_section: "Conformance",
        is_ip_enabled: None,
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
    })
    .generate_all()
    .map_err(|error| format!("generating the BCU2 product file: {error}"))?;

    output
        .application_programs
        .into_iter()
        .next()
        .map(|(_, xml)| xml)
        .ok_or_else(|| "the generator produced no application program".to_string())
}

/// Catch fixture/product drift where the XML advertises tables the concrete
/// secure profile cannot hold. P2P is intentionally zero on both sides.
fn ensure_secure_capacities(def: &zweidraehte_microdevice::Bcu2DeviceDefinition) -> Result<(), String> {
    let go_count = def.comm_objects.len();
    if go_count > bcu2_secure_stack::GROUP_OBJECT_CAPACITY {
        return Err(format!(
            "secure product declares {go_count} group objects, firmware holds {}",
            bcu2_secure_stack::GROUP_OBJECT_CAPACITY
        ));
    }
    if bcu2_secure_stack::P2P_KEY_CAPACITY != 0 {
        return Err("secure BCU2 fixture must remain tool-access-only (P2P capacity zero)".to_string());
    }
    if bcu2_secure_stack::SIAT_CAPACITY > super::fixture_common::sec_table_sizes::SIAT {
        return Err(format!(
            "secure product advertises {} SIAT rows, persistent store holds {}",
            bcu2_secure_stack::SIAT_CAPACITY,
            super::fixture_common::sec_table_sizes::SIAT,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zweidraehte_ets_files::product::ProductData;
    use zweidraehte_proto::com_object::ComObjectType;

    use super::*;

    #[test]
    fn builder_preserves_every_fixture_layout() {
        for (variant, xml) in [
            (ProductVariant::Plain0020, generate_mtxml()),
            (ProductVariant::Plain0021, generate_plain_0021_mtxml()),
            (ProductVariant::Secure0021, generate_secure_mtxml()),
        ] {
            let product = ProductData::from_mtxml_str(&xml.expect("fixture generates")).expect("fixture parses");
            let definition = variant.definition();

            assert_eq!(product.mask_version(), Some(variant.mask_version()));
            assert_eq!(product.application_identity().application_id, [
                (definition.app_manufacturer_id >> 8) as u8,
                definition.app_manufacturer_id as u8,
                (definition.device_type >> 8) as u8,
                definition.device_type as u8,
                definition.version,
            ]);

            assert_eq!(product.segments().len(), 1);

            let segment = &product.segments()[0];
            assert_eq!(segment.address, Some(SEGMENT_ADDRESS as u16));
            assert_eq!(segment.size, SEGMENT_SIZE as u32);
            assert_eq!(segment.data, variant.tables_data());

            assert_eq!(product.address_table_segment(), Some(segment.id.as_str()));
            assert_eq!(product.association_table_segment(), Some(segment.id.as_str()));
            assert_eq!(product.com_object_table_segment(), Some(segment.id.as_str()));
            assert_eq!(product.address_table_offset(), definition.addr_table_offset() as u32);
            assert_eq!(product.association_table_offset(), definition.assoc_table_offset() as u32);
            assert_eq!(product.com_object_table_offset(), definition.cot_offset() as u32);

            let flags: Vec<_> = product.com_objects().iter().map(|object| object.flags.to_byte()).collect();
            let expected_flags: Vec<_> = definition.comm_objects.iter().map(|object| object.config).collect();
            assert_eq!(flags, expected_flags);

            let object_types: Vec<_> = product.com_objects().iter().map(|object| object.object_type).collect();
            let expected_types: Vec<_> = definition
                .comm_objects
                .iter()
                .map(|object| match object.value_type {
                    0x00 => ComObjectType::Uint1,
                    0x06 => ComObjectType::Byte1,
                    0x08 => ComObjectType::Byte3,
                    other => panic!("fixture has unsupported RT2 value type {other:#04X}"),
                })
                .collect();
            assert_eq!(object_types, expected_types);
        }
    }

    #[test]
    fn secure_product_matches_the_micro_profile_capacities() {
        let xml = generate_secure_mtxml().expect("secure fixture generates");
        let product = ProductData::from_mtxml_str(&xml).expect("secure fixture parses");

        assert_eq!(product.mask_version(), Some(MaskVersion::Bcu2Tp1));
        assert!(product.supports_data_secure());
        assert_eq!(product.max_security_individual_address_entries(), Some(bcu2_secure_stack::SIAT_CAPACITY as u16));
        assert_eq!(product.max_security_group_key_table_entries(), Some(bcu2_secure_stack::GROUP_KEY_CAPACITY as u16));
        assert_eq!(product.max_security_p2p_key_table_entries(), Some(0));
        assert_eq!(product.com_object_numbers().len(), bcu2_secure_stack::definition().comm_objects.len());
    }
}
