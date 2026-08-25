//! The BCU2 DUT's product file, generated in-process.
//!
//! Same round-trip idea as [`super::system7_product`]: the product
//! layer the client's download engine consumes is generated from the
//! very definition the DUT boots from, so generator, parser, and
//! device cannot drift apart.
//!
//! The shape is the vendor BCU-era shape (`LoadProcedureStyle=
//! "DefaultProcedure"`): one absolute EEPROM segment covering the
//! table page at 0100h whose default `<Data>` **is** the corresponding
//! prefix of the DUT's boot image, and the three tables pointing into it at the offsets
//! the definition computed. The MV-0020 mask template then supplies
//! the whole procedure — LSM cycling over the property path, task
//! records, and the explicit verify-mode memory phase.
//!
//! `DynamicTableManagement="true"` so the download loop exercises the
//! client's table relocation (association table packed behind the
//! actual-size address table, AssocTabPtr repointed, TSAP FEh
//! placeholders) against a DUT that resolves the tables through the
//! pointer bytes, the way real BCU silicon does.
//!
//! TODO: a shipping BCU2 product wants a proper `Bcu2MemoryLayout` in
//! `zweidraehte-knxprod`'s builder; this hand-rolled XML is fixture
//! grade (tracked in SESSION.md).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zweidraehte_microdevice::families::bcu2::{BCU2_EEPROM_SIZE, Bcu2CoDescriptor};

use super::{bcu2_secure_stack, bcu2_stack};

/// The application-owned table page downloaded by this synthetic product.
///
/// The rest of BCU2 EEPROM is not application content here. Including the
/// whole address space made the synthetic image overwrite the adjacent
/// direction-protected AN177 conformance windows on the secure DUT. The real
/// light-switch product declares its parameter segment separately.
const SEGMENT_ADDRESS: usize = 0x0100;
const SEGMENT_SIZE: usize = 0x0100;

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

    fn program_id(self) -> &'static str {
        match self {
            Self::Plain0020 => "M-00FA_A-0B20-01-0000",
            Self::Plain0021 => "M-00FA_A-0B21-01-0000",
            Self::Secure0021 => "M-00FA_A-0B21-01-0001",
        }
    }

    fn program_attributes(self) -> Result<String, String> {
        match self {
            Self::Plain0020 => {
                Ok("ApplicationNumber=\"2848\" MaskVersion=\"MV-0020\" Name=\"BCU2 Conformance DUT\"".to_string())
            }
            Self::Plain0021 => {
                Ok("ApplicationNumber=\"2849\" MaskVersion=\"MV-0021\" Name=\"BCU2 0021 Conformance DUT\"".to_string())
            }
            Self::Secure0021 => {
                ensure_secure_capacities(&self.definition())?;
                Ok(format!(
                    "ApplicationNumber=\"2850\" MaskVersion=\"MV-0021\" Name=\"Secure BCU2 Conformance DUT\" IsSecureEnabled=\"true\" MaxSecurityIndividualAddressEntries=\"{}\" MaxSecurityGroupKeyTableEntries=\"{}\" MaxSecurityP2PKeyTableEntries=\"{}\"",
                    bcu2_secure_stack::SIAT_CAPACITY,
                    bcu2_secure_stack::GROUP_KEY_CAPACITY,
                    bcu2_secure_stack::P2P_KEY_CAPACITY,
                ))
            }
        }
    }

    fn eeprom(self) -> [u8; BCU2_EEPROM_SIZE] {
        let definition = self.definition();
        match self {
            Self::Plain0020 => definition.build_eeprom(),
            Self::Plain0021 | Self::Secure0021 => definition.build_eeprom_for_mask(0x0021),
        }
    }
}

fn generate(variant: ProductVariant) -> Result<String, String> {
    let def = variant.definition();
    let program_attributes = variant.program_attributes()?;
    let image = variant.eeprom();
    let data = BASE64.encode(&image[..SEGMENT_SIZE]);

    let program_id = variant.program_id();
    let seg_id = format!("{program_id}_AS-0100");
    let mut com_objects = String::new();
    for (number, co) in def.comm_objects.iter().enumerate() {
        com_objects.push_str(&com_object_xml(program_id, number, co));
    }

    Ok(format!(
        r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte-conformance" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="{program_id}" {program_attributes} ApplicationVersion="1" ProgramType="ApplicationProgram" LoadProcedureStyle="DefaultProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="true" Linkable="false">
      <Static>
        <Code>
          <AbsoluteSegment Id="{seg_id}" Address="{address}" Size="{size}" MemoryType="EEPROM"><Data>{data}</Data></AbsoluteSegment>
        </Code>
        <ComObjectTable CodeSegment="{seg_id}" Offset="{cot_offset}">
{com_objects}        </ComObjectTable>
        <AddressTable CodeSegment="{seg_id}" Offset="{addr_offset}" MaxEntries="{max_gas}" />
        <AssociationTable CodeSegment="{seg_id}" Offset="{assoc_offset}" MaxEntries="{max_assocs}" />
        <LoadProcedures />
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#,
        seg_id = seg_id,
        program_id = program_id,
        program_attributes = program_attributes,
        address = SEGMENT_ADDRESS,
        size = SEGMENT_SIZE,
        data = data,
        cot_offset = def.cot_offset(),
        addr_offset = def.addr_table_offset(),
        assoc_offset = def.assoc_table_offset(),
        max_gas = def.max_group_addresses,
        max_assocs = def.max_associations,
        com_objects = com_objects,
    ))
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

/// One `<ComObject>` element, its flags spelled from the RT2 config
/// octet so the overlay the client compiles reproduces the DUT's own
/// table bytes.
fn com_object_xml(program_id: &str, number: usize, co: &Bcu2CoDescriptor) -> String {
    let flag = |mask: u8| if co.config & mask != 0 { "Enabled" } else { "Disabled" };
    let object_size = match co.value_type {
        0x00 => "1 Bit",
        0x06 => "1 Byte",
        0x08 => "3 Bytes",
        other => panic!("extend com_object_xml for value type {other:#04X}"),
    };
    format!(
        "          <ComObject Id=\"{program_id}_O-{number}\" Name=\"GO{number}\" Text=\"GO{number}\" Number=\"{number}\" FunctionText=\"conformance\" ObjectSize=\"{object_size}\" ReadFlag=\"{read}\" WriteFlag=\"{write}\" CommunicationFlag=\"{comm}\" TransmitFlag=\"{transmit}\" UpdateFlag=\"{update}\" ReadOnInitFlag=\"{roi}\" />\n",
        program_id = program_id,
        number = number,
        object_size = object_size,
        read = flag(0x08),
        write = flag(0x10),
        comm = flag(0x04),
        transmit = flag(0x40),
        update = flag(0x80),
        roi = flag(0x20),
    )
}

#[cfg(test)]
mod tests {
    use zweidraehte_client::download::ProductData;
    use zweidraehte_proto::device::MaskVersion;

    use super::*;

    #[test]
    fn secure_product_matches_the_micro_profile_capacities() {
        let xml = generate_secure_mtxml().expect("secure fixture generates");
        let product = ProductData::from_mtxml_str(&xml).expect("secure fixture parses");

        assert_eq!(product.mask_version, Some(MaskVersion::Bcu2Tp1));
        assert!(product.supports_data_secure);
        assert_eq!(product.max_security_individual_address_entries, Some(bcu2_secure_stack::SIAT_CAPACITY as u16));
        assert_eq!(product.max_security_group_key_table_entries, Some(bcu2_secure_stack::GROUP_KEY_CAPACITY as u16));
        assert_eq!(product.max_security_p2p_key_table_entries, Some(0));
        assert_eq!(product.com_object_numbers.len(), bcu2_secure_stack::definition().comm_objects.len());
    }
}
