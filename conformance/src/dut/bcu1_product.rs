//! MTXML product for the minimal BCU1 configuration fixture.
//!
//! BCU1 is too small for the normal generated application layout, but the
//! project programmer still needs a real product model for flag and DPT
//! lowering. Keep this fixture beside the BCU1 stack definition so its table
//! offsets, capacities, and default EEPROM image cannot drift.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::bcu1_stack;

pub fn generate_mtxml() -> String {
    let definition = bcu1_stack::definition();
    let data = BASE64.encode(definition.build_eeprom());
    format!(
        r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0B10-01-0000" ApplicationNumber="2832" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0012" Name="BCU1 Conformance DUT" LoadProcedureStyle="DefaultProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <Code><AbsoluteSegment Id="M-00FA_A-0B10-01-0000_AS-0100" Address="256" Size="256" MemoryType="EEPROM"><Data>{data}</Data></AbsoluteSegment></Code>
        <ComObjectTable CodeSegment="M-00FA_A-0B10-01-0000_AS-0100" Offset="{}">
          <ComObject Id="M-00FA_A-0B10-01-0000_O-0" Name="Byte" Text="Byte" Number="0" FunctionText="Byte" ObjectSize="1 Byte" ReadFlag="Enabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Enabled" UpdateFlag="Enabled" ReadOnInitFlag="Disabled" />
          <ComObject Id="M-00FA_A-0B10-01-0000_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Enabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Enabled" UpdateFlag="Enabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <AddressTable CodeSegment="M-00FA_A-0B10-01-0000_AS-0100" Offset="{}" MaxEntries="{}" />
        <AssociationTable CodeSegment="M-00FA_A-0B10-01-0000_AS-0100" Offset="{}" MaxEntries="{}" />
        <LoadProcedures />
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#,
        definition.cot_offset(),
        definition.addr_table_offset(),
        definition.max_group_addresses,
        definition.assoc_table_offset(),
        definition.max_associations,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_product_matches_the_stack_layout() {
        let xml = generate_mtxml();
        let product = zweidraehte_ets_files::product::ProductData::from_mtxml_str(&xml).expect("BCU1 MTXML parses");
        let definition = bcu1_stack::definition();
        assert_eq!(product.address_table_offset(), definition.addr_table_offset() as u32);
        assert_eq!(product.association_table_offset(), definition.assoc_table_offset() as u32);
        assert_eq!(product.com_object_table_offset(), definition.cot_offset() as u32);
        assert_eq!(product.segments()[0].data, definition.build_eeprom());
    }
}
