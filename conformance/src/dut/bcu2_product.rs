//! The BCU2 DUT's product file, generated in-process.
//!
//! Same round-trip idea as [`super::system7_product`]: the product
//! layer the client's download engine consumes is generated from the
//! very definition the DUT boots from, so generator, parser, and
//! device cannot drift apart.
//!
//! The shape is the vendor BCU-era shape (`LoadProcedureStyle=
//! "DefaultProcedure"`): one absolute EEPROM segment covering the
//! ETS-visible window at 0100h whose default `<Data>` **is** the DUT's
//! boot image, and the three tables pointing into it at the offsets
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
use zweidraehte_microdevice::device_def::Bcu2CoDescriptor;

use super::bcu2_stack;

/// The ETS-visible EEPROM window a BCU2 product's segment covers.
const SEGMENT_ADDRESS: usize = 0x0100;
const SEGMENT_SIZE: usize = 0x0370;

/// Generate the DUT's application program as MTXML.
pub fn generate_mtxml() -> Result<String, String> {
    let def = bcu2_stack::definition();
    let image = def.build_eeprom();
    let data = BASE64.encode(&image[..SEGMENT_SIZE]);

    let seg_id = "M-00FA_A-0B20-01-0000_AS-0100";
    let mut com_objects = String::new();
    for (number, co) in def.comm_objects.iter().enumerate() {
        com_objects.push_str(&com_object_xml(number, co));
    }

    Ok(format!(
        r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte-conformance" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0B20-01-0000" ApplicationNumber="2848" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0020" Name="BCU2 Conformance DUT" LoadProcedureStyle="DefaultProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="true" Linkable="false">
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

/// One `<ComObject>` element, its flags spelled from the RT2 config
/// octet so the overlay the client compiles reproduces the DUT's own
/// table bytes.
fn com_object_xml(number: usize, co: &Bcu2CoDescriptor) -> String {
    let flag = |mask: u8| if co.config & mask != 0 { "Enabled" } else { "Disabled" };
    let object_size = match co.value_type {
        0x00 => "1 Bit",
        0x06 => "1 Byte",
        0x08 => "3 Bytes",
        other => panic!("extend com_object_xml for value type {other:#04X}"),
    };
    format!(
        "          <ComObject Id=\"M-00FA_A-0B20-01-0000_O-{number}\" Name=\"GO{number}\" Text=\"GO{number}\" Number=\"{number}\" FunctionText=\"conformance\" ObjectSize=\"{object_size}\" ReadFlag=\"{read}\" WriteFlag=\"{write}\" CommunicationFlag=\"{comm}\" TransmitFlag=\"{transmit}\" UpdateFlag=\"{update}\" ReadOnInitFlag=\"{roi}\" />\n",
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
