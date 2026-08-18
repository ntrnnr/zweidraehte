//! KNX ApplicationProgram XML Parser
//!
//! This module provides functions to parse KNX ApplicationProgram MTXML files
//! into the schema types defined in [`crate::schema`].
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte_knxprod::{parse_application_program, parse_application_program_from_file};
//! use std::path::Path;
//!
//! // Parse from a string
//! let xml = std::fs::read_to_string("device.xml")?;
//! let knx = parse_application_program(&xml)?;
//!
//! // Or parse directly from a file
//! let knx = parse_application_program_from_file(Path::new("device.xml"))?;
//!
//! // Access the application program
//! let program = &knx.manufacturer_data.manufacturer.application_programs.programs[0];
//! println!("Application: {}", program.name);
//! ```

use std::path::Path;

use crate::schema::Knx;

/// Error type for XML parsing operations.
#[derive(Debug)]
pub enum ParseError {
    /// Error reading the file from disk.
    Io(std::io::Error),
    /// Error parsing the XML content.
    Xml(quick_xml::DeError),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "I/O error: {}", e),
            ParseError::Xml(e) => write!(f, "XML parsing error: {}", e),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Io(e) => Some(e),
            ParseError::Xml(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

impl From<quick_xml::DeError> for ParseError {
    fn from(e: quick_xml::DeError) -> Self {
        ParseError::Xml(e)
    }
}

/// Parse a KNX ApplicationProgram from an XML string.
///
/// # Arguments
///
/// * `xml` - The XML content as a string slice.
///
/// # Returns
///
/// The parsed [`Knx`] root element containing the application program.
///
/// # Errors
///
/// Returns a [`ParseError::Xml`] if the XML cannot be parsed.
pub fn parse_application_program(xml: &str) -> Result<Knx, ParseError> {
    let knx: Knx = quick_xml::de::from_str(xml)?;
    Ok(knx)
}

/// Parse a KNX ApplicationProgram from an XML file.
///
/// # Arguments
///
/// * `path` - Path to the XML file.
///
/// # Returns
///
/// The parsed [`Knx`] root element containing the application program.
///
/// # Errors
///
/// Returns a [`ParseError::Io`] if the file cannot be read, or
/// [`ParseError::Xml`] if the XML cannot be parsed.
pub fn parse_application_program_from_file(path: &Path) -> Result<Knx, ParseError> {
    let xml = std::fs::read_to_string(path)?;
    parse_application_program(&xml)
}

/// Summary statistics for a parsed application program.
#[derive(Debug, Clone, Default)]
pub struct ProgramSummary {
    /// Application program name.
    pub name: String,
    /// Application program ID.
    pub id: String,
    /// Mask version (e.g., "MV-0705").
    pub mask_version: String,
    /// Number of parameter types defined.
    pub parameter_type_count: usize,
    /// Number of parameters defined.
    pub parameter_count: usize,
    /// Number of parameter references.
    pub parameter_ref_count: usize,
    /// Number of communication objects.
    pub com_object_count: usize,
    /// Number of communication object references.
    pub com_object_ref_count: usize,
    /// Number of channels in dynamic section.
    pub channel_count: usize,
    /// Whether a channel-independent block exists.
    pub has_channel_independent_block: bool,
    /// Number of code segments.
    pub code_segment_count: usize,
}

impl ProgramSummary {
    /// Create a summary from a parsed [`Knx`] document.
    pub fn from_knx(knx: &Knx) -> Option<Self> {
        let programs = &knx.manufacturer_data.manufacturer.application_programs.programs;
        let program = programs.first()?;

        let static_section = &program.static_section;

        let parameter_type_count = static_section.parameter_types.as_ref().map(|pt| pt.types.len()).unwrap_or(0);

        let parameter_count = static_section.parameters.as_ref().map(|p| count_parameters(&p.items)).unwrap_or(0);

        let parameter_ref_count = static_section.parameter_refs.as_ref().map(|pr| pr.refs.len()).unwrap_or(0);

        let com_object_count = static_section.com_object_table.as_ref().map(|cot| cot.objects.len()).unwrap_or(0);

        let com_object_ref_count = static_section.com_object_refs.as_ref().map(|cor| cor.refs.len()).unwrap_or(0);

        let code_segment_count =
            static_section.code.as_ref().map(|c| c.absolute_segments.len() + c.relative_segments.len()).unwrap_or(0);

        let (channel_count, has_channel_independent_block) = program
            .dynamic
            .as_ref()
            .map(|d| (d.all_channels().len(), d.channel_independent_block().is_some()))
            .unwrap_or((0, false));

        Some(ProgramSummary {
            name: program.name.clone(),
            id: program.id.clone(),
            mask_version: program.mask_version.clone(),
            parameter_type_count,
            parameter_count,
            parameter_ref_count,
            com_object_count,
            com_object_ref_count,
            channel_count,
            has_channel_independent_block,
            code_segment_count,
        })
    }
}

/// Count the number of parameters in a list of parameter items, including those in unions.
fn count_parameters(items: &[crate::schema::ParameterItem]) -> usize {
    items
        .iter()
        .map(|item| match item {
            crate::schema::ParameterItem::Parameter(_) => 1,
            crate::schema::ParameterItem::Union(u) => u.parameters.len(),
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
     CreatedBy="test"
     ToolVersion="1.0"
     xmlns="http://knx.org/xml/project/20">
  <ManufacturerData>
    <Manufacturer RefId="M-0001">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-0001_A-0001-01-0001"
                           ApplicationNumber="1"
                           ApplicationVersion="1"
                           ProgramType="ApplicationProgram"
                           MaskVersion="MV-07B0"
                           Name="Test Application"
                           LoadProcedureStyle="MergedProcedure"
                           PeiType="0"
                           DefaultLanguage="en-US"
                           DynamicTableManagement="false"
                           Linkable="false">
          <Static>
          </Static>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>"#;

        let result = parse_application_program(xml);
        assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

        let knx = result.unwrap();
        let program = &knx.manufacturer_data.manufacturer.application_programs.programs[0];
        assert_eq!(program.name, "Test Application");
        assert_eq!(program.mask_version, "MV-07B0");
    }

    #[test]
    fn test_parse_module_definition() {
        // XML with a ModuleDef containing arguments, parameters with BaseOffset, and ComObjects with BaseNumber
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
     CreatedBy="test"
     ToolVersion="1.0"
     xmlns="http://knx.org/xml/project/20">
  <ManufacturerData>
    <Manufacturer RefId="M-0001">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-0001_A-0001-01-0001"
                           ApplicationNumber="1"
                           ApplicationVersion="1"
                           ProgramType="ApplicationProgram"
                           MaskVersion="MV-07B0"
                           Name="Module Test"
                           LoadProcedureStyle="MergedProcedure"
                           PeiType="0"
                           DefaultLanguage="en-US"
                           DynamicTableManagement="false"
                           Linkable="false">
          <Static/>
          <ModuleDefs>
            <ModuleDef Id="M-0001_A-0001-01-0001_MD-1" Name="TestModule">
              <Arguments>
                <Argument Id="M-0001_A-0001-01-0001_MD-1_A-1" Name="ParamBase" Allocates="10" />
                <Argument Id="M-0001_A-0001-01-0001_MD-1_A-2" Name="ObjBase" Allocates="3" />
              </Arguments>
              <Static>
                <Parameters>
                  <Parameter Id="M-0001_A-0001-01-0001_MD-1_P-1" Name="TestParam" Text="Test Parameter" ParameterType="M-0001_A-0001-01-0001_PT-1" Value="0">
                    <Memory CodeSegment="M-0001_A-0001-01-0001_CS-1" Offset="0" BitOffset="0" BaseOffset="M-0001_A-0001-01-0001_MD-1_A-1" />
                  </Parameter>
                </Parameters>
                <ComObjectTable>
                  <ComObject Id="M-0001_A-0001-01-0001_MD-1_O-1" Name="TestObj" Text="Test Object" Number="0" BaseNumber="M-0001_A-0001-01-0001_MD-1_A-2" FunctionText="Switch" ObjectSize="1 Bit" ReadFlag="Enabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Enabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
                </ComObjectTable>
              </Static>
            </ModuleDef>
          </ModuleDefs>
          <Dynamic>
            <Channel Id="M-0001_A-0001-01-0001_CH-1" Name="Test Channel">
              <choose ParamRefId="M-0001_A-0001-01-0001_P-Enable_R-1">
                <when test="1">
                  <Module Id="M-0001_A-0001-01-0001_MD-1_M-1" RefId="M-0001_A-0001-01-0001_MD-1">
                    <NumericArg RefId="M-0001_A-0001-01-0001_MD-1_A-1" Value="100" />
                    <NumericArg RefId="M-0001_A-0001-01-0001_MD-1_A-2" Value="10" />
                  </Module>
                </when>
              </choose>
            </Channel>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>"#;

        let result = parse_application_program(xml);
        assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

        let knx = result.unwrap();
        let program = &knx.manufacturer_data.manufacturer.application_programs.programs[0];

        // Verify ModuleDefs was parsed (at ApplicationProgram level, not in Static)
        let module_defs = program.module_defs.as_ref().expect("ModuleDefs should be present");
        assert_eq!(module_defs.module_defs.len(), 1);

        let module_def = &module_defs.module_defs[0];
        assert_eq!(module_def.name, "TestModule");
        assert_eq!(module_def.id, "M-0001_A-0001-01-0001_MD-1");

        // Verify Arguments
        let args = module_def.arguments.as_ref().expect("Arguments should be present");
        assert_eq!(args.arguments.len(), 2);
        assert_eq!(args.arguments[0].name, "ParamBase");
        assert_eq!(args.arguments[0].allocates, 10);

        // Verify Module instance in Dynamic section
        let dynamic = program.dynamic.as_ref().expect("Dynamic should be present");
        let channels = dynamic.all_channels();
        assert_eq!(channels.len(), 1);

        let channel = channels[0];
        assert_eq!(channel.items.len(), 1);

        // Check that the choose/when/Module structure is parsed
        if let crate::schema::ChannelItem::Choose(choose) = &channel.items[0] {
            assert_eq!(choose.whens.len(), 1);
            assert_eq!(choose.whens[0].items.len(), 1);

            if let crate::schema::WhenItem::Module(module) = &choose.whens[0].items[0] {
                assert_eq!(module.ref_id, "M-0001_A-0001-01-0001_MD-1");
                assert_eq!(module.args.len(), 2);

                // Verify NumericArg values
                if let crate::schema::ModuleArg::NumericArg { ref_id, value } = &module.args[0] {
                    assert_eq!(ref_id, "M-0001_A-0001-01-0001_MD-1_A-1");
                    assert_eq!(*value, 100);
                } else {
                    panic!("Expected NumericArg");
                }
            } else {
                panic!("Expected Module in when block");
            }
        } else {
            panic!("Expected Choose in channel items");
        }
    }

    #[test]
    fn test_roundtrip_module_serialization() {
        use crate::schema::*;

        // Create a ModuleDef programmatically
        let module_def = ModuleDef {
            id: "M-0001_MD-1".to_string(),
            name: "TestModule".to_string(),
            internal_description: None,
            arguments: Some(ModuleDefArguments {
                arguments: vec![ModuleDefArgument {
                    id: "M-0001_MD-1_A-1".to_string(),
                    name: "ParamBase".to_string(),
                    allocates: 10,
                    alignment: None,
                    arg_type: None,
                }],
            }),
            static_section: ModuleDefStatic {
                parameters: None,
                parameter_refs: None,
                com_objects: None,
                com_object_refs: None,
            },
            dynamic: None,
        };

        // Serialize to XML
        let xml_result = quick_xml::se::to_string(&module_def);
        assert!(xml_result.is_ok(), "Serialization failed: {:?}", xml_result.err());

        let xml = xml_result.unwrap();
        assert!(xml.contains("TestModule"));
        assert!(xml.contains("ParamBase"));
        assert!(xml.contains("Allocates=\"10\""));

        // Deserialize back
        let parsed: Result<ModuleDef, _> = quick_xml::de::from_str(&xml);
        assert!(parsed.is_ok(), "Deserialization failed: {:?}", parsed.err());

        let parsed_def = parsed.unwrap();
        assert_eq!(parsed_def.name, "TestModule");
        assert_eq!(parsed_def.arguments.as_ref().unwrap().arguments.len(), 1);
    }
}
