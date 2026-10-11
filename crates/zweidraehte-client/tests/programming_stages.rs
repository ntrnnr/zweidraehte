//! Public compile and preview tests use complete product and target fixtures.

use std::collections::BTreeMap;
use zweidraehte_client::IndividualAddress;
use zweidraehte_client::commissioning::ImageLocation;
use zweidraehte_client::commissioning::input::{CommissioningIntent, DownloadMode, ProgrammingInput, TargetSelection};
use zweidraehte_client::commissioning::inspection::{OperationData, ProcedureOperation};
use zweidraehte_client::commissioning::{CompileErrorKind, CompileOptions, ProgrammingCatalog};
use zweidraehte_client::commissioning::{DesiredDataSecurity, ManagementCredential, ObservedDataSecurity};
use zweidraehte_client::commissioning::{ObservedTarget, ProgrammingFacts};
use zweidraehte_client::commissioning::{ProfileDiscovery, ProfileSelection, ResourceManagementStyle};
use zweidraehte_client::configuration::ResolvedKeyMaterial;
use zweidraehte_client::configuration::{LoweredDeviceConfiguration, MaterializedDevice};
use zweidraehte_ets_files::product::ProductData;

const MASTER_DATA: &str = r#"
<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-STAGES" Version="1"><MaskVersions>
    <MaskVersion Id="MV-0012" MaskVersion="18" Name="Stage fixture" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
      <HawkConfigurationData><Procedures>
        <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
          <LdCtrlConnect />
          <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
          <LdCtrlDisconnect />
        </Procedure>
      </Procedures></HawkConfigurationData>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;

const PRODUCT: &str = r#"
<KNX xmlns="http://knx.org/xml/project/23" CreatedBy="stage-test" ToolVersion="1">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1"
      ProgramType="ApplicationProgram" MaskVersion="MV-0012" Name="Stage fixture"
      LoadProcedureStyle="DefaultProcedure" PeiType="0" DefaultLanguage="en-US"
      DynamicTableManagement="false" Linkable="false">
      <Static><Code>
        <AbsoluteSegment Id="M-00FA_A-0001-01-0000_AS-100" Address="256" Size="4" MemoryType="EEPROM">
          <Data>AQIDBA==</Data>
        </AbsoluteSegment>
      </Code></Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

fn fixture() -> (ProgrammingCatalog, ProfileSelection, MaterializedDevice, CompileOptions) {
    fixture_catalog(MASTER_DATA)
}

fn fixture_catalog(xml: &str) -> (ProgrammingCatalog, ProfileSelection, MaterializedDevice, CompileOptions) {
    let catalog = ProgrammingCatalog::from_xml(xml).expect("synthetic catalog parses");
    let product = ProductData::from_mtxml_str(PRODUCT).expect("synthetic product parses");
    let profile = ProfileSelection::new(ProfileDiscovery {
        dd0: 0x0012,
        management_descriptor_01: None,
        management_style: Some(ResourceManagementStyle::Simple),
    });
    let address = IndividualAddress::new(1, 1, 23);
    let configuration = LoweredDeviceConfiguration::new(address, Some(15));
    let device = MaterializedDevice::new(
        product.bind_master_data(catalog.document()).expect("fixture document binds"),
        configuration,
        Vec::new(),
        ResolvedKeyMaterial::new(None),
    );
    let options = CompileOptions {
        target: TargetSelection::ExistingAddress(address),
        automatic_sections: None,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    };
    (catalog, profile, device, options)
}

#[test]
fn management_credentials_do_not_change_authored_control_guards() {
    for credential in [ManagementCredential::Plaintext, ManagementCredential::ToolKey] {
        let (_catalog, profile, device, options) = fixture();
        let facts = ProgrammingFacts::new(ObservedTarget {
            credential,
            ..plain_facts().target.expect("fixture has target evidence")
        })
        .with_data_security(ObservedDataSecurity::Disabled);
        let input = ProgrammingInput::new(device, CommissioningIntent::Download(DownloadMode::Full), options)
            .data_security(DesiredDataSecurity::Disabled)
            .facts(facts);

        assert_eq!(input.observed_facts(), facts);

        input.preview(&profile).expect("disabled application image compiles");
        let program = input.compile(&profile).expect("selected management credential lowers");
        let write = program
            .procedure()
            .expect("download procedure")
            .steps
            .iter()
            .find(|step| matches!(step.operation, ProcedureOperation::Write { .. }))
            .expect("fixture writes its image");

        assert_eq!(program.facts(), facts);
        assert_eq!(program.desired_data_security(), DesiredDataSecurity::Disabled);
        assert!(!write.secure_only);
    }
}

#[test]
fn a_requested_address_does_not_implicitly_select_plaintext_management() {
    let (_catalog, profile, device, options) = fixture();
    let input = ProgrammingInput::new(device, CommissioningIntent::Download(DownloadMode::Full), options);
    assert_eq!(input.observed_facts(), ProgrammingFacts::default());

    let image = input.preview(&profile).expect("image remains inspectable");
    assert!(!image.image().is_empty());
    let error = input.compile(&profile).expect_err("target access must be supplied");

    assert_eq!(error.kind, CompileErrorKind::MissingEvidence);
    assert!(error.message.contains("target"));
}

#[test]
fn missing_acquisition_facts_do_not_prevent_image_inspection() {
    let (_catalog, profile, device, mut options) = fixture();
    options.target = TargetSelection::SerialNumber([0, 0xfa, 0, 0, 0, 23]);
    let input = ProgrammingInput::new(device, CommissioningIntent::Download(DownloadMode::Full), options);

    let image = input.preview(&profile).expect("the complete desired image remains inspectable");
    assert!(!image.image().is_empty());
    let error = input.compile(&profile).expect_err("execution cannot be bound without acquisition facts");
    assert_eq!(error.kind, CompileErrorKind::MissingEvidence);
    assert!(error.message.contains("target"));
}

#[test]
fn selected_candidate_resolves_choices_merges_and_scope_before_image() {
    use zweidraehte_client::configuration::{ProcedureParameter, ProcedureParameterValue};
    use zweidraehte_ets_files::product::LoadProcedureStyle;
    use zweidraehte_ets_files::schema::{LdCtrlWriteMem, LoadControl, LoadProcedure};

    let (_, _, device, options) = fixture();
    let source = MASTER_DATA.replace(r#"ProcedureSubType="all""#, r#"ProcedureSubType="ap1""#).replace(
        r#"<LdCtrlWriteMem Address="256" Size="4" Verify="false" />"#,
        r#"<choose ParamRefId="DownloadPath">
            <when test="0"><LdCtrlWriteProp ObjIdx="4" PropId="31" Verify="false" /></when>
            <when test="9"><LdCtrlMerge MergeId="7" /></when>
           </choose>
           <LdCtrlDelay AppliesTo="par" MilliSeconds="900" />"#,
    );
    let catalog = ProgrammingCatalog::from_xml(&source).expect("branching catalog parses");
    let product = ProductData::from_mtxml_str(PRODUCT)
        .expect("fixture product")
        .with_fixture_load_procedure_style(LoadProcedureStyle::Merged)
        .with_fixture_load_procedures(vec![LoadProcedure {
            merge_id: Some(7),
            controls: vec![LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                address: 256,
                size: 4,
                verify: false,
                ..Default::default()
            })],
        }]);
    let profile = ProfileSelection::new(ProfileDiscovery {
        dd0: 0x0012,
        management_descriptor_01: None,
        management_style: Some(ResourceManagementStyle::Simple),
    });
    let mut configuration = device.configuration().clone();
    configuration.procedure_parameters.insert("DownloadPath".to_owned(), ProcedureParameter {
        active: true,
        value: ProcedureParameterValue::Unsigned(9),
    });
    let device = MaterializedDevice::new(
        product.bind_master_data(catalog.document()).expect("fixture document binds"),
        configuration,
        Vec::new(),
        ResolvedKeyMaterial::new(None),
    );
    let input =
        ProgrammingInput::new(device, CommissioningIntent::Download(DownloadMode::Full), options).facts(plain_facts());

    input.preview(&profile).expect("unselected property needs no image facts");
    let program = input.compile(&profile).expect("flat recipe binds the declared placement");
    let procedure = program.procedure().expect("download has executable controls");
    assert_eq!(procedure.steps.len(), 3);
    assert_eq!(procedure.steps[1].path.control_indices, [1, 1, 0, 0]);
}

#[test]
fn unload_probe_uses_selected_branch_and_declared_placement() {
    use zweidraehte_client::commissioning::input::UnloadMode;
    use zweidraehte_client::configuration::{ProcedureParameter, ProcedureParameterValue};

    let (_, _, device, options) = fixture();
    let source = MASTER_DATA.replace(r#"ProcedureType="Load""#, r#"ProcedureType="Unload""#).replace(
        r#"<LdCtrlWriteMem Address="256" Size="4" Verify="false" />"#,
        r#"<choose ParamRefId="DownloadPath">
            <when test="0"><LdCtrlWriteProp ObjIdx="4" PropId="31" Verify="false" /></when>
            <when test="9"><LdCtrlWriteMem Address="256" Size="1024" Verify="false" /></when>
           </choose>"#,
    );
    let catalog = ProgrammingCatalog::from_xml(&source).expect("unload catalog parses");
    let product = ProductData::from_mtxml_str(PRODUCT).expect("fixture product");
    let profile = ProfileSelection::new(ProfileDiscovery {
        dd0: 0x0012,
        management_descriptor_01: None,
        management_style: Some(ResourceManagementStyle::Simple),
    });
    let mut configuration = device.configuration().clone();
    configuration.procedure_parameters.insert("DownloadPath".to_owned(), ProcedureParameter {
        active: true,
        value: ProcedureParameterValue::Unsigned(9),
    });
    let device = MaterializedDevice::new(
        product.bind_master_data(catalog.document()).expect("fixture document binds"),
        configuration,
        Vec::new(),
        ResolvedKeyMaterial::new(None),
    );
    let input = ProgrammingInput::new(device, CommissioningIntent::Unload(UnloadMode::Application), options)
        .facts(plain_facts());

    let imaged = input.preview(&profile).expect("probe clips to the declared four-byte segment");
    assert_eq!(
        imaged
            .image()
            .range(&ImageLocation::standard_memory(256), 4)
            .expect("scoped image retains declared product bytes")
            .data(),
        [1, 2, 3, 4]
    );
    let program = input.compile(&profile).expect("scoped recipe lowers");
    let write = &program.procedure().expect("unload controls exist").steps[1];
    assert!(matches!(write.operation, ProcedureOperation::Write { extent, .. } if extent.byte_length == 4));
}

#[test]
fn unload_comparison_of_a_prior_read_requires_no_desired_image_bytes() {
    use zweidraehte_client::commissioning::input::UnloadMode;
    use zweidraehte_client::commissioning::inspection::Comparison;

    let (_, _, _, options) = fixture();
    let source = MASTER_DATA.replace(r#"ProcedureType="Load""#, r#"ProcedureType="Unload""#).replace(
        r#"<LdCtrlWriteMem Address="256" Size="4" Verify="false" />"#,
        r#"<LdCtrlLoadImageMem Address="256" Size="4" />
           <LdCtrlCompareMem Address="256" Size="4" />"#,
    );
    let device = fixture_catalog(&source).2;
    let profile = ProfileSelection::new(ProfileDiscovery {
        dd0: 0x0012,
        management_descriptor_01: None,
        management_style: Some(ResourceManagementStyle::Simple),
    });
    let input = ProgrammingInput::new(device, CommissioningIntent::Unload(UnloadMode::Application), options)
        .facts(plain_facts());

    let imaged = input.preview(&profile).expect("no desired product bytes are needed");
    assert!(imaged.image().is_empty());
    let program = input.compile(&profile).expect("comparison binds to the prior read");
    assert!(program.procedure().expect("unload has controls").steps.iter().any(|step| matches!(
        step.operation,
        ProcedureOperation::Compare { comparison: Comparison::ImageExact { length: 4, .. }, .. }
    )));
}

fn automatic_fixture() -> (ProgrammingCatalog, ProfileSelection, MaterializedDevice, CompileOptions) {
    let (_, _, _, options) = fixture();
    let source = MASTER_DATA.replace(
        "<Procedures>",
        r#"<Procedures>
        <Procedure ProcedureType="Load" ProcedureSubType="par" Access="remote">
          <LdCtrlConnect />
          <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
          <LdCtrlDisconnect />
        </Procedure>"#,
    );
    let catalog = ProgrammingCatalog::from_xml(&source).expect("partial and full procedures parse");
    let device = fixture_catalog(&source).2;
    let profile = ProfileSelection::new(ProfileDiscovery {
        dd0: 0x0012,
        management_descriptor_01: None,
        management_style: Some(ResourceManagementStyle::Simple),
    });

    (catalog, profile, device, options)
}

#[test]
fn disabled_security_requires_observation_only_when_group_scope_is_selected() {
    use zweidraehte_client::commissioning::input::ProgramSections;

    let (catalog, profile, device, options) = automatic_fixture();
    let product = device.product().clone().with_fixture_data_secure(true);
    let device = MaterializedDevice::new(
        product.bind_master_data(catalog.document()).expect("fixture document binds"),
        device.configuration().clone(),
        Vec::new(),
        ResolvedKeyMaterial::new(None),
    );

    for mode in [ObservedDataSecurity::Unknown, ObservedDataSecurity::Enabled, ObservedDataSecurity::Disabled] {
        for sections in [ProgramSections::PARAMETERS, ProgramSections::all()] {
            let mut options = options.clone();
            options.automatic_sections = Some(sections);
            let input =
                ProgrammingInput::new(device.clone(), CommissioningIntent::Download(DownloadMode::Automatic), options)
                    .facts(plain_facts().with_data_security(mode));

            input.preview(&profile).expect("disabled desired security has no image writes");

            let result = input.compile(&profile);
            if sections == ProgramSections::PARAMETERS || mode == ObservedDataSecurity::Disabled {
                let program = result.expect("selected scope needs no security transition");
                assert_eq!(
                    program.desired_data_security(),
                    if sections == ProgramSections::PARAMETERS {
                        DesiredDataSecurity::Preserve
                    } else {
                        DesiredDataSecurity::Disabled
                    },
                    "network bootstrap follows the selected security scope"
                );
            } else {
                let error = result.expect_err("selected disabled security requires a supported observed transition");
                let text = error.to_string();
                match mode {
                    ObservedDataSecurity::Unknown => assert!(text.contains("observed"), "unexpected error: {text}"),
                    ObservedDataSecurity::Enabled => assert!(text.contains("disabl"), "unexpected error: {text}"),
                    ObservedDataSecurity::Disabled => unreachable!("known disabled transition succeeded above"),
                }
            }
        }
    }
}

fn plain_facts() -> ProgrammingFacts {
    ProgrammingFacts::new(ObservedTarget {
        previous_address: IndividualAddress::new(1, 1, 23),
        serial_number: None,
        credential: ManagementCredential::Plaintext,
    })
}

#[test]
fn preview_and_compile_share_the_desired_image() {
    let (_, profile, device, options) = fixture();
    let input =
        ProgrammingInput::new(device, CommissioningIntent::Download(DownloadMode::Full), options).facts(plain_facts());
    let image = input.preview(&profile).expect("desired image compiles");
    let program = input.compile(&profile).expect("program compiles");
    assert_eq!(image.image(), program.image());
}

#[test]
fn one_compiler_uses_each_products_exact_document_even_with_the_same_schema() {
    let mut fingerprints = Vec::new();

    for delay in [17, 23] {
        let source = MASTER_DATA
            .replace("<LdCtrlDisconnect />", &format!("<LdCtrlDelay MilliSeconds=\"{delay}\" /><LdCtrlDisconnect />"));
        let (catalog, selection, device, options) = fixture_catalog(&source);
        let input = ProgrammingInput::new(device, CommissioningIntent::Download(DownloadMode::Full), options)
            .facts(plain_facts());

        let program = input.compile(&selection).expect("product supplies its own catalog");
        assert!(program.procedure().expect("download procedure").steps.iter().any(|step| {
            matches!(step.operation, ProcedureOperation::Delay { milliseconds } if milliseconds == delay)
        }));
        assert_eq!(program.profile().master_data_fingerprint(), catalog.fingerprint());
        fingerprints.push(program.profile().master_data_fingerprint());
    }

    assert_ne!(fingerprints[0], fingerprints[1]);
}

#[test]
fn loose_input_requires_an_associated_document_before_resolution() {
    let (_, selection, device, options) = fixture();
    let product = ProductData::from_mtxml_str(PRODUCT).expect("loose product parses");
    let device =
        MaterializedDevice::new(product, device.configuration().clone(), Vec::new(), ResolvedKeyMaterial::new(None));
    let input = ProgrammingInput::new(device, CommissioningIntent::Download(DownloadMode::Full), options);

    let error = input.compile(&selection).expect_err("compilation cannot choose another source");
    assert_eq!(error.kind, CompileErrorKind::MissingEvidence);
    assert!(error.message.contains("Master Data"));
}
