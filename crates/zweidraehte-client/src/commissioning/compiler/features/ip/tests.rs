use super::security::validate_secure_intent;
use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::compiler::secrets::CredentialTransition;
use crate::commissioning::image::ImageSpace;
use crate::commissioning::procedure::FunctionPropertyOperation;
use crate::commissioning::procedure::OperationData;
use crate::commissioning::procedure::OperationExtent;
use crate::commissioning::procedure::OperationTarget;
use crate::commissioning::procedure::ProcedureOperation;
use crate::configuration::LoweredDeviceConfiguration;
use crate::configuration::ResolvedIpSecureConfiguration;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::num::NonZeroU8;
use zweidraehte_project::IpAssignment;
use zweidraehte_project::IpServiceSecurity;
use zweidraehte_proto::pid;

use zweidraehte_project::{IpSecurityIntent, IpTunnellingUserBinding, ProjectInstallationId};
use zweidraehte_proto::address::IndividualAddress;

use super::*;
use crate::commissioning::catalog::profile::testing::fixture_profile;
use crate::commissioning::procedure::operands::PropertyAddress;
use crate::configuration::TopologyConfiguration;

#[test]
fn plain_management_binds_public_ip_settings_with_dormant_security_controls() {
    use crate::bus::access::ManagementCredential;
    use crate::commissioning::input::ProgramSections;
    use crate::commissioning::{
        CommissioningIntent, DesiredDataSecurity, DownloadMode, ObservedDataSecurity, ObservedTarget, ProgrammingFacts,
    };

    let product = product(true);
    let mut profile = profile("MV-57B0");
    let mut intent = basic_secure_intent();
    intent.security = Some(IpSecurityIntent {
        routing: IpServiceSecurity::Plain,
        device_management: IpServiceSecurity::Plain,
        tunnelling: IpServiceSecurity::Plain,
        multicast_latency_tolerance_ms: 1000,
        sync_latency_fraction: 0,
        tunnelling_users: Vec::new(),
    });
    intent.password_users.clear();
    let configuration = configuration(&product, intent);
    prepare_classic_ip_profile(&mut profile, &product, configuration.topology.ip.as_ref())
        .expect("standard IP configuration metadata");
    let target = ObservedTarget {
        previous_address: configuration.individual_address,
        serial_number: None,
        credential: ManagementCredential::Plaintext,
    };
    let mut input = super::super::fixture_input(&product, &configuration, None, None)
        .data_security(DesiredDataSecurity::Disabled)
        .facts(ProgrammingFacts::new(target).with_data_security(ObservedDataSecurity::Disabled));
    input.intent = CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::CONFIGURATION));
    let mut compiler = super::super::fixture_compiler(&input, &profile);
    compiler.select_controls().expect("configuration-only source");
    compiler.contribute_ip().expect("public and guarded IP controls");
    let mut protected = super::super::fixture_compiler(&input, &profile);
    protected.select_controls().expect("protected source");
    protected.contribute_ip().expect("protected IP controls");
    let crate::commissioning::compiler::selection::RecipeSet::Exact { procedure, .. } = &mut protected.recipes else {
        panic!("exact configuration source");
    };
    procedure.insert_builtin(
        super::super::ProcedureCompilationPhase::BeforeSessionClose,
        "standard-data-secure",
        zweidraehte_project::ProgrammingSection::GroupCommunication,
        true,
        ProcedureOperation::MapError { filter: None, original: 1, mapped: 1 },
    );
    let error = protected.bind_operands().err().expect("Data Secure still requires secure management");
    assert_eq!(error.message, "Data Secure programming requires secure management access");
    let output = compiler.bind_operands().expect("plain credentials permit dormant IP security controls");
    let procedure = output.program.procedure.expect("IP procedure");
    let guarded: Vec<_> = procedure
        .steps
        .iter()
        .filter(|step| step.path.contribution == Some("standard-ip-secure-configuration"))
        .collect();
    assert!(guarded.is_empty(), "plain management omits the reference's dormant security controls");
    assert!(
        procedure.steps.iter().any(|step| step.path.contribution == Some("standard-ip-configuration")),
        "public IP configuration remains executable"
    );
    assert!(procedure.steps.iter().all(|step| !step.secure_only));
}

#[test]
fn configuration_only_ip_controls_frame_the_selected_empty_source_and_restart() {
    use crate::commissioning::compiler::selection::RecipeSet;
    use crate::commissioning::input::ProgramSections;
    use crate::commissioning::procedure::ProcedureSourceId;
    use crate::commissioning::{CommissioningIntent, DesiredDataSecurity, DownloadMode, RestartKind};

    // Native configuration-only compilation starts with no application source.
    // Its IP task requests a restart, then final session correction frames the
    // generated controls. Data Secure support selects the confirmed terminal
    // even when application security and all IP families are disabled.
    for secure_product in [false, true] {
        let product = product(secure_product);
        let mut profile = profile("MV-57B0");
        let mut intent = basic_secure_intent();
        intent.security = secure_product.then_some(IpSecurityIntent {
            routing: IpServiceSecurity::Plain,
            device_management: IpServiceSecurity::Plain,
            tunnelling: IpServiceSecurity::Plain,
            multicast_latency_tolerance_ms: 1500,
            sync_latency_fraction: 3,
            tunnelling_users: Vec::new(),
        });
        intent.password_users.clear();
        let configuration = configuration(&product, intent);
        prepare_classic_ip_profile(&mut profile, &product, configuration.topology.ip.as_ref())
            .expect("standard OT11 facts resolve");
        let mut input = super::super::fixture_input(&product, &configuration, None, None)
            .data_security(DesiredDataSecurity::Disabled);
        input.intent = CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::CONFIGURATION));
        let mut compiler = super::super::fixture_compiler(&input, &profile);
        compiler.select_controls().expect("configuration-only source selection resolves");
        let RecipeSet::Exact { procedure, .. } = &compiler.recipes else {
            panic!("configuration-only selects an exact source");
        };
        assert_eq!(procedure.program.id, ProcedureSourceId::Generated {
            name: "empty application configuration source".into(),
        });
        assert!(procedure.program.steps.is_empty());

        compiler.contribute_ip().expect("IP configuration emits controls");
        let RecipeSet::Exact { procedure, .. } = compiler.recipes else {
            panic!("IP configuration retains the selected source");
        };
        let program = procedure
            .finish(&profile, &compiler.image.image, true)
            .expect("generated IP controls receive a session and restart");
        assert!(matches!(program.steps[0].operation, ProcedureOperation::Connect));
        assert!(matches!(program.steps[1].operation, ProcedureOperation::LoadImage { .. }));
        let last = program.steps.len() - 1;
        assert!(matches!(program.steps[last].operation, ProcedureOperation::Disconnect));
        let expected = if secure_product { RestartKind::Confirmed } else { RestartKind::Basic };
        assert!(matches!(program.steps[last - 1].operation, ProcedureOperation::Restart { kind } if kind == expected));
        assert_eq!(
            program.steps.iter().filter(|step| matches!(step.operation, ProcedureOperation::Restart { .. })).count(),
            1
        );
    }
}

#[test]
fn generated_ip_controls_keep_their_own_guards_under_keyed_source_selection() {
    use crate::bus::access::ManagementCredential;
    use crate::commissioning::compiler::selection::RecipeSet;
    use crate::commissioning::input::ProgramSections;
    use crate::commissioning::{
        CommissioningIntent, DesiredDataSecurity, DownloadMode, ObservedDataSecurity, ObservedTarget, ProgrammingFacts,
    };

    let product = product(true);
    let mut profile = profile("MV-57B0");
    let mut intent = basic_secure_intent();
    intent.security = Some(IpSecurityIntent {
        routing: IpServiceSecurity::Plain,
        device_management: IpServiceSecurity::Plain,
        tunnelling: IpServiceSecurity::Plain,
        multicast_latency_tolerance_ms: 1500,
        sync_latency_fraction: 3,
        tunnelling_users: Vec::new(),
    });
    intent.password_users.clear();
    let configuration = configuration(&product, intent);
    prepare_classic_ip_profile(&mut profile, &product, configuration.topology.ip.as_ref())
        .expect("standard OT11 facts resolve");

    // Native IP task controls own their guards, even when a tool key opens the
    // selected management session. Public configuration must remain usable in
    // either management mode; service-family security still requires a key.
    for credential in [ManagementCredential::Plaintext, ManagementCredential::ToolKey, ManagementCredential::Fdsk] {
        let target =
            ObservedTarget { previous_address: configuration.individual_address, serial_number: None, credential };
        let mut input = super::super::fixture_input(&product, &configuration, None, None)
            .data_security(DesiredDataSecurity::Disabled)
            .facts(ProgrammingFacts::new(target).with_data_security(ObservedDataSecurity::Disabled));
        input.intent = CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::CONFIGURATION));
        let mut compiler = super::super::fixture_compiler(&input, &profile);
        compiler.select_controls().expect("configuration source selection resolves");
        compiler.contribute_ip().expect("IP controls emit");
        let RecipeSet::Exact { procedure, .. } = compiler.recipes else {
            panic!("configuration selects an exact procedure");
        };
        let program = procedure.finish(&profile, &compiler.image.image, true).expect("IP controls bind");
        let public: Vec<_> =
            program.steps.iter().filter(|step| step.path.contribution == Some("standard-ip-configuration")).collect();
        let secured: Vec<_> = program
            .steps
            .iter()
            .filter(|step| step.path.contribution == Some("standard-ip-secure-configuration"))
            .collect();
        assert!(!public.is_empty());
        assert!(!secured.is_empty());
        assert!(
            public.iter().all(|step| !step.secure_only),
            "public IP controls inherit no source guard: {credential:?}"
        );
        assert!(secured.iter().all(|step| step.secure_only), "IP security controls retain their guard: {credential:?}");
    }
}

// A product procedure may write an OT-11 parameter without InlineData; one
// merged fragment writes a single friendly-name element. The IP feature fills
// that image only after source selection, so lowering keeps the write and
// binding sends the configured byte. Without a configured image it stays a
// no-op, as the reference's write finds no segment.
#[test]
fn authored_ip_property_writes_take_the_configured_feature_image() {
    use crate::bus::access::ManagementCredential;
    use crate::commissioning::{DesiredDataSecurity, ObservedDataSecurity, ObservedTarget, ProgrammingFacts};

    let procedures = r#"<LoadProcedures><LoadProcedure>
        <LdCtrlConnect /><LdCtrlWriteProp ObjType="11" PropId="76" Verify="false" /><LdCtrlDisconnect />
      </LoadProcedure></LoadProcedures>"#;
    let product = product_with_procedures(false, "ProductProcedure", procedures);
    let mut profile = profile("MV-57B0");
    let mut intent = basic_secure_intent();
    intent.security = None;
    intent.password_users.clear();
    intent.friendly_name = "KNX IP test".to_owned();
    let configuration = configuration(&product, intent);
    prepare_classic_ip_profile(&mut profile, &product, configuration.topology.ip.as_ref())
        .expect("standard OT11 facts resolve");
    let target = ObservedTarget {
        previous_address: configuration.individual_address,
        serial_number: None,
        credential: ManagementCredential::Plaintext,
    };
    let input = super::super::fixture_input(&product, &configuration, None, None)
        .data_security(DesiredDataSecurity::Disabled)
        .facts(ProgrammingFacts::new(target).with_data_security(ObservedDataSecurity::Disabled));
    let mut compiler = super::super::fixture_compiler(&input, &profile);
    compiler.select_controls().expect("product procedure selection");
    compiler.build_image().expect("IP feature image");
    let program = compiler.bind_operands().expect("authored IP write binds").program;
    let procedure = program.procedure.clone().expect("download procedure");

    let authored: Vec<_> = procedure
        .steps
        .iter()
        .filter(|step| {
            step.path.contribution.is_none() && property_write(&step.operation) == Some(pid::ip::FRIENDLY_NAME)
        })
        .collect();
    assert_eq!(authored.len(), 1, "the authored friendly-name write survives lowering");
    let ProcedureOperation::Write { data, extent, .. } = &authored[0].operation else { unreachable!() };
    let location = property_image_location(pid::ip::FRIENDLY_NAME);
    assert_eq!(data, &OperationData::Buffer { location: location.clone(), length: 1, fallback: None });
    assert_eq!(program.image.byte(&location), Some((b'K', 0xff)));
    assert_eq!(extent, &OperationExtent::property(1, 1));
}

#[test]
fn basic_tool_configuration_has_exact_ot11_image_shape() {
    let product = product(false);
    let mut profile = profile("MV-57B0");
    let configuration = configuration(&product, ToolManagedIpConfiguration {
        project_installation_id: ProjectInstallationId::new(0x123, 4).expect("project ID is in range"),
        assignment: IpAssignment::Fixed {
            address: [192, 0, 2, 10],
            subnet_mask: [255, 255, 255, 0],
            default_gateway: [192, 0, 2, 1],
        },
        routing_multicast_address: [224, 0, 23, 12],
        multicast_ttl: 16,
        friendly_name: "  KNX IP test  ".to_owned(),
        additional_individual_addresses: vec![IndividualAddress::new(1, 1, 11)],
        security: None,
        password_users: Vec::new(),
    });
    prepare_classic_ip_profile(&mut profile, &product, configuration.topology.ip.as_ref())
        .expect("standard OT11 facts resolve");

    let (image, operations) =
        super::super::compile_fixture(&profile, &product, &configuration, None, None, |compiler| {
            compiler.contribute_ip()
        });
    let image: BTreeMap<_, _> = image
        .image
        .segments()
        .iter()
        .map(|segment| {
            let ImageSpace::Property { object, property_id } = &segment.location().space else {
                panic!("IP overlay produces only property image segments");
            };
            assert_eq!(object, &IP_OBJECT);
            (*property_id, segment.data().to_vec())
        })
        .collect();

    assert_eq!(image[&pid::ip::PROJECT_INSTALLATION_ID], [0x12, 0x34]);
    assert_eq!(image[&pid::ip::ADDITIONAL_INDIVIDUAL_ADDRESSES], [0x11, 0x0b, 0xff, 0xff]);
    assert_eq!(image[&pid::ip::IP_ASSIGNMENT_METHOD], [1]);
    assert_eq!(image[&pid::ip::IP_ADDRESS], [192, 0, 2, 10]);
    assert_eq!(image[&pid::ip::SUBNET_MASK], [255, 255, 255, 0]);
    assert_eq!(image[&pid::ip::DEFAULT_GATEWAY], [192, 0, 2, 1]);
    assert_eq!(image[&pid::ip::ROUTING_MULTICAST_ADDRESS], [224, 0, 23, 12]);
    assert_eq!(image[&pid::ip::TTL], [16]);
    assert_eq!(&image[&pid::ip::FRIENDLY_NAME][..11], b"KNX IP test");
    assert_eq!(image[&pid::ip::FRIENDLY_NAME].len(), FRIENDLY_NAME_ELEMENTS);
    assert!(image[&pid::ip::FRIENDLY_NAME][11..].iter().all(|byte| *byte == 0));
    assert!(!image.contains_key(&pid::ip::MAC_ADDRESS));

    assert!(matches!(
        &operations[0].operation,
        ProcedureOperation::LoadImage {
            target: OperationTarget::Property {
                address,

                start_element: 1,
            },
            extent: OperationExtent { byte_length: 6, property_elements: Some(1), property_element_width: None },
            alignment: 6,
            ..
        } if *address == crate::commissioning::procedure::operands::pure_property_address(&IP_OBJECT, pid::ip::MAC_ADDRESS).expect("OT11 property")
    ));
    assert!(operations.iter().all(|step| step.path.contribution.is_some()));
    assert!(matches!(
        operations.last().expect("IP configuration requires a terminal").operation,
        ProcedureOperation::Restart { kind: crate::commissioning::RestartKind::Basic }
    ));
    assert_eq!(property_write_pid(&operations[operations.len() - 2].operation), Some(pid::ip::IP_ASSIGNMENT_METHOD),);
}

#[test]
fn all_plain_ip_secure_families_need_no_private_payload_and_keep_order() {
    let product = product(true);
    let mut profile = profile("MV-57B0");
    let mut intent = basic_secure_intent();
    intent.security = Some(IpSecurityIntent {
        routing: IpServiceSecurity::Plain,
        device_management: IpServiceSecurity::Plain,
        tunnelling: IpServiceSecurity::Plain,
        multicast_latency_tolerance_ms: 1500,
        sync_latency_fraction: 3,
        tunnelling_users: Vec::new(),
    });
    intent.password_users.clear();
    let configuration = configuration(&product, intent);
    prepare_classic_ip_profile(&mut profile, &product, configuration.topology.ip.as_ref())
        .expect("standard OT11 facts resolve");

    let (_image, operations) =
        super::super::compile_fixture(&profile, &product, &configuration, None, None, |compiler| {
            compiler.contribute_ip()
        });
    let family5 = operation_index(&operations, |operation| service_family(operation) == Some(5));
    let family3 = operation_index(&operations, |operation| service_family(operation) == Some(3));
    let family4 = operation_index(&operations, |operation| service_family(operation) == Some(4));

    assert!(family5 < family3 && family3 < family4);
    assert!(!operations.iter().any(|operation| { matches!(property_write_pid(&operation.operation), Some(95 | 96)) }));
    assert!(!operations.iter().any(|operation| matches!(&operation.operation, ProcedureOperation::Write {
        data: OperationData::Secret(_),
        ..
    })));
}

#[test]
fn secure_service_credentials_are_redacted_and_ordered_by_family() {
    let product = product(true);
    let mut profile = profile("MV-57B0");
    let configuration = configuration(&product, basic_secure_intent());
    prepare_classic_ip_profile(&mut profile, &product, configuration.topology.ip.as_ref())
        .expect("standard OT11 facts resolve");
    let secrets = ResolvedIpSecureConfiguration {
        backbone_key: Some([0xa1; 16].into()),
        device_authentication_code: Some([0xb2; 16].into()),
        password_hashes: vec![
            (NonZeroU8::new(1).expect("nonzero"), [0xc3; 16].into()),
            (NonZeroU8::new(2).expect("nonzero"), [0xd4; 16].into()),
        ],
    };

    let (image, operations) =
        super::super::compile_fixture(&profile, &product, &configuration, None, Some(&secrets), |compiler| {
            compiler.contribute_ip()
        });
    let payload = &image.secret_payload;
    let pid91 = operation_index(&operations, |operation| secret_write_pid(operation) == Some(91));
    let pid95 = operation_index(&operations, |operation| property_write_pid(operation) == Some(95));
    let pid96 = operation_index(&operations, |operation| property_write_pid(operation) == Some(96));
    let family5 = operation_index(&operations, |operation| service_family(operation) == Some(5));
    let pid92 = operation_index(&operations, |operation| secret_write_pid(operation) == Some(92));
    let pid93 = operation_index(&operations, |operation| secret_write_pid(operation) == Some(93));
    let family3 = operation_index(&operations, |operation| service_family(operation) == Some(3));
    let pid97 = operation_index(&operations, |operation| property_write_pid(operation) == Some(97));
    let family4 = operation_index(&operations, |operation| service_family(operation) == Some(4));

    assert!(pid91 < pid95 && pid95 < pid96 && pid96 < family5);
    assert!(family5 < pid92 && pid92 < pid93 && pid93 < family3);
    assert!(family3 < pid97 && pid97 < family4);

    let transitions: BTreeSet<_> = operations
        .iter()
        .filter_map(|operation| match &operation.operation {
            ProcedureOperation::Write { data: OperationData::Secret(reference), .. } => Some(*reference),
            _ => None,
        })
        .flat_map(|reference| payload.transitions(reference).expect("secret reference resolves").iter().copied())
        .collect();
    assert_eq!(
        transitions,
        BTreeSet::from([
            CredentialTransition::IpBackboneKey,
            CredentialTransition::IpDeviceAuthenticationCode,
            CredentialTransition::IpPasswordHash { user_id: NonZeroU8::new(1).expect("nonzero") },
            CredentialTransition::IpPasswordHash { user_id: NonZeroU8::new(2).expect("nonzero") },
        ])
    );

    let debug = format!("{image:?} {operations:?} {payload:?}");
    for secret in ["a1", "b2", "c3", "d4", "A1", "B2", "C3", "D4"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn secure_credential_binding_rejects_duplicate_missing_extra_and_short_material() {
    let product = product(true);
    let mut profile = profile("MV-57B0");
    let configuration = configuration(&product, basic_secure_intent());
    prepare_classic_ip_profile(&mut profile, &product, configuration.topology.ip.as_ref())
        .expect("standard OT11 facts resolve");
    let first = NonZeroU8::new(1).expect("nonzero");
    let second = NonZeroU8::new(2).expect("nonzero");
    let valid = ResolvedIpSecureConfiguration {
        backbone_key: Some([0xa1; 16].into()),
        device_authentication_code: Some([0xb2; 16].into()),
        password_hashes: vec![(first, [0xc3; 16].into()), (second, [0xd4; 16].into())],
    };
    for case in 0..6 {
        let mut secrets = valid.clone();
        let expected = match case {
            0 => {
                secrets.password_hashes.push((first, [0xff; 16].into()));
                "repeats password hash"
            }
            1 => {
                secrets.password_hashes.pop();
                "do not match requested users"
            }
            2 => {
                secrets.password_hashes.push((NonZeroU8::new(3).expect("nonzero"), [0xff; 16].into()));
                "do not match requested users"
            }
            3 => {
                secrets.password_hashes[0].1 = vec![0xc3; 15].into();
                "IP password hash has 15 bytes"
            }
            4 => {
                secrets.backbone_key = None;
                "missing IP backbone key"
            }
            _ => {
                secrets.device_authentication_code = Some(vec![0xb2; 15].into());
                "IP device authentication code has 15 bytes"
            }
        };
        let input = super::super::fixture_input(&product, &configuration, None, Some(&secrets));
        let mut compiler = super::super::fixture_compiler(&input, &profile);
        let error = compiler.contribute_ip().expect_err("invalid credentials cannot produce an executable program");
        assert!(error.message.contains(expected), "case {case}: {error}");
    }
}

#[test]
fn tunnelling_bindings_are_one_to_one() {
    let product = product(true);
    let mut duplicate_user = basic_secure_intent();
    duplicate_user
        .security
        .as_mut()
        .expect("security intent exists")
        .tunnelling_users
        .push(IpTunnellingUserBinding { user_id: NonZeroU8::new(1).expect("nonzero"), address_index: 2 });
    let error = validate_secure_intent(
        &product,
        &duplicate_user,
        duplicate_user.security.as_ref().expect("security intent exists"),
    )
    .expect_err("one user cannot select two tunnelling addresses");
    assert_eq!(error.message, "tunnelling user 1 is bound to more than one address index");

    let mut duplicate_address = basic_secure_intent();
    duplicate_address
        .security
        .as_mut()
        .expect("security intent exists")
        .tunnelling_users
        .push(IpTunnellingUserBinding { user_id: NonZeroU8::new(2).expect("nonzero"), address_index: 1 });
    let error = validate_secure_intent(
        &product,
        &duplicate_address,
        duplicate_address.security.as_ref().expect("security intent exists"),
    )
    .expect_err("one tunnelling address cannot select two users");
    assert_eq!(error.message, "tunnelling address index 1 is bound to more than one user");
}

fn product(secure: bool) -> ProductData {
    product_with_procedures(secure, "DefaultProcedure", "<LoadProcedures />")
}

fn product_with_procedures(secure: bool, style: &str, procedures: &str) -> ProductData {
    let secure_attributes = if secure {
        r#" IsSecureEnabled="true" MaxUserEntries="2" MaxTunnelingUserEntries="2""#
    } else {
        r#" IsSecureEnabled="false""#
    };
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23" CreatedBy="ip-overlay-test" ToolVersion="1">
          <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
            <ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1"
              ProgramType="ApplicationProgram" MaskVersion="MV-57B0" Name="IP fixture"
              LoadProcedureStyle="{style}" PeiType="0" DefaultLanguage="en-US"
              DynamicTableManagement="false" Linkable="false" IPConfig="Tool"
              AdditionalAddressesCount="2"{secure_attributes}>
              <Static>
                <BusInterfaces>
                  <BusInterface Id="M-00FA_A-0001-01-0000_BI-1" AddressIndex="1" AccessType="Tunneling" />
                  <BusInterface Id="M-00FA_A-0001-01-0000_BI-2" AddressIndex="2" AccessType="Routing" />
                </BusInterfaces>
                {procedures}
              </Static>
            </ApplicationProgram>
          </ApplicationPrograms></Manufacturer></ManufacturerData>
        </KNX>"#,
    );
    ProductData::from_mtxml_str(&xml).expect("IP product fixture parses")
}

fn profile(mask: &str) -> ResolvedProfile {
    fixture_profile(
        mask,
        "SystemB",
        "MT-5",
        r#"<Features><Feature Name="FirstAppObjectIdx" Value="3"/></Features><Resources></Resources><InterfaceObjects></InterfaceObjects>"#,
    )
}

fn configuration(product: &ProductData, ip: ToolManagedIpConfiguration) -> LoweredDeviceConfiguration {
    let mut topology = TopologyConfiguration::default();
    topology.ip = Some(ip);
    LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 10), Some(15))
        .with_com_objects((product).com_objects().to_vec())
        .with_topology(topology)
}

fn basic_secure_intent() -> ToolManagedIpConfiguration {
    ToolManagedIpConfiguration {
        project_installation_id: ProjectInstallationId::new(1, 1).expect("project ID is in range"),
        assignment: IpAssignment::AutomaticDhcp,
        routing_multicast_address: [224, 0, 23, 12],
        multicast_ttl: 16,
        friendly_name: "Secure IP fixture".to_owned(),
        additional_individual_addresses: vec![IndividualAddress::new(1, 1, 11), IndividualAddress::new(1, 1, 12)],
        security: Some(IpSecurityIntent {
            routing: IpServiceSecurity::Secure,
            device_management: IpServiceSecurity::Secure,
            tunnelling: IpServiceSecurity::Secure,
            multicast_latency_tolerance_ms: 1500,
            sync_latency_fraction: 3,
            tunnelling_users: vec![IpTunnellingUserBinding {
                user_id: NonZeroU8::new(1).expect("nonzero"),
                address_index: 1,
            }],
        }),
        password_users: vec![NonZeroU8::new(1).expect("nonzero"), NonZeroU8::new(2).expect("nonzero")],
    }
}

fn operation_index(
    operations: &[crate::commissioning::procedure::ProcedureStep],
    predicate: impl Fn(&ProcedureOperation) -> bool,
) -> usize {
    operations.iter().position(|operation| predicate(&operation.operation)).expect("operation is present")
}

fn property_write_pid(operation: &ProcedureOperation) -> Option<u16> {
    match operation {
        ProcedureOperation::Write {
            target: OperationTarget::Property { address: PropertyAddress::Extended { property_id, .. }, .. },
            data: OperationData::Image { .. },
            ..
        } => Some(*property_id),
        _ => None,
    }
}

fn property_write(operation: &ProcedureOperation) -> Option<u16> {
    match operation {
        ProcedureOperation::Write {
            target: OperationTarget::Property { address: PropertyAddress::Extended { property_id, .. }, .. },
            ..
        } => Some(*property_id),
        _ => None,
    }
}

fn secret_write_pid(operation: &ProcedureOperation) -> Option<u16> {
    match operation {
        ProcedureOperation::Write {
            target: OperationTarget::Property { address: PropertyAddress::Extended { property_id, .. }, .. },
            data: OperationData::Secret(_),
            ..
        } => Some(*property_id),
        _ => None,
    }
}

fn service_family(operation: &ProcedureOperation) -> Option<u8> {
    match operation {
        ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke {
            address: PropertyAddress::Extended { property_id: pid::ip::SECURED_SERVICE_FAMILIES, .. },
            data,
            ..
        }) => data.get(2).copied(),
        _ => None,
    }
}
