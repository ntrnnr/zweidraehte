use super::*;

fn program() -> ApplicationProgram {
    let xml = fixtures::SYSTEM7_MTXML
        .replace("<Parameters>", r#"<ParameterTypes><ParameterType Id="byte" Name="Byte"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255"/></ParameterType></ParameterTypes><Parameters>"#)
        .replace("</ApplicationProgram>", r#"
          <ModuleDefs><ModuleDef Id="channel" Name="Channel">
            <Arguments><Argument Id="base-id" Name="ParameterBase"/></Arguments>
            <Static><Parameters>
              <Parameter Id="level" Name="Level" Text="Level" ParameterType="byte" Value="1">
                <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" BaseOffset="base-id" Offset="1" BitOffset="0"/>
              </Parameter>
              <Union SizeInBit="24">
                <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" BaseOffset="base-id" Offset="2" BitOffset="6"/>
                <Parameter Id="union" Name="Union" Text="Union" ParameterType="byte" Value="2" Offset="1" BitOffset="3" DefaultUnionParameter="true"/>
              </Union>
              <Parameter Id="property" Name="Property" Text="Property" ParameterType="byte" Value="3">
                <Property ObjectIndex="3" PropertyId="100" Offset="4" BitOffset="2"/>
              </Parameter>
            </Parameters></Static>
          </ModuleDef></ModuleDefs>
          <Dynamic><Module Id="first" RefId="channel"><NumericArg RefId="base-id" Value="10"/></Module></Dynamic>
        </ApplicationProgram>"#);
    let knx = parse_application_program(&xml).expect("synthetic module program parses");
    knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program")
}

fn instance(id: &str, base: i64) -> MaterializedModule {
    MaterializedModule {
        instance_id: id.to_owned(),
        definition_id: "channel".to_owned(),
        arguments: BTreeMap::from([("ParameterBase".to_owned(), MaterializedModuleArgument::Numeric(base))]),
    }
}

#[test]
fn evaluated_roster_resolves_without_replaying_dynamic_instances() {
    let program = program();
    let product = ProductData::from_program(&program).expect("product extracts");
    // The XML activates only `first` at 10. The supplied roster is the sole
    // authority at the compiler boundary, including a second instance at 20.
    let modules = [instance("second", 20), instance("first", 10)];
    let resolved = product.resolve_module_geometry(&modules).expect("static geometry resolves");
    let rows: Vec<_> = resolved
        .parameters()
        .iter()
        .skip(product.parameters().len())
        .map(|p| (p.id.as_str(), p.offset, p.bit_offset, p.size_bits, p.seeds_default))
        .collect();
    assert_eq!(rows, vec![
        ("first::level", 11, 0, 8, true),
        ("first::union", 14, 1, 8, true),
        ("second::level", 21, 0, 8, true),
        ("second::union", 24, 1, 8, true),
    ]);
    let properties: Vec<_> = resolved
        .property_parameters()
        .iter()
        .map(|p| (p.id.as_str(), p.object.clone(), p.property_id, p.offset, p.bit_offset, p.size_bits))
        .collect();
    assert_eq!(properties, vec![
        ("first::property", PropertyObject::Index(3), 100, 4, 2, 8),
        ("second::property", PropertyObject::Index(3), 100, 4, 2, 8),
    ]);

    let repeated = resolved.resolve_module_geometry(&modules).expect("resolution is idempotent");
    assert_eq!(repeated.parameters(), resolved.parameters());
    assert_eq!(repeated.property_parameters(), resolved.property_parameters());
    let removed = resolved.resolve_module_geometry(&[]).expect("empty roster removes instances");
    assert_eq!(removed.parameters(), product.parameters());
    assert_eq!(removed.property_parameters(), product.property_parameters());
    assert_eq!(removed.schema_provenance(), product.schema_provenance());

    let device = Device::new(program, None);
    assert_eq!(device.derivation_error(), None);
    let runtime = product.resolve_device_geometry(&device).expect("runtime geometry resolves");
    let explicit = product.resolve_module_geometry(&[instance("first", 10)]).expect("wire geometry resolves");
    assert_eq!(runtime.parameters(), explicit.parameters());
    assert_eq!(runtime.property_parameters(), explicit.property_parameters());
}

#[test]
fn invalid_rosters_and_base_offsets_fail_without_partial_geometry() {
    let product = ProductData::from_program(&program()).expect("product extracts");
    let original = product.parameters().to_vec();
    assert!(matches!(
        product.resolve_module_geometry(&[instance("same", 0), instance("same", 1)]),
        Err(ProductError::DuplicateModuleInstance(_))
    ));
    let mut unknown = instance("first", 0);
    unknown.definition_id = "absent".to_owned();
    assert!(matches!(product.resolve_module_geometry(&[unknown]), Err(ProductError::UnknownModuleDefinition { .. })));
    for argument in [None, Some(MaterializedModuleArgument::Text("10".to_owned()))] {
        let mut module = instance("first", 0);
        module.arguments.clear();
        if let Some(argument) = argument {
            module.arguments.insert("ParameterBase".to_owned(), argument);
        }
        assert!(matches!(
            product.resolve_module_geometry(&[module]),
            Err(ProductError::UnresolvedModuleBaseOffset { .. })
        ));
    }
    for base in [-1, i64::MAX, i64::from(u32::MAX)] {
        assert!(matches!(
            product.resolve_module_geometry(&[instance("first", base)]),
            Err(ProductError::InvalidModuleParameterOffset { .. })
        ));
    }
    assert_eq!(product.parameters(), original);
}
