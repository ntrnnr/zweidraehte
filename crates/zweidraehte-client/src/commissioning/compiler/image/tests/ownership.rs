use super::*;
use crate::commissioning::image::ImageSegment;
use std::sync::Arc;
use zweidraehte_ets_files::product::SelectedProduct;

#[test]
fn evaluated_parameter_overlays_preserve_union_property_legacy_and_module_order() {
    use crate::configuration::{DeviceIdentity, InstallationConfiguration, ResolvedDevice, ResolvedKeyMaterial};
    use zweidraehte_ets_files::runtime::{
        Device,
        configuration::{ProductConfiguration, apply_configuration},
    };

    let template = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;
    let (prefix, rest) = template.split_once("<Parameters>").expect("fixture parameters");
    let (_, suffix) = rest.split_once("</Parameters>").expect("fixture parameter end");
    let xml = format!(r#"{prefix}
      <ParameterTypes><ParameterType Id="byte" Name="Byte"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType></ParameterTypes>
      <Parameters>
        <Union SizeInBit="8"><Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="0" BitOffset="0" />
          <Parameter Id="base" Name="Base" Text="Base" ParameterType="byte" Value="7" Offset="0" BitOffset="0" DefaultUnionParameter="true" />
          <Parameter Id="overlay" Name="Overlay" Text="Overlay" ParameterType="byte" Value="8" Offset="0" BitOffset="0" />
        </Union>
        <Parameter Id="legacy" Name="Legacy" Text="Legacy" ParameterType="byte" Value="21" LegacyPatchAlways="true"><Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" /></Parameter>
        <Union SizeInBit="8"><Property ObjectIndex="3" PropertyId="100" Offset="0" BitOffset="0" />
          <Parameter Id="property-base" Name="PropertyBase" Text="Property base" ParameterType="byte" Value="3" Offset="0" BitOffset="0" DefaultUnionParameter="true" />
          <Parameter Id="property-overlay" Name="PropertyOverlay" Text="Property overlay" ParameterType="byte" Value="6" Offset="0" BitOffset="0" />
        </Union>
        <Parameter Id="property-legacy" Name="PropertyLegacy" Text="Property legacy" ParameterType="byte" Value="23" LegacyPatchAlways="true"><Property ObjectIndex="3" PropertyId="100" Offset="1" BitOffset="0" /></Parameter>
      </Parameters>
      <ParameterRefs>
        <ParameterRef Id="base-ref" RefId="base" Value="9" />
        <ParameterRef Id="overlay-ref" RefId="overlay" Value="11" />
        <ParameterRef Id="property-base-ref" RefId="property-base" Value="4" />
      </ParameterRefs>{suffix}"#).replace("</ApplicationProgram>", r#"
      <ModuleDefs><ModuleDef Id="channel" Name="Channel"><Arguments><Argument Id="base-arg" Name="ParameterBase" /></Arguments>
        <Static><Parameters><Parameter Id="level" Name="Level" Text="Level" ParameterType="byte" Value="5"><Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" BaseOffset="base-arg" Offset="0" BitOffset="0" /></Parameter></Parameters>
        <ParameterRefs><ParameterRef Id="level-ref" RefId="level" Value="13" /></ParameterRefs></Static>
        <Dynamic><ChannelIndependentBlock><ParameterBlock Id="channel-page" Name="Channel"><ParameterRefRef RefId="level-ref" /></ParameterBlock></ChannelIndependentBlock></Dynamic>
      </ModuleDef></ModuleDefs>
      <Dynamic><ChannelIndependentBlock><ParameterBlock Id="page" Name="Settings"><ParameterRefRef RefId="base-ref" /><ParameterRefRef RefId="overlay-ref" /><ParameterRefRef RefId="property-base-ref" /></ParameterBlock></ChannelIndependentBlock>
        <Module Id="first" RefId="channel"><NumericArg RefId="base-arg" Value="3" /></Module>
      </Dynamic></ApplicationProgram>"#)
      .replace("<LdCtrlConnect />", r#"<LdCtrlConnect /><choose ParamRefId="first::level-ref"><when test="13" /></choose>"#);
    for duplicate in [None, Some(9), Some(10)] {
        let xml = if let Some(value) = duplicate {
            xml.replace(
                "<ParameterRefs>",
                &format!(r#"<ParameterRefs><ParameterRef Id="second-base-ref" RefId="base" Value="{value}" />"#),
            )
            .replacen(
                r#"<ParameterRefRef RefId="base-ref" />"#,
                r#"<ParameterRefRef RefId="base-ref" /><ParameterRefRef RefId="second-base-ref" />"#,
                1,
            )
        } else {
            xml.clone()
        };
        let parsed = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("overlay fixture");
        let selected = SelectedProduct::from_document(parsed, None, None).expect("product geometry");
        let mut device = Device::from_product(Arc::new(selected), None, None);
        let settings = ProductConfiguration::default();
        apply_configuration(&mut device, &settings).expect("overlay configuration");
        let configuration = InstallationConfiguration {
            identity: DeviceIdentity { desired_address: IndividualAddress::new(1, 1, 1), serial_number: None },
            data_secure_enabled: false,
            object_memberships: Vec::new(),
            net_security: Default::default(),
            topology: Default::default(),
            max_apdu: None,
        };
        let evaluated = device.evaluate(&settings.objects).expect("checked overlays");
        assert_eq!(evaluated.modules().len(), 1);
        assert_eq!(evaluated.modules()[0].instance_id, "first");
        let modules = evaluated.modules().as_ptr();
        let resolved = ResolvedDevice::from_evaluated(evaluated, configuration);
        if duplicate == Some(10) {
            assert!(resolved.expect_err("conflicting visible refs").to_string().contains("conflicting values"));
            continue;
        }
        let resolved = resolved.expect("equal references share one overlay");
        // The compiler receives the allocation that geometry was resolved from,
        // without a second editor traversal or cloning the evaluated roster.
        assert_eq!(resolved.modules().as_ptr(), modules);
        let materialized = resolved.into_materialized(ResolvedKeyMaterial::new(None)).expect("materialized input");
        assert_eq!(materialized.modules().as_ptr(), modules);
        let selector = materialized
            .configuration()
            .procedure_parameters
            .get("first::level-ref")
            .expect("load procedure retains its concrete module selector");
        assert!(selector.active);
        assert_eq!(selector.value, crate::configuration::ProcedureParameterValue::Signed(13));
        let mut image = SparseDeviceImage::new();
        let regions = seed_segments(materialized.product(), ImageDemand::Complete, &mut image).expect("seeded memory");
        apply_parameters(
            materialized.product(),
            materialized.configuration(),
            &regions,
            &mut image,
            ImageDemand::Complete,
        )
        .expect("memory overlays");
        apply_property_parameters(
            materialized.product(),
            materialized.configuration(),
            &mut image,
            ImageDemand::Complete,
        )
        .expect("property overlays");

        // Both union members own the same byte: the visible later member wins.
        // The hidden legacy value and instantiated reference retain their slots.
        assert_eq!(image.byte(&ImageLocation::standard_memory(0x4300)), Some((11, 255)));
        assert_eq!(image.byte(&ImageLocation::standard_memory(0x4302)), Some((21, 255)));
        assert_eq!(image.byte(&ImageLocation::standard_memory(0x4303)), Some((13, 255)));
        let property = ImageLocation {
            space: ImageSpace::Property {
                object: crate::commissioning::catalog::profile::ObjectSelector::Index { index: 3 },
                property_id: 100,
            },
            offset: 0,
        };
        let bytes = image.range(&property, 2).expect("property union and hidden legacy");
        assert_eq!(bytes.data(), [6, 23]);
        assert_eq!(bytes.mask(), [255, 255]);
    }
}

#[test]
fn bit_parameter_patch_claims_only_its_bits() {
    // `BitOffset` counts from the byte's MSB. Flip all three bits in the
    // declared window so this test proves both that the value is written
    // and that the five neighbouring bits remain untouched.
    let mut image = SparseDeviceImage::new();
    let location = ParameterLocation {
        id: "P-1".to_owned(),
        code_segment: "S-1".to_owned(),
        offset: 0,
        bit_offset: 2,
        size_bits: 3,
        legacy_patch_always: false,
        seeds_default: true,
    };
    let value = ParameterValue { id: "P-1".to_owned(), value: vec![0b0000_0010] };

    let (data, mask) =
        encode_parameter(&value, location.size_bits, location.bit_offset, &ParameterByteOrder::BigEndian)
            .expect("parameter encodes");
    let address = ImageLocation::standard_memory(0x100);
    image.apply(&ImageSegment::new(address.clone(), data, mask).expect("parameter segment"));
    assert_eq!(image.overlay(&address, &[0b1010_1010]).expect("overlay"), [0b1001_0010]);
    assert_eq!(image.range(&address, 1).expect("parameter byte").mask(), [0b0011_1000]);
}

#[test]
fn parameter_values_do_not_change_application_program_ownership() {
    let location = ParameterLocation {
        id: "P-1".to_owned(),
        code_segment: "S-1".to_owned(),
        offset: 0,
        bit_offset: 0,
        size_bits: 2,
        legacy_patch_always: false,
        seeds_default: true,
    };
    let compile = |raw| {
        let value = ParameterValue { id: "P-1".to_owned(), value: vec![raw] };
        let (data, mask) =
            encode_parameter(&value, location.size_bits, location.bit_offset, &ParameterByteOrder::BigEndian)
                .expect("parameter encodes");

        let mut manifest = SparseDeviceImage::default();
        manifest.apply_section(
            ProgrammingSection::ApplicationProgram1,
            &ImageSegment::owned(ImageLocation::standard_memory(0x100), vec![0]).expect("application segment"),
        );
        manifest.apply_section(
            ProgrammingSection::Parameters,
            &ImageSegment::new(ImageLocation::standard_memory(0x100), data, mask).expect("parameter ownership segment"),
        );
        manifest.manifest()
    };

    let default_value = compile(0);
    let changed_value = compile(2);

    assert_eq!(
        default_value.section(ProgrammingSection::ApplicationProgram1),
        changed_value.section(ProgrammingSection::ApplicationProgram1),
    );
    assert_ne!(
        default_value.section(ProgrammingSection::Parameters),
        changed_value.section(ProgrammingSection::Parameters),
    );
}

#[test]
fn expert_image_input_rejects_oversized_packed_parameter_with_short_value() {
    let (catalog, profile, product, mut configuration) = plain_fixture();
    let parameter_id = "P-oversized-packed-field";
    configuration.parameters = vec![ParameterValue { id: parameter_id.to_owned(), value: vec![1] }];

    // Expert inputs can bypass product-value lowering. Validate the field
    // declaration as well as the supplied bytes before the bit encoder
    // shifts: neither a 65-bit field nor a misaligned 72-bit field fits.
    for (size_bits, bit_offset) in [(65, 0), (72, 1)] {
        let malformed = product.clone().with_fixture_parameters(vec![ParameterLocation {
            id: parameter_id.to_owned(),
            code_segment: product.segments()[0].id.clone(),
            offset: 0,
            bit_offset,
            size_bits,
            legacy_patch_always: false,
            seeds_default: false,
        }]);

        let error = compile_full_image(&catalog, &profile, &malformed, &configuration)
            .expect_err("packed fields must fit the parameter type");
        assert_eq!(error.kind, CompileErrorKind::InvalidInput);
        assert!(error.message.contains(parameter_id));
    }
}

#[test]
fn native_regions_preserve_adjacent_allocations_and_unowned_capacity() {
    let (catalog, profile, product, configuration) = plain_fixture();
    let mut sources = product.segments().to_vec();
    let mut reserved = sources[0].clone();
    reserved.id = "reserved".to_owned();
    reserved.address = Some(0x200);
    reserved.size = 4;
    reserved.data = vec![0xA5];
    reserved.mask = Some(vec![0x0F]);
    sources.push(reserved);
    let product = product.with_fixture_segments(sources);
    let image = compile_full_image(&catalog, &profile, &product, &configuration).expect("native image");
    assert_eq!(image.regions.len(), 2);
    let reserved = &image.regions[1];
    assert_eq!(reserved.source_id.as_deref(), Some("reserved"));
    assert_eq!(reserved.seed, [0xA5]);
    let projected = image.image.project(&reserved.location, &[0xA5, 0, 0, 0]).expect("native region");
    assert_eq!(projected.data(), [0xA5, 0, 0, 0]);
    assert_eq!(projected.mask(), [0x0F, 0, 0, 0]);
    let preview: Vec<_> = image.projected_regions().collect();
    assert_eq!(preview.len(), 2);
    assert_eq!(preview[1].1.mask(), [0x0F, 0, 0, 0]);
}

#[test]
fn segments_without_a_mask_own_their_whole_size_zero_filled() {
    let (catalog, profile, product, configuration) = plain_fixture();
    let mut sources = product.segments().to_vec();
    let mut allocation = sources[0].clone();
    allocation.id = "allocation".to_owned();
    allocation.address = Some(0x200);
    allocation.size = 4;
    allocation.data = vec![0xA5];
    allocation.mask = None;
    sources.push(allocation);
    let product = product.with_fixture_segments(sources);
    let image = compile_full_image(&catalog, &profile, &product, &configuration).expect("native image");
    // Without an explicit mask, the declared allocation is fully owned;
    // bytes beyond the supplied data are zero-filled.
    let projected = image.image.project(&ImageLocation::standard_memory(0x200), &[0; 4]).expect("native region");
    assert_eq!(projected.data(), [0xA5, 0, 0, 0]);
    assert_eq!(projected.mask(), [0xFF; 4]);
}
