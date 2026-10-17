use super::*;
use crate::commissioning::catalog::profile::ObjectSelector;
use crate::commissioning::catalog::profile::testing::fixture_profile;

#[test]
fn pl110_reconfiguration_owns_its_exact_memory_or_property_byte() {
    let memory = ImageLocation::standard_memory(0x101);
    let property = ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 0 }, property_id: 73 },
        offset: 0,
    };
    for (mask, model, medium, xml_location, location, expected) in [
        ("MV-1013", "Bcu1", "MT-1", r#"AddressSpace="StandardMemory" StartAddress="257""#, memory.clone(), 0xff),
        (
            "MV-17B0",
            "SystemB",
            "MT-1",
            r#"AddressSpace="SystemProperty" InterfaceObjectRef="0" PropertyID="73" StartAddress="0""#,
            property,
            0xff,
        ),
        ("MV-1013", "Bcu1", "MT-0", r#"AddressSpace="StandardMemory" StartAddress="257""#, memory, 0x12),
    ] {
        let profile = fixture_profile(
            mask,
            model,
            medium,
            &format!(
                r#"<Resources><Resource Name="ReConfig" Access="remote"><Location {xml_location}/>
              <ResourceType Length="1" Flavour="ReConfig_Bcu1PL"/>
              <AccessRights Read="Runtime" Write="Configuration"/></Resource></Resources>"#,
            ),
        );
        for supplied in [false, true] {
            let mut image = SparseDeviceImage::new();
            if supplied {
                image.apply_owned(location.clone(), vec![0x12]).expect("authored reconfiguration byte");
            }
            apply_pl110_configuration_defaults(&profile, &mut image).expect("exact PL110 resource");
            if medium == "MT-1" || supplied {
                assert_eq!(image.byte(&location), Some((expected, 0xff)));
            } else {
                assert!(image.byte(&location).is_none(), "a TP profile does not allocate PL defaults");
            }
        }
    }
}
