use super::*;

fn absent_relation(hardware2program_id: &str) -> ApplicationProgram2Binding {
    ApplicationProgram2Binding::Absent {
        relation: ApplicationProgramRelationIdentity {
            catalog_product_id: Some("M-00FA_H-1_P-1".to_owned()),
            catalog_item_id: Some("M-00FA_CI-1".to_owned()),
            hardware_id: "M-00FA_H-1".to_owned(),
            hardware2program_id: hardware2program_id.to_owned(),
            application_program_id: "M-00FA_A-0001-01-0000".to_owned(),
        },
    }
}

#[test]
fn package_relation_identity_participates_in_the_product_fingerprint() {
    let first = ProductData::default().with_fixture_application_program_2(absent_relation("M-00FA_H-1_HP-1"));
    let replacement = ProductData::default().with_fixture_application_program_2(absent_relation("M-00FA_H-1_HP-2"));

    assert_ne!(fingerprint_product(&first), fingerprint_product(&replacement));
}

#[test]
fn four_byte_application_id_uses_the_declared_bcu1_codec() {
    let identity = ApplicationIdentity { application_id: [0x00, 0xfa, 0x0b, 0x10, 0x01], pei_type: 0 };

    assert_eq!(
        application_identity_resource_value("ApplicationId", 4, &identity.application_id)
            .expect("zero-extended BCU1 manufacturer fits"),
        [0xfa, 0x0b, 0x10, 0x01]
    );
    assert_eq!(
        application_identity_resource_value("ApplicationId", 5, &identity.application_id)
            .expect("modern application identity remains complete"),
        identity.application_id
    );
}

#[test]
fn four_byte_application_id_rejects_a_two_octet_manufacturer() {
    let identity = ApplicationIdentity { application_id: [0x01, 0xfa, 0x0b, 0x10, 0x01], pei_type: 0 };

    let error = application_identity_resource_value("ApplicationId", 4, &identity.application_id)
        .expect_err("a two-octet manufacturer cannot fit a BCU1 identity");
    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert_eq!(error.message, "resource \"ApplicationId\" has capacity 4, but its value has 5 bytes");
}

#[test]
fn peiprog_id_always_uses_the_five_byte_product_identity() {
    let identity = ApplicationIdentity { application_id: [0x00, 0xfa, 0x0b, 0x10, 0x01], pei_type: 0 };

    assert_eq!(
        application_identity_resource_value("PeiprogId", 5, &identity.application_id)
            .expect("Peiprog identity keeps both manufacturer octets"),
        identity.application_id
    );
    let error = application_identity_resource_value("PeiprogId", 4, &identity.application_id)
        .expect_err("PEI identity has a fixed five-byte representation");
    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert_eq!(error.message, "identity resource \"PeiprogId\" has unsupported length 4");
}
