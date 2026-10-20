use super::*;
use crate::commissioning::ProgrammingCatalogLoadError;
use zweidraehte_ets_files::MasterDataError;

#[test]
fn acquisition_keeps_file_and_xml_causes() {
    use std::error::Error as _;
    use std::io::ErrorKind;

    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("missing-master.xml");
    for error in [
        ProgrammingCatalog::from_file(&path).err().expect("missing inspection source"),
        ProgrammingCatalog::load(ProgrammingCatalogLoadRequest::File(&path)).err().expect("missing loading source"),
    ] {
        assert!(matches!(&error, ProgrammingCatalogLoadError::MasterData(MasterDataError::Io {
            path: retained, source,
        }) if retained == &path && source.kind() == ErrorKind::NotFound));
        assert_eq!(
            error.source().expect("I/O cause").downcast_ref::<std::io::Error>().expect("typed I/O").kind(),
            ErrorKind::NotFound
        );
    }

    for error in [
        ProgrammingCatalog::from_xml("<KNX><MasterData").err().expect("malformed inspection source"),
        ProgrammingCatalog::load(ProgrammingCatalogLoadRequest::Xml("<KNX><MasterData"))
            .err()
            .expect("malformed loading source"),
    ] {
        let ProgrammingCatalogLoadError::MasterData(MasterDataError::Xml(source)) = &error else {
            panic!("expected a typed XML error: {error:?}");
        };
        assert_eq!(error.source().expect("XML cause").to_string(), source.to_string());
    }
}

#[test]
fn loads_an_explicit_file_with_exact_versioned_provenance() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("knx_master.xml");
    std::fs::write(&path, AMBIGUOUS_0300).expect("fixture writes");

    let loaded = ProgrammingCatalog::load(ProgrammingCatalogLoadRequest::File(&path)).expect("catalog loads");
    let direct = ProgrammingCatalog::from_file(&path).expect("direct catalog loads");

    assert_eq!(loaded.catalog().fingerprint(), direct.fingerprint());
    assert_eq!(loaded.provenance().master_data_schema_version, 20);
    assert_eq!(loaded.provenance().master_data_id.as_deref(), Some("MD"));
    assert_eq!(loaded.provenance().master_data_version, "1");
    assert_eq!(loaded.provenance().fingerprint, direct.fingerprint());
    assert_eq!(loaded.provenance().source, ProgrammingCatalogSource::ExplicitFile(path));
}

#[test]
fn products_of_every_generation_select_the_newest_installation() {
    // The product's own generation never chooses its catalog: an installation
    // compiles every product against its own, newest-generation catalog.
    let missing = ProductData::default();
    let products: Vec<_> = [11, 20, 23]
        .into_iter()
        .map(|version| product_with_schema(version, "MV-0900", "DefaultProcedure", false))
        .chain([missing])
        .collect();
    for product in &products {
        let selected = super::super::loading::select_source(ProgrammingCatalogLoadRequest::Product(product))
            .expect("installation source");

        assert_eq!(
            selected,
            ProgrammingCatalogSource::Installation(Box::new(ProgrammingCatalogSource::VersionedResolver(23)))
        );
    }
}

#[test]
fn explicit_version_selects_exactly_that_generation() {
    let selected =
        super::super::loading::select_source(ProgrammingCatalogLoadRequest::Version(20)).expect("explicit generation");

    assert_eq!(selected, ProgrammingCatalogSource::VersionedResolver(20));
}

#[test]
fn rejects_versionless_or_unsupported_master_data() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("knx_master.xml");
    std::fs::write(&path, r#"<KNX><MasterData Id="MD" Version="1" /></KNX>"#).expect("versionless fixture writes");

    let versionless = ProgrammingCatalog::load(ProgrammingCatalogLoadRequest::File(&path));
    assert!(matches!(
        versionless,
        Err(ProgrammingCatalogLoadError::MasterData(MasterDataError::MissingSchema { namespace: None }))
    ));

    let unsupported_xml = AMBIGUOUS_0300.replace("/project/20", "/project/24");
    std::fs::write(&path, unsupported_xml).expect("unsupported fixture writes");
    let unsupported = ProgrammingCatalog::load(ProgrammingCatalogLoadRequest::File(&path));
    assert!(matches!(unsupported, Err(ProgrammingCatalogLoadError::Policy(error))
            if error.kind == CompileErrorKind::Unsupported && error.message.contains("schema 24")));
}

#[test]
fn explicit_master_data_completes_products_without_schema_provenance() {
    let catalog = ProgrammingCatalog::from_xml(TOPOLOGY_DEPENDENT_PROFILE).expect("catalog parses");
    let product = ProductData::default().bind_master_data(catalog.document()).expect("document binds");
    let associated = ProgrammingCatalog::for_product(&product).expect("association supplies the catalog");

    associated.validate_for_live_commissioning().expect("associated document provides its own provenance");
}

#[test]
fn live_commissioning_rejects_missing_master_data_schema_namespace() {
    let xml = TOPOLOGY_DEPENDENT_PROFILE.replace(r#" xmlns="http://knx.org/xml/project/23""#, "");
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("versionless catalog remains inspectable");

    let error =
        catalog.validate_for_live_commissioning().expect_err("versionless Master Data cannot reach live commissioning");

    assert_eq!(error.kind, CompileErrorKind::MissingEvidence);
    assert!(error.message.contains("namespace (None)"));
}

#[test]
fn explicit_catalog_can_program_products_from_another_generation() {
    let catalog = ProgrammingCatalog::from_xml(TOPOLOGY_DEPENDENT_PROFILE).expect("project-23 catalog parses");

    for version in [11, 20] {
        catalog
            .validate_for_live_commissioning()
            .unwrap_or_else(|error| panic!("project-{version} product can use an explicit catalog override: {error}"));
    }
}

#[test]
fn live_commissioning_rejects_unsupported_master_data_schema() {
    let xml = TOPOLOGY_DEPENDENT_PROFILE.replace("/project/23", "/project/24");
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("newer catalog remains inspectable");
    assert!(matches!(
        catalog.validate_for_live_commissioning(),
        Err(error) if error.kind == CompileErrorKind::Unsupported && error.message.contains("schema 24")
    ));
}

#[test]
fn raw_catalog_validates_provenance_without_interpreting_unselected_profiles() {
    let catalog = ProgrammingCatalog::from_xml(TOPOLOGY_DEPENDENT_PROFILE).expect("raw catalog parses");

    catalog.validate_for_live_commissioning().expect("matching supported raw inputs audit successfully");

    let invalid = unauditable_catalog();
    let catalog = ProgrammingCatalog::from_xml(&invalid).expect("invalid catalog remains inspectable");

    catalog.validate_for_live_commissioning().expect("selected profile is validated during compilation");
}

#[test]
fn catalog_loader_preserves_supported_documents_for_target_selection() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("knx_master.xml");
    std::fs::write(&path, unauditable_catalog()).expect("fixture writes");

    let result = ProgrammingCatalog::load(ProgrammingCatalogLoadRequest::File(&path));

    assert!(result.is_ok(), "unselected unsupported operations do not prevent loading");
}

#[test]
#[ignore = "requires the published project-20 through project-23 Master Data cache"]
fn cached_catalogs_preserve_descriptor_qualified_masks() {
    for version in 20..=23 {
        let path = cached_master_data(version);
        let catalog = ProgrammingCatalog::from_file(&path)
            .unwrap_or_else(|error| panic!("{} does not parse: {error}", path.display()));
        catalog.validate_for_live_commissioning().expect("supported catalog provenance");
        assert!(catalog.requires_management_descriptor_01(0x0300).expect("known DD0"));
        let masks = &catalog.master_data.mask_versions().expect("published masks").versions;
        for mask in masks.iter().filter(|mask| mask.management_descriptor_01.is_some()) {
            let exact = catalog
                .resolve_exact_mask(&ProfileDiscovery {
                    dd0: mask.mask_version_code,
                    management_descriptor_01: mask.management_descriptor_01,
                    management_style: None,
                })
                .expect("published exact descriptor resolves");
            assert_eq!(exact.id, mask.id);
        }
    }
}
