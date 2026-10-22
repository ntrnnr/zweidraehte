//! Which Master Data documents resolution and live commissioning accept.
//!
//! Acquisition (files, cache, installation selection) is tested with the
//! loader in `zweidraehte_ets_files::master_data`; this layer only applies
//! commissioning policy to a document it is handed.

use super::*;
use crate::commissioning::catalog::{bound_master_data, resolve_exact_mask, validate_for_live_commissioning};

#[test]
fn resolution_rejects_unsupported_schema_generations() {
    let unsupported = parse_master_data(&AMBIGUOUS_0300.replace("/project/20", "/project/24"))
        .expect("newer catalog remains inspectable");
    let selection = ProfileSelection::discovered(0x0300).with_management_descriptor([0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let error = resolve_catalog_profile(&unsupported, None, &selection).expect_err("schema 24 is not compiled");

    assert_eq!(error.kind, ProfileErrorKind::Unsupported);
    assert!(error.message.contains("schema 24"));
}

#[test]
fn resolution_keeps_versionless_documents_inspectable() {
    let xml = TOPOLOGY_DEPENDENT_PROFILE.replace(r#" xmlns="http://knx.org/xml/project/23""#, "");
    let catalog = parse_master_data(&xml).expect("versionless catalog remains inspectable");

    resolve_catalog_profile(&catalog, None, &ProfileSelection::discovered(0x0900))
        .expect("offline inspection does not require a schema namespace");
}

#[test]
fn bound_master_data_completes_products_without_schema_provenance() {
    let catalog = parse_master_data(TOPOLOGY_DEPENDENT_PROFILE).expect("catalog parses");
    let product = ProductData::default().bind_master_data(std::sync::Arc::clone(&catalog)).expect("document binds");
    let associated = bound_master_data(&product).expect("association supplies the document");

    assert!(std::sync::Arc::ptr_eq(associated, &catalog));
    validate_for_live_commissioning(associated).expect("associated document provides its own provenance");
}

#[test]
fn compilation_requires_bound_master_data() {
    let error = bound_master_data(&ProductData::default()).expect_err("loose products have no document");

    assert_eq!(error.kind, ProfileErrorKind::MissingEvidence);
}

#[test]
fn live_commissioning_rejects_missing_master_data_schema_namespace() {
    let xml = TOPOLOGY_DEPENDENT_PROFILE.replace(r#" xmlns="http://knx.org/xml/project/23""#, "");
    let catalog = parse_master_data(&xml).expect("versionless catalog remains inspectable");

    let error =
        validate_for_live_commissioning(&catalog).expect_err("versionless Master Data cannot reach live commissioning");

    assert_eq!(error.kind, ProfileErrorKind::MissingEvidence);
    assert!(error.message.contains("namespace (None)"));
}

#[test]
fn explicit_catalog_can_program_products_from_another_generation() {
    let catalog = parse_master_data(TOPOLOGY_DEPENDENT_PROFILE).expect("project-23 catalog parses");

    for version in [11, 20] {
        validate_for_live_commissioning(&catalog)
            .unwrap_or_else(|error| panic!("project-{version} product can use an explicit catalog override: {error}"));
    }
}

#[test]
fn live_commissioning_rejects_unsupported_master_data_schema() {
    let xml = TOPOLOGY_DEPENDENT_PROFILE.replace("/project/23", "/project/24");
    let catalog = parse_master_data(&xml).expect("newer catalog remains inspectable");
    assert!(matches!(
        validate_for_live_commissioning(&catalog),
        Err(error) if error.kind == ProfileErrorKind::Unsupported && error.message.contains("schema 24")
    ));
}

#[test]
fn raw_catalog_validates_provenance_without_interpreting_unselected_profiles() {
    let catalog = parse_master_data(TOPOLOGY_DEPENDENT_PROFILE).expect("raw catalog parses");

    validate_for_live_commissioning(&catalog).expect("matching supported raw inputs audit successfully");

    let invalid = unauditable_catalog();
    let catalog = parse_master_data(&invalid).expect("invalid catalog remains inspectable");

    validate_for_live_commissioning(&catalog).expect("selected profile is validated during compilation");
}

#[test]
#[ignore = "requires the published project-20 through project-23 Master Data cache"]
fn cached_catalogs_preserve_descriptor_qualified_masks() {
    for version in 20..=23 {
        let path = cached_master_data(version);
        let catalog =
            MasterData::from_file(&path).unwrap_or_else(|error| panic!("{} does not parse: {error}", path.display()));
        validate_for_live_commissioning(&catalog).expect("supported catalog provenance");
        assert!(requires_management_descriptor_01(&catalog, 0x0300).expect("known DD0"));
        let masks = &catalog.mask_versions().expect("published masks").versions;
        for mask in masks.iter().filter(|mask| mask.management_descriptor_01.is_some()) {
            let exact = resolve_exact_mask(&catalog, mask.mask_version_code, mask.management_descriptor_01.as_ref())
                .expect("published exact descriptor resolves");
            assert_eq!(exact.id, mask.id);
        }
    }
}
