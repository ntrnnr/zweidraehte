//! Target capability refinement and exact selector semantics.

use super::testing::{association_profile, association_profile_xml};
use super::*;
use crate::commissioning::error::AssociationTableEntrySizeError;

#[test]
fn association_entry_size_resolves_generic_profile_without_changing_other_facts() {
    let original = association_profile("AssociationTable_SystemB");
    assert_eq!(original.image_requirements().expect("metadata resolves"), vec![
        ImageRequirement::AssociationTableEntrySize {
            resource: original.resource("GroupAssociationTable").expect("table selection").expect("table").id,
        }
    ]);
    for (size, flavour) in [
        (AssociationTableEntrySize::TwoBytes, "AssociationTable_SystemBSmall"),
        (AssociationTableEntrySize::FourBytes, "AssociationTable_SystemBBig"),
    ] {
        let resolved = original.clone().with_association_table_entry_size(size).expect("generic row size resolves");
        assert!(resolved.image_requirements().expect("metadata resolves").is_empty());
        assert_eq!(
            resolved
                .resource("GroupAssociationTable")
                .expect("table selection")
                .expect("table")
                .flavour()
                .expect("known flavour"),
            Some(flavour.parse().expect("known resource flavour"))
        );
        assert_eq!(resolved.master_data_fingerprint(), original.master_data_fingerprint());
        assert_eq!(resolved.mask, original.mask);
        assert_eq!(resolved.clone().with_association_table_entry_size(size).expect("same size agrees"), resolved);
    }
}

#[test]
fn association_entry_size_rejects_conflicting_or_non_system_b_profiles() {
    assert_eq!(
        association_profile("AssociationTable_SystemBSmall")
            .with_association_table_entry_size(AssociationTableEntrySize::FourBytes),
        Err(AssociationTableEntrySizeError::ConflictingSize {
            declared: AssociationTableEntrySize::TwoBytes,
            requested: AssociationTableEntrySize::FourBytes,
        })
    );
    assert!(matches!(
        association_profile("AssociationTable_SystemBBig")
            .with_association_table_entry_size(AssociationTableEntrySize::TwoBytes),
        Err(AssociationTableEntrySizeError::ConflictingSize { .. })
    ));
    assert!(matches!(
        association_profile("AssociationTable_M112")
            .with_association_table_entry_size(AssociationTableEntrySize::TwoBytes),
        Err(AssociationTableEntrySizeError::UnsupportedFlavour { .. })
    ));

    let profile = association_profile_xml(
        r#"<Resource Name="GroupAssociationTable"><Location AddressSpace="StandardMemory" StartAddress="256"/><ResourceType Length="2"/></Resource>"#,
    );
    assert!(matches!(
        profile.with_association_table_entry_size(AssociationTableEntrySize::TwoBytes),
        Err(AssociationTableEntrySizeError::UnsupportedFlavour { flavour: None })
    ));
}

#[test]
fn association_entry_size_requires_one_selected_table() {
    let profile = association_profile_xml(
        r#"<Resource Name="GroupAssociationTable"><ResourceType Length="2" Flavour="AssociationTable_SystemB"/></Resource><Resource Name="GroupAssociationTable"><ResourceType Length="2" Flavour="AssociationTable_SystemB"/></Resource>"#,
    );
    assert!(matches!(
        profile.clone().with_association_table_entry_size(AssociationTableEntrySize::TwoBytes),
        Err(AssociationTableEntrySizeError::Metadata(_))
    ));

    let profile = association_profile_xml("");
    assert_eq!(
        profile.with_association_table_entry_size(AssociationTableEntrySize::TwoBytes),
        Err(AssociationTableEntrySizeError::MissingTable)
    );
}

#[test]
fn occurrence_preserves_absent_zero_and_positive_forms() {
    assert_eq!(Occurrence::from_option(None), Occurrence::Absent);
    assert_eq!(Occurrence::from_option(Some(0)), Occurrence::Zero);
    assert_eq!(Occurrence::from_option(Some(1)).value(), Some(1));
}
