//! Stable fingerprints of product and image content.

use crate::commissioning::catalog::profile::ObjectSelector;
use crate::commissioning::image::{ImageSpace, SparseDeviceImage};
use sha2::{Digest, Sha256};
use zweidraehte_ets_files::product::ProductData;

pub(crate) fn fingerprint_product(product: &ProductData) -> [u8; 32] {
    let mut hash = Sha256::new();

    // The product owner declares the fields; this encoder fixes their wire
    // representation independently of Rust Debug and JSON map feature flags.
    let mut identity = serde_json::to_value(product.programming_identity()).expect("product identity serializes");
    identity.sort_all_objects();
    let version = identity["version"].as_u64().expect("product identity declares its version");
    hash.update(format!("zweidraehte-product-v{version}\0").as_bytes());
    hash.update(serde_json::to_vec(&identity).expect("JSON identity serializes"));

    hash.finalize().into()
}

pub(crate) fn fingerprint_image(image: &SparseDeviceImage) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"zweidraehte-image-v1\0");

    for segment in image.segments() {
        hash_image_space(&mut hash, &segment.location().space);
        hash.update(segment.location().offset.to_be_bytes());
        hash.update((segment.data().len() as u64).to_be_bytes());
        hash.update(segment.data());
        hash.update(segment.mask());
    }

    hash.finalize().into()
}

pub(super) fn hash_image_space(hash: &mut Sha256, space: &ImageSpace) {
    match space {
        ImageSpace::StandardMemory => hash.update([0]),
        ImageSpace::UserMemory => hash.update([1]),
        ImageSpace::RelativeMemory { object } => {
            hash.update([2]);
            hash_object_selector(hash, object);
        }
        ImageSpace::Property { object, property_id } => {
            hash.update([3]);
            hash_object_selector(hash, object);
            hash.update(property_id.to_be_bytes());
        }
        ImageSpace::Pointer { resource_id: resource } => {
            hash.update([4]);
            hash.update((resource.0.len() as u64).to_be_bytes());
            hash.update(resource.0.as_bytes());
        }
        ImageSpace::LineCouplerFilter => hash.update([5]),
        ImageSpace::LineCouplerSlave => hash.update([6]),
        ImageSpace::PropertyCount { object, property_id } => {
            hash.update([7]);
            hash_object_selector(hash, object);
            hash.update(property_id.to_be_bytes());
        }
    }
}

fn hash_object_selector(hash: &mut Sha256, object: &ObjectSelector) {
    match object {
        ObjectSelector::Index { index } => {
            hash.update([0]);
            hash.update(index.to_be_bytes());
        }
        ObjectSelector::Type { object_type, occurrence } => {
            hash.update([1]);
            hash.update(object_type.to_be_bytes());
            match occurrence {
                crate::commissioning::catalog::profile::Occurrence::Absent => hash.update([0]),
                crate::commissioning::catalog::profile::Occurrence::Zero => hash.update([1]),
                crate::commissioning::catalog::profile::Occurrence::Positive { value } => {
                    hash.update([2]);
                    hash.update(value.get().to_be_bytes());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_ets_files::product::fixtures::{BCU1_MTXML, SYSTEM7_MTXML};

    #[test]
    fn property_count_fingerprint_is_distinct_from_property_data() {
        let object = ObjectSelector::Index { index: 4 };
        let property = ImageSpace::Property { object: object.clone(), property_id: 71 };
        let count = ImageSpace::PropertyCount { object, property_id: 71 };
        let mut property_hash = Sha256::new();
        hash_image_space(&mut property_hash, &property);
        let mut count_hash = Sha256::new();
        hash_image_space(&mut count_hash, &count);

        // The existing property's discriminator and selector encoding remain
        // stable; count state gets its own tag rather than a sentinel offset.
        assert_eq!(property_hash.finalize(), Sha256::digest([3, 0, 0, 4, 0, 71]));
        assert_eq!(count_hash.finalize(), Sha256::digest([7, 0, 0, 4, 0, 71]));
    }

    #[test]
    fn product_identity_v3_has_stable_golden_digests() {
        let actual = [BCU1_MTXML, SYSTEM7_MTXML].map(|xml| {
            let product = ProductData::from_mtxml_str(xml).expect("representative product");
            fingerprint_product(&product)
        });
        assert_eq!(actual, [
            [
                15, 137, 107, 106, 216, 46, 146, 95, 190, 7, 190, 87, 181, 141, 209, 19, 190, 121, 21, 255, 195, 231,
                38, 54, 144, 187, 5, 38, 41, 46, 100, 219
            ],
            [
                182, 242, 65, 241, 129, 74, 236, 237, 241, 157, 160, 145, 203, 95, 23, 233, 43, 189, 147, 243, 140,
                137, 156, 69, 69, 14, 159, 236, 104, 176, 78, 195
            ],
        ]);
    }

    #[test]
    fn product_identity_tracks_semantic_fields_and_excludes_diagnostic_context() {
        let product = ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("product fixture");
        let original = fingerprint_product(&product);
        let changed_tool = SYSTEM7_MTXML.replace(
            "CreatedBy=\"zweidraehte\" ToolVersion=\"0.1.0\"",
            "CreatedBy=\"Different author\" ToolVersion=\"999\"",
        );
        let diagnostic = ProductData::from_mtxml_str(&changed_tool).expect("diagnostic provenance");
        assert_ne!(format!("{product:?}"), format!("{diagnostic:?}"));
        assert_eq!(fingerprint_product(&diagnostic), original);
        let master_data = r#"<KNX xmlns="http://knx.org/xml/project/20"><MasterData Id="MD" Version="99"><MaskVersions /></MasterData></KNX>"#.parse().expect("separate Master Data");
        assert_eq!(
            fingerprint_product(
                &product.clone().bind_master_data(std::sync::Arc::new(master_data)).expect("bound catalog")
            ),
            original
        );

        let mut segments = product.segments().to_vec();
        segments.iter_mut().find(|segment| !segment.data.is_empty()).expect("fixture has program bytes").data[0] ^= 1;
        assert_ne!(fingerprint_product(&product.clone().with_fixture_segments(segments)), original);
        let mut parameters = product.parameters().to_vec();
        parameters[0].bit_offset ^= 1;
        assert_ne!(fingerprint_product(&product.clone().with_fixture_parameters(parameters)), original);
        for changed in [
            product.clone().with_fixture_security_capacities(1, 2, 3),
            product.clone().with_fixture_data_secure(true),
            product.clone().with_fixture_association_table_max_entries(99),
            product.clone().with_fixture_relative_segment_offset("module-storage", 17),
        ] {
            assert_ne!(fingerprint_product(&changed), original);
        }
        for (from, to) in [
            ("<LdCtrlConnect />", "<LdCtrlConnect /><LdCtrlDisconnect /><LdCtrlConnect />"),
            ("<Static>", "<Static><Options LegacyNoOptimisticWrite=\"true\" />"),
            ("Offset=\"2\"", "Offset=\"3\""),
        ] {
            let xml = SYSTEM7_MTXML.replace(from, to);
            assert_ne!(xml, SYSTEM7_MTXML, "fixture contains {from}");
            assert_ne!(fingerprint_product(&ProductData::from_mtxml_str(&xml).expect("changed semantics")), original);
        }
    }
}
