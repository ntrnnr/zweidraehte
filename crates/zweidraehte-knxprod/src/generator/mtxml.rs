//! MtxmlGenerator - ApplicationProgram MTXML generation.
//!
//! This is the main generator for creating ApplicationProgram XML files from device definitions.
//! The implementation handles:
//! - Parameter types, parameters, and parameter refs
//! - Communication objects and object refs
//! - Dynamic section with choose/when conditional blocks
//! - Module definitions and instances
//! - Load procedures for different mask families

use std::collections::{BTreeMap, HashMap};

use base64::Engine;

use zweidraehte_ets_model::{EtsCommObjectDef, EtsParamType, EtsTranslation, EtsUnionFieldInfo, TranslationAttribute};

use super::baggage::{baggages_to_refs, make_baggage_id};
use crate::definition::module::{ModuleArgRole, ModuleArgType, StoredModuleDef};
use crate::definition::page_layout::{
    ChannelDef, ChannelEntry, Condition, ConditionalElement, ConditionalItem, PageBlock, PageElement, PageItem,
    PageStructure,
};
use zweidraehte_ets_files::schema::*;

use super::helpers::{block_com_obj_ref, block_items_to_when_items, block_param_ref, when_com_obj_ref, when_param_ref};
use super::traversal::{
    collect_pictures_from_layout, collect_pictures_from_module_layout, collect_union_variant_texts,
    validate_separator_texts,
};
use super::{
    ActiveConditions, ApplicationProgramConfig, Bcu2MemoryLayout, GeneratorError, MaskFamily, ParamRefMap,
    System7MemoryLayout, System7Segment, validate_param_offsets,
};
use zweidraehte_ets_files::schema::KnxSchemaVersion;

// Include the rest of the MtxmlGenerator implementation.
// Shared statics (PARAM_TEMPLATE_RE, MULTI_SPACE_RE) live in mtxml_impl.rs.
include!("mtxml_impl.rs");

#[cfg(test)]
#[path = "separator_tests.rs"]
mod separator_tests;

#[cfg(test)]
#[path = "system7_tests.rs"]
mod system7_tests;

#[cfg(test)]
mod mask_family_tests {
    use super::*;
    use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

    #[test]
    fn unknown_mask_is_rejected_instead_of_guessed() {
        // 37B0h looks like System B by its suffix, but no family owns it.
        const DEVICE: DeviceDescriptor =
            DeviceDescriptor::new(MaskVersion::Other(0x37B0), 0x00fa, [0; 6], 0xf001, 1, 8, 8, 8, 0);
        let mut config = separator_tests::config();
        config.device = &DEVICE;

        assert!(matches!(MtxmlGenerator::generate(&config, None), Err(GeneratorError::UnsupportedMaskVersion(0x37B0))));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn direct_channel_object_references_are_validated() {
        let items = [ChannelItem::ComObjectRefRef(ComObjectRefRef {
            ref_id: "object-ref".to_string(),
            internal_description: None,
        })];
        let parameter_refs = HashSet::new();
        let object_refs = HashSet::from(["object-ref"]);

        MtxmlGenerator::validate_channel_items(&items, &parameter_refs, &object_refs)
            .expect("the direct channel object reference exists");

        let error = MtxmlGenerator::validate_channel_items(&items, &parameter_refs, &HashSet::new())
            .expect_err("the missing direct channel object reference is rejected");
        assert!(matches!(
            error,
            GeneratorError::MissingReference { ref_type, ref_id, context }
                if ref_type == "ComObjectRef"
                    && ref_id == "object-ref"
                    && context == "ComObjectRefRef in Channel"
        ));
    }
}
