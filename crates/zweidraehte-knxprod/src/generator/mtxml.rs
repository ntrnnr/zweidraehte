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

use zweidraehte_device::ets::{
    EtsCommObjectDef, EtsParamType, EtsTranslation, EtsUnionFieldInfo, TranslationAttribute,
};

use super::baggage::{baggages_to_refs, make_baggage_id};
use crate::definition::module::{ModuleArgRole, ModuleArgType, StoredModuleDef};
use crate::definition::page_layout::{
    ConditionalElement, ConditionalItem, PageBlock, PageElement, PageItem, PageStructure,
};
use crate::schema::*;

use super::helpers::{block_com_obj_ref, block_items_to_when_items, block_param_ref, when_com_obj_ref, when_param_ref};
use super::traversal::{
    collect_pictures_from_layout, collect_pictures_from_module_layout, collect_union_variant_texts,
};
use super::{
    ActiveConditions, ApplicationProgramConfig, GeneratorError, MaskFamily, ParamRefMap, System7MemoryLayout,
    strip_no_memory_bytes,
};
use crate::signing::KnxSchemaVersion;

// Include the rest of the MtxmlGenerator implementation
include!("mtxml_impl.rs");
