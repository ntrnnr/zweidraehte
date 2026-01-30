//! MtxmlGenerator - ApplicationProgram MTXML generation.
//!
//! This is the main generator for creating ApplicationProgram XML files from device definitions.
//! The implementation handles:
//! - Parameter types, parameters, and parameter refs
//! - Communication objects and object refs
//! - Dynamic section with choose/when conditional blocks
//! - Module definitions and instances
//! - Load procedures for different mask families

use std::collections::HashMap;

use base64::Engine;

use zweidraehte::ets::{EtsCommObjectDef, EtsParamType, EtsUnionFieldInfo};

use crate::page_layout::{
    ConditionalElement, ConditionalItem, PageBlock, PageElement, PageItem, PageStructure,
};
use crate::module::{ModuleArgRole, ModuleArgType, StoredModuleDef};
use crate::schema::*;
use super::baggage::{baggages_to_refs, make_baggage_id};

use super::{
    ActiveConditions, ApplicationProgramConfig, GeneratorError, MaskFamily, MultiParamRefMap,
    SelectorRefCounters, System7MemoryLayout, strip_no_memory_bytes,
};
use super::traversal::{
    collect_pictures_from_layout, collect_pictures_from_module_layout,
    collect_union_variant_texts, count_selector_usages_with_objects,
};
use super::helpers::{
    block_com_obj_ref, block_param_ref, block_items_to_when_items, when_com_obj_ref, when_param_ref,
};

// Include the rest of the MtxmlGenerator implementation
include!("mtxml_impl.rs");
