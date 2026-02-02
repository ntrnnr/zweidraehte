//! Device Definition DSL
//!
//! This module provides the DSL (Domain Specific Language) for defining KNX devices
//! in Rust code. It contains:
//!
//! - [`module`] - Reusable module definitions (`KnxModule` trait, `ModuleCollection`)
//! - [`page_layout`] - ETS page structure definitions (`EtsPageLayout`, `ets_pages!` macro)
//!
//! These types are used when generating MTXML files from Rust device definitions.

pub mod module;
pub mod page_layout;

// Re-export key types for convenience
pub use module::{
    ConditionalModuleInstance, KnxModule, ModuleArgDef, ModuleArgRole, ModuleArgType, ModuleArgValue, ModuleCollection,
    ModuleInstance, ModuleInstanceBuilder, StoredModuleDef, StoredModuleInstance,
};
pub use page_layout::{
    ChannelDef, Condition, ConditionalElement, ConditionalItem, ElementCase, EtsPageLayout, ItemCase, ModulePageLayout,
    PageBlock, PageElement, PageItem, PageStructure,
};
