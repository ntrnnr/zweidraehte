//! Page layout traversal utilities using a visitor pattern.
//!
//! This module provides a generic traversal mechanism for page layouts (both device-level
//! and module-level) using the visitor pattern. This allows multiple collectors (pictures,
//! texts, selector counts) to share the same traversal logic.

use std::collections::{HashMap, HashSet};

use crate::definition::page_layout::{
    ConditionalElement, ConditionalItem, ItemCase, ModuleLayoutBlock, ModuleLayoutCase, ModuleLayoutElement,
    ModuleLayoutItem, ModuleLayoutWhen, ModulePageLayout, PageBlock, PageElement, PageItem, PageStructure,
};

use super::ApplicationProgramConfig;

// ============================================================================
// Page Layout Visitor Trait
// ============================================================================

/// Visitor trait for traversing page layouts.
///
/// Implement this trait to collect information from page layouts. The walker
/// calls these methods as it traverses the structure. All methods have default
/// empty implementations so you only need to implement what you care about.
pub(crate) trait PageLayoutVisitor {
    /// Called when visiting a picture item.
    fn visit_picture(&mut self, _baggage_name: &str) {}

    /// Called when visiting a parameter reference.
    fn visit_param(&mut self, _name: &str) {}

    /// Called when visiting a communication object reference.
    fn visit_obj(&mut self, _name: &str) {}

    /// Called when visiting an ObjWithValue item (object + selector + union).
    fn visit_obj_with_value(
        &mut self,
        _obj_name: &str,
        _selector_param: &str,
        _value_union: &str,
        _extra_params: &[&str],
        _sub_selectors: &[(i64, &str, &[(i64, &str, &str)])],
    ) {
    }

    /// Called when visiting a GroupedObjChoose item.
    fn visit_grouped_obj_choose(&mut self, _selector_param: &str, _hidden_params: &[&str], _objects: &[(&str, &str)]) {}

    /// Called when visiting a UnionVariantDirect item.
    fn visit_union_variant_direct(&mut self, _union_field: &str, _variant_name: &str, _text_override: Option<&str>) {}

    /// Called when visiting a UnionVariantWithChoose item.
    fn visit_union_variant_with_choose(
        &mut self,
        _union_field: &str,
        _variant_name: &str,
        _text_override: Option<&str>,
    ) {
    }

    /// Called when visiting a ChooseOnUnionVariant item.
    fn visit_choose_on_union_variant(&mut self, _union_field: &str, _variant_name: &str) {}
}

// ============================================================================
// Walk Functions
// ============================================================================

/// Walk a page structure with a visitor.
pub(crate) fn walk_page_structure<V: PageLayoutVisitor>(layout: &PageStructure, visitor: &mut V) {
    // Walk device settings
    for elem in &layout.device_settings {
        walk_page_element(elem, visitor);
    }

    // Walk channels — every definition, choose gating included, so
    // collectors see the full roster.
    for channel in layout.channel_defs() {
        for elem in &channel.elements {
            walk_page_element(elem, visitor);
        }
    }
}

fn walk_page_element<V: PageLayoutVisitor>(elem: &PageElement, visitor: &mut V) {
    match elem {
        PageElement::Block(block) => {
            walk_page_block(block, visitor);
        }
        PageElement::When(cond) => {
            walk_conditional_element(cond, visitor);
        }
        PageElement::UnionSelector(_) => {}
    }
}

fn walk_page_block<V: PageLayoutVisitor>(block: &PageBlock, visitor: &mut V) {
    for item in &block.items {
        walk_page_item(item, visitor);
    }
}

fn walk_conditional_element<V: PageLayoutVisitor>(cond: &ConditionalElement, visitor: &mut V) {
    for case in &cond.cases {
        for elem in &case.elements {
            walk_page_element(elem, visitor);
        }
    }
}

fn walk_page_item<V: PageLayoutVisitor>(item: &PageItem, visitor: &mut V) {
    match item {
        PageItem::Param(name) => {
            visitor.visit_param(name);
        }
        PageItem::Obj(name) => {
            visitor.visit_obj(name);
        }
        PageItem::Picture(baggage_name) => {
            visitor.visit_picture(baggage_name);
        }
        PageItem::Separator(_) => {}
        PageItem::When(cond) => {
            walk_conditional_item(cond, visitor);
        }
        PageItem::UnionSelector(_) => {}
        PageItem::ObjWithValue { obj_name, selector_param, value_union, extra_params, sub_selectors } => {
            visitor.visit_obj_with_value(obj_name, selector_param, value_union, extra_params, sub_selectors);
        }
        PageItem::GroupedObjChoose { selector_param, hidden_params, objects } => {
            visitor.visit_grouped_obj_choose(selector_param, hidden_params, objects);
        }
        PageItem::ObjDirect { obj_name, params } => {
            visitor.visit_obj(obj_name);
            for p in *params {
                visitor.visit_param(p);
            }
        }
        PageItem::ObjsDirectWithParams { obj_names, params } => {
            for o in *obj_names {
                visitor.visit_obj(o);
            }
            for p in *params {
                visitor.visit_param(p);
            }
        }
        PageItem::ObjsByRefName { ref_names, params } => {
            // ref_names are object refs, not object names directly
            for p in *params {
                visitor.visit_param(p);
            }
            // We could add a separate callback for ref names if needed
            let _ = ref_names;
        }
        PageItem::ObjWithFixedVariant { obj_name, hidden_params, union_field, variant_name, text_override, .. } => {
            visitor.visit_obj(obj_name);
            for p in *hidden_params {
                visitor.visit_param(p);
            }
            visitor.visit_union_variant_direct(union_field, variant_name, *text_override);
        }
        PageItem::UnionVariantDirect { union_field, variant_name, text_override } => {
            visitor.visit_union_variant_direct(union_field, variant_name, *text_override);
        }
        PageItem::UnionVariantWithChoose { union_field, variant_name, text_override, cases } => {
            visitor.visit_union_variant_with_choose(union_field, variant_name, *text_override);
            for case in cases {
                walk_item_case(case, visitor);
            }
        }
        PageItem::ChooseOnUnionVariant { union_field, variant_name, cases } => {
            visitor.visit_choose_on_union_variant(union_field, variant_name);
            for case in cases {
                walk_item_case(case, visitor);
            }
        }
        PageItem::Module { .. } => {
            // Module instances are handled separately via module layouts
        }
        PageItem::ModuleInline { .. } => {
            // Module instances are handled separately via module layouts
        }
        PageItem::ModuleInstances { .. } => {
            // Module instances are handled separately via module layouts
        }
    }
}

fn walk_conditional_item<V: PageLayoutVisitor>(cond: &ConditionalItem, visitor: &mut V) {
    for case in &cond.cases {
        walk_item_case(case, visitor);
    }
}

fn walk_item_case<V: PageLayoutVisitor>(case: &ItemCase, visitor: &mut V) {
    for item in &case.items {
        walk_page_item(item, visitor);
    }
}

/// Walk a module page layout with a visitor.
pub(crate) fn walk_module_layout<V: PageLayoutVisitor>(layout: &ModulePageLayout, visitor: &mut V) {
    for elem in &layout.elements {
        walk_module_element(elem, visitor);
    }
}

fn walk_module_element<V: PageLayoutVisitor>(elem: &ModuleLayoutElement, visitor: &mut V) {
    match elem {
        ModuleLayoutElement::Block(block) => {
            walk_module_block(block, visitor);
        }
        ModuleLayoutElement::When(when_elem) => {
            walk_module_when(when_elem, visitor);
        }
    }
}

fn walk_module_block<V: PageLayoutVisitor>(block: &ModuleLayoutBlock, visitor: &mut V) {
    for item in &block.items {
        walk_module_item(item, visitor);
    }
}

fn walk_module_when<V: PageLayoutVisitor>(when_elem: &ModuleLayoutWhen, visitor: &mut V) {
    for case in &when_elem.cases {
        walk_module_case(case, visitor);
    }
}

fn walk_module_case<V: PageLayoutVisitor>(case: &ModuleLayoutCase, visitor: &mut V) {
    for item in &case.items {
        walk_module_item(item, visitor);
    }
}

fn walk_module_item<V: PageLayoutVisitor>(item: &ModuleLayoutItem, visitor: &mut V) {
    match item {
        ModuleLayoutItem::Param(name) => {
            visitor.visit_param(name);
        }
        ModuleLayoutItem::Obj(name) => {
            visitor.visit_obj(name);
        }
        ModuleLayoutItem::Picture(baggage_name) => {
            visitor.visit_picture(baggage_name);
        }
        ModuleLayoutItem::Separator(_) => {}
        ModuleLayoutItem::When(when_elem) => {
            walk_module_when(when_elem, visitor);
        }
    }
}

// ============================================================================
// Picture Collection
// ============================================================================

/// Information about a picture collected from page layouts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PictureInfo {
    /// The baggage filename (e.g., "xmas.png")
    pub baggage_name: String,
}

/// Visitor that collects pictures.
struct PictureCollector<'a> {
    pictures: &'a mut Vec<PictureInfo>,
    seen: &'a mut HashSet<String>,
}

impl PageLayoutVisitor for PictureCollector<'_> {
    fn visit_picture(&mut self, baggage_name: &str) {
        if !self.seen.contains(baggage_name) {
            self.seen.insert(baggage_name.to_string());
            self.pictures.push(PictureInfo { baggage_name: baggage_name.to_string() });
        }
    }
}

/// Collects all pictures from page layouts (device-level and module-level).
pub(crate) fn collect_pictures_from_layout(config: &ApplicationProgramConfig) -> Vec<PictureInfo> {
    let mut pictures = Vec::new();
    let mut seen = HashSet::new();

    // Collect from device page layout
    if let Some(layout) = &config.page_layout {
        let mut collector = PictureCollector { pictures: &mut pictures, seen: &mut seen };
        walk_page_structure(layout, &mut collector);
    }

    // Collect from module layouts
    if let Some(modules) = &config.modules {
        for def in modules.definitions() {
            if let Some(module_layout) = &def.page_layout {
                let mut collector = PictureCollector { pictures: &mut pictures, seen: &mut seen };
                walk_module_layout(module_layout, &mut collector);
            }
        }
    }

    pictures
}

/// Collect pictures from a module layout (used by module generator).
pub(crate) fn collect_pictures_from_module_layout(
    layout: &ModulePageLayout,
    pictures: &mut Vec<PictureInfo>,
    seen: &mut HashSet<String>,
) {
    let mut collector = PictureCollector { pictures, seen };
    walk_module_layout(layout, &mut collector);
}

// ============================================================================
// Text Collection (for union variant params)
// ============================================================================

/// Visitor that collects union variant texts.
struct TextCollector<'a> {
    texts: &'a mut HashMap<(String, String), Vec<Option<String>>>,
}

impl PageLayoutVisitor for TextCollector<'_> {
    fn visit_union_variant_direct(&mut self, union_field: &str, variant_name: &str, text_override: Option<&str>) {
        let key = (union_field.to_string(), variant_name.to_string());
        let text = text_override.map(|s| s.to_string());
        let entry = self.texts.entry(key).or_default();
        if !entry.contains(&text) {
            entry.push(text);
        }
    }

    fn visit_union_variant_with_choose(&mut self, union_field: &str, variant_name: &str, text_override: Option<&str>) {
        let key = (union_field.to_string(), variant_name.to_string());
        let text = text_override.map(|s| s.to_string());
        let entry = self.texts.entry(key).or_default();
        if !entry.contains(&text) {
            entry.push(text);
        }
    }

    fn visit_obj_with_value(
        &mut self,
        _obj_name: &str,
        _selector_param: &str,
        value_union: &str,
        _extra_params: &[&str],
        sub_selectors: &[(i64, &str, &[(i64, &str, &str)])],
    ) {
        // ObjWithValue outputs union variant params without text override
        // Add a None text for all variants we might use
        let key = (value_union.to_string(), String::new());
        let entry = self.texts.entry(key).or_default();
        if !entry.contains(&None) {
            entry.push(None);
        }

        // Also handle sub_selectors which have their own variant params
        for (_, _, sub_variants) in sub_selectors.iter() {
            for (_, _, variant_name) in sub_variants.iter() {
                let key = (value_union.to_string(), variant_name.to_string());
                let entry = self.texts.entry(key).or_default();
                if !entry.contains(&None) {
                    entry.push(None);
                }
            }
        }
    }
}

/// Collects union variant text overrides from the page layout.
pub(crate) fn collect_union_variant_texts(layout: &PageStructure) -> HashMap<(String, String), Vec<Option<String>>> {
    let mut texts: HashMap<(String, String), Vec<Option<String>>> = HashMap::new();
    let mut collector = TextCollector { texts: &mut texts };
    walk_page_structure(layout, &mut collector);
    texts
}
