//! Helper functions for generator code to reduce duplication.

use crate::schema::{ComObjectRefRef, ParameterBlockItem, ParameterRefRef, WhenItem};

// ============================================================================
// Factory functions for creating common items
// ============================================================================

/// Create a ParameterRefRef with default text and description.
#[inline]
fn param_ref(ref_id: String) -> ParameterRefRef {
    ParameterRefRef { ref_id, text: None, internal_description: None }
}

/// Create a ComObjectRefRef with default description.
#[inline]
fn com_obj_ref(ref_id: String) -> ComObjectRefRef {
    ComObjectRefRef { ref_id, internal_description: None }
}

// ============================================================================
// Wrapped items for ParameterBlockItem
// ============================================================================

/// Create a ParameterBlockItem::ParameterRefRef with default text.
#[inline]
pub(crate) fn block_param_ref(ref_id: String) -> ParameterBlockItem {
    ParameterBlockItem::ParameterRefRef(param_ref(ref_id))
}

/// Create a ParameterBlockItem::ComObjectRefRef.
#[inline]
pub(crate) fn block_com_obj_ref(ref_id: String) -> ParameterBlockItem {
    ParameterBlockItem::ComObjectRefRef(com_obj_ref(ref_id))
}

// ============================================================================
// Wrapped items for WhenItem
// ============================================================================

/// Create a WhenItem::ParameterRefRef with default text.
#[inline]
pub(crate) fn when_param_ref(ref_id: String) -> WhenItem {
    WhenItem::ParameterRefRef(param_ref(ref_id))
}

/// Create a WhenItem::ComObjectRefRef.
#[inline]
pub(crate) fn when_com_obj_ref(ref_id: String) -> WhenItem {
    WhenItem::ComObjectRefRef(com_obj_ref(ref_id))
}

// ============================================================================
// Conversion functions
// ============================================================================

/// Convert a ParameterBlockItem to a WhenItem if possible.
///
/// Returns None for items that don't have a WhenItem equivalent (Button, Rows, Columns).
fn block_item_to_when_item(item: ParameterBlockItem) -> Option<WhenItem> {
    match item {
        ParameterBlockItem::ParameterRefRef(r) => Some(WhenItem::ParameterRefRef(r)),
        ParameterBlockItem::ParameterBlockRename(r) => Some(WhenItem::ParameterBlockRename(r)),
        ParameterBlockItem::ComObjectRefRef(r) => Some(WhenItem::ComObjectRefRef(r)),
        ParameterBlockItem::ParameterSeparator(s) => Some(WhenItem::ParameterSeparator(s)),
        ParameterBlockItem::Choose(c) => Some(WhenItem::Choose(c)),
        ParameterBlockItem::Module(m) => Some(WhenItem::Module(m)),
        ParameterBlockItem::Button(_) => None,
        ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => None,
    }
}

/// Convert a vector of ParameterBlockItem to WhenItem, filtering out unconvertible items.
pub(crate) fn block_items_to_when_items(items: Vec<ParameterBlockItem>) -> Vec<WhenItem> {
    items.into_iter().filter_map(block_item_to_when_item).collect()
}
