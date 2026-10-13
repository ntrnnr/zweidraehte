//! Terminal navigation and sizing around the shared product-form projection.

use super::ProductEditor;
use crate::app::NavigationState;
use std::collections::HashSet;
use unicode_width::UnicodeWidthStr;
pub use zweidraehte_ets_files::runtime::presentation::{
    ContentItem, NodeType, ParameterTable, ParameterTableCell, ParameterTableColumn, ParameterTableRow,
    TreeBuilderVisitor, VisibleNodeType, VisibleTreeNode, WidgetType,
};
use zweidraehte_ets_files::runtime::presentation::{FormNode, FormPresentation};

/// A node in the sidebar tree (for Parameters tab).
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Unique ID for selection
    pub id: String,
    /// Display name
    pub name: String,
    /// Nesting depth (0 = root)
    pub depth: usize,
    /// Whether this node is expanded
    pub expanded: bool,
    /// Whether this node has children
    pub has_children: bool,
    /// Node type for content loading
    pub node_type: NodeType,
}

impl TreeNode {
    /// Group headers — the ETS-style main groups (channels, the
    /// device-settings block): never selectable, never a page of
    /// their own; only the sub-pages below them carry settings.
    pub fn is_group(&self) -> bool {
        matches!(self.node_type, NodeType::DeviceSettings | NodeType::Channel(_))
    }
}

trait TerminalWidgetWidth {
    fn display_width(&self, suffix: &str) -> usize;
}

impl TerminalWidgetWidth for WidgetType {
    fn display_width(&self, suffix: &str) -> usize {
        match self {
            WidgetType::Dropdown { options, .. } => {
                options.iter().map(|(_, text)| UnicodeWidthStr::width(text.as_str())).max().unwrap_or(1) + 4
            }
            WidgetType::Number { value, .. } => value.to_string().len() + UnicodeWidthStr::width(suffix) + 3,
            WidgetType::Text { value } => UnicodeWidthStr::width(value.as_str()) + 2,
            WidgetType::ReadOnly { value } => {
                UnicodeWidthStr::width(value.as_str()) + UnicodeWidthStr::width(suffix) + 1
            }
        }
    }
}

trait TerminalContentWidth {
    fn label_width(&self) -> Option<usize>;
    fn value_width(&self) -> Option<usize>;
}

impl TerminalContentWidth for ContentItem {
    fn label_width(&self) -> Option<usize> {
        match self {
            ContentItem::Parameter { text, .. } | ContentItem::Picture { text: Some(text), .. } => {
                text.lines().map(UnicodeWidthStr::width).max()
            }
            ContentItem::CommObject { name, .. } => Some(UnicodeWidthStr::width(name.as_str()) + 2),
            ContentItem::Separator { .. } | ContentItem::Picture { text: None, .. } | ContentItem::Table(_) => None,
        }
    }

    fn value_width(&self) -> Option<usize> {
        match self {
            ContentItem::Parameter { suffix, widget, .. } => {
                Some(widget.display_width(suffix.as_deref().unwrap_or("")))
            }
            ContentItem::CommObject { function, dpt, .. } => {
                let dpt_width = if dpt.is_empty() { 0 } else { UnicodeWidthStr::width(dpt.as_str()) + 3 };
                Some(UnicodeWidthStr::width(function.as_str()) + dpt_width)
            }
            // Keep a useful value area for the image even when its label is long.
            ContentItem::Picture { .. } => Some(24),
            ContentItem::Separator { .. } | ContentItem::Table(_) => None,
        }
    }
}

impl ProductEditor {
    pub(in crate::app) fn rebuild_tree(&mut self, navigation: &mut NavigationState) {
        self.content_page = None;
        self.view.tree_nodes.clear();
        let nodes = FormPresentation::new(&self.view.device).tree();
        self.flatten_form_nodes(&nodes, 0, &navigation.expanded_nodes);
        self.snap_selection_to_page(navigation);
    }

    fn flatten_form_nodes(&mut self, nodes: &[FormNode], depth: usize, expanded: &HashSet<String>) {
        for node in nodes {
            // Top-level groups are permanent headers. Nested pages keep the
            // same expansion and cursor behavior as before the shared projection.
            let is_expanded = depth == 0 || expanded.contains(&node.id);
            self.view.tree_nodes.push(TreeNode {
                id: node.id.clone(),
                name: node.name.clone(),
                depth,
                expanded: is_expanded,
                has_children: !node.children.is_empty(),
                node_type: node.node_type.clone(),
            });
            if is_expanded {
                self.flatten_form_nodes(&node.children, depth + 1, expanded);
            }
        }
    }

    /// Move `selected_tree_idx` onto the nearest selectable page —
    /// forward first, then backward; a tree of nothing but headers
    /// leaves it at 0 with no content.
    fn snap_selection_to_page(&self, navigation: &mut NavigationState) {
        if self.view.tree_nodes.get(navigation.selected_tree_idx).is_some_and(|n| !n.is_group()) {
            return;
        }
        let forward = self.view.tree_nodes.iter().skip(navigation.selected_tree_idx).position(|n| !n.is_group());
        let index = match forward {
            Some(offset) => Some(navigation.selected_tree_idx + offset),
            None => self.view.tree_nodes.iter().rposition(|n| !n.is_group()),
        };
        navigation.selected_tree_idx = index.unwrap_or(0);
    }

    pub(in crate::app) fn ensure_content(&mut self, selected_tree_idx: usize) {
        if self.content_page != Some(selected_tree_idx) {
            self.rebuild_content(selected_tree_idx);
        }
    }

    pub(in crate::app) fn rebuild_content(&mut self, selected_tree_idx: usize) {
        self.content_page = Some(selected_tree_idx);
        self.view.content_items = match self.view.tree_nodes.get(selected_tree_idx) {
            Some(node) => FormPresentation::new(&self.view.device).page(&node.node_type),
            None => Vec::new(),
        };
        self.view.content_label_width =
            self.view.content_items.iter().filter_map(ContentItem::label_width).max().unwrap_or(0);
        self.view.content_value_width =
            self.view.content_items.iter().filter_map(ContentItem::value_width).max().unwrap_or(0);
    }
}
