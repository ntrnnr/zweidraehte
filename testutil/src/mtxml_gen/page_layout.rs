//! Page Layout Definition for ETS Parameter Pages
//!
//! This module provides types and a macro for defining the structure of ETS parameter pages
//! in a declarative, Rust-native way. The layout controls how parameters are organized in
//! the ETS software's parameter configuration UI.
//!
//! # Overview
//!
//! ETS displays device parameters in a hierarchical structure:
//! - **ChannelIndependentBlock** - Device-wide settings (always visible)
//! - **Channel** - Tabs for different functional areas
//! - **ParameterBlock** - Collapsible sections containing parameters
//! - **choose/when** - Conditional visibility based on parameter values
//!
//! # Usage
//!
//! Implement `EtsPageLayout` on your device type and use the `ets_pages!` macro:
//!
//! ```ignore
//! impl EtsPageLayout for MyDevice {
//!     fn page_layout() -> PageStructure {
//!         ets_pages! {
//!             device {
//!                 block "general" => "General Settings" {
//!                     param mode_selector
//!                 }
//!                 when mode_selector {
//!                     [Mode1] => {
//!                         block "mode1" => "Mode 1 Settings" {
//!                             param mode1_param1
//!                         }
//!                     }
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```

/// Trait for devices that define their own ETS page layout.
///
/// Implement this on your device type to control how parameters are organized
/// in the ETS parameter configuration UI.
pub trait EtsPageLayout {
    /// Returns the page structure definition for this device.
    fn page_layout() -> PageStructure;
}

/// Root page structure definition.
///
/// Contains device-wide settings (ChannelIndependentBlock) and optional channel tabs.
#[derive(Debug, Clone, Default)]
pub struct PageStructure {
    /// Content for ChannelIndependentBlock (device-wide settings, always visible)
    pub device_settings: Vec<PageElement>,
    /// Channel tabs for organizing parameters into functional groups
    pub channels: Vec<ChannelDef>,
}

/// Channel definition (appears as a tab in ETS).
#[derive(Debug, Clone)]
pub struct ChannelDef {
    /// Internal name (used in XML Id)
    pub name: &'static str,
    /// Display text shown in ETS
    pub text: &'static str,
    /// Optional channel number
    pub number: Option<u32>,
    /// Elements within this channel
    pub elements: Vec<PageElement>,
}

/// Top-level elements that can appear in device settings or a channel.
#[derive(Debug, Clone)]
pub enum PageElement {
    /// A collapsible parameter block (section)
    Block(PageBlock),
    /// Conditional visibility - can wrap entire blocks
    When(ConditionalElement),
}

/// A parameter block (collapsible section in ETS).
#[derive(Debug, Clone)]
pub struct PageBlock {
    /// Internal name (used in XML Id)
    pub name: &'static str,
    /// Display text shown in ETS (supports `{{param_ref_id:default}}` interpolation)
    pub text: &'static str,
    /// Items within this block
    pub items: Vec<PageItem>,
}

/// Items within a parameter block.
#[derive(Debug, Clone)]
pub enum PageItem {
    /// A parameter reference by name
    Param(&'static str),
    /// A communication object reference by name (field name from EtsComObjects struct)
    Obj(&'static str),
    /// Visual separator with optional text
    Separator(Option<&'static str>),
    /// Nested conditional within a block
    When(ConditionalItem),
}

/// Conditional visibility at the block level (can wrap entire ParameterBlocks).
///
/// This corresponds to MDT's pattern where selecting a button mode causes
/// different ParameterBlocks to appear/disappear as siblings.
#[derive(Debug, Clone)]
pub struct ConditionalElement {
    /// Parameter name that controls visibility
    pub selector: &'static str,
    /// Cases for different selector values
    pub cases: Vec<ElementCase>,
}

/// A case for block-level conditional visibility.
#[derive(Debug, Clone)]
pub struct ElementCase {
    /// Condition that must match for these elements to be visible
    pub condition: Condition,
    /// Blocks/elements shown when condition matches
    pub elements: Vec<PageElement>,
}

/// Conditional visibility at the item level (within a block).
#[derive(Debug, Clone)]
pub struct ConditionalItem {
    /// Parameter name that controls visibility
    pub selector: &'static str,
    /// Cases for different selector values
    pub cases: Vec<ItemCase>,
}

/// A case for item-level conditional visibility.
#[derive(Debug, Clone)]
pub struct ItemCase {
    /// Condition that must match for these items to be visible
    pub condition: Condition,
    /// Items shown when condition matches
    pub items: Vec<PageItem>,
}

/// Condition types for choose/when visibility.
#[derive(Debug, Clone)]
pub enum Condition {
    /// Match specific numeric values (e.g., "1", "2 3", "0 1 2")
    Values(Vec<i64>),
    /// Default case (when no other condition matches)
    Default,
}

impl Condition {
    /// Create a condition from a slice of values.
    pub fn values(vals: &[i64]) -> Self {
        Condition::Values(vals.to_vec())
    }

    /// Convert condition to ETS test string format.
    pub fn to_test_string(&self) -> Option<String> {
        match self {
            Condition::Values(vals) => {
                Some(vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" "))
            }
            Condition::Default => None,
        }
    }

    /// Check if this is a default condition.
    pub fn is_default(&self) -> bool {
        matches!(self, Condition::Default)
    }

    /// Get the values of this condition as a Vec.
    /// Returns an empty Vec for Default conditions.
    pub fn to_values(&self) -> Vec<i64> {
        match self {
            Condition::Values(vals) => vals.clone(),
            Condition::Default => Vec::new(),
        }
    }
}

/// Declarative macro for defining ETS page layouts.
///
/// # Syntax
///
/// ```text
/// ets_pages! {
///     device {                           // ChannelIndependentBlock content
///         <elements>
///     }
///
///     channel "name" => "Display Text" (number) {   // Optional channel tab
///         <elements>
///     }
/// }
///
/// <elements> can be:
///     block "name" => "Display Text" {   // ParameterBlock
///         <items>
///     }
///
///     when <union_field> {               // Conditional blocks (selector is implicit)
///         [Variant1, Variant2] => { <elements> }  // Enum discriminants
///         [1, 2, 3] => { <elements> }             // Integer literals
///         _ => { <elements> }                      // Default case
///     }
///
/// <items> can be:
///     param <name>                                // Simple parameter → "name"
///     param <union>::<Variant>.<field>           // Union field → "union_Variant_field"
///     selector <union_field>                     // Selector param → "union_field_selector"
///     obj <name>                                 // Communication object reference
///     sep                                        // ParameterSeparator (empty)
///     sep "text"                                 // ParameterSeparator with text
///
///     when <union_field> {                       // Conditional items (selector implicit)
///         [Variant] => { <items> }
///         [1] => { <items> }
///     }
/// ```
///
/// # Path Syntax
///
/// The macro provides a readable path syntax for referencing parameters:
///
/// - `param simple_name` → `"simple_name"`
/// - `selector union_field` → `"union_field_selector"`
/// - `param union_field::Variant.field` → `"union_field_Variant_field"`
/// - `when union_field { ... }` → selector = `"union_field_selector"`
///
/// # Examples
///
/// ```ignore
/// ets_pages! {
///     device {
///         block "general" => "General Settings" {
///             param send_cycle_time
///             param lock_behavior
///         }
///         block "channels" => "Channel Configuration" {
///             selector channel_a_config
///             selector channel_b_config
///         }
///         when channel_a_config {
///             [Switch] => {
///                 block "channel_a_switch" => "    Channel A: Switch Mode" {
///                     param channel_a_config::Switch.invert
///                 }
///             }
///             [Dimmer] => {
///                 block "channel_a_dimmer" => "    Channel A: Dimmer Mode" {
///                     param channel_a_config::Dimmer.min_level
///                     param channel_a_config::Dimmer.max_level
///                 }
///             }
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! ets_pages {
    // Entry point: device block only
    (device { $($device_content:tt)* }) => {
        $crate::mtxml_gen::page_layout::PageStructure {
            device_settings: $crate::ets_pages!(@elements $($device_content)*),
            channels: vec![],
        }
    };

    // Entry point: device block followed by channels
    (
        device { $($device_content:tt)* }
        $($rest:tt)+
    ) => {
        $crate::mtxml_gen::page_layout::PageStructure {
            device_settings: $crate::ets_pages!(@elements $($device_content)*),
            channels: $crate::ets_pages!(@channels $($rest)+),
        }
    };

    // Entry point: channels only (no device block)
    (
        channel $ch_name:literal => $ch_text:literal $(( $ch_num:expr ))? { $($ch_content:tt)* }
        $($rest:tt)*
    ) => {
        $crate::mtxml_gen::page_layout::PageStructure {
            device_settings: vec![],
            channels: $crate::ets_pages!(@channels channel $ch_name => $ch_text $(( $ch_num ))? { $($ch_content)* } $($rest)*),
        }
    };

    // Entry point: empty
    () => {
        $crate::mtxml_gen::page_layout::PageStructure {
            device_settings: vec![],
            channels: vec![],
        }
    };

    // Parse multiple channels
    (@channels) => {
        vec![]
    };

    (@channels channel $ch_name:literal => $ch_text:literal ( $ch_num:expr ) { $($ch_content:tt)* } $($rest:tt)*) => {{
        let mut chans = vec![$crate::mtxml_gen::page_layout::ChannelDef {
            name: $ch_name,
            text: $ch_text,
            number: Some($ch_num),
            elements: $crate::ets_pages!(@elements $($ch_content)*),
        }];
        chans.extend($crate::ets_pages!(@channels $($rest)*));
        chans
    }};

    (@channels channel $ch_name:literal => $ch_text:literal { $($ch_content:tt)* } $($rest:tt)*) => {{
        let mut chans = vec![$crate::mtxml_gen::page_layout::ChannelDef {
            name: $ch_name,
            text: $ch_text,
            number: None,
            elements: $crate::ets_pages!(@elements $($ch_content)*),
        }];
        chans.extend($crate::ets_pages!(@channels $($rest)*));
        chans
    }};

    // Parse elements (blocks and when clauses) - base case (empty)
    (@elements) => {
        vec![]
    };

    // Parse a block element
    (@elements block $name:literal => $text:literal { $($items:tt)* } $($rest:tt)*) => {{
        let mut elems = vec![$crate::mtxml_gen::page_layout::PageElement::Block(
            $crate::mtxml_gen::page_layout::PageBlock {
                name: $name,
                text: $text,
                items: $crate::ets_pages!(@items $($items)*),
            }
        )];
        elems.extend($crate::ets_pages!(@elements $($rest)*));
        elems
    }};

    // Parse a when element (conditional blocks)
    // The selector is the union field name - we append _selector automatically
    // Example: when channel_a_config { ... } → selector = "channel_a_config_selector"
    (@elements when $selector:ident { $($cases:tt)* } $($rest:tt)*) => {{
        let mut elems = vec![$crate::mtxml_gen::page_layout::PageElement::When(
            $crate::mtxml_gen::page_layout::ConditionalElement {
                selector: concat!(stringify!($selector), "_selector"),
                cases: $crate::ets_pages!(@element_cases $($cases)*),
            }
        )];
        elems.extend($crate::ets_pages!(@elements $($rest)*));
        elems
    }};

    // Parse element cases (for when at element level) - base case
    (@element_cases) => {
        vec![]
    };

    // Parse element case with enum variants (cast directly to i64 since they're repr(isize))
    (@element_cases [$($variant:ident),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::mtxml_gen::page_layout::ElementCase {
            condition: $crate::mtxml_gen::page_layout::Condition::values(&[
                $($variant as i64),+
            ]),
            elements: $crate::ets_pages!(@elements $($content)*),
        }];
        cases.extend($crate::ets_pages!(@element_cases $($rest)*));
        cases
    }};

    // Parse element case with integer literals
    (@element_cases [$($val:literal),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::mtxml_gen::page_layout::ElementCase {
            condition: $crate::mtxml_gen::page_layout::Condition::values(&[$($val as i64),+]),
            elements: $crate::ets_pages!(@elements $($content)*),
        }];
        cases.extend($crate::ets_pages!(@element_cases $($rest)*));
        cases
    }};

    // Parse element case with default (_)
    (@element_cases _ => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::mtxml_gen::page_layout::ElementCase {
            condition: $crate::mtxml_gen::page_layout::Condition::Default,
            elements: $crate::ets_pages!(@elements $($content)*),
        }];
        cases.extend($crate::ets_pages!(@element_cases $($rest)*));
        cases
    }};

    // Parse items (params, separators, when clauses) - base case
    (@items) => {
        vec![]
    };

    // Parse param with ::Variant.field path syntax (must come before simple param)
    // Example: param channel_a_config::Dimmer.min_level → "channel_a_config_Dimmer_min_level"
    (@items param $union:ident :: $variant:ident . $field:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::mtxml_gen::page_layout::PageItem::Param(
            concat!(stringify!($union), "_", stringify!($variant), "_", stringify!($field))
        )];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse simple param item (single identifier)
    // Example: param send_cycle_time → "send_cycle_time"
    (@items param $name:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::mtxml_gen::page_layout::PageItem::Param(stringify!($name))];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse selector keyword (for union selector parameters)
    // Example: selector channel_a_config → "channel_a_config_selector"
    (@items selector $field:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::mtxml_gen::page_layout::PageItem::Param(
            concat!(stringify!($field), "_selector")
        )];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse obj item (communication object reference)
    (@items obj $name:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::mtxml_gen::page_layout::PageItem::Obj(stringify!($name))];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse separator with text (must come before the version without text)
    (@items sep $text:literal $($rest:tt)*) => {{
        let mut items = vec![$crate::mtxml_gen::page_layout::PageItem::Separator(Some($text))];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse separator without text
    (@items sep $($rest:tt)*) => {{
        let mut items = vec![$crate::mtxml_gen::page_layout::PageItem::Separator(None)];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse when item (conditional within a block)
    // The selector is the union field name - we append _selector automatically
    // Example: when channel_a_config { ... } → selector = "channel_a_config_selector"
    (@items when $selector:ident { $($cases:tt)* } $($rest:tt)*) => {{
        let mut items = vec![$crate::mtxml_gen::page_layout::PageItem::When(
            $crate::mtxml_gen::page_layout::ConditionalItem {
                selector: concat!(stringify!($selector), "_selector"),
                cases: $crate::ets_pages!(@item_cases $($cases)*),
            }
        )];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse item cases (for when at item level) - base case
    (@item_cases) => {
        vec![]
    };

    // Parse item case with enum variants (cast directly to i64 since they're repr(isize))
    (@item_cases [$($variant:ident),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::mtxml_gen::page_layout::ItemCase {
            condition: $crate::mtxml_gen::page_layout::Condition::values(&[
                $($variant as i64),+
            ]),
            items: $crate::ets_pages!(@items $($content)*),
        }];
        cases.extend($crate::ets_pages!(@item_cases $($rest)*));
        cases
    }};

    // Parse item case with integer literals
    (@item_cases [$($val:literal),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::mtxml_gen::page_layout::ItemCase {
            condition: $crate::mtxml_gen::page_layout::Condition::values(&[$($val as i64),+]),
            items: $crate::ets_pages!(@items $($content)*),
        }];
        cases.extend($crate::ets_pages!(@item_cases $($rest)*));
        cases
    }};

    // Parse item case with default (_)
    (@item_cases _ => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::mtxml_gen::page_layout::ItemCase {
            condition: $crate::mtxml_gen::page_layout::Condition::Default,
            items: $crate::ets_pages!(@items $($content)*),
        }];
        cases.extend($crate::ets_pages!(@item_cases $($rest)*));
        cases
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test basic structure creation
    #[test]
    fn test_basic_page_structure() {
        let structure = ets_pages! {
            device {
                block "general" => "General Settings" {
                    param test_param
                }
            }
        };

        assert_eq!(structure.device_settings.len(), 1);
        assert!(structure.channels.is_empty());

        if let PageElement::Block(block) = &structure.device_settings[0] {
            assert_eq!(block.name, "general");
            assert_eq!(block.text, "General Settings");
            assert_eq!(block.items.len(), 1);
            if let PageItem::Param(name) = &block.items[0] {
                assert_eq!(*name, "test_param");
            } else {
                panic!("Expected Param item");
            }
        } else {
            panic!("Expected Block element");
        }
    }

    #[test]
    fn test_separator() {
        let structure = ets_pages! {
            device {
                block "test" => "Test Block" {
                    param before
                    sep
                    param middle
                    sep "Section"
                    param after
                }
            }
        };

        if let PageElement::Block(block) = &structure.device_settings[0] {
            assert_eq!(block.items.len(), 5);
            assert!(matches!(block.items[0], PageItem::Param("before")));
            assert!(matches!(block.items[1], PageItem::Separator(None)));
            assert!(matches!(block.items[2], PageItem::Param("middle")));
            if let PageItem::Separator(Some(text)) = &block.items[3] {
                assert_eq!(*text, "Section");
            } else {
                panic!("Expected Separator with text");
            }
            assert!(matches!(block.items[4], PageItem::Param("after")));
        } else {
            panic!("Expected Block element");
        }
    }

    #[test]
    fn test_conditional_blocks() {
        let structure = ets_pages! {
            device {
                block "config" => "Configuration" {
                    param mode_selector
                }
                when mode_selector {
                    [1] => {
                        block "mode1" => "Mode 1" {
                            param mode1_param
                        }
                    }
                    [2, 3] => {
                        block "mode2" => "Mode 2/3" {
                            param mode2_param
                        }
                    }
                    _ => {
                        block "default" => "Default Mode" {
                            param default_param
                        }
                    }
                }
            }
        };

        assert_eq!(structure.device_settings.len(), 2);

        // Check config block
        if let PageElement::Block(block) = &structure.device_settings[0] {
            assert_eq!(block.name, "config");
        } else {
            panic!("Expected Block element");
        }

        // Check when element - selector now has _selector appended automatically
        if let PageElement::When(when) = &structure.device_settings[1] {
            assert_eq!(when.selector, "mode_selector_selector");
            assert_eq!(when.cases.len(), 3);

            // Check first case [1]
            if let Condition::Values(vals) = &when.cases[0].condition {
                assert_eq!(vals, &[1]);
            } else {
                panic!("Expected Values condition");
            }

            // Check second case [2, 3]
            if let Condition::Values(vals) = &when.cases[1].condition {
                assert_eq!(vals, &[2, 3]);
            } else {
                panic!("Expected Values condition");
            }

            // Check default case
            assert!(when.cases[2].condition.is_default());
        } else {
            panic!("Expected When element");
        }
    }

    #[test]
    fn test_channel_definition() {
        let structure = ets_pages! {
            device {
                block "global" => "Global Settings" {
                    param global_param
                }
            }
            channel "ch1" => "Channel 1" (1) {
                block "ch1_block" => "Channel 1 Settings" {
                    param ch1_param
                }
            }
        };

        assert_eq!(structure.device_settings.len(), 1);
        assert_eq!(structure.channels.len(), 1);

        let ch = &structure.channels[0];
        assert_eq!(ch.name, "ch1");
        assert_eq!(ch.text, "Channel 1");
        assert_eq!(ch.number, Some(1));
        assert_eq!(ch.elements.len(), 1);
    }

    #[test]
    fn test_condition_to_string() {
        let single = Condition::Values(vec![1]);
        assert_eq!(single.to_test_string(), Some("1".to_string()));

        let multi = Condition::Values(vec![1, 2, 3]);
        assert_eq!(multi.to_test_string(), Some("1 2 3".to_string()));

        let default = Condition::Default;
        assert_eq!(default.to_test_string(), None);
    }

    // Tests for new path syntax

    #[test]
    fn test_selector_keyword() {
        let structure = ets_pages! {
            device {
                block "test" => "Test" {
                    selector channel_config
                }
            }
        };

        if let PageElement::Block(block) = &structure.device_settings[0] {
            assert_eq!(block.items.len(), 1);
            // selector channel_config → "channel_config_selector"
            assert!(matches!(block.items[0], PageItem::Param("channel_config_selector")));
        } else {
            panic!("Expected Block element");
        }
    }

    #[test]
    fn test_param_path_syntax() {
        let structure = ets_pages! {
            device {
                block "test" => "Test" {
                    param channel_a::Dimmer.min_level
                    param simple_param
                }
            }
        };

        if let PageElement::Block(block) = &structure.device_settings[0] {
            assert_eq!(block.items.len(), 2);
            // param channel_a::Dimmer.min_level → "channel_a_Dimmer_min_level"
            assert!(matches!(block.items[0], PageItem::Param("channel_a_Dimmer_min_level")));
            // param simple_param → "simple_param"
            assert!(matches!(block.items[1], PageItem::Param("simple_param")));
        } else {
            panic!("Expected Block element");
        }
    }

    #[test]
    fn test_when_implicit_selector() {
        let structure = ets_pages! {
            device {
                when channel_config {
                    [1] => {
                        block "mode1" => "Mode 1" {
                            param channel_config::Mode1.value
                        }
                    }
                }
            }
        };

        if let PageElement::When(when) = &structure.device_settings[0] {
            // when channel_config { ... } → selector = "channel_config_selector"
            assert_eq!(when.selector, "channel_config_selector");
            assert_eq!(when.cases.len(), 1);

            // Check the nested param path
            if let PageElement::Block(block) = &when.cases[0].elements[0] {
                assert!(matches!(block.items[0], PageItem::Param("channel_config_Mode1_value")));
            } else {
                panic!("Expected Block element");
            }
        } else {
            panic!("Expected When element");
        }
    }
}
