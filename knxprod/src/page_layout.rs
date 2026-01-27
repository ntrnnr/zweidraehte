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
    /// Union selector - shows selector param + choose/when for each variant's parameters
    /// The string is the union field name (e.g., "button1_value_00")
    /// This will emit both the selector param and a choose/when block for variant params
    UnionSelector(&'static str),
    /// Object with selector - combines object ref and value param in same when blocks.
    /// Optionally includes extra unconditional params via `with [...]` and sub-selectors.
    ///
    /// DSL syntax:
    /// - `obj_with_value obj by selector => union` - basic form
    /// - `obj_with_value obj by selector => union with [param1, param2]` - with extra params
    /// - `obj_with_value obj by selector => union with [...] sub_select { ... }` - with sub-selectors
    ///
    /// The `with [...]` params are included unconditionally in each when block.
    /// Their visibility (hidden or visible) is controlled by `#[ets(hidden)]` in the struct definition.
    ///
    /// For variants that need a sub-selector (like RGB needing colour_control to choose between
    /// RGB and HSV), use `sub_select { ... }` to specify which variants need nested choose blocks.
    ObjWithValue {
        obj_name: &'static str,
        selector_param: &'static str,
        value_union: &'static str,
        /// Extra params to include unconditionally in each when block (can be empty)
        extra_params: &'static [&'static str],
        /// Optional sub-selectors for specific variants that need nested choose blocks.
        /// Each entry is (variant_value, sub_selector_param, sub_variants) where:
        /// - variant_value: The selector value that triggers nested handling (e.g., 9 for RGB)
        /// - sub_selector_param: The param that controls the nested choose (e.g., "button1_colour_control")
        /// - sub_variants: Array of (sub_value, ref_name, variant_name) tuples for the nested when blocks
        ///   e.g., [(1, "button1_main_rgb", "Rgb"), (2, "button1_main_hsv", "Hsv")]
        sub_selectors: &'static [(i64, &'static str, &'static [(i64, &'static str, &'static str)])],
    },
    /// Grouped object type choose - puts multiple objects under one choose block
    /// This matches MDT's structure where one choose contains all objects for each type variant
    /// Format: selector_param, hidden_params, list of (obj_name, value_union) pairs
    GroupedObjChoose {
        selector_param: &'static str,
        hidden_params: &'static [&'static str],
        objects: &'static [(&'static str, &'static str)], // (obj_name, value_union)
    },
    /// Direct object output with params - no choose block, just the object and params directly
    /// Used in switch mode where object type is fixed (always 1Bit Switch)
    /// Format: object_name, followed by param names to include
    /// This outputs: ComObjectRefRef, then ParameterRefRefs for each param
    ObjDirect {
        obj_name: &'static str,
        params: &'static [&'static str],
    },
    /// Multiple objects output directly with params - no choose block
    /// Used in toggle mode where both O-0 and O-1 appear together
    ObjsDirectWithParams {
        obj_names: &'static [&'static str],
        params: &'static [&'static str],
    },
    /// Multiple objects output directly selecting refs by their ref_name
    /// Used when objects have named refs for different modes (e.g., "dimming", "blinds")
    /// The ref_names array must have the same length as obj_names
    ObjsByRefName {
        /// Ref names to look up (one per object, same order)
        ref_names: &'static [&'static str],
        params: &'static [&'static str],
    },
    /// Object with fixed union variant - outputs object + hidden params + specific union variant
    /// Used in switch mode where object type is fixed (always Switch/1Bit)
    /// This matches MDT's pattern: ComObjectRefRef + hidden param refs + specific UP-xxx
    /// Format: object_name, hidden_params, union_field_name, variant_name, selector_value
    /// The selector_value specifies which object ref to use (matching the selector_param's value)
    ObjWithFixedVariant {
        obj_name: &'static str,
        hidden_params: &'static [&'static str],
        union_field: &'static str,
        variant_name: &'static str, // e.g., "Switch" to get button1_value_00_Switch_value
        selector_value: i64, // e.g., 10 for ObjectType::Switch
        text_override: Option<&'static str>, // Optional Text attribute override for ParameterRefRef
    },
    /// Union variant params direct output - outputs specific variant's params without a choose block
    /// Used when the variant is already determined by outer context (e.g., inside switch mode)
    /// This matches MDT's pattern where UP-xxx params appear directly without choose
    /// Format: union_field_name, variant_name, optional text_override
    UnionVariantDirect {
        union_field: &'static str,
        variant_name: &'static str, // e.g., "Switch" to get button1_value_01_Switch_value
        text_override: Option<&'static str>, // Optional Text attribute override for ParameterRef
    },
    /// Union variant with conditional content - outputs the union variant param FIRST,
    /// then creates a choose block referencing that same param for conditional content.
    /// This matches MDT's pattern where UP-xxx is output, then choose ParamRefId references it.
    /// Example in MDT XML:
    ///   <ParameterRefRef RefId="...UP-143_R-172" />
    ///   <choose ParamRefId="...UP-143_R-172">
    ///     <when test="2">...</when>
    ///   </choose>
    UnionVariantWithChoose {
        union_field: &'static str,
        variant_name: &'static str,
        text_override: Option<&'static str>,
        cases: Vec<ItemCase>,
    },
    /// Choose block referencing an already-output union variant parameter.
    /// This is the companion to UnionVariantDirect - use UnionVariantDirect first to output
    /// the param, then use this to create choose blocks that reference it.
    /// This matches MDT's pattern where UP-xxx is output once at top, then multiple
    /// choose ParamRefId blocks reference it in nested contexts.
    ///
    /// Example in MDT XML:
    ///   <ParameterRefRef RefId="...UP-156_R-306" />  <!-- UnionVariantDirect outputs this -->
    ///   <choose ParamRefId="...UP-41_R-305">
    ///     <when test="1">
    ///       ...
    ///       <choose ParamRefId="...UP-156_R-306">  <!-- ChooseOnUnionVariant creates this -->
    ///         <when test="2 3">...</when>
    ///       </choose>
    ///     </when>
    ///   </choose>
    ChooseOnUnionVariant {
        union_field: &'static str,
        variant_name: &'static str,
        cases: Vec<ItemCase>,
    },
    /// A module instance reference by index.
    ///
    /// This represents a module instantiation within the page layout. The module definition
    /// must be registered in the ModuleCollection, and this creates a reference to instantiate
    /// it with specific argument values.
    ///
    /// Example in MDT XML:
    ///   <Module Id="M-0083_..._MD-1_M-1" RefId="M-0083_..._MD-1">
    ///     <NumericArg RefId="M-0083_..._MD-1_A-1" Value="5506" />
    ///     <NumericArg RefId="M-0083_..._MD-1_A-2" Value="116" />
    ///     <NumericArg RefId="M-0083_..._MD-1_A-3" Value="1" />
    ///   </Module>
    ///
    /// Fields:
    /// - `module_name`: The name of the module definition (matches KnxModule::NAME)
    /// - `instance_index`: Index into the module instances (0-based)
    Module {
        module_name: &'static str,
        instance_index: usize,
    },
    /// A module instance with inline argument values.
    ///
    /// This allows defining module instances directly in the page layout DSL without
    /// needing a separate `create_modules()` function. The module definition must still
    /// be registered, but instances are created from the inline arguments.
    ///
    /// DSL syntax in `ets_pages!` macro:
    /// ```ignore
    /// // With literal values:
    /// module DimmerChannelModule { ParamBase: 5, ObjBase: 0, ChNo: 1 }
    ///
    /// // With expressions (using auto-generated helpers):
    /// module DimmerChannelModule {
    ///     ParamBase: DeviceParams::channel_param_offset(1),
    ///     ObjBase: DeviceParams::channel_object_base(1),
    ///     ChNo: 1
    /// }
    /// ```
    ///
    /// This is more self-contained than `Module` as it includes all argument values
    /// directly rather than referencing a pre-created instance by index.
    ///
    /// Fields:
    /// - `module_name`: The name of the module definition (matches KnxModule::NAME)
    /// - `args`: Vec of (argument_name, value) pairs - supports expressions
    ModuleInline {
        module_name: &'static str,
        args: Vec<(&'static str, i64)>,
    },
    /// Multiple module instances with visibility conditions.
    ///
    /// This is a convenience variant that generates multiple `When` blocks containing
    /// `ModuleInline` items. Used for ergonomic multi-channel module instantiation.
    ///
    /// Each instance entry contains:
    /// - `selector`: Parameter name that controls visibility (e.g., "enable_ch1")
    /// - `args`: Argument values for this instance
    ///
    /// Use the `module_instances()` helper function to create this:
    /// ```ignore
    /// module_instances::<DimmerChannelModule, DeviceParams, 4>("enable_ch")
    /// ```
    ModuleInstances {
        module_name: &'static str,
        /// Vec of (selector_param, args) - each entry becomes a when block
        instances: Vec<(String, Vec<(&'static str, i64)>)>,
    },
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
        $crate::page_layout::PageStructure {
            device_settings: $crate::ets_pages!(@elements $($device_content)*),
            channels: vec![],
        }
    };

    // Entry point: device block followed by channels
    (
        device { $($device_content:tt)* }
        $($rest:tt)+
    ) => {
        $crate::page_layout::PageStructure {
            device_settings: $crate::ets_pages!(@elements $($device_content)*),
            channels: $crate::ets_pages!(@channels $($rest)+),
        }
    };

    // Entry point: channels only (no device block)
    (
        channel $ch_name:literal => $ch_text:literal $(( $ch_num:expr ))? { $($ch_content:tt)* }
        $($rest:tt)*
    ) => {
        $crate::page_layout::PageStructure {
            device_settings: vec![],
            channels: $crate::ets_pages!(@channels channel $ch_name => $ch_text $(( $ch_num ))? { $($ch_content)* } $($rest)*),
        }
    };

    // Entry point: empty
    () => {
        $crate::page_layout::PageStructure {
            device_settings: vec![],
            channels: vec![],
        }
    };

    // Parse multiple channels
    (@channels) => {
        vec![]
    };

    (@channels channel $ch_name:literal => $ch_text:literal ( $ch_num:expr ) { $($ch_content:tt)* } $($rest:tt)*) => {{
        let mut chans = vec![$crate::page_layout::ChannelDef {
            name: $ch_name,
            text: $ch_text,
            number: Some($ch_num),
            elements: $crate::ets_pages!(@elements $($ch_content)*),
        }];
        chans.extend($crate::ets_pages!(@channels $($rest)*));
        chans
    }};

    (@channels channel $ch_name:literal => $ch_text:literal { $($ch_content:tt)* } $($rest:tt)*) => {{
        let mut chans = vec![$crate::page_layout::ChannelDef {
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
        let mut elems = vec![$crate::page_layout::PageElement::Block(
            $crate::page_layout::PageBlock {
                name: $name,
                text: $text,
                items: $crate::ets_pages!(@items $($items)*),
            }
        )];
        elems.extend($crate::ets_pages!(@elements $($rest)*));
        elems
    }};

    // Parse a when element with @ prefix (conditional blocks) - for regular parameters
    // The @ prefix means use the parameter name directly without appending _selector
    // Example: when @eingang_type { ... } → selector = "eingang_type"
    (@elements when @ $param:ident { $($cases:tt)* } $($rest:tt)*) => {{
        let mut elems = vec![$crate::page_layout::PageElement::When(
            $crate::page_layout::ConditionalElement {
                selector: stringify!($param),
                cases: $crate::ets_pages!(@element_cases $($cases)*),
            }
        )];
        elems.extend($crate::ets_pages!(@elements $($rest)*));
        elems
    }};

    // Parse a when element (conditional blocks) - for union selectors
    // The selector is the union field name - we append _selector automatically
    // Example: when channel_a_config { ... } → selector = "channel_a_config_selector"
    (@elements when $selector:ident { $($cases:tt)* } $($rest:tt)*) => {{
        let mut elems = vec![$crate::page_layout::PageElement::When(
            $crate::page_layout::ConditionalElement {
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

    // Parse element case with enum path expressions (e.g., EnumType::Variant)
    // Must come before the simple ident rule to match first
    (@element_cases [$($enum_type:ident :: $variant:ident),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::page_layout::ElementCase {
            condition: $crate::page_layout::Condition::values(&[
                $($enum_type::$variant as i64),+
            ]),
            elements: $crate::ets_pages!(@elements $($content)*),
        }];
        cases.extend($crate::ets_pages!(@element_cases $($rest)*));
        cases
    }};

    // Parse element case with simple enum variants (cast directly to i64 since they're repr(isize))
    (@element_cases [$($variant:ident),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::page_layout::ElementCase {
            condition: $crate::page_layout::Condition::values(&[
                $($variant as i64),+
            ]),
            elements: $crate::ets_pages!(@elements $($content)*),
        }];
        cases.extend($crate::ets_pages!(@element_cases $($rest)*));
        cases
    }};

    // Parse element case with integer literals
    (@element_cases [$($val:literal),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::page_layout::ElementCase {
            condition: $crate::page_layout::Condition::values(&[$($val as i64),+]),
            elements: $crate::ets_pages!(@elements $($content)*),
        }];
        cases.extend($crate::ets_pages!(@element_cases $($rest)*));
        cases
    }};

    // Parse element case with default (_)
    (@element_cases _ => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::page_layout::ElementCase {
            condition: $crate::page_layout::Condition::Default,
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
        let mut items = vec![$crate::page_layout::PageItem::Param(
            concat!(stringify!($union), "_", stringify!($variant), "_", stringify!($field))
        )];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse simple param item (single identifier)
    // Example: param send_cycle_time → "send_cycle_time"
    (@items param $name:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::Param(stringify!($name))];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse params shorthand for multiple parameters
    // Example: params [field1, field2, field3] → three Param items
    (@items params [ $($name:ident),* $(,)? ] $($rest:tt)*) => {{
        let mut items = vec![
            $($crate::page_layout::PageItem::Param(stringify!($name))),*
        ];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse selector keyword (for union selector parameters)
    // Example: selector channel_a_config → "channel_a_config"
    // This generates a UnionSelector which will emit:
    // 1. The selector parameter itself
    // 2. A choose/when block for each variant's parameters
    (@items selector $field:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::UnionSelector(
            stringify!($field)
        )];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse obj item (communication object reference)
    (@items obj $name:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::Obj(stringify!($name))];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse objs shorthand for multiple communication objects
    // Example: objs [obj1, obj2, obj3] → three Obj items
    (@items objs [ $($name:ident),* $(,)? ] $($rest:tt)*) => {{
        let mut items = vec![
            $($crate::page_layout::PageItem::Obj(stringify!($name))),*
        ];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse obj_with_value with sub_selectors - for variants that need nested choose
    // Syntax: obj_with_value obj_name by selector_param => value_union with [param1, param2]
    //         sub_select { variant_value => sub_param [ (sub_value, ref_name, variant_name), ... ], ... }
    // The with [...] params are included unconditionally; their visibility is controlled by #[ets(hidden)]
    (@items obj_with_value $obj:ident by $selector:ident => $value:ident with [$($extra:ident),* $(,)?] sub_select { $($variant_val:literal => $sub_param:ident [ $(($sub_val:literal, $ref_name:ident, $var_name:ident)),+ $(,)? ]),+ $(,)? } $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ObjWithValue {
            obj_name: stringify!($obj),
            selector_param: stringify!($selector),
            value_union: stringify!($value),
            extra_params: &[$(stringify!($extra)),*],
            sub_selectors: &[
                $(
                    ($variant_val, stringify!($sub_param), &[$(($sub_val, stringify!($ref_name), stringify!($var_name))),+])
                ),+
            ],
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse obj_with_value with extra params (no sub_selectors)
    // Syntax: obj_with_value obj_name by selector_param => value_union with [param1, param2]
    // The with [...] params are included unconditionally; their visibility is controlled by #[ets(hidden)]
    (@items obj_with_value $obj:ident by $selector:ident => $value:ident with [$($extra:ident),* $(,)?] $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ObjWithValue {
            obj_name: stringify!($obj),
            selector_param: stringify!($selector),
            value_union: stringify!($value),
            extra_params: &[$(stringify!($extra)),*],
            sub_selectors: &[],
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse obj_with_value - basic form without extra params
    // Syntax: obj_with_value obj_name by selector_param => value_union
    (@items obj_with_value $obj:ident by $selector:ident => $value:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ObjWithValue {
            obj_name: stringify!($obj),
            selector_param: stringify!($selector),
            value_union: stringify!($value),
            extra_params: &[],
            sub_selectors: &[],
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse grouped_obj_choose - combines multiple objects under ONE choose block
    // Syntax: grouped_obj_choose selector_param with [hidden1, hidden2] => [(obj1, union1), (obj2, union2)]
    // This creates a single choose block containing all objects, reducing the number of choose elements
    (@items grouped_obj_choose $selector:ident with [$($hidden:ident),* $(,)?] => [$(($obj:ident, $union:ident)),+ $(,)?] $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::GroupedObjChoose {
            selector_param: stringify!($selector),
            hidden_params: &[$(stringify!($hidden)),*],
            objects: &[$((stringify!($obj), stringify!($union))),+],
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse obj_direct - outputs object directly with params (no choose block)
    // Syntax: obj_direct obj_name with [param1, param2]
    // Used in switch mode where object type is fixed
    (@items obj_direct $obj:ident with [$($param:ident),* $(,)?] $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ObjDirect {
            obj_name: stringify!($obj),
            params: &[$(stringify!($param)),*],
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse objs_direct - outputs multiple objects directly with params (no choose block)
    // Syntax: objs_direct [obj1, obj2] with [param1, param2]
    // Used in toggle mode where O-0 and O-1 appear together
    (@items objs_direct [$($obj:ident),+ $(,)?] with [$($param:ident),* $(,)?] $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ObjsDirectWithParams {
            obj_names: &[$(stringify!($obj)),+],
            params: &[$(stringify!($param)),*],
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse objs_by_ref_name - outputs objects by looking up specific ref_names
    // Syntax: objs_by_ref_name ["ref1", "ref2", "ref3"] with [param1, param2]
    // Used when objects have named refs for different modes (e.g., dimming, blinds)
    (@items objs_by_ref_name [$($ref_name:literal),+ $(,)?] with [$($param:ident),* $(,)?] $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ObjsByRefName {
            ref_names: &[$($ref_name),+],
            params: &[$(stringify!($param)),*],
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse obj_fixed_variant with text override - outputs object + hidden params + specific union variant (no choose)
    // Syntax: obj_fixed_variant obj_name with [hidden1, hidden2] => union_field::VariantName @ selector_value text "Custom text"
    // Used in switch mode where object type is fixed (always Switch/1Bit) with custom label
    (@items obj_fixed_variant $obj:ident with [$($hidden:ident),* $(,)?] => $union:ident :: $variant:ident @ $selector_val:literal text $text:literal $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ObjWithFixedVariant {
            obj_name: stringify!($obj),
            hidden_params: &[$(stringify!($hidden)),*],
            union_field: stringify!($union),
            variant_name: stringify!($variant),
            selector_value: $selector_val,
            text_override: Some($text),
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse obj_fixed_variant without text override - outputs object + hidden params + specific union variant (no choose)
    // Syntax: obj_fixed_variant obj_name with [hidden1, hidden2] => union_field::VariantName @ selector_value
    // Used in switch mode where object type is fixed (always Switch/1Bit)
    // The selector_value (e.g., 10) specifies which object ref to use
    (@items obj_fixed_variant $obj:ident with [$($hidden:ident),* $(,)?] => $union:ident :: $variant:ident @ $selector_val:literal $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ObjWithFixedVariant {
            obj_name: stringify!($obj),
            hidden_params: &[$(stringify!($hidden)),*],
            union_field: stringify!($union),
            variant_name: stringify!($variant),
            selector_value: $selector_val,
            text_override: None,
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse union_variant with text override - outputs specific variant's params directly (no choose block)
    // Syntax: union_variant union_field::VariantName text "Custom text"
    // Used when variant is already determined by outer context with custom label
    (@items union_variant $union:ident :: $variant:ident text $text:literal $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::UnionVariantDirect {
            union_field: stringify!($union),
            variant_name: stringify!($variant),
            text_override: Some($text),
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse union_variant without text override - outputs specific variant's params directly (no choose block)
    // Syntax: union_variant union_field::VariantName
    // Used when variant is already determined by outer context (e.g., inside switch mode)
    (@items union_variant $union:ident :: $variant:ident $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::UnionVariantDirect {
            union_field: stringify!($union),
            variant_name: stringify!($variant),
            text_override: None,
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse separator with text (must come before the version without text)
    (@items sep $text:literal $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::Separator(Some($text))];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse separator without text
    (@items sep $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::Separator(None)];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse module instance with inline arguments
    // Syntax: module ModuleName { ArgName: value, ArgName2: value2, ... }
    // Example: module DimmerChannel { ParamBase: 5, ObjBase: 0, ChNo: 1 }
    // This creates a ModuleInline PageItem with the specified argument values.
    // The module definition must be registered in the ModuleCollection.
    // Compile-time validation ensures all argument names match the module's ARGUMENTS definition.
    // Values can be expressions (e.g., DeviceParams::channel_param_offset(1)).
    (@items module $module_name:ident { $($arg_name:ident : $arg_value:expr),* $(,)? } $($rest:tt)*) => {{
        // Compile-time validation: check argument names match module definition
        const _: () = $crate::module::validate_module_args(
            <$module_name as $crate::module::KnxModule>::ARGUMENTS,
            &[$(stringify!($arg_name)),*]
        );
        let mut items = vec![$crate::page_layout::PageItem::ModuleInline {
            module_name: <$module_name as $crate::module::KnxModule>::NAME,
            args: vec![
                $((stringify!($arg_name), $arg_value as i64)),*
            ],
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse raw PageItem expression
    // Syntax: raw <expression>
    // Example: raw module_instances::<DimmerChannelModule, DeviceParams>("enable_ch")
    // This allows passing any expression that evaluates to a PageItem.
    // Useful for computed items like multi-channel module instances.
    (@items raw $item_expr:expr) => {{
        vec![$item_expr]
    }};
    (@items raw $item_expr:expr, $($rest:tt)*) => {{
        let mut items = vec![$item_expr];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse when item with @ prefix (conditional within a block) - for regular parameters
    // The @ prefix means use the parameter name directly without appending _selector
    // Example: when @button1_function { ... } → selector = "button1_function"
    (@items when @ $param:ident { $($cases:tt)* } $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::When(
            $crate::page_layout::ConditionalItem {
                selector: stringify!($param),
                cases: $crate::ets_pages!(@item_cases $($cases)*),
            }
        )];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse when item (conditional within a block) - for union selectors
    // The selector is the union field name - we append _selector automatically
    // Example: when channel_a_config { ... } → selector = "channel_a_config_selector"
    (@items when $selector:ident { $($cases:tt)* } $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::When(
            $crate::page_layout::ConditionalItem {
                selector: concat!(stringify!($selector), "_selector"),
                cases: $crate::ets_pages!(@item_cases $($cases)*),
            }
        )];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse when_union_variant with text override - outputs union variant param FIRST, then choose block
    // Syntax: when_union_variant union_field::VariantName text "Label" { [values] => { ... } }
    // This matches MDT's pattern: output ParameterRefRef, then choose ParamRefId referencing it
    (@items when_union_variant $union:ident :: $variant:ident text $text:literal { $($cases:tt)* } $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::UnionVariantWithChoose {
            union_field: stringify!($union),
            variant_name: stringify!($variant),
            text_override: Some($text),
            cases: $crate::ets_pages!(@item_cases $($cases)*),
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse when_union_variant without text override - outputs union variant param FIRST, then choose block
    // Syntax: when_union_variant union_field::VariantName { [values] => { ... } }
    (@items when_union_variant $union:ident :: $variant:ident { $($cases:tt)* } $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::UnionVariantWithChoose {
            union_field: stringify!($union),
            variant_name: stringify!($variant),
            text_override: None,
            cases: $crate::ets_pages!(@item_cases $($cases)*),
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse choose_on_union_variant - creates a choose block referencing an already-output union variant param
    // Use union_variant first to output the param, then this to create choose blocks
    // Syntax: choose_on_union_variant union_field::VariantName { [values] => { ... } }
    (@items choose_on_union_variant $union:ident :: $variant:ident { $($cases:tt)* } $($rest:tt)*) => {{
        let mut items = vec![$crate::page_layout::PageItem::ChooseOnUnionVariant {
            union_field: stringify!($union),
            variant_name: stringify!($variant),
            cases: $crate::ets_pages!(@item_cases $($cases)*),
        }];
        items.extend($crate::ets_pages!(@items $($rest)*));
        items
    }};

    // Parse item cases (for when at item level) - base case
    (@item_cases) => {
        vec![]
    };

    // Parse item case with enum path expressions (e.g., EnumType::Variant)
    // Must come before the simple ident rule to match first
    (@item_cases [$($enum_type:ident :: $variant:ident),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::page_layout::ItemCase {
            condition: $crate::page_layout::Condition::values(&[
                $($enum_type::$variant as i64),+
            ]),
            items: $crate::ets_pages!(@items $($content)*),
        }];
        cases.extend($crate::ets_pages!(@item_cases $($rest)*));
        cases
    }};

    // Parse item case with simple enum variants (cast directly to i64 since they're repr(isize))
    (@item_cases [$($variant:ident),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::page_layout::ItemCase {
            condition: $crate::page_layout::Condition::values(&[
                $($variant as i64),+
            ]),
            items: $crate::ets_pages!(@items $($content)*),
        }];
        cases.extend($crate::ets_pages!(@item_cases $($rest)*));
        cases
    }};

    // Parse item case with integer literals
    (@item_cases [$($val:literal),+ $(,)?] => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::page_layout::ItemCase {
            condition: $crate::page_layout::Condition::values(&[$($val as i64),+]),
            items: $crate::ets_pages!(@items $($content)*),
        }];
        cases.extend($crate::ets_pages!(@item_cases $($rest)*));
        cases
    }};

    // Parse item case with default (_)
    (@item_cases _ => { $($content:tt)* } $($rest:tt)*) => {{
        let mut cases = vec![$crate::page_layout::ItemCase {
            condition: $crate::page_layout::Condition::Default,
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
            // selector channel_config → UnionSelector("channel_config")
            assert!(matches!(block.items[0], PageItem::UnionSelector("channel_config")));
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
