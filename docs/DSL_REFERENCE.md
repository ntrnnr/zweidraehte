# KNX Product Definition DSL Reference

This document provides a comprehensive reference for the DSL (Domain Specific Language) used to define KNX device parameters, communication objects, and ETS page layouts.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [EtsParams - Parameter Definitions](#etsparams---parameter-definitions)
4. [ets_range_enum! - Numeric Range Enums](#ets_range_enum---numeric-range-enums)
5. [EtsEnum - Simple Enumerations](#etsenum---simple-enumerations)
6. [EtsUnion - Tagged Unions](#etsunion---tagged-unions)
7. [EtsComObjects - Communication Objects](#etscomobjects---communication-objects)
8. [ets_pages! - Page Layout Macro](#ets_pages---page-layout-macro)
9. [Complete Example](#complete-example)
10. [Common Patterns](#common-patterns)
11. [Troubleshooting](#troubleshooting)
12. [Firmware Code Access Patterns](#firmware-code-access-patterns)
13. [Migration Guide](#migration-guide)

---

## Overview

The KNX Product Definition DSL generates ETS MTXML files from Rust code. This allows you to:

- Define device parameters with type safety
- Create communication objects with multiple DPT support
- Build dynamic parameter pages with conditional visibility
- Generate XML files that work with the ETS software

The DSL consists of derive macros and a declarative macro:

| Component | Purpose |
|-----------|---------|
| `#[derive(EtsParams)]` | Define device parameters |
| `#[derive(EtsEnum)]` | Define simple enumerations for dropdowns |
| `#[derive(EtsUnion)]` | Define tagged unions for variant parameters |
| `#[derive(EtsComObjects)]` | Define communication objects |
| `ets_pages!` | Define the ETS parameter page layout |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Rust Source Code                            │
├─────────────────────────────────────────────────────────────────┤
│  EtsParams Struct    │  EtsEnum/EtsUnion  │  EtsComObjects     │
│  (device parameters) │  (enum types)       │  (group objects)   │
└──────────┬───────────┴─────────┬───────────┴─────────┬──────────┘
           │                     │                     │
           ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Derive Macros (ets-macros)                   │
│  Generates: ETS_PARAMS, ETS_VARIANTS, ETS_UNION_INFO,          │
│             ETS_COMM_OBJECTS, Index enum                        │
└──────────┬───────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ets_pages! Macro                             │
│  Defines: Page structure, blocks, conditionals                  │
└──────────┬───────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MtxmlGenerator (knxprod)                     │
│  Produces: ApplicationProgram.mtxml, Hardware.mtxml, etc.       │
└─────────────────────────────────────────────────────────────────┘
```

---

## EtsParams - Parameter Definitions

Use `#[derive(EtsParams)]` on a struct to define device parameters.

### Basic Usage

```rust
#[derive(Debug, Clone, Copy, EtsParams)]
#[repr(C)]  // Required for predictable memory layout
pub struct MyDeviceParams {
    /// Simple numeric parameter
    #[ets(display = "Startup Timeout", suffix = "s", default = 2)]
    pub startup_timeout: u8,

    /// Parameter with enum dropdown
    #[ets(display = "Send Mode", enum_variants("cyclic" => 0, "on change" => 1))]
    pub send_mode: u8,

    /// Hidden parameter (not shown in ETS)
    #[ets(display = "Internal Counter", hidden)]
    pub internal_counter: u16,

    /// Union field for variant parameters
    #[ets(display = "Output Config", union)]
    pub output_config: OutputConfigUnion,
}
```

#### Auto-generated Defaults

`#[derive(EtsParams)]` automatically generates `Default` and `ConstDefault` implementations from your field defaults:

```rust
#[derive(EtsParams)]
#[repr(C)]
pub struct MyParams {
    #[ets(display = "Timeout", default = 100)]
    pub timeout: u16,

    #[ets(display = "Mode", ets_enum)]  // Uses enum's ConstDefault
    pub mode: MyMode,
}
// Default and ConstDefault are generated automatically!
```

The macro generates defaults as follows:
- Fields with `#[ets(default = N)]` use that value
- Fields with `ets_enum` or `union` use their type's `ConstDefault::DEFAULT`
- Primitive fields without defaults use zero (`0`, `false`, `[0u8; N]`)

### Field Attributes

| Attribute | Description | Example |
|-----------|-------------|---------|
| `display = "..."` | Human-readable name in ETS | `display = "Reaction Time"` |
| `suffix = "..."` | Unit suffix shown after value | `suffix = "ms"` |
| `default = N` | Default value | `default = 100` |
| `enum_variants(...)` | Inline dropdown options | `enum_variants("off" => 0, "on" => 1)` |
| `ets_enum` | Simple enum dropdown | Use with `#[derive(EtsEnum)]` types |
| `union` | Discriminated union field | Use with `#[derive(EtsUnion)]` types |
| `hidden` | Hide from ETS UI | For internal parameters |
| `bits = N` | Override bit size | `bits = 4` for nibble |
| `bit_offset = N` | Bit offset within byte | `bit_offset = 4` |
| `type_name = "..."` | Override ETS type name | `type_name = "MyCustomType"` |
| `skip` | Exclude from ETS output | For padding fields |
| `string` | Treat `[u8; N]` as text | For text parameters |

### Supported Field Types

| Rust Type | ETS Type | Size |
|-----------|----------|------|
| `u8` | Unsigned 8-bit | 1 byte |
| `u16` | Unsigned 16-bit | 2 bytes |
| `u32` | Unsigned 32-bit | 4 bytes |
| `i8` | Signed 8-bit | 1 byte |
| `i16` | Signed 16-bit | 2 bytes |
| `i32` | Signed 32-bit | 4 bytes |
| `bool` | Boolean | 1 byte |
| `[u8; N]` | Array / String | N bytes |
| Enum types | Via `ets_enum` | Depends on repr |

### `ets_enum` vs `union` - What's the Difference?

Both mark fields with custom types, but they serve different purposes:

| Aspect | `ets_enum` | `union` |
|--------|-----------|---------|
| **Type** | Simple enum (`#[derive(EtsEnum)]`) | Discriminated union (`#[derive(EtsUnion)]`) |
| **Parameters** | Single parameter with dropdown | Selector param + variant-specific params |
| **Memory** | Just the enum value (1 byte) | Discriminant + largest variant data |
| **Use Case** | Fixed choices (On/Off, RGB/HSV) | Dynamic structure (different fields per mode) |

**Simple enum (`ets_enum`)** - for dropdowns where you just pick a value:
```rust
#[ets(display = "Colour Mode", ets_enum)]
pub colour_mode: ColourControl,  // Just stores 1 (RGB) or 2 (HSV)
```

**Union (`union`)** - for variant data structures where different modes have different parameters:
```rust
#[ets(display = "Output Value", union)]
pub output_value: ValueUnion,  // Stores discriminant + value (Switch has 1-bit, Percent has 1-byte, etc.)
```

**Why explicit markers?** The proc macro runs before type checking, so it can't determine whether a field type implements `EtsEnum` or `EtsUnion`. The attribute tells it which code to generate.

### Using Enum Types in EtsParams

When your field type is an `EtsEnum`, use the `ets_enum` attribute:

```rust
#[derive(EtsParams)]
pub struct Params {
    // Use the enum's ETS_VARIANTS for the dropdown
    #[ets(display = "Enable Feature", ets_enum)]
    pub feature_enable: EnableDisable,
}

#[derive(EtsEnum, Default)]
#[repr(u8)]
pub enum EnableDisable {
    #[default]
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "active")]
    Active = 1,
}
```

**Important**: Only use `ets_enum` with enums that have a variant with value 0, as `MdtParams` uses `zeroed()` initialization.

---

## ets_range_enum! - Numeric Range Enums

Use `ets_range_enum!` to generate enums with sequential numeric values, like scene numbers (1-64) or percentages (0-100%).

### Basic Usage

```rust
// Scene numbers: values 0-63, display "1" through "64"
ets_range_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[ets(type_name = "SceneValue")]
    pub enum SceneValue {
        range 0..64 => "Scene{}";
        default = 0;
    }
}

// Percentages: values use formula round(percent * 2.55)
ets_range_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[ets(type_name = "select0to100percent")]
    pub enum Select0to100Percent {
        range 0..=100 => percent_to_byte "P{}%";
        default = 0;
    }
}
```

### Syntax

```
ets_range_enum! {
    #[derive(...)]
    #[ets(type_name = "TypeName")]
    pub enum EnumName {
        range START..END => [formula] "Prefix{}Suffix";
        default = DEFAULT_INDEX;
    }
}
```

| Element | Description |
|---------|-------------|
| `range START..END` | Exclusive range (0..64 = 0 to 63) |
| `range START..=END` | Inclusive range (0..=100 = 0 to 100) |
| `formula` | Optional: `percent_to_byte` for value = round(index * 2.55) |
| `"Prefix{}Suffix"` | Pattern for variant names and display text |
| `default = N` | Index of the default variant |

### What Gets Generated

- Enum with variants (e.g., `Scene1 = 0`, `Scene2 = 1`, ...)
- `ETS_VARIANTS: &'static [EtsEnumVariant]`
- `ETS_SIZE_BITS: u8`
- `ETS_TYPE_NAME: &'static str`
- `impl Default`
- `impl ConstDefault`

---

## EtsEnum - Simple Enumerations

Use `#[derive(EtsEnum)]` for simple enums that appear as dropdowns in ETS.

### Basic Usage

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Default)]
#[repr(u8)]  // Required: must have a primitive repr
pub enum SendMode {
    #[default]
    #[ets(display = "cyclic")]
    Cyclic = 0,
    #[ets(display = "on change")]
    OnChange = 1,
    #[ets(display = "on request")]
    OnRequest = 2,
}
```

### What Gets Generated

The macro generates:

```rust
impl SendMode {
    pub const ETS_VARIANTS: &'static [EtsEnumVariant] = &[
        EtsEnumVariant { text: "cyclic", value: 0 },
        EtsEnumVariant { text: "on change", value: 1 },
        EtsEnumVariant { text: "on request", value: 2 },
    ];
    pub const ETS_SIZE_BITS: u8 = 8;
}

// Auto-generated from #[default] attribute
impl ConstDefault for SendMode {
    const DEFAULT: Self = Self::Cyclic;
}
```

### Variant Attributes

| Attribute | Description |
|-----------|-------------|
| `display = "..."` | Text shown in ETS dropdown |
| `#[default]` | Marks the default variant (also generates `ConstDefault`) |

---

## EtsUnion - Tagged Unions

Use `#[derive(EtsUnion)]` for parameters that have different fields depending on a mode selector.

### Basic Usage

```rust
#[derive(Debug, Clone, Copy, EtsUnion)]
#[repr(C, u8)]  // Required: C layout with u8 discriminant
pub enum OutputConfigUnion {
    #[ets(display = "Switch")]
    Switch {
        #[ets(display = "Invert Output")]
        invert: bool,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 0,

    #[ets(display = "Dimmer")]
    Dimmer {
        #[ets(display = "Min Level", suffix = "%")]
        min_level: u8,
        #[ets(display = "Max Level", suffix = "%")]
        max_level: u8,
        #[ets(skip)]
        _pad: [u8; 2],
    } = 1,

    #[ets(display = "Scene")]
    Scene {
        #[ets(display = "Scene Number", ets_enum)]
        scene: SceneValue,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 2,
}
```

### What Gets Generated

```rust
impl OutputConfigUnion {
    pub const ETS_UNION_INFO: EtsUnionInfo = /* variant info */;
    pub const ETS_SELECTOR_VARIANTS: &'static [EtsEnumVariant] = &[
        EtsEnumVariant { text: "Switch", value: 0 },
        EtsEnumVariant { text: "Dimmer", value: 1 },
        EtsEnumVariant { text: "Scene", value: 2 },
    ];
}

// Discriminant enum for type-safe access
pub enum OutputConfigUnionDiscriminant {
    Switch = 0,
    Dimmer = 1,
    Scene = 2,
}
```

### Auto-Generated Default Implementation

Mark a variant with `#[ets(default_variant)]` to auto-generate `Default` and `ConstDefault` implementations:

```rust
#[derive(Debug, Clone, Copy, EtsUnion)]
#[repr(C, u8)]
pub enum OutputConfigUnion {
    #[ets(default_variant, display = "Switch")]  // <-- This variant is the default
    Switch {
        #[ets(display = "Invert Output")]
        invert: bool,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 0,

    #[ets(display = "Dimmer")]
    Dimmer {
        #[ets(display = "Min Level", suffix = "%")]
        min_level: u8,
        // ...
    } = 1,
}

// Generated automatically:
impl Default for OutputConfigUnion {
    fn default() -> Self {
        Self::Switch { invert: false, _pad: [0; 3] }
    }
}

impl ConstDefault for OutputConfigUnion {
    const DEFAULT: Self = Self::Switch { invert: false, _pad: [0; 3] };
}
```

Note: Fields starting with `_` (like `_pad`) are zero-initialized. Other fields use `ConstDefault::DEFAULT`.

### Padding Requirements

All union variants must have the same total size. Add `_pad` fields to ensure this:

```rust
#[ets(display = "Mode A")]
ModeA {
    value: u8,       // 1 byte
    #[ets(skip)]
    _pad: [u8; 3],   // 3 bytes padding
} = 0,               // Total: 4 bytes

#[ets(display = "Mode B")]
ModeB {
    value: u32,      // 4 bytes
                     // No padding needed
} = 1,               // Total: 4 bytes
```

---

## EtsComObjects - Communication Objects

Use `#[derive(EtsComObjects)]` to define communication objects (group objects).

### Basic Usage

```rust
#[derive(Debug, EtsComObjects)]
pub struct MyComObjects {
    /// Simple switch object
    #[ets_ref(dpt = DPT_Switch, text = "Switch Output", function = "Switching")]
    pub switch_output: ComObject<ComObjectStorage<1>>,

    /// Object with multiple DPT types based on selector
    #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "Value Output", function = "Switch")]
    #[ets_ref(dpt = DPT_Value_1_Ucount, when = ObjectType::Percent, text = "Value Output", function = "Value")]
    #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "Value Output", function = "Scene")]
    #[ets(selector_enum = "ObjectType")]
    pub value_output: ComObject<ComObjectStorage<4>>,
}
```

### Object Attributes

| Attribute | Description |
|-----------|-------------|
| `#[ets_ref(...)]` | Define a communication object reference |
| `#[ets(selector_enum = "...")]` | Enum for multi-DPT selection |
| `#[ets(index = N)]` | Override object index |

### `#[ets_ref]` Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `dpt = DPT_xxx` | Data Point Type | `dpt = DPT_Switch` |
| `text = "..."` | Display text (supports `{{param}}` interpolation) | `text = "{{button_name}}: Switch"` |
| `function = "..."` | Function text | `function = "Switching"` |
| `when = EnumVariant` | Condition for multi-DPT objects | `when = ObjectType::Switch` |
| `flags = "..."` | Object flags (C/R/W/T/U) | `flags = "CRT"` |

### Text Interpolation

Use `{{param_name}}` or `{{param_name:default}}` for dynamic text:

```rust
#[ets_ref(dpt = DPT_Switch, text = "{{channel_name:Channel 1}}: Switch")]
```

---

## ets_pages! - Page Layout Macro

The `ets_pages!` macro defines how parameters appear in the ETS configuration UI.

### Structure Overview

```rust
impl EtsPageLayout for MyDevice {
    fn page_layout() -> PageStructure {
        ets_pages! {
            device {
                // Device-wide settings (ChannelIndependentBlock)
                block "general" => "General Settings" {
                    param startup_timeout
                    param send_mode
                }
            }

            channel "ch1" => "Channel 1" (0) {
                // Channel-specific settings
                block "output" => "Output Configuration" {
                    selector output_config
                    when output_config {
                        [Switch] => { param output_config::Switch.invert }
                        [Dimmer] => {
                            param output_config::Dimmer.min_level
                            param output_config::Dimmer.max_level
                        }
                    }
                }
            }
        }
    }
}
```

### Keyword Reference

#### Structure Keywords

| Keyword | Purpose | Syntax |
|---------|---------|--------|
| `device { }` | Device-wide settings block | `device { <elements> }` |
| `channel "id" => "Name" (N) { }` | Channel tab | `channel "ch1" => "Channel 1" (0) { <elements> }` |
| `block "id" => "Name" { }` | Collapsible parameter section | `block "general" => "General" { <items> }` |

#### Parameter Keywords

| Keyword | Purpose | XML Output |
|---------|---------|------------|
| `param name` | Simple parameter reference | `<ParameterRefRef />` |
| `param union::Variant.field` | Union field parameter | `<ParameterRefRef />` (with computed name) |
| `selector union_field` | Union selector (shows selector + choose/when) | Selector param + choose block |

#### Object Keywords

| Keyword | Purpose | Syntax |
|---------|---------|--------|
| `obj name` | Simple object reference | `obj switch_output` |
| `obj_direct obj [params]` | Object with fixed type, no choose | `obj_direct switch_out with [param1]` |
| `objs_direct [objs] [params]` | Multiple objects, no choose | `objs_direct [obj1, obj2] with [param1]` |
| `objs_by_ref_name ["refs"] [params]` | Objects by named ref lookup | `objs_by_ref_name ["dimming", "blinds"] with []` |

#### Value Object Keywords

| Keyword | Purpose | Syntax |
|---------|---------|--------|
| `obj_with_value obj by param => union` | Object + value with selector | `obj_with_value value_out by obj_type => ValueUnion` |
| `obj_with_value ... with [extras]` | + extra unconditional params | `obj_with_value ... with [param1, param2]` |
| `obj_with_value ... with [...] sub_select { }` | + nested sub-selectors | For RGB/HSV style nesting |
| `obj_fixed_variant obj [hidden] => U::V @ sel` | Fixed variant, no choose | `obj_fixed_variant out with [] => Val::Switch @ 10` |
| `grouped_obj_choose param [hidden] => [(o,u)]` | Multiple objects, one choose | For grouped object output |

#### Union Variant Keywords

| Keyword | Purpose | Syntax |
|---------|---------|--------|
| `union_variant U::V` | Output variant param only | `union_variant ValueUnion::Switch` |
| `union_variant U::V text "Label"` | With custom label | `union_variant ValueUnion::Switch text "Value"` |
| `when_union_variant U::V { }` | Param + choose block | `when_union_variant Val::Percent { [0,1] => { } }` |
| `choose_on_union_variant U::V { }` | Choose block only (param exists) | For nested conditionals |

#### Conditional Keywords

| Keyword | Purpose | Syntax |
|---------|---------|--------|
| `when union_field { }` | Conditional on union selector | Auto-appends `_selector` |
| `when @param_name { }` | Conditional on regular param | Uses name directly |

**Why the `@` prefix?**

Union fields have an implicit `_selector` parameter that stores the discriminant. When you write:
```rust
when button_value { ... }  // No @
```
The macro generates `ParamRefId="button_value_selector"` (appends `_selector`).

For regular parameters (non-union fields), use `@` to use the name as-is:
```rust
when @button_function { ... }  // With @
```
The macro generates `ParamRefId="button_function"` (no suffix).

**Why can't we auto-detect?** The macro runs before type checking, so it doesn't know whether `button_value` is a union field or a regular parameter. The `@` prefix is explicit disambiguation.

#### Condition Syntax

Conditions in `when` blocks can use either integer literals or enum variants:

```rust
// Using integer literals (matches discriminant values)
when @button_function {
    [0] => { /* function = 0 */ }
    [1, 2] => { /* function = 1 or 2 */ }
    _ => { /* default */ }
}

// Using enum variants (preferred - more readable!)
// The variant is cast to i64 at compile time
when @button_function {
    [ButtonFunction::Switch] => { /* Switch = 0 */ }
    [ButtonFunction::Toggle, ButtonFunction::Dimmer] => { /* Toggle or Dimmer */ }
    _ => { /* default */ }
}
```

**Why prefer enum variants?**
- Self-documenting: `[ButtonFunction::Switch]` is clearer than `[0]`
- Type-safe: Compiler catches typos in variant names
- Refactor-friendly: If enum values change, the code still works

**How it works internally:**
The macro expands `[Variant]` to `[Variant as i64]`, so both forms generate identical XML:
```xml
<choose ParamRefId="button_function">
  <when test="0">...</when>
</choose>
```

**Important:** The enum must be in scope where `ets_pages!` is invoked. Import it at the top of your page layout definition.

#### Utility Keywords

| Keyword | Purpose | Syntax |
|---------|---------|--------|
| `sep` | Visual separator | `sep` |
| `sep "text"` | Separator with label | `sep "Advanced Settings"` |

---

## Complete Example

```rust
use knxprod::page_layout::{EtsPageLayout, PageStructure};
use ets_macros::{EtsParams, EtsEnum, EtsUnion, EtsComObjects};

// Simple enum for dropdowns
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Default)]
#[repr(u8)]
pub enum EnableDisable {
    #[default]
    #[ets(display = "not active")]
    NotActive = 0,
    #[ets(display = "active")]
    Active = 1,
}

// Union for variant parameters
#[derive(Debug, Clone, Copy, EtsUnion)]
#[repr(C, u8)]
pub enum OutputModeUnion {
    #[ets(display = "Switch")]
    Switch {
        #[ets(display = "Value", ets_enum)]
        value: EnableDisable,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 0,

    #[ets(display = "Dimmer")]
    Dimmer {
        #[ets(display = "Level", suffix = "%")]
        level: u8,
        #[ets(skip)]
        _pad: [u8; 3],
    } = 1,
}

// Device parameters
#[derive(Debug, Clone, Copy, EtsParams)]
#[repr(C)]
pub struct DeviceParams {
    #[ets(display = "Startup Delay", suffix = "s", default = 2)]
    pub startup_delay: u8,

    #[ets(display = "Output Mode", union)]
    pub output_mode: OutputModeUnion,

    #[ets(display = "Blocking", ets_enum)]
    pub blocking_enable: EnableDisable,
}

// Communication objects
#[derive(Debug, EtsComObjects)]
pub struct DeviceObjects {
    #[ets_ref(dpt = DPT_Switch, text = "Main Output", function = "Switching")]
    pub main_output: ComObject<ComObjectStorage<1>>,
}

// Page layout
impl EtsPageLayout for DeviceParams {
    fn page_layout() -> PageStructure {
        ets_pages! {
            device {
                block "general" => "General Settings" {
                    param startup_delay
                    param blocking_enable
                }

                block "output" => "Output Configuration" {
                    selector output_mode
                    when output_mode {
                        [Switch] => {
                            param output_mode::Switch.value
                        }
                        [Dimmer] => {
                            param output_mode::Dimmer.level
                        }
                    }
                }
            }
        }
    }
}
```

---

## Common Patterns

### Pattern 1: Simple Parameter with Dropdown

```rust
// Inline enum variants
#[ets(display = "Mode", enum_variants("auto" => 0, "manual" => 1))]
pub mode: u8,

// Or use a separate enum
#[ets(display = "Mode", ets_enum)]
pub mode: ModeEnum,
```

### Pattern 2: Conditional Parameter Blocks

```rust
// Use @ prefix for regular parameters (not union selectors)
when @button_function {
    [0] => {  // Switch mode
        block "switch" => "Switch Settings" {
            param switch_type
        }
    }
    [1] => {  // Dimmer mode
        block "dimmer" => "Dimmer Settings" {
            param dimmer_speed
        }
    }
}

// For union selectors, omit @ (auto-appends _selector)
when output_mode {
    [Switch] => { param output_mode::Switch.value }
    [Dimmer] => { param output_mode::Dimmer.level }
}
```

### Pattern 3: Object with Type Selector (Dynamic DPT)

**Use Case:** A communication object whose data type (DPT) depends on a user-selected parameter.

**Syntax:**
```rust
// Basic form (object + value only):
obj_with_value main_obj by object_type => value_union

// With extra params (output unconditionally in each when block):
obj_with_value main_obj by object_type => value_union with [extra_param1, extra_param2]
```

The `with [...]` clause is optional. When present, the listed params are included unconditionally in each `<when>` block. Whether these params are visible or hidden in the ETS UI is controlled by `#[ets(hidden)]` on the parameter definition itself, not by this syntax.

**Complete Example:**

Given these definitions:
```rust
// Parameter: user picks the DPT (Switch=0, Percent=2, Scene=4)
#[ets(display = "Object Type", ets_enum)]
pub object_type: ObjectType,

// Union: stores the value for whichever DPT is selected
#[ets(display = "Value", union)]
pub value_union: ValueUnion,

// Extra param: internal state (hidden in ETS UI via #[ets(hidden)])
#[ets(display = "Value Type", hidden)]
pub value_type: u8,
```

And this page layout:
```rust
block "output" => "Output Settings" {
    param object_type
    obj_with_value main_obj by object_type => value_union with [value_type]
}
```

**Generated XML:**
```xml
<!-- Choose block for object + value based on selector -->
<choose ParamRefId="P-object_type">
  <when test="0">  <!-- ObjectType::Switch -->
    <ComObjectRefRef RefId="O-main_obj_switch" />
    <ParameterRefRef RefId="P-value_type" />
    <ParameterRefRef RefId="P-value_union.Switch.value" />
  </when>
  <when test="2">  <!-- ObjectType::Percent -->
    <ComObjectRefRef RefId="O-main_obj_percent" />
    <ParameterRefRef RefId="P-value_type" />
    <ParameterRefRef RefId="P-value_union.Percent.value" />
  </when>
  <when test="4">  <!-- ObjectType::Scene -->
    <ComObjectRefRef RefId="O-main_obj_scene" />
    <ParameterRefRef RefId="P-value_type" />
    <ParameterRefRef RefId="P-value_union.Scene.value" />
  </when>
</choose>
```

**Without extra params:**
```rust
obj_with_value main_obj by object_type => value_union
```
Generates the same `<choose>` block but without the `<ParameterRefRef RefId="P-value_type" />` lines.

### Pattern 4: Fixed Variant Output (No Choose)

**Use Case:** When the object type is known at design time (not user-selectable). Outputs the object directly without a `<choose>` block.

**Syntax:**
```rust
obj_fixed_variant <object> with [<extra_params>] => <union_field>::<Variant> @ <discriminant> text "<label>"
```

**Complete Example:**

Given the same definitions as Pattern 3 (ObjectType enum, ValueUnion, etc.):

```rust
// In a context where we KNOW the type is always Switch (no user choice)
when @switch_mode {
    [0] => {
        // Output Switch object directly - no choose block needed
        obj_fixed_variant main_obj with [value_type] => value_union::Switch @ 0 text "Switch Value"
    }
    [1] => {
        // User can pick type - use Pattern 3
        obj_with_value main_obj by object_type => value_union with [value_type]
    }
}
```

**Generated XML** (for the `[0]` case):
```xml
<!-- No <choose> - direct output -->
<ComObjectRefRef RefId="O-main_obj_switch" />
<ParameterRefRef RefId="P-value_type" />
<ParameterRefRef RefId="P-value_union.Switch.value" Text="Switch Value" />
```

**Components:**
- `main_obj` - The communication object field name
- `with [value_type]` - Extra parameters to output alongside
- `value_union::Switch` - The specific union variant
- `@ 0` - The discriminant value (must match `Switch = 0`)
- `text "Switch Value"` - Label shown in ETS for the value parameter

### Pattern 5: Nested Conditionals (Sub-Selection)

**Use Case:** When a specific DPT variant has additional sub-options. For example, a "3-Byte Colour" type might use either RGB or HSV encoding - you need a nested choose.

**Syntax:**
```rust
obj_with_value <object> by <main_selector> => <union_field> with [<extra>] sub_select {
    <variant_value> => <sub_selector_param> [(<sub_val>, <obj_ref_suffix>, <UnionVariant>), ...]
}
```

**Complete Example:**

Given these definitions:
```rust
// Main selector: which DPT? (Switch=0, Percent=2, Colour=9)
#[ets(display = "Object Type", ets_enum)]
pub object_type: ObjectType,

// Sub-selector: for Colour type, RGB or HSV? (RGB=1, HSV=2)
#[ets(display = "Colour Mode", ets_enum)]
pub colour_mode: ColourMode,

// Union with variants including Rgb and Hsv
#[ets(display = "Value", union)]
pub value_union: ValueUnion,  // Has Switch, Percent, Rgb, Hsv variants
```

And this page layout:
```rust
block "output" => "Output Settings" {
    param object_type
    param colour_mode  // Only shown/relevant when object_type = Colour

    obj_with_value main_obj by object_type => value_union with [value_type] sub_select {
        // For variant 9 (Colour), add nested selection on colour_mode:
        // colour_mode=1 → use "main_obj_rgb" object ref + Rgb union variant
        // colour_mode=2 → use "main_obj_hsv" object ref + Hsv union variant
        9 => colour_mode [(1, main_obj_rgb, Rgb), (2, main_obj_hsv, Hsv)]
    }
}
```

**Generated XML:**
```xml
<ParameterRefRef RefId="P-value_type" />

<choose ParamRefId="P-object_type">
  <when test="0">  <!-- Switch - no sub-select needed -->
    <ComObjectRefRef RefId="O-main_obj_switch" />
    <ParameterRefRef RefId="P-value_union.Switch.value" />
  </when>
  <when test="2">  <!-- Percent - no sub-select needed -->
    <ComObjectRefRef RefId="O-main_obj_percent" />
    <ParameterRefRef RefId="P-value_union.Percent.value" />
  </when>
  <when test="9">  <!-- Colour - has sub-select! -->
    <choose ParamRefId="P-colour_mode">
      <when test="1">  <!-- RGB -->
        <ComObjectRefRef RefId="O-main_obj_rgb" />
        <ParameterRefRef RefId="P-value_union.Rgb.value" />
      </when>
      <when test="2">  <!-- HSV -->
        <ComObjectRefRef RefId="O-main_obj_hsv" />
        <ParameterRefRef RefId="P-value_union.Hsv.value" />
      </when>
    </choose>
  </when>
</choose>
```

**How it works:**
1. Main selector (`object_type`) determines the primary DPT
2. Most variants (Switch, Percent) work like Pattern 3 - simple choose
3. For variant 9 (Colour), the `sub_select` adds a nested choose on `colour_mode`
4. The tuple `(1, main_obj_rgb, Rgb)` means: when `colour_mode=1`, use object ref suffix `_rgb` and union variant `Rgb`

**When to Use Each Pattern:**

| Scenario | Pattern |
|----------|---------|
| User picks DPT from dropdown | Pattern 3 (`obj_with_value`) |
| DPT is fixed/known at design | Pattern 4 (`obj_fixed_variant`) |
| User picks DPT AND sub-option (RGB/HSV) | Pattern 5 (`sub_select`) |

---

## Troubleshooting

### Error: "Unsupported type 'EnumName'"

The `ets_enum` attribute is missing. Add it:
```rust
#[ets(display = "...", ets_enum)]
pub field: EnumName,
```

### Error: "conflicting implementations of trait ConstDefault"

This happens when `#[derive(EtsEnum)]` auto-generates `ConstDefault` but you also have a manual impl. Remove the manual impl.

### Error: "attempted to zero-initialize type"

Enums without a 0 value can't be used as field types in structs that use `zeroed()` initialization. Either:
1. Add a variant with value 0, or
2. Keep the field as `u8` with `enum_variants(...)`

### Parameter not showing in ETS

Check:
1. Is it marked `hidden`?
2. Is it inside a `when` block with a condition that doesn't match?
3. Is the page layout correctly referencing it?

### Object references not working

Ensure:
1. The object name matches the field name in `EtsComObjects`
2. For multi-DPT objects, the `when` conditions match the selector values
3. The `selector_enum` matches the actual enum used

---

## Firmware Code Access Patterns

This section documents how to access parameters and communication objects in your device firmware code. The DSL generates not only ETS XML but also Rust types and constants that you use at runtime.

### Accessing Simple Parameters

Parameters are stored in a `#[repr(C)]` struct that you can read directly:

```rust
// In your device code
fn handle_startup(params: &DeviceParams) {
    // Direct field access for primitives
    let delay_seconds = params.startup_delay;

    // Enum fields work the same way
    if params.blocking_enable == EnableDisable::Active {
        enable_blocking();
    }

    // Numeric fields with inline enum_variants are just integers
    match params.send_mode {
        0 => setup_cyclic_send(),
        1 => setup_on_change_send(),
        _ => {}
    }
}
```

### Accessing Enum Parameters

Enums marked with `#[derive(EtsEnum)]` can be used directly:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, EtsEnum, Default)]
#[repr(u8)]
pub enum SendMode {
    #[default]
    Cyclic = 0,
    OnChange = 1,
    OnRequest = 2,
}

// In your code - direct pattern matching
fn configure_send(params: &DeviceParams) {
    match params.send_mode {
        SendMode::Cyclic => {
            start_timer(params.cyclic_interval);
        }
        SendMode::OnChange => {
            register_change_callback();
        }
        SendMode::OnRequest => {
            // Wait for external trigger
        }
    }
}

// Convert from raw value (e.g., when loading from memory)
let mode = SendMode::try_from(raw_byte).unwrap_or_default();
```

### Accessing Union Parameters

Unions (`#[derive(EtsUnion)]`) require matching on the discriminant:

```rust
#[derive(Debug, Clone, Copy, EtsUnion)]
#[repr(C, u8)]
pub enum OutputModeUnion {
    Switch { value: bool, _pad: [u8; 3] } = 0,
    Dimmer { level: u8, speed: u8, _pad: [u8; 2] } = 1,
    Scene { scene_number: u8, _pad: [u8; 3] } = 2,
}

fn apply_output(params: &DeviceParams) {
    match &params.output_mode {
        OutputModeUnion::Switch { value, .. } => {
            set_output(*value);
        }
        OutputModeUnion::Dimmer { level, speed, .. } => {
            dim_to(*level, *speed);
        }
        OutputModeUnion::Scene { scene_number, .. } => {
            recall_scene(*scene_number);
        }
    }
}
```

**Generated discriminant enum:** The macro also generates a discriminant enum for when you need the variant without the data:

```rust
// Auto-generated by #[derive(EtsUnion)]
pub enum OutputModeUnionDiscriminant {
    Switch = 0,
    Dimmer = 1,
    Scene = 2,
}

// Get just the discriminant
fn log_mode(params: &DeviceParams) {
    let discriminant = OutputModeUnionDiscriminant::from(&params.output_mode);
    log!("Current mode: {:?}", discriminant);
}
```

### Accessing Communication Objects - Basic

For simple communication objects with a single DPT:

```rust
#[derive(Debug, EtsComObjects)]
pub struct DeviceObjects {
    #[ets(index = 0)]
    #[ets_ref(dpt = DPT_Switch, text = "Switch Output", function = "Switching")]
    pub switch_output: ComObject<DPT_Switch>,

    #[ets(index = 1)]
    #[ets_ref(dpt = DPT_Scaling, text = "Dimmer Output", function = "Value")]
    pub dimmer_output: ComObject<DPT_Scaling>,
}

// Reading and writing
fn handle_objects(objs: &mut DeviceObjects) {
    // Read current value
    let is_on: bool = objs.switch_output.value();

    // Write a new value
    objs.switch_output.set_value(true);

    // Mark object for transmission
    objs.switch_output.set_transmit_request();

    // Check if object was updated externally
    if objs.dimmer_output.was_updated() {
        let level: u8 = objs.dimmer_output.value();
        apply_dimmer_level(level);
    }
}
```

**Generated Index enum:** The macro generates an `Index` enum for object iteration:

```rust
// Auto-generated
pub enum Index {
    SwitchOutput = 0,
    DimmerOutput = 1,
}

// Iterate over all objects
fn reset_all(objs: &mut DeviceObjects) {
    for idx in [Index::SwitchOutput, Index::DimmerOutput] {
        objs.get_mut(idx).clear_transmit_request();
    }
}
```

### Accessing Communication Objects - Multi-DPT (Without selector_enum)

For objects that support multiple DPTs based on a parameter, without `selector_enum`:

```rust
#[derive(Debug, EtsComObjects)]
pub struct DeviceObjects {
    /// Multi-DPT output - type determined by object_type parameter
    #[ets(index = 0)]
    #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "Output", function = "Switch")]
    #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "Output", function = "Value")]
    #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "Output", function = "Scene")]
    pub main_output: ComObject<ComObjectStorage<4>>,  // 4 bytes to fit largest DPT
}

// Manual type handling based on parameter
fn handle_output(params: &DeviceParams, objs: &mut DeviceObjects) {
    match params.object_type {
        ObjectType::Switch => {
            // Cast the storage to the appropriate DPT
            let value: bool = objs.main_output.value_as::<DPT_Switch>();
            set_switch(value);
        }
        ObjectType::Percent => {
            let value: u8 = objs.main_output.value_as::<DPT_Scaling>();
            set_level(value);
        }
        ObjectType::Scene => {
            let scene: u8 = objs.main_output.value_as::<DPT_SceneNumber>();
            recall_scene(scene);
        }
        _ => {}
    }
}

// Writing values
fn send_output(params: &DeviceParams, objs: &mut DeviceObjects, value: OutputValue) {
    match value {
        OutputValue::Switch(on) => {
            objs.main_output.set_value_as::<DPT_Switch>(on);
        }
        OutputValue::Percent(level) => {
            objs.main_output.set_value_as::<DPT_Scaling>(level);
        }
        OutputValue::Scene(num) => {
            objs.main_output.set_value_as::<DPT_SceneNumber>(num);
        }
    }
    objs.main_output.set_transmit_request();
}
```

### Accessing Communication Objects - Multi-DPT (With selector_enum)

The `selector_enum` attribute generates a typed accessor pattern for cleaner code:

```rust
#[derive(Debug, EtsComObjects)]
#[ets(selector_enum = ObjectType)]  // Generate typed accessors
pub struct DeviceObjects {
    #[ets(index = 0)]
    #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "Output", function = "Switch")]
    #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "Output", function = "Value")]
    #[ets_ref(dpt = DPT_SceneNumber, when = ObjectType::Scene, text = "Output", function = "Scene")]
    pub main_output: ComObject<ComObjectStorage<4>>,

    #[ets(index = 1)]
    #[ets_ref(dpt = DPT_Switch, when = ObjectType::Switch, text = "Status", function = "Switch")]
    #[ets_ref(dpt = DPT_Scaling, when = ObjectType::Percent, text = "Status", function = "Value")]
    pub status_output: ComObject<ComObjectStorage<4>>,
}

// Generated by the macro:
pub enum ObjectTypeObjs<'a> {
    Switch {
        main_output: TypedComObj<'a, DPT_Switch, 0>,
        status_output: TypedComObj<'a, DPT_Switch, 1>,
    },
    Percent {
        main_output: TypedComObj<'a, DPT_Scaling, 0>,
        status_output: TypedComObj<'a, DPT_Scaling, 1>,
    },
    Scene {
        main_output: TypedComObj<'a, DPT_SceneNumber, 0>,
        // status_output not included - no Scene ref for it
    },
}
```

**Using the typed accessor:**

```rust
fn handle_output_typed(params: &DeviceParams, objs: &mut DeviceObjects) {
    // Get typed object references based on current mode
    match params.object_type.comm_objects(objs) {
        ObjectTypeObjs::Switch { main_output, status_output } => {
            // main_output is TypedComObj<DPT_Switch> - fully typed!
            let value: bool = main_output.value();
            set_switch(value);

            // Update status
            status_output.set_value(value);
            status_output.set_transmit_request();
        }
        ObjectTypeObjs::Percent { main_output, status_output } => {
            let level: u8 = main_output.value();
            set_level(level);

            status_output.set_value(level);
            status_output.set_transmit_request();
        }
        ObjectTypeObjs::Scene { main_output } => {
            let scene: u8 = main_output.value();
            recall_scene(scene);
            // No status_output available in Scene mode
        }
    }
}
```

**Benefits of `selector_enum`:**
- Type-safe: Can't accidentally read a Switch value as a Percent
- IDE support: Autocomplete shows only objects available for current mode
- Compile-time errors: If you try to access an object not available for a variant
- Self-documenting: The enum variant clearly shows what's available

**When NOT to use `selector_enum`:**
- Objects with many refs per selector value (causes generated code bloat)
- Simple devices with single-DPT objects (no benefit)
- When you need to access objects by index dynamically

### Accessing Union Values from Communication Objects

When a communication object's value is stored in a union (common for multi-DPT objects):

```rust
// The value union stores the actual data based on selected type
#[derive(EtsUnion)]
#[repr(C, u8)]
pub enum ButtonValueUnion {
    Switch { value: bool, _pad: [u8; 3] } = 0,
    Percent { value: u8, _pad: [u8; 3] } = 2,
    Scene { value: SceneValue, _pad: [u8; 3] } = 4,
}

// Access pattern: read parameter to know type, then access union
fn get_button_value(params: &ButtonParams) -> OutputValue {
    match params.object_type {
        ObjectType::Switch => {
            if let ButtonValueUnion::Switch { value, .. } = params.button_value {
                OutputValue::Switch(value)
            } else {
                OutputValue::default()
            }
        }
        ObjectType::Percent => {
            if let ButtonValueUnion::Percent { value, .. } = params.button_value {
                OutputValue::Percent(value)
            } else {
                OutputValue::default()
            }
        }
        ObjectType::Scene => {
            if let ButtonValueUnion::Scene { value, .. } = params.button_value {
                OutputValue::Scene(value as u8)
            } else {
                OutputValue::default()
            }
        }
        _ => OutputValue::default(),
    }
}
```

### Converting Between Params and Bytes

For storage or transmission:

```rust
// Convert params to bytes (for saving to EEPROM)
fn save_params(params: &DeviceParams) -> &[u8] {
    // Safe because of #[repr(C)]
    unsafe {
        core::slice::from_raw_parts(
            params as *const _ as *const u8,
            core::mem::size_of::<DeviceParams>()
        )
    }
}

// Convert bytes back to params (when loading)
fn load_params(bytes: &[u8]) -> Option<&DeviceParams> {
    if bytes.len() >= core::mem::size_of::<DeviceParams>() {
        // Safe because of #[repr(C)] and size check
        Some(unsafe { &*(bytes.as_ptr() as *const DeviceParams) })
    } else {
        None
    }
}

// Using the generated defaults
fn reset_to_defaults() -> DeviceParams {
    DeviceParams::default()  // Uses EtsParams-generated Default impl
}

// Or in const context
const DEFAULT_PARAMS: DeviceParams = DeviceParams::DEFAULT;  // Uses ConstDefault
```

### Complete Device Firmware Example

```rust
use crate::params::{DeviceParams, OutputModeUnion, ObjectType};
use crate::objects::DeviceObjects;

pub struct Device {
    params: DeviceParams,
    objects: DeviceObjects,
}

impl Device {
    pub fn new() -> Self {
        Self {
            params: DeviceParams::DEFAULT,
            objects: DeviceObjects::new(),
        }
    }

    pub fn process_input(&mut self, input: InputEvent) {
        match &self.params.output_mode {
            OutputModeUnion::Switch { value, .. } => {
                // Toggle on button press
                if input == InputEvent::ButtonPress {
                    let new_value = !self.objects.switch_output.value();
                    self.objects.switch_output.set_value(new_value);
                    self.objects.switch_output.set_transmit_request();
                }
            }
            OutputModeUnion::Dimmer { level, speed, .. } => {
                // Dim on button hold
                if input == InputEvent::ButtonHold {
                    self.start_dimming(*level, *speed);
                }
            }
            OutputModeUnion::Scene { scene_number, .. } => {
                // Send scene on button press
                if input == InputEvent::ButtonPress {
                    self.objects.scene_output.set_value(*scene_number);
                    self.objects.scene_output.set_transmit_request();
                }
            }
        }
    }

    pub fn handle_group_telegram(&mut self, obj_index: u16) {
        // Use generated Index enum
        let index = Index::try_from(obj_index).ok();

        match index {
            Some(Index::SwitchInput) => {
                let value = self.objects.switch_input.value();
                self.apply_switch(value);
            }
            Some(Index::DimmerInput) => {
                let level = self.objects.dimmer_input.value();
                self.apply_level(level);
            }
            _ => {}
        }
    }
}
```

---

## Migration Guide

### From `enum_variants` to `ets_enum`

Before:
```rust
#[ets(display = "Enable", enum_variants("not active" => 0, "active" => 1))]
pub enable: u8,
```

After:
```rust
#[ets(display = "Enable", ets_enum)]
pub enable: EnableDisable,  // Must have #[derive(EtsEnum)]
```

**Note**: Only works if the enum has a 0 value variant for zeroed initialization.

### From manual ConstDefault to auto-generation

Before:
```rust
#[derive(EtsEnum, Default)]
pub enum MyEnum {
    #[default]
    First = 0,
    Second = 1,
}
impl ConstDefault for MyEnum {
    const DEFAULT: Self = Self::First;
}
```

After:
```rust
#[derive(EtsEnum, Default)]  // ConstDefault auto-generated from #[default]
pub enum MyEnum {
    #[default]
    First = 0,
    Second = 1,
}
// No manual impl needed!
```
