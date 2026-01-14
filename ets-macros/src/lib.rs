//! Proc-macros for KNX ETS parameter export.
//!
//! This crate provides derive macros for generating ETS parameter definitions:
//! - `#[derive(EtsParams)]` - For structs containing parameters
//! - `#[derive(EtsUnion)]` - For enums representing union parameters
//!
//! # EtsParams Usage
//!
//! ```rust,ignore
//! use ets_macros::EtsParams;
//!
//! #[derive(EtsParams)]
//! #[repr(C)]
//! pub struct MyParams {
//!     /// Operating mode with enum variants for ETS
//!     #[ets(display = "Operating Mode", enum_variants("Off" => 0, "Normal" => 1))]
//!     pub mode: u8,
//!
//!     /// Temperature setpoint
//!     #[ets(display = "Setpoint")]
//!     pub setpoint: u16,
//! }
//!
//! // Generated:
//! // impl MyParams {
//! //     pub const ETS_PARAMS: &'static [EtsParamDef] = &[...];
//! //     pub const ETS_PARAMS_EXT: &'static [EtsParamDefExt] = &[...];
//! //     pub const MODE_VARIANTS: &[EtsEnumVariant] = &[...];
//! // }
//! ```
//!
//! # EtsUnion Usage
//!
//! Use `#[derive(EtsUnion)]` on `#[repr(C, u8)]` enums to create union parameters
//! where the discriminant acts as the selector:
//!
//! ```rust,ignore
//! use ets_macros::EtsUnion;
//!
//! #[derive(EtsUnion)]
//! #[repr(C, u8)]
//! pub enum ConfigUnion {
//!     #[ets(display = "Off")]
//!     Off,
//!
//!     #[ets(display = "Normal Mode")]
//!     Normal {
//!         #[ets(display = "Normal Config")]
//!         config: u32,
//!     },
//!
//!     #[ets(display = "Eco Mode")]
//!     Eco {
//!         #[ets(display = "Eco Temperature")]
//!         temp: u16,
//!         #[ets(display = "Eco Timeout")]
//!         timeout: u16,
//!     },
//! }
//!
//! // Generated:
//! // impl ConfigUnion {
//! //     pub const ETS_UNION_INFO: EtsUnionInfo = ...;
//! //     pub const ETS_SELECTOR_VARIANTS: &[EtsEnumVariant] = &[...];
//! // }
//! ```
//!
//! # Supported Field Types
//!
//! - `u8`, `u16`, `u32` - Unsigned integers
//! - `i8`, `i16`, `i32` - Signed integers
//! - `bool` - Boolean (1 byte)
//! - `[u8; N]` - Raw byte arrays
//!
//! # EtsParams Attributes
//!
//! - `#[ets(display = "...")]` - Human-readable name for ETS UI
//! - `#[ets(skip)]` - Skip this field (don't generate ETS parameter)
//! - `#[ets(bits = N)]` - Override size in bits (for bitfields)
//! - `#[ets(bit_offset = N)]` - Bit offset within byte (for bitfields)
//! - `#[ets(enum_variants("Name" => 0, "Other" => 1))]` - Define enum variants for ETS
//!
//! # EtsUnion Attributes
//!
//! On the enum:
//! - `#[repr(C, u8)]` - Required, ensures predictable memory layout
//!
//! On variants:
//! - `#[ets(display = "...")]` - Human-readable name for ETS selector dropdown
//!
//! On variant fields:
//! - `#[ets(display = "...")]` - Human-readable name for the parameter

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse_macro_input, Data, DeriveInput, Fields, Type, Attribute,
    Lit, Expr, Token,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

/// A single enum variant: "Name" => value
struct EnumVariantDef {
    text: String,
    value: i64,
}

impl Parse for EnumVariantDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let text: syn::LitStr = input.parse()?;
        input.parse::<Token![=>]>()?;
        let value: syn::LitInt = input.parse()?;
        Ok(EnumVariantDef {
            text: text.value(),
            value: value.base10_parse()?,
        })
    }
}

/// List of enum variants: ("Off" => 0, "On" => 1)
struct EnumVariantList {
    variants: Vec<EnumVariantDef>,
}

impl Parse for EnumVariantList {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let variants: Punctuated<EnumVariantDef, Token![,]> =
            input.parse_terminated(EnumVariantDef::parse, Token![,])?;
        Ok(EnumVariantList {
            variants: variants.into_iter().collect(),
        })
    }
}

/// Derive macro for generating ETS parameter definitions.
///
/// Generates an `ETS_PARAMS` constant containing metadata for each field
/// that can be used for ETS export.
#[proc_macro_derive(EtsParams, attributes(ets))]
pub fn derive_ets_params(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match derive_ets_params_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn derive_ets_params_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_name = &input.ident;

    // Extract fields from struct
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => return Err(syn::Error::new_spanned(
                input,
                "EtsParams can only be derived for structs with named fields"
            )),
        },
        _ => return Err(syn::Error::new_spanned(
            input,
            "EtsParams can only be derived for structs"
        )),
    };

    // Generate parameter definitions
    let mut param_defs = Vec::new();
    let mut param_ext_defs = Vec::new();
    let mut enum_variant_consts = Vec::new();
    let mut union_field_entries = Vec::new();
    let mut current_offset: usize = 0;

    for field in fields.iter() {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;

        // Parse field attributes
        let attrs = parse_field_attrs(&field.attrs)?;

        // Skip if marked with #[ets(skip)]
        if attrs.skip {
            // Still advance offset for alignment
            if let Ok(size) = get_type_size(field_type) {
                current_offset += size;
            }
            continue;
        }

        let display_name = attrs.display.clone().unwrap_or_else(|| {
            // Convert snake_case to Title Case
            field_name.to_string()
                .split('_')
                .map(|word| {
                    let mut chars = word.chars();
                    match chars.next() {
                        Some(first) => first.to_uppercase().chain(chars).collect(),
                        None => String::new(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        });

        let name_str = field_name.to_string();

        // Check if this is a union field (unknown type that might implement EtsUnionType)
        if attrs.union_field {
            // This is a union field - generate selector parameter and track the union
            let offset_u16 = current_offset as u16;
            let selector_name = format!("{}_selector", field_name);
            let selector_display = format!("{} Mode", display_name);

            // Generate selector parameter (the discriminant, 1 byte)
            param_defs.push(quote! {
                zweidraehte::ets::EtsParamDef {
                    name: #selector_name,
                    display_name: #selector_display,
                    offset: #offset_u16,
                    size_bits: 8,
                    bit_offset: 0,
                    param_type: zweidraehte::ets::EtsParamType::Enum,
                }
            });

            // Generate selector enum variants from the union type
            let selector_const_name = syn::Ident::new(
                &format!("{}_SELECTOR_VARIANTS", field_name.to_string().to_uppercase()),
                field_name.span(),
            );

            enum_variant_consts.push(quote! {
                const #selector_const_name: &[zweidraehte::ets::EtsEnumVariant] =
                    #field_type::ETS_SELECTOR_VARIANTS;
            });

            param_ext_defs.push(quote! {
                zweidraehte::ets::EtsParamDefExt {
                    base: zweidraehte::ets::EtsParamDef {
                        name: #selector_name,
                        display_name: #selector_display,
                        offset: #offset_u16,
                        size_bits: 8,
                        bit_offset: 0,
                        param_type: zweidraehte::ets::EtsParamType::Enum,
                    },
                    enum_variants: Some(Self::#selector_const_name),
                }
            });

            // Track the union field for ETS_UNIONS generation
            union_field_entries.push(quote! {
                zweidraehte::ets::EtsUnionFieldInfo {
                    field_name: #name_str,
                    offset: #offset_u16,
                    union_info: &#field_type::ETS_UNION_INFO,
                    selector_variants: #field_type::ETS_SELECTOR_VARIANTS,
                }
            });

            // Advance offset by the union's total size
            // We can't know the size at macro time, so we use a workaround:
            // The user must ensure proper alignment, or we skip offset tracking for unions
            // For now, we leave offset tracking to the user for union fields
            // (they can use #[ets(skip)] on following fields and manage manually)

            // Actually, since we require #[repr(C)], we need to know the size.
            // The safest approach: require the user to specify the size or use std::mem::size_of at runtime.
            // For compile-time, we'll just note that unions need special handling.

            continue; // Skip adding to regular params, we handled it specially
        }

        let type_info = get_type_info(field_type)?;

        let size_bits = attrs.bits.unwrap_or(type_info.size_bits);
        let bit_offset = attrs.bit_offset.unwrap_or(0);

        // Determine param type - if has enum_variants, it's an Enum type
        let param_type = if attrs.enum_variants.is_some() {
            quote!(zweidraehte::ets::EtsParamType::Enum)
        } else {
            type_info.param_type.clone()
        };

        let offset_u16 = current_offset as u16;

        // Generate basic ETS_PARAMS entry
        param_defs.push(quote! {
            zweidraehte::ets::EtsParamDef {
                name: #name_str,
                display_name: #display_name,
                offset: #offset_u16,
                size_bits: #size_bits,
                bit_offset: #bit_offset,
                param_type: #param_type,
            }
        });

        // Generate ETS_PARAMS_EXT entry with enum variants
        let enum_variants_expr = if let Some(variants) = &attrs.enum_variants {
            // Generate a const for the enum variants
            let const_name = syn::Ident::new(
                &format!("{}_VARIANTS", field_name.to_string().to_uppercase()),
                field_name.span(),
            );

            let variant_defs: Vec<_> = variants.iter().map(|v| {
                let text = &v.text;
                let value = v.value;
                quote! {
                    zweidraehte::ets::EtsEnumVariant { text: #text, value: #value }
                }
            }).collect();

            enum_variant_consts.push(quote! {
                const #const_name: &[zweidraehte::ets::EtsEnumVariant] = &[
                    #(#variant_defs),*
                ];
            });

            quote!(Some(Self::#const_name))
        } else {
            quote!(None)
        };

        param_ext_defs.push(quote! {
            zweidraehte::ets::EtsParamDefExt {
                base: zweidraehte::ets::EtsParamDef {
                    name: #name_str,
                    display_name: #display_name,
                    offset: #offset_u16,
                    size_bits: #size_bits,
                    bit_offset: #bit_offset,
                    param_type: #param_type,
                },
                enum_variants: #enum_variants_expr,
            }
        });

        // Advance offset
        current_offset += type_info.size_bytes;
    }

    let param_count = param_defs.len();

    // Generate union info if we have any union fields
    let union_info_output = if union_field_entries.is_empty() {
        quote! {}
    } else {
        quote! {
            /// Information about union fields in this struct.
            pub const ETS_UNIONS: &'static [zweidraehte::ets::EtsUnionFieldInfo] = &[
                #(#union_field_entries),*
            ];
        }
    };

    Ok(quote! {
        impl #struct_name {
            // Enum variant constants
            #(#enum_variant_consts)*

            /// ETS parameter definitions for this struct.
            ///
            /// Contains metadata for each field that can be exported to ETS format.
            pub const ETS_PARAMS: &'static [zweidraehte::ets::EtsParamDef] = &[
                #(#param_defs),*
            ];

            /// Extended ETS parameter definitions with enum variants.
            ///
            /// Contains full metadata including enum variants for ETS export.
            pub const ETS_PARAMS_EXT: &'static [zweidraehte::ets::EtsParamDefExt] = &[
                #(#param_ext_defs),*
            ];

            /// Number of ETS parameters.
            pub const NUM_PARAMS: usize = #param_count;

            #union_info_output
        }
    })
}

/// Parsed field attributes
struct FieldAttrs {
    display: Option<String>,
    skip: bool,
    bits: Option<u8>,
    bit_offset: Option<u8>,
    enum_variants: Option<Vec<EnumVariantDef>>,
    /// Marks this field as a union type
    union_field: bool,
}

fn parse_field_attrs(attrs: &[Attribute]) -> syn::Result<FieldAttrs> {
    let mut result = FieldAttrs {
        display: None,
        skip: false,
        bits: None,
        bit_offset: None,
        enum_variants: None,
        union_field: false,
    };

    for attr in attrs {
        if !attr.path().is_ident("ets") {
            continue;
        }

        // Parse the attribute tokens manually to support enum_variants(...)
        let tokens = attr.meta.require_list()?.tokens.clone();
        let parser = |input: ParseStream| {
            while !input.is_empty() {
                let ident: syn::Ident = input.parse()?;

                if ident == "display" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.display = Some(value.value());
                } else if ident == "skip" {
                    result.skip = true;
                } else if ident == "bits" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitInt = input.parse()?;
                    result.bits = Some(value.base10_parse()?);
                } else if ident == "bit_offset" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitInt = input.parse()?;
                    result.bit_offset = Some(value.base10_parse()?);
                } else if ident == "enum_variants" {
                    let content;
                    syn::parenthesized!(content in input);
                    let list: EnumVariantList = content.parse()?;
                    result.enum_variants = Some(list.variants);
                } else if ident == "union" {
                    result.union_field = true;
                }

                // Consume optional comma
                let _ = input.parse::<Option<Token![,]>>();
            }
            Ok(())
        };

        syn::parse::Parser::parse2(parser, tokens)?;
    }

    Ok(result)
}

struct TypeInfo {
    size_bytes: usize,
    size_bits: u8,
    param_type: TokenStream2,
}

fn get_type_info(ty: &Type) -> syn::Result<TypeInfo> {
    match ty {
        Type::Path(type_path) => {
            let segment = type_path.path.segments.last()
                .ok_or_else(|| syn::Error::new_spanned(ty, "Empty type path"))?;

            let ident_str = segment.ident.to_string();

            match ident_str.as_str() {
                "u8" => Ok(TypeInfo {
                    size_bytes: 1,
                    size_bits: 8,
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                "u16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                "u32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                "i8" => Ok(TypeInfo {
                    size_bytes: 1,
                    size_bits: 8,
                    param_type: quote!(zweidraehte::ets::EtsParamType::SignedInt),
                }),
                "i16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    param_type: quote!(zweidraehte::ets::EtsParamType::SignedInt),
                }),
                "i32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    param_type: quote!(zweidraehte::ets::EtsParamType::SignedInt),
                }),
                "bool" => Ok(TypeInfo {
                    size_bytes: 1,
                    size_bits: 1,
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                _ => {
                    // Unknown type - treat as raw bytes
                    // Could be a custom enum or struct
                    Err(syn::Error::new_spanned(
                        ty,
                        format!("Unsupported type '{}'. Use u8, u16, u32, i8, i16, i32, bool, or [u8; N]", ident_str)
                    ))
                }
            }
        }
        Type::Array(array) => {
            // Handle [u8; N] arrays
            if let Type::Path(inner) = array.elem.as_ref() {
                if inner.path.is_ident("u8") {
                    // Extract array length
                    if let Expr::Lit(lit) = &array.len {
                        if let Lit::Int(int) = &lit.lit {
                            let len: usize = int.base10_parse()?;
                            return Ok(TypeInfo {
                                size_bytes: len,
                                size_bits: (len * 8) as u8,
                                param_type: quote!(zweidraehte::ets::EtsParamType::None),
                            });
                        }
                    }
                }
            }
            Err(syn::Error::new_spanned(ty, "Only [u8; N] arrays are supported"))
        }
        _ => Err(syn::Error::new_spanned(ty, "Unsupported type")),
    }
}

fn get_type_size(ty: &Type) -> syn::Result<usize> {
    Ok(get_type_info(ty)?.size_bytes)
}

// ============================================================================
// EtsUnion Derive Macro
// ============================================================================

/// Derive macro for generating ETS union definitions from Rust enums.
///
/// Requires `#[repr(C, u8)]` on the enum for predictable memory layout.
/// The discriminant becomes the ETS selector parameter.
///
/// # Generated Items
///
/// - `ETS_UNION_INFO: EtsUnionInfo` - Union metadata including size and variant params
/// - `ETS_SELECTOR_VARIANTS: &[EtsEnumVariant]` - Enum variants for the selector param
///
/// # Example
///
/// ```rust,ignore
/// #[derive(EtsUnion)]
/// #[repr(C, u8)]
/// pub enum ConfigUnion {
///     #[ets(display = "Off")]
///     Off,
///
///     #[ets(display = "Normal")]
///     Normal { config: u32 },
/// }
/// ```
#[proc_macro_derive(EtsUnion, attributes(ets))]
pub fn derive_ets_union(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match derive_ets_union_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn derive_ets_union_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let enum_name = &input.ident;

    // Verify it's an enum
    let variants = match &input.data {
        Data::Enum(data) => &data.variants,
        _ => return Err(syn::Error::new_spanned(
            input,
            "EtsUnion can only be derived for enums"
        )),
    };

    // Verify #[repr(C, u8)] or similar
    let has_repr_c = input.attrs.iter().any(|attr| {
        if attr.path().is_ident("repr") {
            if let Ok(meta) = attr.meta.require_list() {
                let tokens = meta.tokens.to_string();
                // Check for repr(C, u8) or repr(u8, C) or just repr(u8)
                tokens.contains("C") || tokens.contains("u8")
            } else {
                false
            }
        } else {
            false
        }
    });

    if !has_repr_c {
        return Err(syn::Error::new_spanned(
            input,
            "EtsUnion requires #[repr(C, u8)] or #[repr(u8)] for predictable memory layout"
        ));
    }

    // Calculate max variant size (excluding discriminant)
    let mut max_variant_size: usize = 0;
    let mut selector_variants = Vec::new();
    let mut union_params = Vec::new();

    for (idx, variant) in variants.iter().enumerate() {
        let variant_name = &variant.ident;
        let discriminant_value = idx as i64;

        // Parse variant attributes for display name
        let variant_attrs = parse_variant_attrs(&variant.attrs)?;
        let display_name = variant_attrs.display.unwrap_or_else(|| {
            // Convert CamelCase to Title Case with spaces
            let name = variant_name.to_string();
            let mut result = String::new();
            for (i, c) in name.chars().enumerate() {
                if i > 0 && c.is_uppercase() {
                    result.push(' ');
                }
                result.push(c);
            }
            result
        });

        // Add to selector variants
        selector_variants.push(quote! {
            zweidraehte::ets::EtsEnumVariant {
                text: #display_name,
                value: #discriminant_value,
            }
        });

        // Calculate variant size and collect field params
        let variant_size: usize;
        match &variant.fields {
            syn::Fields::Unit => {
                variant_size = 0;
                // Unit variant - no union parameters
            }
            syn::Fields::Named(fields) => {
                let mut size = 0usize;
                let mut field_offset = 0u16;

                for field in &fields.named {
                    let field_name = field.ident.as_ref().unwrap();
                    let field_type = &field.ty;

                    let field_attrs = parse_field_attrs(&field.attrs)?;
                    let field_display = field_attrs.display.unwrap_or_else(|| {
                        field_name.to_string()
                            .split('_')
                            .map(|word| {
                                let mut chars = word.chars();
                                match chars.next() {
                                    Some(first) => first.to_uppercase().chain(chars).collect(),
                                    None => String::new(),
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(" ")
                    });

                    let type_info = get_type_info(field_type)?;
                    let size_bits = field_attrs.bits.unwrap_or(type_info.size_bits);
                    let bit_offset = field_attrs.bit_offset.unwrap_or(0);
                    let param_type = type_info.param_type;

                    let variant_name_str = variant_name.to_string();
                    let field_name_str = field_name.to_string();
                    // Use the field offset within the variant data area
                    let param_offset = field_offset;

                    union_params.push(quote! {
                        zweidraehte::ets::EtsUnionVariantParam {
                            variant_name: #variant_name_str,
                            variant_value: #discriminant_value,
                            param: zweidraehte::ets::EtsParamDef {
                                name: #field_name_str,
                                display_name: #field_display,
                                offset: #param_offset,
                                size_bits: #size_bits,
                                bit_offset: #bit_offset,
                                param_type: #param_type,
                            },
                        }
                    });

                    size += type_info.size_bytes;
                    field_offset += type_info.size_bytes as u16;
                }

                variant_size = size;
            }
            syn::Fields::Unnamed(fields) => {
                // Tuple variants - treat as raw bytes
                let mut size = 0usize;
                for field in &fields.unnamed {
                    size += get_type_size(&field.ty)?;
                }
                variant_size = size;
            }
        }

        if variant_size > max_variant_size {
            max_variant_size = variant_size;
        }
    }

    let enum_name_str = enum_name.to_string();
    let variant_count = variants.len();
    // NOTE: We use core::mem::size_of to get the actual Rust size including alignment
    // padding. The calculated max_variant_size is only used for data_size (the logical
    // size of variant data), but total_size must match the actual struct layout for
    // correct memory mapping in ETS export.

    Ok(quote! {
        impl #enum_name {
            /// ETS union information for this enum.
            ///
            /// Contains metadata about the union structure for ETS export.
            pub const ETS_UNION_INFO: zweidraehte::ets::EtsUnionInfo = zweidraehte::ets::EtsUnionInfo {
                name: #enum_name_str,
                // Use actual Rust size including alignment padding
                total_size: core::mem::size_of::<#enum_name>() as u16,
                // data_size is the logical size without discriminant (may be less due to padding)
                data_size: (core::mem::size_of::<#enum_name>() - 1) as u16,
                variant_count: #variant_count,
                variant_params: &[
                    #(#union_params),*
                ],
            };

            /// Selector variants for ETS dropdown.
            ///
            /// These are the display names and values for the discriminant.
            pub const ETS_SELECTOR_VARIANTS: &'static [zweidraehte::ets::EtsEnumVariant] = &[
                #(#selector_variants),*
            ];
        }

        // Implement the marker trait
        impl zweidraehte::ets::EtsUnionType for #enum_name {
            fn ets_union_info() -> &'static zweidraehte::ets::EtsUnionInfo {
                &Self::ETS_UNION_INFO
            }

            fn ets_selector_variants() -> &'static [zweidraehte::ets::EtsEnumVariant] {
                Self::ETS_SELECTOR_VARIANTS
            }
        }
    })
}

/// Parse variant-level attributes
fn parse_variant_attrs(attrs: &[Attribute]) -> syn::Result<VariantAttrs> {
    let mut result = VariantAttrs { display: None };

    for attr in attrs {
        if !attr.path().is_ident("ets") {
            continue;
        }

        let tokens = attr.meta.require_list()?.tokens.clone();
        let parser = |input: ParseStream| {
            while !input.is_empty() {
                let ident: syn::Ident = input.parse()?;

                if ident == "display" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.display = Some(value.value());
                }

                // Consume optional comma
                let _ = input.parse::<Option<Token![,]>>();
            }
            Ok(())
        };

        syn::parse::Parser::parse2(parser, tokens)?;
    }

    Ok(result)
}

/// Parsed variant attributes
struct VariantAttrs {
    display: Option<String>,
}
