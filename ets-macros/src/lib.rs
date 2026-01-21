//! Proc-macros for KNX ETS parameter export.
//!
//! This crate provides derive macros for generating ETS parameter definitions:
//! - `#[derive(EtsParams)]` - For structs containing parameters
//! - `#[derive(EtsUnion)]` - For enums representing union parameters (with data)
//! - `#[derive(EtsEnum)]` - For simple enums (no data) used as dropdown parameters
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
//! - `#[ets(enum_variants("Name" => 0, "Other" => 1))]` - Define enum variants for ETS dropdown
//! - `#[ets(ets_enum)]` - Mark field as an EtsEnum type (uses type's ETS_VARIANTS)
//!
//! # EtsEnum Attributes
//!
//! On the enum:
//! - `#[repr(u8)]` - Required, ensures predictable memory layout
//!
//! On variants:
//! - `#[ets(display = "...")]` - Human-readable name for ETS dropdown

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

    // Generate parameter definitions using core::mem::offset_of! for accurate offsets.
    // This handles all alignment and union sizing correctly at const-eval time.
    let mut param_defs = Vec::new();
    let mut param_ext_defs = Vec::new();
    let mut enum_variant_consts = Vec::new();
    let mut union_field_entries = Vec::new();

    for field in fields.iter() {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;

        // Parse field attributes
        let attrs = parse_field_attrs(&field.attrs)?;

        // Skip if marked with #[ets(skip)]
        if attrs.skip {
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

        // Use offset_of! to get the actual field offset at const-eval time
        // This correctly handles all alignment padding and works with any field type
        let offset_expr = quote! {
            core::mem::offset_of!(#struct_name, #field_name) as u16
        };

        // Check if this is a union field (unknown type that might implement EtsUnionType)
        if attrs.union_field {
            let selector_name = format!("{}_selector", field_name);
            let selector_display = format!("{} Mode", display_name);

            // Generate selector parameter (the discriminant, 1 byte)
            param_defs.push(quote! {
                zweidraehte::ets::EtsParamDef {
                    name: #selector_name,
                    display_name: #selector_display,
                    suffix: None,
                    offset: #offset_expr,
                    size_bits: 8,
                    bit_offset: 0,
                    param_type: zweidraehte::ets::EtsParamType::Enum,
                    hidden: false,
                    type_name: None,
                    text_pattern: None,
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
                        suffix: None,
                        offset: #offset_expr,
                        size_bits: 8,
                        bit_offset: 0,
                        param_type: zweidraehte::ets::EtsParamType::Enum,
                        hidden: false,
                        type_name: None,
                        text_pattern: None,
                    },
                    enum_variants: Some(Self::#selector_const_name),
                }
            });

            // Track the union field for ETS_UNIONS generation
            union_field_entries.push(quote! {
                zweidraehte::ets::EtsUnionFieldInfo {
                    field_name: #name_str,
                    offset: #offset_expr,
                    union_info: &#field_type::ETS_UNION_INFO,
                    selector_variants: #field_type::ETS_SELECTOR_VARIANTS,
                }
            });

            continue; // Skip adding to regular params, we handled it specially
        }

        let type_info = get_type_info(field_type)?;

        let size_bits = attrs.bits.unwrap_or(type_info.size_bits);
        let bit_offset = attrs.bit_offset.unwrap_or(0);

        // Determine param type - if has enum_variants, it's an Enum type
        // If marked as string, it's a String type
        let param_type = if attrs.enum_variants.is_some() {
            quote!(zweidraehte::ets::EtsParamType::Enum)
        } else if attrs.string_field {
            quote!(zweidraehte::ets::EtsParamType::String)
        } else {
            type_info.param_type.clone()
        };

        // Generate suffix expression
        let suffix_expr = if let Some(s) = &attrs.suffix {
            quote!(Some(#s))
        } else {
            quote!(None)
        };

        // Generate basic ETS_PARAMS entry
        let hidden = attrs.hidden;
        let type_name_expr = if let Some(ref tn) = attrs.type_name {
            quote!(Some(#tn))
        } else {
            quote!(None)
        };
        param_defs.push(quote! {
            zweidraehte::ets::EtsParamDef {
                name: #name_str,
                display_name: #display_name,
                suffix: #suffix_expr,
                offset: #offset_expr,
                size_bits: #size_bits,
                bit_offset: #bit_offset,
                param_type: #param_type,
                hidden: #hidden,
                type_name: #type_name_expr,
                text_pattern: None,
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
                    suffix: #suffix_expr,
                    offset: #offset_expr,
                    size_bits: #size_bits,
                    bit_offset: #bit_offset,
                    param_type: #param_type,
                    hidden: #hidden,
                    type_name: #type_name_expr,
                    text_pattern: None,
                },
                enum_variants: #enum_variants_expr,
            }
        });
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

    // Generate compile-time assertions to verify our hardcoded alignments match reality.
    // This catches any exotic architectures where alignments might differ.
    let alignment_assertions = quote! {
        const _: () = {
            assert!(core::mem::align_of::<u8>() == 1, "u8 alignment mismatch");
            assert!(core::mem::align_of::<u16>() == 2, "u16 alignment mismatch");
            assert!(core::mem::align_of::<u32>() == 4, "u32 alignment mismatch");
            assert!(core::mem::align_of::<i8>() == 1, "i8 alignment mismatch");
            assert!(core::mem::align_of::<i16>() == 2, "i16 alignment mismatch");
            assert!(core::mem::align_of::<i32>() == 4, "i32 alignment mismatch");
            assert!(core::mem::align_of::<bool>() == 1, "bool alignment mismatch");
        };
    };

    Ok(quote! {
        #alignment_assertions

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
    suffix: Option<String>,
    skip: bool,
    bits: Option<u8>,
    bit_offset: Option<u8>,
    enum_variants: Option<Vec<EnumVariantDef>>,
    /// Marks this field as a union type
    union_field: bool,
    /// Marks this field as an EtsEnum type (simple enum with no data)
    ets_enum_field: bool,
    /// Marks this field as a string/text type (for [u8; N] arrays)
    string_field: bool,
    /// Marks this field as hidden (Access="None" in ETS)
    hidden: bool,
    /// Override for the ParameterType name in ETS export
    type_name: Option<String>,
    /// Default value for this field
    default_value: Option<i64>,
    /// Pattern for TypeText parameters (regex with optional comment)
    text_pattern: Option<String>,
}

fn parse_field_attrs(attrs: &[Attribute]) -> syn::Result<FieldAttrs> {
    let mut result = FieldAttrs {
        display: None,
        suffix: None,
        skip: false,
        bits: None,
        bit_offset: None,
        enum_variants: None,
        union_field: false,
        ets_enum_field: false,
        string_field: false,
        hidden: false,
        type_name: None,
        default_value: None,
        text_pattern: None,
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
                } else if ident == "suffix" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.suffix = Some(value.value());
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
                } else if ident == "ets_enum" {
                    result.ets_enum_field = true;
                } else if ident == "string" {
                    result.string_field = true;
                } else if ident == "hidden" {
                    result.hidden = true;
                } else if ident == "type_name" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.type_name = Some(value.value());
                } else if ident == "default" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitInt = input.parse()?;
                    result.default_value = Some(value.base10_parse()?);
                } else if ident == "text_pattern" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.text_pattern = Some(value.value());
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
    align: usize,
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
                    align: 1,
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                "u16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    align: 2,
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                "u32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    align: 4,
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                "i8" => Ok(TypeInfo {
                    size_bytes: 1,
                    size_bits: 8,
                    align: 1,
                    param_type: quote!(zweidraehte::ets::EtsParamType::SignedInt),
                }),
                "i16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    align: 2,
                    param_type: quote!(zweidraehte::ets::EtsParamType::SignedInt),
                }),
                "i32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    align: 4,
                    param_type: quote!(zweidraehte::ets::EtsParamType::SignedInt),
                }),
                "bool" => Ok(TypeInfo {
                    size_bytes: 1,
                    size_bits: 1,
                    align: 1,
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                // Big-endian types - KNX uses big-endian for parameter storage
                // BeU16/BeU32/etc are custom wrappers with serde support
                // BigU16/U16/etc are from zerocopy::big_endian
                "BeU16" | "BigU16" | "U16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    align: 1, // [u8; 2] has alignment 1
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                "BeU32" | "BigU32" | "U32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    align: 1, // [u8; 4] has alignment 1
                    param_type: quote!(zweidraehte::ets::EtsParamType::UnsignedInt),
                }),
                "BeI16" | "BigI16" | "I16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    align: 1,
                    param_type: quote!(zweidraehte::ets::EtsParamType::SignedInt),
                }),
                "BeI32" | "BigI32" | "I32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    align: 1,
                    param_type: quote!(zweidraehte::ets::EtsParamType::SignedInt),
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
                                align: 1, // [u8; N] has alignment of 1
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
    let discriminant_enum_name = syn::Ident::new(
        &format!("{}Discriminant", enum_name),
        enum_name.span(),
    );

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

    // First pass: calculate max alignment across all variants to determine data_offset.
    // In #[repr(C, u8)], the variant data area starts at an offset aligned to the
    // maximum alignment of any field in any variant.
    let mut max_align: usize = 1;
    for variant in variants.iter() {
        if let syn::Fields::Named(fields) = &variant.fields {
            for field in &fields.named {
                if let Ok(type_info) = get_type_info(&field.ty) {
                    if type_info.align > max_align {
                        max_align = type_info.align;
                    }
                }
            }
        }
    }
    // Data offset is the discriminant (1 byte) aligned up to max_align
    let data_offset: usize = (1 + max_align - 1) & !(max_align - 1);

    // Second pass: calculate variant sizes and generate params
    let mut max_variant_size: usize = 0;
    let mut selector_variants = Vec::new();
    let mut union_params = Vec::new();
    // Collect variant names for discriminant enum generation
    let mut discriminant_variants: Vec<(syn::Ident, i64)> = Vec::new();

    let mut current_discriminant: i64 = 0;
    for variant in variants.iter() {
        let variant_name = &variant.ident;
        // Get explicit discriminant if present, otherwise use auto-incrementing value
        let discriminant_value = if let Some((_, expr)) = &variant.discriminant {
            if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(lit), .. }) = expr {
                let val = lit.base10_parse::<i64>().unwrap_or(current_discriminant);
                current_discriminant = val;
                val
            } else {
                let val = current_discriminant;
                val
            }
        } else {
            current_discriminant
        };
        current_discriminant = discriminant_value + 1;

        // Store for discriminant enum generation
        discriminant_variants.push((variant_name.clone(), discriminant_value));

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
                let mut field_offset = 0usize;

                for field in &fields.named {
                    let field_name = field.ident.as_ref().unwrap();
                    let field_type = &field.ty;

                    let field_attrs = parse_field_attrs(&field.attrs)?;

                    // Handle ets_enum fields first - they don't use get_type_info
                    // EtsEnum types are always 1 byte (repr(u8)) with 1-byte alignment
                    if field_attrs.ets_enum_field {
                        // Skip if marked with #[ets(skip)] but still count size for layout
                        if field_attrs.skip {
                            size = field_offset + 1;
                            field_offset += 1;
                            continue;
                        }

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

                        let variant_name_str = variant_name.to_string();
                        let field_name_str = field_name.to_string();
                        let param_offset = field_offset as u16;
                        let bit_offset = field_attrs.bit_offset.unwrap_or(0);

                        // For ets_enum fields, use default_value if specified
                        let default_value_expr = if let Some(val) = field_attrs.default_value {
                            quote!(Some(#val))
                        } else {
                            quote!(None)
                        };

                        // Generate suffix expression for ets_enum fields
                        let suffix_expr = if let Some(ref suffix) = field_attrs.suffix {
                            quote!(Some(#suffix))
                        } else {
                            quote!(None)
                        };

                        union_params.push(quote! {
                            zweidraehte::ets::EtsUnionVariantParam {
                                variant_name: #variant_name_str,
                                variant_value: #discriminant_value,
                                param: zweidraehte::ets::EtsParamDef {
                                    name: #field_name_str,
                                    display_name: #field_display,
                                    suffix: #suffix_expr,
                                    offset: #param_offset,
                                    size_bits: #field_type::ETS_SIZE_BITS,
                                    bit_offset: #bit_offset,
                                    param_type: zweidraehte::ets::EtsParamType::Enum,
                                    hidden: false,
                                    type_name: None,
                                    text_pattern: None,
                                },
                                enum_variants: Some(#field_type::ETS_VARIANTS),
                                default_value: #default_value_expr,
                            }
                        });

                        size = field_offset + 1;
                        field_offset += 1;
                        continue;
                    }

                    // Get type info for non-ets_enum fields
                    let type_info = get_type_info(field_type)?;

                    // Apply alignment padding before this field
                    let align = type_info.align;
                    if align > 1 {
                        field_offset = (field_offset + align - 1) & !(align - 1);
                    }

                    // Skip if marked with #[ets(skip)] but still count size for layout
                    if field_attrs.skip {
                        size = field_offset + type_info.size_bytes;
                        field_offset += type_info.size_bytes;
                        continue;
                    }

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

                    let size_bits = field_attrs.bits.unwrap_or(type_info.size_bits);
                    let bit_offset = field_attrs.bit_offset.unwrap_or(0);

                    // Determine param type - if has enum_variants, it's an Enum type
                    // If marked as string or has text_pattern, it's a String type
                    let param_type = if field_attrs.enum_variants.is_some() {
                        quote!(zweidraehte::ets::EtsParamType::Enum)
                    } else if field_attrs.string_field || field_attrs.text_pattern.is_some() {
                        quote!(zweidraehte::ets::EtsParamType::String)
                    } else {
                        type_info.param_type.clone()
                    };

                    let variant_name_str = variant_name.to_string();
                    let field_name_str = field_name.to_string();
                    // Use the field offset within the variant data area
                    let param_offset = field_offset as u16;

                    // Generate enum_variants expression
                    let enum_variants_expr = if let Some(variants) = &field_attrs.enum_variants {
                        let variant_defs: Vec<_> = variants.iter().map(|v| {
                            let text = &v.text;
                            let value = v.value;
                            quote! {
                                zweidraehte::ets::EtsEnumVariant {
                                    text: #text,
                                    value: #value,
                                }
                            }
                        }).collect();
                        quote!(Some(&[#(#variant_defs),*]))
                    } else {
                        quote!(None)
                    };

                    let default_value_expr = if let Some(val) = field_attrs.default_value {
                        quote!(Some(#val))
                    } else {
                        quote!(None)
                    };

                    // Generate text_pattern expression
                    let text_pattern_expr = if let Some(ref pattern) = field_attrs.text_pattern {
                        quote!(Some(#pattern))
                    } else {
                        quote!(None)
                    };

                    // Generate suffix expression for non-ets_enum fields
                    let suffix_expr = if let Some(ref suffix) = field_attrs.suffix {
                        quote!(Some(#suffix))
                    } else {
                        quote!(None)
                    };

                    union_params.push(quote! {
                        zweidraehte::ets::EtsUnionVariantParam {
                            variant_name: #variant_name_str,
                            variant_value: #discriminant_value,
                            param: zweidraehte::ets::EtsParamDef {
                                name: #field_name_str,
                                display_name: #field_display,
                                suffix: #suffix_expr,
                                offset: #param_offset,
                                size_bits: #size_bits,
                                bit_offset: #bit_offset,
                                param_type: #param_type,
                                hidden: false,
                                type_name: None,
                                text_pattern: #text_pattern_expr,
                            },
                            enum_variants: #enum_variants_expr,
                            default_value: #default_value_expr,
                        }
                    });

                    size = field_offset + type_info.size_bytes;
                    field_offset += type_info.size_bytes;
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
    let data_offset_u16 = data_offset as u16;
    // NOTE: We use core::mem::size_of to get the actual Rust size including alignment
    // padding. The calculated max_variant_size is only used for data_size (the logical
    // size of variant data), but total_size must match the actual struct layout for
    // correct memory mapping in ETS export.

    // Generate discriminant enum variants
    let discriminant_enum_variants: Vec<_> = discriminant_variants.iter().map(|(name, value)| {
        quote! { #name = #value as isize }
    }).collect();

    Ok(quote! {
        /// Discriminant-only enum for use in ComObjectRef `when` clauses.
        ///
        /// This enum has the same variant names and discriminant values as the parent
        /// union enum, but with unit variants that can be cast to integers.
        /// Use this when you need to specify a discriminant value in an attribute.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(isize)]
        pub enum #discriminant_enum_name {
            #(#discriminant_enum_variants),*
        }

        impl #enum_name {
            /// ETS union information for this enum.
            ///
            /// Contains metadata about the union structure for ETS export.
            pub const ETS_UNION_INFO: zweidraehte::ets::EtsUnionInfo = zweidraehte::ets::EtsUnionInfo {
                name: #enum_name_str,
                // Use actual Rust size including alignment padding
                total_size: core::mem::size_of::<#enum_name>() as u16,
                // Offset where variant data begins (after discriminant + alignment padding)
                data_offset: #data_offset_u16,
                // data_size is total_size minus data_offset
                data_size: (core::mem::size_of::<#enum_name>() as u16 - #data_offset_u16),
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

// ============================================================================
// EtsEnum Derive Macro
// ============================================================================

/// Derive macro for generating ETS enum definitions from simple Rust enums.
///
/// Use this for `#[repr(u8)]` enums without data fields. These become dropdown
/// parameters in ETS and can be used as field types in `EtsParams` structs
/// or `EtsUnion` variants.
///
/// # Requirements
///
/// - Enum must have `#[repr(u8)]` (or `#[repr(u16)]` for larger enums)
/// - All variants must be unit variants (no data)
/// - Explicit discriminant values are recommended for stability
///
/// # Generated Items
///
/// - `ETS_VARIANTS: &[EtsEnumVariant]` - Enum variants for ETS dropdown
/// - `ETS_SIZE_BITS: u8` - Size in bits (8 for repr(u8), 16 for repr(u16))
/// - `EtsEnumType` trait implementation
/// - `Display` trait implementation (uses `#[ets(display = "...")]` values)
///
/// # Example
///
/// ```rust,ignore
/// #[derive(EtsEnum)]
/// #[repr(u8)]
/// pub enum SensorType {
///     #[ets(display = "PT100")]
///     Pt100 = 0,
///     #[ets(display = "PT1000")]
///     Pt1000 = 1,
///     #[ets(display = "NTC 10K")]
///     Ntc10K = 2,
/// }
///
/// // Use in EtsUnion variants:
/// #[derive(EtsUnion)]
/// #[repr(C, u8)]
/// pub enum InputSource {
///     Temperature {
///         sensor_type: SensorType,  // Gets dropdown in ETS
///         offset: i8,
///     },
/// }
/// ```
#[proc_macro_derive(EtsEnum, attributes(ets))]
pub fn derive_ets_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match derive_ets_enum_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn derive_ets_enum_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let enum_name = &input.ident;

    // Must be an enum
    let variants = match &input.data {
        Data::Enum(data) => &data.variants,
        _ => return Err(syn::Error::new_spanned(
            input,
            "EtsEnum can only be derived for enums"
        )),
    };

    // Check for #[repr(u8)] or #[repr(u16)]
    let mut repr_size: usize = 0;
    for attr in &input.attrs {
        if attr.path().is_ident("repr") {
            let tokens = attr.meta.require_list()?.tokens.to_string();
            if tokens.contains("u8") {
                repr_size = 1;
            } else if tokens.contains("u16") {
                repr_size = 2;
            }
        }
    }

    if repr_size == 0 {
        return Err(syn::Error::new_spanned(
            input,
            "EtsEnum requires #[repr(u8)] or #[repr(u16)] for predictable memory layout"
        ));
    }

    // Generate variant definitions and display match arms
    let mut enum_variants = Vec::new();
    let mut display_arms = Vec::new();
    let mut current_discriminant: i64 = 0;

    for variant in variants.iter() {
        // Must be unit variant
        if !matches!(&variant.fields, syn::Fields::Unit) {
            return Err(syn::Error::new_spanned(
                variant,
                "EtsEnum only supports unit variants (no data fields). Use EtsUnion for variants with data."
            ));
        }

        let variant_ident = &variant.ident;

        // Get discriminant value
        let discriminant = if let Some((_, expr)) = &variant.discriminant {
            if let syn::Expr::Lit(lit) = expr {
                if let syn::Lit::Int(int) = &lit.lit {
                    let val: i64 = int.base10_parse()?;
                    current_discriminant = val;
                    val
                } else {
                    return Err(syn::Error::new_spanned(expr, "Expected integer discriminant"));
                }
            } else {
                return Err(syn::Error::new_spanned(expr, "Expected literal discriminant"));
            }
        } else {
            let val = current_discriminant;
            current_discriminant += 1;
            val
        };

        // Parse variant attributes for display name
        let variant_attrs = parse_variant_attrs(&variant.attrs)?;
        let display_name = variant_attrs.display.unwrap_or_else(|| {
            // Convert CamelCase to Title Case with spaces
            let name = variant.ident.to_string();
            let mut result = String::new();
            for (i, c) in name.chars().enumerate() {
                if i > 0 && c.is_uppercase() {
                    result.push(' ');
                }
                result.push(c);
            }
            result
        });

        enum_variants.push(quote! {
            zweidraehte::ets::EtsEnumVariant {
                text: #display_name,
                value: #discriminant,
            }
        });

        // Generate Display match arm
        display_arms.push(quote! {
            Self::#variant_ident => write!(f, #display_name)
        });

        current_discriminant = discriminant + 1;
    }

    let size_bits = (repr_size * 8) as u8;

    Ok(quote! {
        impl #enum_name {
            /// ETS enum variants for dropdown display.
            pub const ETS_VARIANTS: &'static [zweidraehte::ets::EtsEnumVariant] = &[
                #(#enum_variants),*
            ];

            /// Size of this enum in bits (for ETS parameter definition).
            pub const ETS_SIZE_BITS: u8 = #size_bits;
        }

        impl zweidraehte::ets::EtsEnumType for #enum_name {
            fn ets_variants() -> &'static [zweidraehte::ets::EtsEnumVariant] {
                Self::ETS_VARIANTS
            }

            fn ets_size_bytes() -> usize {
                #repr_size
            }
        }

        impl core::fmt::Display for #enum_name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    #(#display_arms),*
                }
            }
        }
    })
}

// ============================================================================
// EtsComObjects Derive Macro
// ============================================================================

/// Derive macro for generating KNX communication objects with ETS metadata.
///
/// This macro replaces the `define_com_objects!` declarative macro with a more
/// powerful proc macro that supports:
/// - ComObjectRef definitions (same object with different DPT/size interpretations)
/// - Selector-based typed access (match on selector to get correctly typed refs)
/// - Auto-derived storage size for multi-ref objects
/// - Zero-overhead type-safe accessors
///
/// # Basic Usage
///
/// ```rust,ignore
/// use ets_macros::EtsComObjects;
/// use zweidraehte::dpt::*;
///
/// #[derive(EtsComObjects)]
/// pub struct MyComObjects {
///     /// Simple switch input
///     #[ets(index = 1, display = "Switch Input", function = "On/Off")]
///     pub switch_in: DPT_Switch,
///
///     /// Temperature value
///     #[ets(index = 2, display = "Temperature")]
///     pub temperature: DPT_Value_Temp,
/// }
/// ```
///
/// # Multi-Ref Objects (ComObjectRefs)
///
/// For objects that can have different DPT interpretations based on ETS parameters:
///
/// ```rust,ignore
/// #[derive(EtsComObjects)]
/// #[ets(selector_enum = ButtonMode)]
/// pub struct MyComObjects {
///     /// Multi-type output controlled by button_mode parameter
///     #[ets(index = 1, display = "Output", flags = 0x5F)]
///     #[ets_ref(dpt = DPT_Switch, when = ButtonMode::Switch)]
///     #[ets_ref(dpt = DPT_Scaling, when = ButtonMode::Dimmer)]
///     pub output: (),  // Placeholder - replaced with ComObjectStorage<N>
/// }
///
/// // Generated: ButtonModeObjs enum for typed access
/// match params.button_mode.comm_objects(&mut objs) {
///     ButtonModeObjs::Switch { output, .. } => {
///         // output is TypedComObj<DPT_Switch, 1>
///     }
///     ButtonModeObjs::Dimmer { output, .. } => {
///         // output is TypedComObj<DPT_Scaling, 1>
///     }
/// }
/// ```
///
/// # Attributes
///
/// ## On struct:
/// - `#[ets(manual_impl)]` - Don't generate `ComObjects` trait impl
/// - `#[ets(selector_enum = EnumType)]` - Generate selector-based typed access
///
/// ## On fields (base object):
/// - `#[ets(index = N)]` - **Required**. ASAP index for this comm object
/// - `#[ets(display = "...")]` - Human-readable name for ETS
/// - `#[ets(function = "...")]` - Function text (for simple objects)
/// - `#[ets(flags = 0xNN)]` - Default flags byte (default: 0xDF)
///
/// ## On multi-ref fields:
/// - `#[ets_ref(dpt = TYPE, when = Selector::Variant)]` - Define a ref for a variant
/// - `#[ets_ref(..., function = "...")]` - Function text for this ref
/// - `#[ets_ref(..., read = true/false)]` - Override read flag
/// - `#[ets_ref(..., write = true/false)]` - Override write flag
/// - etc. for other flags
#[proc_macro_derive(EtsComObjects, attributes(ets, ets_ref))]
pub fn derive_ets_com_objects(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match derive_ets_com_objects_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Parsed struct-level attributes for EtsComObjects
struct ComObjectsStructAttrs {
    /// Don't generate ComObjects trait impl
    manual_impl: bool,
    /// Selector enum type for generating variant struct
    selector_enum: Option<syn::Type>,
}

/// Parsed field-level attributes for a comm object
struct ComObjectFieldAttrs {
    /// ASAP index (required)
    index: Option<u16>,
    /// Name override for ETS (defaults to field name)
    name: Option<String>,
    /// Display name for ETS (Text attribute in XML)
    display: Option<String>,
    /// Function text
    function: Option<String>,
    /// Default flags byte
    flags: Option<u8>,
    /// Name of the parameter that selects which ref is active (for multi-ref objects)
    selector_param: Option<String>,
    /// Object size override (e.g., "4 Bytes", "1 Bit")
    object_size: Option<String>,
}

/// Selector value for when a ComObjectRef is active.
/// Can be either an enum path (like `OutputConfig::Switch`) or a literal integer.
enum SelectorValue {
    /// Enum path - will be cast to i64
    Path(syn::Path),
    /// Direct integer value
    Int(i64),
}

/// Parsed ets_ref attribute
struct ComObjectRefAttrs {
    /// DPT type for this ref
    dpt: syn::Type,
    /// Selector value this ref is active for (e.g., ButtonMode::Switch or 1)
    when: Option<SelectorValue>,
    /// Unique name for this ref (for direct referencing in page layout)
    ref_name: Option<String>,
    /// Text override (display name for this ref, used for different UI contexts)
    text: Option<String>,
    /// Function text override
    function: Option<String>,
    /// Flag overrides
    read: Option<bool>,
    write: Option<bool>,
    communication: Option<bool>,
    transmit: Option<bool>,
    update: Option<bool>,
    read_on_init: Option<bool>,
}

fn parse_com_objects_struct_attrs(attrs: &[Attribute]) -> syn::Result<ComObjectsStructAttrs> {
    let mut result = ComObjectsStructAttrs {
        manual_impl: false,
        selector_enum: None,
    };

    for attr in attrs {
        if !attr.path().is_ident("ets") {
            continue;
        }

        let tokens = attr.meta.require_list()?.tokens.clone();
        let parser = |input: ParseStream| {
            while !input.is_empty() {
                let ident: syn::Ident = input.parse()?;

                if ident == "manual_impl" {
                    result.manual_impl = true;
                } else if ident == "selector_enum" {
                    input.parse::<Token![=]>()?;
                    result.selector_enum = Some(input.parse()?);
                }

                let _ = input.parse::<Option<Token![,]>>();
            }
            Ok(())
        };

        syn::parse::Parser::parse2(parser, tokens)?;
    }

    Ok(result)
}

fn parse_com_object_field_attrs(attrs: &[Attribute]) -> syn::Result<ComObjectFieldAttrs> {
    let mut result = ComObjectFieldAttrs {
        index: None,
        name: None,
        display: None,
        function: None,
        flags: None,
        selector_param: None,
        object_size: None,
    };

    for attr in attrs {
        if !attr.path().is_ident("ets") {
            continue;
        }

        let tokens = attr.meta.require_list()?.tokens.clone();
        let parser = |input: ParseStream| {
            while !input.is_empty() {
                let ident: syn::Ident = input.parse()?;

                if ident == "index" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitInt = input.parse()?;
                    result.index = Some(value.base10_parse()?);
                } else if ident == "display" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.display = Some(value.value());
                } else if ident == "function" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.function = Some(value.value());
                } else if ident == "flags" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitInt = input.parse()?;
                    result.flags = Some(value.base10_parse()?);
                } else if ident == "selector_param" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.selector_param = Some(value.value());
                } else if ident == "name" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.name = Some(value.value());
                } else if ident == "object_size" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.object_size = Some(value.value());
                }

                let _ = input.parse::<Option<Token![,]>>();
            }
            Ok(())
        };

        syn::parse::Parser::parse2(parser, tokens)?;
    }

    Ok(result)
}

fn parse_ets_ref_attrs(attrs: &[Attribute]) -> syn::Result<Vec<ComObjectRefAttrs>> {
    let mut refs = Vec::new();

    for attr in attrs {
        if !attr.path().is_ident("ets_ref") {
            continue;
        }

        let tokens = attr.meta.require_list()?.tokens.clone();
        let mut ref_attr = ComObjectRefAttrs {
            dpt: syn::parse_quote!(()),
            when: None,
            ref_name: None,
            text: None,
            function: None,
            read: None,
            write: None,
            communication: None,
            transmit: None,
            update: None,
            read_on_init: None,
        };

        let parser = |input: ParseStream| {
            while !input.is_empty() {
                let ident: syn::Ident = input.parse()?;

                if ident == "dpt" {
                    input.parse::<Token![=]>()?;
                    ref_attr.dpt = input.parse()?;
                } else if ident == "when" {
                    input.parse::<Token![=]>()?;
                    // Try to parse as integer literal first, then as path
                    if input.peek(syn::LitInt) {
                        let lit: syn::LitInt = input.parse()?;
                        ref_attr.when = Some(SelectorValue::Int(lit.base10_parse()?));
                    } else {
                        let path: syn::Path = input.parse()?;
                        ref_attr.when = Some(SelectorValue::Path(path));
                    }
                } else if ident == "ref_name" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    ref_attr.ref_name = Some(value.value());
                } else if ident == "text" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    ref_attr.text = Some(value.value());
                } else if ident == "function" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    ref_attr.function = Some(value.value());
                } else if ident == "read" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitBool = input.parse()?;
                    ref_attr.read = Some(value.value);
                } else if ident == "write" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitBool = input.parse()?;
                    ref_attr.write = Some(value.value);
                } else if ident == "communication" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitBool = input.parse()?;
                    ref_attr.communication = Some(value.value);
                } else if ident == "transmit" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitBool = input.parse()?;
                    ref_attr.transmit = Some(value.value);
                } else if ident == "update" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitBool = input.parse()?;
                    ref_attr.update = Some(value.value);
                } else if ident == "read_on_init" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitBool = input.parse()?;
                    ref_attr.read_on_init = Some(value.value);
                }

                let _ = input.parse::<Option<Token![,]>>();
            }
            Ok(())
        };

        syn::parse::Parser::parse2(parser, tokens)?;
        refs.push(ref_attr);
    }

    Ok(refs)
}

/// Information about a field in the comm objects struct
struct ComObjectField {
    /// Field identifier
    ident: syn::Ident,
    /// Field type as declared (ComObject<T> or just T)
    ty: syn::Type,
    /// Inner type (the T in ComObject<T>, or the type itself if not wrapped)
    inner_ty: syn::Type,
    /// Parsed #[ets(...)] attributes
    attrs: ComObjectFieldAttrs,
    /// Parsed #[ets_ref(...)] attributes (empty for simple objects)
    refs: Vec<ComObjectRefAttrs>,
    /// Whether this object has ets_ref attributes
    has_refs: bool,
    /// Whether this is a multi-DPT object (has selector_param, uses ComObjectStorage)
    is_multi_dpt: bool,
}

/// Extract inner type from ComObject<T> or return the type as-is
fn extract_inner_type(ty: &syn::Type) -> syn::Type {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "ComObject" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                        return inner.clone();
                    }
                }
            }
        }
    }
    ty.clone()
}

fn derive_ets_com_objects_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_name = &input.ident;

    // Parse struct-level attributes
    let struct_attrs = parse_com_objects_struct_attrs(&input.attrs)?;

    // Extract fields from struct
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => return Err(syn::Error::new_spanned(
                input,
                "EtsComObjects can only be derived for structs with named fields"
            )),
        },
        _ => return Err(syn::Error::new_spanned(
            input,
            "EtsComObjects can only be derived for structs"
        )),
    };

    // Parse all fields
    let mut com_objects: Vec<ComObjectField> = Vec::new();

    for field in fields.iter() {
        let field_ident = field.ident.as_ref().unwrap().clone();
        let field_ty = field.ty.clone();
        let inner_ty = extract_inner_type(&field_ty);
        let attrs = parse_com_object_field_attrs(&field.attrs)?;
        let refs = parse_ets_ref_attrs(&field.attrs)?;

        // Validate index is present
        if attrs.index.is_none() {
            return Err(syn::Error::new_spanned(
                field,
                "EtsComObjects fields must have #[ets(index = N)]"
            ));
        }

        let has_refs = !refs.is_empty();
        // Multi-DPT objects have selector_param and use ComObjectStorage for runtime type selection
        let is_multi_dpt = attrs.selector_param.is_some();

        com_objects.push(ComObjectField {
            ident: field_ident,
            ty: field_ty,
            inner_ty,
            attrs,
            refs,
            has_refs,
            is_multi_dpt,
        });
    }

    // Generate the Index enum
    let index_variants: Vec<_> = com_objects.iter().map(|obj| {
        let name = to_camel_case(&obj.ident.to_string());
        let variant_ident = syn::Ident::new(&name, obj.ident.span());
        let index = obj.attrs.index.unwrap();
        quote! { #variant_ident = #index }
    }).collect();

    let index_from_arms: Vec<_> = com_objects.iter().map(|obj| {
        let name = to_camel_case(&obj.ident.to_string());
        let variant_ident = syn::Ident::new(&name, obj.ident.span());
        let index = obj.attrs.index.unwrap();
        quote! { #index => Some(Self::#variant_ident) }
    }).collect();

    // Generate info() match arms
    let info_arms: Vec<_> = com_objects.iter().map(|obj| {
        let name = to_camel_case(&obj.ident.to_string());
        let variant_ident = syn::Ident::new(&name, obj.ident.span());
        let field_ident = &obj.ident;
        quote! {
            Index::#variant_ident => zweidraehte::objects::comm::ComObjectInfo {
                status: &self.#field_ident.status,
                value: self.#field_ident.value.as_ref(),
            }
        }
    }).collect();

    // Generate info_mut() match arms
    let info_mut_arms: Vec<_> = com_objects.iter().map(|obj| {
        let name = to_camel_case(&obj.ident.to_string());
        let variant_ident = syn::Ident::new(&name, obj.ident.span());
        let field_ident = &obj.ident;
        quote! {
            Index::#variant_ident => zweidraehte::objects::comm::ComObjectInfoMut {
                status: &mut self.#field_ident.status,
                value: self.#field_ident.value.as_mut(),
            }
        }
    }).collect();

    // Generate new() field initializers
    let new_fields: Vec<_> = com_objects.iter().map(|obj| {
        let ident = &obj.ident;
        if obj.is_multi_dpt {
            // Multi-DPT objects use ComObjectStorage for runtime type selection
            quote! {
                #ident: zweidraehte::objects::comm::ComObject::new(
                    zweidraehte::objects::comm::ComObjectStorage::new()
                )
            }
        } else {
            // Single-DPT objects (including same-DPT multi-ref) use the declared inner type
            let inner_ty = &obj.inner_ty;
            quote! {
                #ident: zweidraehte::objects::comm::ComObject::new(<#inner_ty>::default())
            }
        }
    }).collect();

    // Generate ETS_COMM_OBJECTS const array
    let ets_comm_objects: Vec<_> = com_objects.iter().map(|obj| {
        let index = obj.attrs.index.unwrap();
        // Use name override if provided, otherwise use field ident
        let name = obj.attrs.name.clone().unwrap_or_else(|| obj.ident.to_string());
        let display_name = obj.attrs.display.clone().unwrap_or_else(|| {
            to_title_case(&obj.ident.to_string())
        });
        let function_text = obj.attrs.function.clone().unwrap_or_default();
        let default_flags = obj.attrs.flags.unwrap_or(0xDF);

        // Generate object_size_override expression
        let object_size_override_expr = if let Some(ref size) = obj.attrs.object_size {
            quote!(Some(#size))
        } else {
            quote!(None)
        };

        if obj.has_refs {
            // For objects with refs, use first ref's DPT info as base
            let first_ref_dpt = &obj.refs[0].dpt;
            quote! {
                zweidraehte::ets::EtsCommObjectDef {
                    index: #index,
                    name: #name,
                    display_name: #display_name,
                    function_text: #function_text,
                    dpt_main: <#first_ref_dpt as zweidraehte::ets::HasDptInfo>::DPT_MAIN,
                    dpt_sub: <#first_ref_dpt as zweidraehte::ets::HasDptInfo>::DPT_SUB,
                    size_bits: <#first_ref_dpt as zweidraehte::ets::HasDptInfo>::SIZE_BITS as u8,
                    default_flags: #default_flags,
                    object_size_override: #object_size_override_expr,
                }
            }
        } else {
            // Use inner_ty to extract DPT info (handles both ComObject<T> and bare T)
            let inner_ty = &obj.inner_ty;
            quote! {
                zweidraehte::ets::EtsCommObjectDef {
                    index: #index,
                    name: #name,
                    display_name: #display_name,
                    function_text: #function_text,
                    dpt_main: <#inner_ty as zweidraehte::ets::HasDptInfo>::DPT_MAIN,
                    dpt_sub: <#inner_ty as zweidraehte::ets::HasDptInfo>::DPT_SUB,
                    size_bits: <#inner_ty as zweidraehte::ets::HasDptInfo>::SIZE_BITS as u8,
                    default_flags: #default_flags,
                    object_size_override: #object_size_override_expr,
                }
            }
        }
    }).collect();

    // Generate ETS_COMM_OBJECT_REFS const array
    let mut ets_comm_object_refs: Vec<TokenStream2> = Vec::new();
    for obj in &com_objects {
        let index = obj.attrs.index.unwrap();
        let base_function = obj.attrs.function.clone().unwrap_or_default();

        if obj.has_refs {
            // Get the selector_param from the field attributes (if specified)
            let selector_param_tokens = if let Some(ref param_name) = obj.attrs.selector_param {
                quote!(Some(#param_name))
            } else {
                quote!(None)
            };

            let field_name = obj.ident.to_string();
            for ref_attr in &obj.refs {
                let ref_dpt = &ref_attr.dpt;
                // Use ref_name from attribute if specified, otherwise use field_name
                // This allows direct referencing of specific refs by name in page layout
                let ref_name = ref_attr.ref_name.clone().unwrap_or_else(|| field_name.clone());
                let function_text = ref_attr.function.clone().unwrap_or(base_function.clone());
                let text_tokens = if let Some(ref text) = ref_attr.text {
                    quote!(Some(#text))
                } else {
                    quote!(None)
                };
                // Only include selector info if the ref has a `when` attribute
                // Refs without `when` are unconditional and should NOT have selector_param
                let (selector_value, this_ref_selector_param) = match &ref_attr.when {
                    Some(SelectorValue::Path(path)) => {
                        // Cast the enum variant to i64 to get the discriminant value
                        (quote!(Some(#path as i64)), selector_param_tokens.clone())
                    }
                    Some(SelectorValue::Int(val)) => {
                        (quote!(Some(#val as i64)), selector_param_tokens.clone())
                    }
                    None => {
                        // No `when` = unconditional ref, clear selector_param
                        (quote!(None), quote!(None))
                    }
                };

                // Generate flag overrides
                let flag_overrides = if ref_attr.read.is_some() || ref_attr.write.is_some() ||
                    ref_attr.communication.is_some() || ref_attr.transmit.is_some() ||
                    ref_attr.update.is_some() || ref_attr.read_on_init.is_some()
                {
                    let read = opt_bool_to_tokens(ref_attr.read);
                    let write = opt_bool_to_tokens(ref_attr.write);
                    let communication = opt_bool_to_tokens(ref_attr.communication);
                    let transmit = opt_bool_to_tokens(ref_attr.transmit);
                    let update = opt_bool_to_tokens(ref_attr.update);
                    let read_on_init = opt_bool_to_tokens(ref_attr.read_on_init);
                    quote! {
                        Some(zweidraehte::ets::FlagOverrides {
                            read: #read,
                            write: #write,
                            communication: #communication,
                            transmit: #transmit,
                            update: #update,
                            read_on_init: #read_on_init,
                        })
                    }
                } else {
                    quote!(None)
                };

                ets_comm_object_refs.push(quote! {
                    zweidraehte::ets::EtsCommObjectRefDef {
                        object_index: #index,
                        ref_name: #ref_name,
                        text: #text_tokens,
                        function_text: #function_text,
                        dpt_main: <#ref_dpt as zweidraehte::ets::HasDptInfo>::DPT_MAIN,
                        dpt_sub: <#ref_dpt as zweidraehte::ets::HasDptInfo>::DPT_SUB,
                        size_bits: <#ref_dpt as zweidraehte::ets::HasDptInfo>::SIZE_BITS as u8,
                        flag_overrides: #flag_overrides,
                        selector_value: #selector_value,
                        selector_param: #this_ref_selector_param,
                    }
                });
            }
        } else {
            // Simple object - generate a single implicit ref
            let inner_ty = &obj.inner_ty;
            let ref_name = obj.ident.to_string();
            let function_text = obj.attrs.function.clone().unwrap_or_default();
            ets_comm_object_refs.push(quote! {
                zweidraehte::ets::EtsCommObjectRefDef {
                    object_index: #index,
                    ref_name: #ref_name,
                    text: None,
                    function_text: #function_text,
                    dpt_main: <#inner_ty as zweidraehte::ets::HasDptInfo>::DPT_MAIN,
                    dpt_sub: <#inner_ty as zweidraehte::ets::HasDptInfo>::DPT_SUB,
                    size_bits: <#inner_ty as zweidraehte::ets::HasDptInfo>::SIZE_BITS as u8,
                    flag_overrides: None,
                    selector_value: None,
                    selector_param: None,
                }
            });
        }
    }

    // Generate selector-based variant struct if selector_enum is specified
    let selector_impl = if let Some(selector_enum) = &struct_attrs.selector_enum {
        generate_selector_impl(struct_name, selector_enum, &com_objects)?
    } else {
        quote!()
    };

    // Generate ComObjects impl unless manual_impl is set
    let com_objects_impl = if struct_attrs.manual_impl {
        quote!()
    } else {
        quote! {
            impl zweidraehte::objects::comm::ComObjects for #struct_name {
                type Index = Index;
                type HookContext = ();

                fn new() -> Self {
                    Self {
                        #(#new_fields),*
                    }
                }

                fn info<'a>(&'a self, idx: u16) -> zweidraehte::objects::comm::ComObjectInfo<'a> {
                    match Index::from_index(idx).unwrap() {
                        #(#info_arms),*
                    }
                }

                fn info_mut<'a>(&'a mut self, idx: u16) -> zweidraehte::objects::comm::ComObjectInfoMut<'a> {
                    match Index::from_index(idx).unwrap() {
                        #(#info_mut_arms),*
                    }
                }
            }
        }
    };

    let num_objects = com_objects.len();

    // Generate __max_size helper if we have multi-dpt objects (using ComObjectStorage)
    let has_multi_dpt = com_objects.iter().any(|obj| obj.is_multi_dpt);
    let max_size_helper = if has_multi_dpt {
        quote! {
            impl #struct_name {
                /// Helper const fn to compute max of sizes
                #[doc(hidden)]
                const fn __max_size(sizes: &[usize]) -> usize {
                    let mut max = 0usize;
                    let mut i = 0;
                    while i < sizes.len() {
                        if sizes[i] > max {
                            max = sizes[i];
                        }
                        i += 1;
                    }
                    max
                }
            }
        }
    } else {
        quote!()
    };

    Ok(quote! {
        /// Enum with all communication object names and their indices
        #[allow(dead_code)]
        #[derive(core::marker::ConstParamTy, Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u16)]
        pub enum Index {
            #(#index_variants),*
        }

        #[allow(dead_code)]
        impl zweidraehte::objects::comm::ComObjectIndex for Index {
            fn from_index(idx: u16) -> Option<Self> {
                match idx {
                    #(#index_from_arms,)*
                    _ => None,
                }
            }

            fn index(&self) -> u16 {
                *self as u16
            }
        }

        #max_size_helper

        #com_objects_impl

        /// ETS communication object definitions for this module.
        #[allow(dead_code)]
        pub const ETS_COMM_OBJECTS: &[zweidraehte::ets::EtsCommObjectDef] = &[
            #(#ets_comm_objects),*
        ];

        /// ETS communication object reference definitions.
        #[allow(dead_code)]
        pub const ETS_COMM_OBJECT_REFS: &[zweidraehte::ets::EtsCommObjectRefDef] = &[
            #(#ets_comm_object_refs),*
        ];

        /// Number of communication objects in this module.
        #[allow(dead_code)]
        pub const NUM_COMM_OBJECTS: usize = #num_objects;

        #selector_impl
    })
}

/// Generate the selector-based variant struct and accessor method
fn generate_selector_impl(
    struct_name: &syn::Ident,
    selector_enum: &syn::Type,
    com_objects: &[ComObjectField],
) -> syn::Result<TokenStream2> {
    // Extract the enum name from the type
    let selector_name = match selector_enum {
        syn::Type::Path(p) => p.path.segments.last()
            .map(|s| s.ident.clone())
            .ok_or_else(|| syn::Error::new_spanned(selector_enum, "Invalid selector enum type"))?,
        _ => return Err(syn::Error::new_spanned(selector_enum, "Selector must be a path type")),
    };

    let objs_enum_name = syn::Ident::new(
        &format!("{}Objs", selector_name),
        selector_name.span(),
    );

    // Find all fields that have refs with `when` clauses matching this selector
    let mut selector_fields: Vec<(&ComObjectField, Vec<&ComObjectRefAttrs>)> = Vec::new();

    for obj in com_objects {
        let matching_refs: Vec<_> = obj.refs.iter()
            .filter(|r| {
                match &r.when {
                    Some(SelectorValue::Path(path)) => {
                        // Check if the path starts with the selector enum name
                        path.segments.first()
                            .map(|s| s.ident == selector_name)
                            .unwrap_or(false)
                    }
                    // Integer values don't match a specific selector enum
                    _ => false,
                }
            })
            .collect();

        if !matching_refs.is_empty() {
            selector_fields.push((obj, matching_refs));
        }
    }

    if selector_fields.is_empty() {
        return Ok(quote!());
    }

    // Collect unique variants from all refs
    let mut variants_map: std::collections::HashMap<String, Vec<(&ComObjectField, &ComObjectRefAttrs)>> =
        std::collections::HashMap::new();

    for (obj, refs) in &selector_fields {
        for ref_attr in refs {
            if let Some(SelectorValue::Path(path)) = &ref_attr.when {
                let variant_name = path.segments.last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                variants_map.entry(variant_name).or_default().push((obj, ref_attr));
            }
        }
    }

    // Generate enum variants
    let enum_variants: Vec<_> = variants_map.iter().map(|(variant_name, field_refs)| {
        let variant_ident = syn::Ident::new(variant_name, proc_macro2::Span::call_site());
        let field_defs: Vec<_> = field_refs.iter().map(|(obj, ref_attr)| {
            let field_ident = &obj.ident;
            let dpt_type = &ref_attr.dpt;
            let index = obj.attrs.index.unwrap();
            quote! {
                #field_ident: zweidraehte::objects::comm::TypedComObj<'a, #dpt_type, #index>
            }
        }).collect();

        quote! {
            #variant_ident {
                #(#field_defs),*
            }
        }
    }).collect();

    // Generate match arms for the accessor method
    let match_arms: Vec<_> = variants_map.iter().map(|(variant_name, field_refs)| {
        let variant_ident = syn::Ident::new(variant_name, proc_macro2::Span::call_site());
        let selector_variant = syn::Ident::new(variant_name, proc_macro2::Span::call_site());

        let field_inits: Vec<_> = field_refs.iter().map(|(obj, _ref_attr)| {
            let field_ident = &obj.ident;
            quote! {
                #field_ident: unsafe {
                    zweidraehte::objects::comm::TypedComObj::new(
                        objs.#field_ident.value.as_mut(),
                        &mut objs.#field_ident.status,
                    )
                }
            }
        }).collect();

        quote! {
            #selector_enum::#selector_variant => #objs_enum_name::#variant_ident {
                #(#field_inits),*
            }
        }
    }).collect();

    Ok(quote! {
        /// Generated enum with typed comm object references for each selector variant
        pub enum #objs_enum_name<'a> {
            #(#enum_variants),*
        }

        impl #selector_enum {
            /// Get typed comm object references based on this selector value
            pub fn comm_objects<'a>(&self, objs: &'a mut #struct_name) -> #objs_enum_name<'a> {
                match self {
                    #(#match_arms),*
                }
            }
        }
    })
}

/// Convert Option<bool> to tokens for FlagOverrides field
fn opt_bool_to_tokens(opt: Option<bool>) -> TokenStream2 {
    match opt {
        Some(true) => quote!(Some(true)),
        Some(false) => quote!(Some(false)),
        None => quote!(None),
    }
}

/// Convert snake_case to CamelCase
fn to_camel_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => String::new(),
            }
        })
        .collect()
}

/// Convert snake_case to Title Case (with spaces)
fn to_title_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
