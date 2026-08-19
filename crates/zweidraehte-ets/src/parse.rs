/// Shared attribute-parsing types and helpers used by more than one macro.
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Attribute, Expr, Lit, Token, Type,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

// ============================================================================
// EnumVariantDef / EnumVariantList
// ============================================================================

/// A single enum variant: "Name" => value
pub(crate) struct EnumVariantDef {
    pub(crate) text: String,
    pub(crate) value: i64,
}

impl Parse for EnumVariantDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let text: syn::LitStr = input.parse()?;
        input.parse::<Token![=>]>()?;
        let value: syn::LitInt = input.parse()?;
        Ok(EnumVariantDef { text: text.value(), value: value.base10_parse()? })
    }
}

/// List of enum variants: ("Off" => 0, "On" => 1)
pub(crate) struct EnumVariantList {
    pub(crate) variants: Vec<EnumVariantDef>,
}

impl Parse for EnumVariantList {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let variants: Punctuated<EnumVariantDef, Token![,]> =
            input.parse_terminated(EnumVariantDef::parse, Token![,])?;
        Ok(EnumVariantList { variants: variants.into_iter().collect() })
    }
}

// ============================================================================
// FieldAttrs / parse_field_attrs
// Used by: ets_params, ets_union
// ============================================================================

/// Parsed field attributes
pub(crate) struct FieldAttrs {
    pub(crate) display: Option<String>,
    pub(crate) suffix: Option<String>,
    pub(crate) skip: bool,
    pub(crate) bits: Option<u8>,
    pub(crate) bit_offset: Option<u8>,
    pub(crate) enum_variants: Option<Vec<EnumVariantDef>>,
    /// Marks this field as a union type
    pub(crate) union_field: bool,
    /// Marks this field as an EtsEnum type (simple enum with no data)
    pub(crate) ets_enum_field: bool,
    /// Marks this field as a string/text type (for [u8; N] arrays)
    pub(crate) string_field: bool,
    /// Marks this field as hidden (Access="None" in ETS)
    pub(crate) hidden: bool,
    /// Marks this parameter as tool-only: ETS shows and persists it, but it is
    /// never downloaded, so it occupies no device memory. The field is dropped
    /// from the emitted struct entirely — see the `#[ets_params]` docs.
    pub(crate) no_memory: bool,
    /// Override for the ParameterType name in ETS export
    pub(crate) type_name: Option<String>,
    /// Default value for this field
    pub(crate) default_value: Option<i64>,
    /// Pattern for TypeText parameters (regex with optional comment)
    pub(crate) text_pattern: Option<String>,
    /// Marks this parameter as the source for `{{0}}` text template substitution in modules
    pub(crate) text_source: bool,
    /// Marks this field as containing module instances (array of module params).
    /// The type should be the module type (e.g., DimmerChannelModule).
    pub(crate) module_type: Option<syn::Type>,
}

pub(crate) fn parse_field_attrs(attrs: &[Attribute]) -> syn::Result<FieldAttrs> {
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
        no_memory: false,
        type_name: None,
        default_value: None,
        text_pattern: None,
        text_source: false,
        module_type: None,
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
                } else if ident == "no_memory" {
                    result.no_memory = true;
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
                } else if ident == "text_source" {
                    result.text_source = true;
                } else if ident == "module" {
                    // Parse: module = ModuleType
                    input.parse::<Token![=]>()?;
                    result.module_type = Some(input.parse()?);
                } else {
                    // Reject unknown keys rather than silently skipping them: a
                    // typo like `#[ets(displaj = "Foo")]` would otherwise be a
                    // no-op, producing wrong ETS metadata with no diagnostic.
                    return Err(syn::Error::new(ident.span(), format!("unknown `#[ets(...)]` key `{ident}`")));
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

// ============================================================================
// VariantAttrs / parse_variant_attrs
// Used by: ets_union, ets_enum
// ============================================================================

/// Parsed variant attributes
pub(crate) struct VariantAttrs {
    pub(crate) display: Option<String>,
    pub(crate) is_default: bool,
    pub(crate) skip: bool,
}

/// Parse variant-level attributes
pub(crate) fn parse_variant_attrs(attrs: &[Attribute]) -> syn::Result<VariantAttrs> {
    let mut result = VariantAttrs { display: None, is_default: false, skip: false };

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
                } else if ident == "default_variant" {
                    // Mark this variant as the default for Default/ConstDefault generation
                    result.is_default = true;
                } else if ident == "skip" {
                    // Skip this variant from ETS metadata generation
                    result.skip = true;
                } else {
                    return Err(syn::Error::new(ident.span(), format!("unknown `#[ets(...)]` variant key `{ident}`")));
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

// ============================================================================
// TypeInfo / get_type_info / get_const_zero_expr / get_type_size
// Used by: ets_params and ets_union (get_type_info, get_const_zero_expr, get_type_size)
// ============================================================================

pub(crate) struct TypeInfo {
    pub(crate) size_bytes: usize,
    /// Mirrors `EtsParamDef::size_bits`, which is `u16` so that text
    /// parameters wider than 31 characters remain expressible.
    pub(crate) size_bits: u16,
    pub(crate) align: usize,
    pub(crate) param_type: TokenStream2,
}

pub(crate) fn get_type_info(ty: &Type) -> syn::Result<TypeInfo> {
    match ty {
        Type::Path(type_path) => {
            let segment =
                type_path.path.segments.last().ok_or_else(|| syn::Error::new_spanned(ty, "Empty type path"))?;

            let ident_str = segment.ident.to_string();

            match ident_str.as_str() {
                "u8" => Ok(TypeInfo {
                    size_bytes: 1,
                    size_bits: 8,
                    align: 1,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::UnsignedInt),
                }),
                "u16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    align: 2,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::UnsignedInt),
                }),
                "u32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    align: 4,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::UnsignedInt),
                }),
                "i8" => Ok(TypeInfo {
                    size_bytes: 1,
                    size_bits: 8,
                    align: 1,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::SignedInt),
                }),
                "i16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    align: 2,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::SignedInt),
                }),
                "i32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    align: 4,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::SignedInt),
                }),
                "bool" => Ok(TypeInfo {
                    size_bytes: 1,
                    size_bits: 1,
                    align: 1,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::UnsignedInt),
                }),
                // Big-endian types - KNX uses big-endian for parameter storage
                // BeU16/BeU32/etc are custom wrappers with serde support
                // BigU16/U16/etc are from zerocopy::big_endian
                "BeU16" | "BigU16" | "U16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    align: 1, // [u8; 2] has alignment 1
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::UnsignedInt),
                }),
                "BeU32" | "BigU32" | "U32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    align: 1, // [u8; 4] has alignment 1
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::UnsignedInt),
                }),
                "BeI16" | "BigI16" | "I16" => Ok(TypeInfo {
                    size_bytes: 2,
                    size_bits: 16,
                    align: 1,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::SignedInt),
                }),
                "BeI32" | "BigI32" | "I32" => Ok(TypeInfo {
                    size_bytes: 4,
                    size_bits: 32,
                    align: 1,
                    param_type: quote!(zweidraehte_ets_model::EtsParamType::SignedInt),
                }),
                _ => {
                    // Unknown type - treat as raw bytes
                    // Could be a custom enum or struct
                    Err(syn::Error::new_spanned(
                        ty,
                        format!("Unsupported type '{}'. Use u8, u16, u32, i8, i16, i32, bool, or [u8; N]", ident_str),
                    ))
                }
            }
        }
        Type::Array(array) => {
            // Handle [u8; N] arrays
            if let Type::Path(inner) = array.elem.as_ref()
                && inner.path.is_ident("u8")
            {
                // Extract array length
                if let Expr::Lit(lit) = &array.len
                    && let Lit::Int(int) = &lit.lit
                {
                    let len: usize = int.base10_parse()?;
                    // `size_bits` is a u16; a `[u8; N]` with N >= 8192 would
                    // overflow it and silently truncate, producing a wrongly
                    // sized ETS descriptor. Reject it instead. The bound is far
                    // above any real text parameter — ETS master data tops out
                    // at `String_40Byte` — so this only guards against a typo.
                    let size_bits = u16::try_from(len * 8).map_err(|_| {
                        syn::Error::new_spanned(
                            ty,
                            format!("[u8; {len}] exceeds 65535 bits; ETS size_bits cannot represent it"),
                        )
                    })?;
                    return Ok(TypeInfo {
                        size_bytes: len,
                        size_bits,
                        align: 1, // [u8; N] has alignment of 1
                        param_type: quote!(zweidraehte_ets_model::EtsParamType::None),
                    });
                }
            }
            Err(syn::Error::new_spanned(ty, "Only [u8; N] arrays are supported"))
        }
        _ => Err(syn::Error::new_spanned(ty, "Unsupported type")),
    }
}

/// Generate a const-compatible zero expression for a given type.
/// This is used by derive_defaults to generate zero values in const contexts.
pub(crate) fn get_const_zero_expr(ty: &Type) -> TokenStream2 {
    match ty {
        Type::Path(type_path) => {
            if let Some(segment) = type_path.path.segments.last() {
                let ident_str = segment.ident.to_string();
                match ident_str.as_str() {
                    "u8" | "u16" | "u32" | "u64" | "usize" | "i8" | "i16" | "i32" | "i64" | "isize" => quote!(0),
                    "bool" => quote!(false),
                    // For unknown types (custom structs/enums), try ConstDefault
                    _ => quote!(<#ty as const_default::ConstDefault>::DEFAULT),
                }
            } else {
                // Fallback to ConstDefault
                quote!(<#ty as const_default::ConstDefault>::DEFAULT)
            }
        }
        Type::Array(array) => {
            // For [u8; N], generate [0u8; N]
            let elem = &array.elem;
            let len = &array.len;
            if matches!(elem.as_ref(), Type::Path(p) if p.path.is_ident("u8")) {
                quote!([0u8; #len])
            } else {
                // For other array types, use ConstDefault
                quote!(<#ty as const_default::ConstDefault>::DEFAULT)
            }
        }
        _ => {
            // Fallback to ConstDefault
            quote!(<#ty as const_default::ConstDefault>::DEFAULT)
        }
    }
}

pub(crate) fn get_type_size(ty: &Type) -> syn::Result<usize> {
    Ok(get_type_info(ty)?.size_bytes)
}
