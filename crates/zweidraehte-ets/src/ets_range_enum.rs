use quote::quote;
use syn::Token;

/// Input for ets_range_enum! macro
pub(crate) struct EtsRangeEnumInput {
    pub(crate) attrs: Vec<syn::Attribute>,
    pub(crate) vis: syn::Visibility,
    pub(crate) name: syn::Ident,
    pub(crate) type_name: Option<String>,
    pub(crate) range_start: i64,
    pub(crate) range_end: i64, // exclusive
    pub(crate) value_formula: ValueFormula,
    pub(crate) variant_prefix: String,
    pub(crate) display_suffix: String,
    pub(crate) default_index: i64,
}

#[derive(Clone)]
pub(crate) enum ValueFormula {
    /// Direct: value = index
    Direct,
    /// Percent to byte: value = round(index * 2.55)
    PercentToByte,
}

impl syn::parse::Parse for EtsRangeEnumInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        // Parse attributes
        let attrs = input.call(syn::Attribute::parse_outer)?;

        // Parse visibility
        let vis: syn::Visibility = input.parse()?;

        // Parse "enum"
        input.parse::<syn::Token![enum]>()?;

        // Parse name
        let name: syn::Ident = input.parse()?;

        // Parse braces content
        let content;
        syn::braced!(content in input);

        // Look for type_name in attrs
        let mut type_name = None;
        for attr in &attrs {
            if attr.path().is_ident("ets") {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("type_name") {
                        let _eq: syn::Token![=] = meta.input.parse()?;
                        let lit: syn::LitStr = meta.input.parse()?;
                        type_name = Some(lit.value());
                    }
                    Ok(())
                })?;
            }
        }

        // Parse "range"
        let range_kw: syn::Ident = content.parse()?;
        if range_kw != "range" {
            return Err(syn::Error::new(range_kw.span(), "expected 'range'"));
        }

        // Parse range start
        let range_start: syn::LitInt = content.parse()?;
        let range_start = range_start.base10_parse::<i64>()?;

        // Parse ".." or "..="
        let inclusive = if content.peek(syn::Token![..=]) {
            content.parse::<syn::Token![..=]>()?;
            true
        } else {
            content.parse::<syn::Token![..]>()?;
            false
        };

        // Parse range end
        let range_end: syn::LitInt = content.parse()?;
        let range_end = range_end.base10_parse::<i64>()?;
        let range_end = if inclusive { range_end + 1 } else { range_end };

        // Parse "=>"
        content.parse::<syn::Token![=>]>()?;

        // Check for formula identifier or direct
        let value_formula = if content.peek(syn::Ident) {
            let formula_name: syn::Ident = content.parse()?;
            match formula_name.to_string().as_str() {
                "percent_to_byte" => ValueFormula::PercentToByte,
                "direct" => ValueFormula::Direct,
                _ => {
                    return Err(syn::Error::new(
                        formula_name.span(),
                        "unknown formula, expected 'direct' or 'percent_to_byte'",
                    ));
                }
            }
        } else {
            ValueFormula::Direct
        };

        // Parse variant prefix and display suffix as a string pattern
        // Format: "Prefix{}" or "{}%" etc
        let pattern: syn::LitStr = content.parse()?;
        let pattern_str = pattern.value();

        // Parse the pattern - expect "{}" placeholder
        let (variant_prefix, display_suffix) = if let Some(idx) = pattern_str.find("{}") {
            (pattern_str[..idx].to_string(), pattern_str[idx + 2..].to_string())
        } else {
            return Err(syn::Error::new(pattern.span(), "pattern must contain '{}' placeholder"));
        };

        content.parse::<syn::Token![;]>()?;

        // Parse "default = N;"
        let default_kw: syn::Ident = content.parse()?;
        if default_kw != "default" {
            return Err(syn::Error::new(default_kw.span(), "expected 'default'"));
        }
        content.parse::<Token![=]>()?;
        let default_val: syn::LitInt = content.parse()?;
        let default_index = default_val.base10_parse::<i64>()?;
        content.parse::<syn::Token![;]>()?;

        Ok(EtsRangeEnumInput {
            attrs,
            vis,
            name,
            type_name,
            range_start,
            range_end,
            value_formula,
            variant_prefix,
            display_suffix,
            default_index,
        })
    }
}

pub(crate) fn generate_range_enum(input: EtsRangeEnumInput) -> syn::Result<proc_macro2::TokenStream> {
    let EtsRangeEnumInput {
        attrs,
        vis,
        name,
        type_name,
        range_start,
        range_end,
        value_formula,
        variant_prefix,
        display_suffix,
        default_index,
    } = input;

    // Filter out #[ets(...)] attributes - they're for us, not the enum
    let filtered_attrs: Vec<_> = attrs.iter().filter(|a| !a.path().is_ident("ets")).collect();

    let type_name_str = type_name.unwrap_or_else(|| name.to_string());

    // Generate variants
    let mut variant_defs = Vec::new();
    let mut variant_entries = Vec::new();
    let mut default_variant = None;

    for i in range_start..range_end {
        // For percentage: variant is P0, P1, ..., P100 and display is "0%", "1%", etc.
        // For scenes: variant is Scene1, Scene2, ..., Scene64 and display is "1", "2", etc.
        let variant_num = if display_suffix == "%" {
            i // P0, P1, P2...
        } else {
            i - range_start + 1 // Scene1, Scene2, ...
        };

        let display_text = if display_suffix == "%" {
            format!("{}{}", i, display_suffix) // "0%", "1%", "2%"...
        } else {
            format!("{}", i - range_start + 1) // "1", "2", "3"...
        };

        let value: i64 = match &value_formula {
            ValueFormula::Direct => i,
            ValueFormula::PercentToByte => ((i as f64) * 2.55).round() as i64,
        };

        let variant_name_str = format!("{}{}", variant_prefix, variant_num);
        let variant_name = syn::Ident::new(&variant_name_str, proc_macro2::Span::call_site());
        // The generated enum is `#[repr(u8)]`; a `Direct` formula over a range
        // that reaches >= 256 would silently wrap (`256 as u8 == 0`). Reject it.
        let value_lit = u8::try_from(value).map_err(|_| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("range_enum variant value {value} does not fit in u8; adjust the range or formula"),
            )
        })?;

        let is_default = i == default_index;
        if is_default {
            default_variant = Some(variant_name.clone());
            variant_defs.push(quote! {
                #[default]
                #variant_name = #value_lit
            });
        } else {
            variant_defs.push(quote! {
                #variant_name = #value_lit
            });
        }

        variant_entries.push(quote! {
            zweidraehte_ets_model::EtsEnumVariant { text: #display_text, variant_name: #variant_name_str, value: #value }
        });
    }

    let default_variant = default_variant
        .ok_or_else(|| syn::Error::new(proc_macro2::Span::call_site(), "default index not within range"))?;

    let num_variants = (range_end - range_start) as usize;
    let size_bits: u16 = if num_variants <= 2 {
        1
    } else if num_variants <= 4 {
        2
    } else if num_variants <= 16 {
        4
    } else if num_variants <= 256 {
        8
    } else {
        16
    };

    Ok(quote! {
        #(#filtered_attrs)*
        #[repr(u8)]
        #[derive(Default)]
        #vis enum #name {
            #(#variant_defs),*
        }

        impl #name {
            /// ETS type name for this enum
            pub const ETS_TYPE_NAME: &'static str = #type_name_str;

            /// Number of bits needed to represent this enum
            pub const ETS_SIZE_BITS: u16 = #size_bits;

            /// ETS variant definitions for parameter generation
            pub const ETS_VARIANTS: &'static [zweidraehte_ets_model::EtsEnumVariant] = &[
                #(#variant_entries),*
            ];
        }

        impl const_default::ConstDefault for #name {
            const DEFAULT: Self = Self::#default_variant;
        }
    })
}
