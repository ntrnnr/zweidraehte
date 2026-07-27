use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput};

use crate::parse::parse_variant_attrs;

pub(crate) fn derive_ets_enum_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let enum_name = &input.ident;

    // Must be an enum
    let variants = match &input.data {
        Data::Enum(data) => &data.variants,
        _ => return Err(syn::Error::new_spanned(input, "EtsEnum can only be derived for enums")),
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
            "EtsEnum requires #[repr(u8)] or #[repr(u16)] for predictable memory layout",
        ));
    }

    // Generate variant definitions and display match arms
    let mut enum_variants = Vec::new();
    let mut display_arms = Vec::new();
    let mut next_discriminant: i64 = 0;
    let mut default_variant_ident: Option<&syn::Ident> = None;

    for variant in variants.iter() {
        // Must be unit variant
        if !matches!(&variant.fields, syn::Fields::Unit) {
            return Err(syn::Error::new_spanned(
                variant,
                "EtsEnum only supports unit variants (no data fields). Use EtsUnion for variants with data.",
            ));
        }

        let variant_ident = &variant.ident;

        // Check for #[default] attribute
        for attr in &variant.attrs {
            if attr.path().is_ident("default") {
                default_variant_ident = Some(variant_ident);
            }
        }

        // Get discriminant value (explicit or auto-incrementing)
        let discriminant = if let Some((_, expr)) = &variant.discriminant {
            if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(int), .. }) = expr {
                int.base10_parse()?
            } else {
                return Err(syn::Error::new_spanned(expr, "Expected integer literal discriminant"));
            }
        } else {
            next_discriminant
        };
        next_discriminant = discriminant + 1;

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

        let variant_name_str = variant_ident.to_string();
        enum_variants.push(quote! {
            zweidraehte_device::ets::EtsEnumVariant {
                text: #display_name,
                variant_name: #variant_name_str,
                value: #discriminant,
            }
        });

        // Generate Display match arm
        display_arms.push(quote! {
            Self::#variant_ident => write!(f, #display_name)
        });
    }

    let size_bits = (repr_size * 8) as u16;

    // Generate ConstDefault impl if a #[default] variant was found
    let const_default_impl = if let Some(default_ident) = default_variant_ident {
        quote! {
            impl ::const_default::ConstDefault for #enum_name {
                const DEFAULT: Self = Self::#default_ident;
            }
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        impl #enum_name {
            /// ETS enum variants for dropdown display.
            pub const ETS_VARIANTS: &'static [zweidraehte_device::ets::EtsEnumVariant] = &[
                #(#enum_variants),*
            ];

            /// Size of this enum in bits (for ETS parameter definition).
            pub const ETS_SIZE_BITS: u16 = #size_bits;
        }

        impl zweidraehte_device::ets::EtsEnumType for #enum_name {
            fn ets_variants() -> &'static [zweidraehte_device::ets::EtsEnumVariant] {
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

        #const_default_impl
    })
}
