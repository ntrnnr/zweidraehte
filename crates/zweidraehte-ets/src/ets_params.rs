use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::parse::{get_const_zero_expr, get_type_info, parse_field_attrs};

pub(crate) fn derive_ets_params_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_name = &input.ident;

    // Extract fields from struct
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "EtsParams can only be derived for structs with named fields",
                ));
            }
        },
        _ => return Err(syn::Error::new_spanned(input, "EtsParams can only be derived for structs")),
    };

    // Generate parameter definitions using core::mem::offset_of! for accurate offsets.
    // This handles all alignment and union sizing correctly at const-eval time.
    let mut param_defs = Vec::new();
    let mut param_ext_defs = Vec::new();
    let mut enum_variant_consts = Vec::new();
    let mut union_field_entries = Vec::new();
    // Track field names, types, and default expressions for generating Default/ConstDefault impls
    let mut field_defaults: Vec<(syn::Ident, syn::Type, TokenStream2)> = Vec::new();
    // Track module fields for generating helper methods
    // (field_name, field_type, module_type, array_len)
    let mut module_fields: Vec<(syn::Ident, syn::Type, syn::Type, Option<syn::Expr>)> = Vec::new();

    for field in fields.iter() {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;

        // Parse field attributes
        let attrs = parse_field_attrs(&field.attrs)?;

        // Determine the default value expression for this field.
        //
        // Tool-only parameters are absent from the emitted struct, so they take
        // no part in `Default` / `ConstDefault` — there is no field to
        // initialise. Their ETS default comes from the metadata below instead.
        if !attrs.no_memory {
            let default_expr = if attrs.skip {
                // Skip fields use const-compatible zeroing
                get_const_zero_expr(field_type)
            } else if attrs.union_field {
                // Union fields use their type's ConstDefault
                quote!(<#field_type as const_default::ConstDefault>::DEFAULT)
            } else if attrs.ets_enum_field {
                // EtsEnum fields use their type's ConstDefault
                quote!(<#field_type as const_default::ConstDefault>::DEFAULT)
            } else if attrs.module_type.is_some() {
                // Module fields use their type's ConstDefault (array of module params)
                quote!(<#field_type as const_default::ConstDefault>::DEFAULT)
            } else if let Some(default_val) = attrs.default_value {
                // Explicit #[ets(default = X)] value
                let lit = syn::LitInt::new(&default_val.to_string(), proc_macro2::Span::call_site());
                quote!(#lit as _)
            } else {
                // No explicit default, use const-compatible zeroing
                get_const_zero_expr(field_type)
            };
            field_defaults.push((field_name.clone(), field_type.clone(), default_expr));
        }

        // Skip if marked with #[ets(skip)]
        if attrs.skip {
            continue;
        }

        // Skip module fields - their params come from the module definition, not from here
        // The module field is just for runtime access to the combined struct
        if let Some(module_type) = attrs.module_type {
            // Extract array length if this is an array type
            let array_len = if let syn::Type::Array(array) = field_type { Some(array.len.clone()) } else { None };
            module_fields.push((field_name.clone(), field_type.clone(), module_type, array_len));
            continue;
        }

        let display_name = attrs.display.clone().unwrap_or_else(|| {
            // Convert snake_case to Title Case
            field_name
                .to_string()
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
        // This correctly handles all alignment padding and works with any field type.
        //
        // A tool-only parameter has no field to take the offset of, and nothing
        // reads the value: `build_parameters` emits no `<Memory>` element for
        // it, so the offset is inert. Zero rather than a sentinel, because the
        // generator must never treat it as a location in the defaults blob.
        let offset_expr = if attrs.no_memory {
            quote!(0u16)
        } else {
            quote! {
                core::mem::offset_of!(#struct_name, #field_name) as u16
            }
        };
        let no_memory = attrs.no_memory;

        // Check if this is a union field (unknown type that might implement EtsUnionType).
        // The `no_memory` literals below stay `false`: `#[ets_params]` rejects
        // `no_memory` on a union field, so a selector can never be tool-only.
        if attrs.union_field {
            let selector_name = format!("{}_selector", field_name);
            let selector_display = format!("{} Mode", display_name);

            // Generate selector parameter (the discriminant, 1 byte)
            param_defs.push(quote! {
                zweidraehte_device::ets::EtsParamDef {
                    name: #selector_name,
                    display_name: #selector_display,
                    suffix: None,
                    offset: #offset_expr,
                    size_bits: 8,
                    bit_offset: 0,
                    param_type: zweidraehte_device::ets::EtsParamType::Enum,
                    hidden: false,
                    no_memory: false,
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
                const #selector_const_name: &[zweidraehte_device::ets::EtsEnumVariant] =
                    #field_type::ETS_SELECTOR_VARIANTS;
            });

            // For union selector, use the default_value if specified (overrides the union's default variant)
            let selector_default_expr =
                if let Some(val) = attrs.default_value { quote!(Some(#val)) } else { quote!(None) };

            param_ext_defs.push(quote! {
                zweidraehte_device::ets::EtsParamDefExt {
                    base: zweidraehte_device::ets::EtsParamDef {
                        name: #selector_name,
                        display_name: #selector_display,
                        suffix: None,
                        offset: #offset_expr,
                        size_bits: 8,
                        bit_offset: 0,
                        param_type: zweidraehte_device::ets::EtsParamType::Enum,
                        hidden: false,
                        no_memory: false,
                        type_name: None,
                        text_pattern: None,
                    },
                    enum_variants: Some(Self::#selector_const_name),
                    default_value: #selector_default_expr,
                    is_text_source: false,
                }
            });

            // Track the union field for ETS_UNIONS generation
            union_field_entries.push(quote! {
                zweidraehte_device::ets::EtsUnionFieldInfo {
                    field_name: #name_str,
                    display_name: #selector_display,
                    offset: #offset_expr,
                    union_info: &#field_type::ETS_UNION_INFO,
                    selector_variants: #field_type::ETS_SELECTOR_VARIANTS,
                }
            });

            continue; // Skip adding to regular params, we handled it specially
        }

        // Handle ets_enum fields - they use the enum type's ETS_SIZE_BITS and ETS_VARIANTS
        if attrs.ets_enum_field {
            let size_bits_expr = quote!(#field_type::ETS_SIZE_BITS);
            let bit_offset = attrs.bit_offset.unwrap_or(0);

            // Generate suffix expression
            let suffix_expr = if let Some(s) = &attrs.suffix { quote!(Some(#s)) } else { quote!(None) };

            let hidden = attrs.hidden;
            let type_name_expr = if let Some(ref tn) = attrs.type_name { quote!(Some(#tn)) } else { quote!(None) };

            param_defs.push(quote! {
                zweidraehte_device::ets::EtsParamDef {
                    name: #name_str,
                    display_name: #display_name,
                    suffix: #suffix_expr,
                    offset: #offset_expr,
                    size_bits: #size_bits_expr,
                    bit_offset: #bit_offset,
                    param_type: zweidraehte_device::ets::EtsParamType::Enum,
                    hidden: #hidden,
                    no_memory: #no_memory,
                    type_name: #type_name_expr,
                    text_pattern: None,
                }
            });

            // Generate a const for the enum variants that references the type's ETS_VARIANTS
            let const_name =
                syn::Ident::new(&format!("{}_VARIANTS", field_name.to_string().to_uppercase()), field_name.span());

            enum_variant_consts.push(quote! {
                const #const_name: &[zweidraehte_device::ets::EtsEnumVariant] = #field_type::ETS_VARIANTS;
            });

            // For ets_enum fields, use explicit default if provided, otherwise use the enum's
            // ConstDefault::DEFAULT value. This ensures the XML default matches the Rust default.
            let default_value_expr = if let Some(val) = attrs.default_value {
                quote!(Some(#val))
            } else {
                // Use the enum's ConstDefault to get its default discriminant value
                quote!(Some(<#field_type as const_default::ConstDefault>::DEFAULT as i64))
            };

            param_ext_defs.push(quote! {
                zweidraehte_device::ets::EtsParamDefExt {
                    base: zweidraehte_device::ets::EtsParamDef {
                        name: #name_str,
                        display_name: #display_name,
                        suffix: #suffix_expr,
                        offset: #offset_expr,
                        size_bits: #size_bits_expr,
                        bit_offset: #bit_offset,
                        param_type: zweidraehte_device::ets::EtsParamType::Enum,
                        hidden: #hidden,
                        no_memory: #no_memory,
                        type_name: #type_name_expr,
                        text_pattern: None,
                    },
                    enum_variants: Some(Self::#const_name),
                    default_value: #default_value_expr,
                    is_text_source: false,
                }
            });

            continue;
        }

        let type_info = get_type_info(field_type)?;

        let size_bits = attrs.bits.unwrap_or(type_info.size_bits);
        let bit_offset = attrs.bit_offset.unwrap_or(0);

        // Determine param type - if has enum_variants, it's an Enum type
        // If marked as string, it's a String type
        let param_type = if attrs.enum_variants.is_some() {
            quote!(zweidraehte_device::ets::EtsParamType::Enum)
        } else if attrs.string_field {
            quote!(zweidraehte_device::ets::EtsParamType::String)
        } else {
            type_info.param_type.clone()
        };

        // Generate suffix expression
        let suffix_expr = if let Some(s) = &attrs.suffix { quote!(Some(#s)) } else { quote!(None) };

        // Generate basic ETS_PARAMS entry
        let hidden = attrs.hidden;
        let is_text_source = attrs.text_source;
        let type_name_expr = if let Some(ref tn) = attrs.type_name { quote!(Some(#tn)) } else { quote!(None) };
        param_defs.push(quote! {
            zweidraehte_device::ets::EtsParamDef {
                name: #name_str,
                display_name: #display_name,
                suffix: #suffix_expr,
                offset: #offset_expr,
                size_bits: #size_bits,
                bit_offset: #bit_offset,
                param_type: #param_type,
                hidden: #hidden,
                no_memory: #no_memory,
                type_name: #type_name_expr,
                text_pattern: None,
            }
        });

        // Generate ETS_PARAMS_EXT entry with enum variants
        let enum_variants_expr = if let Some(variants) = &attrs.enum_variants {
            // Generate a const for the enum variants
            let const_name =
                syn::Ident::new(&format!("{}_VARIANTS", field_name.to_string().to_uppercase()), field_name.span());

            let variant_defs: Vec<_> = variants
                .iter()
                .map(|v| {
                    let text = &v.text;
                    let value = v.value;
                    quote! {
                        zweidraehte_device::ets::EtsEnumVariant { text: #text, variant_name: #text, value: #value }
                    }
                })
                .collect();

            enum_variant_consts.push(quote! {
                const #const_name: &[zweidraehte_device::ets::EtsEnumVariant] = &[
                    #(#variant_defs),*
                ];
            });

            quote!(Some(Self::#const_name))
        } else {
            quote!(None)
        };

        let default_value_expr = if let Some(val) = attrs.default_value { quote!(Some(#val)) } else { quote!(None) };

        param_ext_defs.push(quote! {
            zweidraehte_device::ets::EtsParamDefExt {
                base: zweidraehte_device::ets::EtsParamDef {
                    name: #name_str,
                    display_name: #display_name,
                    suffix: #suffix_expr,
                    offset: #offset_expr,
                    size_bits: #size_bits,
                    bit_offset: #bit_offset,
                    param_type: #param_type,
                    hidden: #hidden,
                    no_memory: #no_memory,
                    type_name: #type_name_expr,
                    text_pattern: None,
                },
                enum_variants: #enum_variants_expr,
                default_value: #default_value_expr,
                is_text_source: #is_text_source,
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
            pub const ETS_UNIONS: &'static [zweidraehte_device::ets::EtsUnionFieldInfo] = &[
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

    // Generate helper methods for module fields
    // These provide compile-time access to module parameter offsets and object indices
    let module_helper_impls = if module_fields.is_empty() {
        quote! {}
    } else {
        let helper_methods: Vec<_> = module_fields.iter().map(|(field_name, _field_type, module_type, array_len)| {
            let field_name_str = field_name.to_string();

            // Generate method name based on field name (e.g., "channels" -> "channel_param_offset")
            // Singularize: "channels" -> "channel", "dimmers" -> "dimmer", etc.
            let singular_name = if field_name_str.ends_with("es") && field_name_str.len() > 2 {
                // Handle cases like "switches" -> "switch" (strip "es")
                // But not "issues" which would go to "issu"
                let stripped = &field_name_str[..field_name_str.len()-2];
                if stripped.ends_with("ch") || stripped.ends_with("sh") || stripped.ends_with("ss") {
                    stripped.to_string()
                } else {
                    // Strip just "s" for other "es" cases like "values" -> "value"
                    field_name_str.trim_end_matches('s').to_string()
                }
            } else if field_name_str.ends_with('s') {
                field_name_str.trim_end_matches('s').to_string()
            } else {
                field_name_str.clone()
            };

            let param_offset_fn = syn::Ident::new(&format!("{}_param_offset", singular_name), field_name.span());
            let object_base_fn = syn::Ident::new(&format!("{}_object_base", singular_name), field_name.span());
            let object_index_fn = syn::Ident::new(&format!("{}_object_index", singular_name), field_name.span());
            let count_const = syn::Ident::new(&format!("{}_COUNT", field_name_str.to_uppercase()), field_name.span());

            // Generate array length constant if applicable
            let count_const_def = if let Some(len) = array_len {
                quote! {
                    /// Number of module instances.
                    pub const #count_const: usize = #len;
                }
            } else {
                quote! {}
            };

            quote! {
                #count_const_def

                /// Compute parameter offset for module instance N (1-indexed).
                ///
                /// This matches the `ParamBase` argument value used in module instantiation.
                pub const fn #param_offset_fn(instance: usize) -> usize {
                    core::mem::offset_of!(Self, #field_name)
                        + (instance - 1) * core::mem::size_of::<<#module_type as zweidraehte_knxprod::definition::module::KnxModule>::Params>()
                }

                /// Compute first object index for module instance N (1-indexed).
                ///
                /// This matches the `ObjBase` argument value used in module instantiation.
                pub const fn #object_base_fn(instance: usize) -> usize {
                    // Get the number of objects from the module's comm object definitions
                    const OBJECT_COUNT: usize = match <#module_type as zweidraehte_knxprod::definition::module::KnxModule>::MODULE_COMM_OBJECTS {
                        Some(objs) => objs.len(),
                        None => 0,
                    };
                    (instance - 1) * OBJECT_COUNT
                }

                /// Get absolute object index for a specific object in a module instance.
                ///
                /// # Arguments
                /// * `instance` - Module instance number (1-indexed)
                /// * `local_index` - Object index within the module (0-indexed)
                pub const fn #object_index_fn(instance: usize, local_index: usize) -> usize {
                    Self::#object_base_fn(instance) + local_index
                }
            }
        }).collect();

        // Generate HasChannelHelpers implementations for each module field
        let has_channel_helpers_impls: Vec<_> = module_fields
            .iter()
            .map(|(field_name, _field_type, module_type, array_len)| {
                let field_name_str = field_name.to_string();

                // Generate singular name for method names
                let singular_name = if field_name_str.ends_with("es") && field_name_str.len() > 2 {
                    let stripped = &field_name_str[..field_name_str.len() - 2];
                    if stripped.ends_with("ch") || stripped.ends_with("sh") || stripped.ends_with("ss") {
                        stripped.to_string()
                    } else {
                        field_name_str.trim_end_matches('s').to_string()
                    }
                } else if field_name_str.ends_with('s') {
                    field_name_str.trim_end_matches('s').to_string()
                } else {
                    field_name_str.clone()
                };

                let param_offset_fn = syn::Ident::new(&format!("{}_param_offset", singular_name), field_name.span());
                let object_base_fn = syn::Ident::new(&format!("{}_object_base", singular_name), field_name.span());

                // Get the array length for COUNT
                let count_expr = if let Some(len) = array_len {
                    quote! { #len }
                } else {
                    quote! { 1 }
                };

                quote! {
                    impl zweidraehte_knxprod::definition::module::HasChannelHelpers<#module_type> for #struct_name {
                        const COUNT: usize = #count_expr;

                        fn param_offset(instance: usize) -> usize {
                            Self::#param_offset_fn(instance)
                        }

                        fn object_base(instance: usize) -> usize {
                            Self::#object_base_fn(instance)
                        }
                    }
                }
            })
            .collect();

        quote! {
            impl #struct_name {
                #(#helper_methods)*
            }

            #(#has_channel_helpers_impls)*
        }
    };

    // Generate Default and ConstDefault impls from field defaults
    let field_names: Vec<_> = field_defaults.iter().map(|(name, _, _)| name).collect();
    let field_exprs: Vec<_> = field_defaults.iter().map(|(_, _, expr)| expr).collect();
    let defaults_impls = quote! {
        impl core::default::Default for #struct_name {
            fn default() -> Self {
                Self {
                    #(#field_names: #field_exprs),*
                }
            }
        }

        impl const_default::ConstDefault for #struct_name {
            const DEFAULT: Self = Self {
                #(#field_names: #field_exprs),*
            };
        }
    };

    Ok(quote! {
        #alignment_assertions

        impl #struct_name {
            // Enum variant constants
            #(#enum_variant_consts)*

            /// ETS parameter definitions for this struct.
            ///
            /// Contains metadata for each field that can be exported to ETS format.
            pub const ETS_PARAMS: &'static [zweidraehte_device::ets::EtsParamDef] = &[
                #(#param_defs),*
            ];

            /// Extended ETS parameter definitions with enum variants.
            ///
            /// Contains full metadata including enum variants for ETS export.
            pub const ETS_PARAMS_EXT: &'static [zweidraehte_device::ets::EtsParamDefExt] = &[
                #(#param_ext_defs),*
            ];

            /// Number of ETS parameters.
            pub const NUM_PARAMS: usize = #param_count;

            #union_info_output
        }

        impl zweidraehte_device::ets::HasModuleParams for #struct_name {
            const ETS_PARAMS_EXT: &'static [zweidraehte_device::ets::EtsParamDefExt] = #struct_name::ETS_PARAMS_EXT;
        }

        #module_helper_impls

        #defaults_impls
    })
}
