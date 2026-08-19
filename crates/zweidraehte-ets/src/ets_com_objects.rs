use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::ParseStream;
use syn::spanned::Spanned;
use syn::{Attribute, Fields, Token};

/// Parse the attribute macro's arguments: optionally
/// `runtime_cfg = "feature-name"`.
fn parse_macro_args(args: TokenStream2) -> syn::Result<Option<String>> {
    if args.is_empty() {
        return Ok(None);
    }
    let mut runtime_cfg = None;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("runtime_cfg") {
            let lit: syn::LitStr = meta.value()?.parse()?;
            runtime_cfg = Some(lit.value());
            Ok(())
        } else {
            Err(meta.error("unknown ets_com_objects argument; expected `runtime_cfg = \"feature\"`"))
        }
    });
    syn::parse::Parser::parse2(parser, args)?;
    Ok(runtime_cfg)
}

/// Keep every attribute the macro does not consume (doc comments,
/// derives, ...), dropping the `#[ets]` / `#[ets_ref]` ones.
fn strip_ets_attrs(attrs: &[Attribute]) -> Vec<Attribute> {
    attrs.iter().filter(|a| !a.path().is_ident("ets") && !a.path().is_ident("ets_ref")).cloned().collect()
}

pub(crate) fn ets_com_objects_impl(args: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let runtime_cfg = parse_macro_args(args)?;
    let input: syn::ItemStruct = syn::parse2(item)?;
    let struct_name = &input.ident;
    let struct_vis = &input.vis;

    // Parse struct-level attributes
    let struct_attrs = parse_com_objects_struct_attrs(&input.attrs)?;
    let passthrough_attrs = strip_ets_attrs(&input.attrs);

    // Extract fields from struct
    let fields = match &input.fields {
        Fields::Named(fields) => &fields.named,
        _ => {
            return Err(syn::Error::new_spanned(&input, "#[ets_com_objects] requires a struct with named fields"));
        }
    };

    // Parse all fields, separating regular fields from module fields
    let mut com_objects: Vec<ComObjectField> = Vec::new();
    let mut module_fields: Vec<ModuleFieldInfo> = Vec::new();

    for field in fields.iter() {
        let field_ident = field.ident.as_ref().unwrap().clone();
        let field_ty = field.ty.clone();
        let attrs = parse_com_object_field_attrs(&field.attrs)?;

        // Check if this is a module field
        if let Some(module_type) = attrs.module_type {
            // Module field - extract array info
            let (element_type, instance_count) = extract_array_info(&field_ty).ok_or_else(|| {
                syn::Error::new_spanned(&field_ty, "Module fields must be arrays, e.g., [ModuleObjects; 4]")
            })?;

            module_fields.push(ModuleFieldInfo { ident: field_ident, module_type, instance_count, element_type });
            continue;
        }

        // Regular field. The declared type is the object's
        // factory-default DPT (`extract_inner_type` also tolerates a
        // spelled-out `ComObject<T>`, taking `T`).
        let inner_ty = extract_inner_type(&field_ty);
        let refs = parse_ets_ref_attrs(&field.attrs)?;

        if attrs.index.is_none() {
            return Err(syn::Error::new_spanned(
                field,
                "#[ets_com_objects] fields must have #[ets(index = N)] or #[ets(module = ...)]",
            ));
        }

        let has_refs = !refs.is_empty();
        // Multi-DPT objects have selector_param and use ComObjectStorage for runtime type selection
        let is_multi_dpt = attrs.selector_param.is_some();

        com_objects.push(ComObjectField {
            ident: field_ident,
            passthrough_attrs: strip_ets_attrs(&field.attrs),
            vis: field.vis.clone(),
            inner_ty,
            attrs,
            refs,
            has_refs,
            is_multi_dpt,
        });
    }

    // For now, we support at most one module field
    if module_fields.len() > 1 {
        return Err(syn::Error::new_spanned(&input, "Only one module field is currently supported per struct"));
    }

    // If we have a module field, generate module-based implementation
    if let Some(module_field) = module_fields.into_iter().next() {
        if runtime_cfg.is_some() {
            return Err(syn::Error::new_spanned(
                &input,
                "module-based declarations always need the device stack; runtime_cfg is not supported here",
            ));
        }
        let struct_emission = emit_struct_verbatim(&input);
        let generated = generate_module_based_impl(struct_name, &struct_attrs, &com_objects, &module_field)?;
        return Ok(quote! {
            #struct_emission
            #generated
        });
    }

    // The lowest logical index in the struct, exposed as
    // `ComObjects::FIRST_INDEX` (the AL's read-on-init self-detection
    // probes this object's status).
    let first_index = com_objects.iter().filter_map(|obj| obj.attrs.index).min().unwrap_or(0);

    // Generate the Index enum
    let index_variants: Vec<_> = com_objects
        .iter()
        .map(|obj| {
            let name = to_camel_case(&obj.ident.to_string());
            let variant_ident = syn::Ident::new(&name, obj.ident.span());
            let index = obj.attrs.index.unwrap();
            quote! { #variant_ident = #index }
        })
        .collect();

    let index_from_arms: Vec<_> = com_objects
        .iter()
        .map(|obj| {
            let name = to_camel_case(&obj.ident.to_string());
            let variant_ident = syn::Ident::new(&name, obj.ident.span());
            let index = obj.attrs.index.unwrap();
            quote! { #index => Some(Self::#variant_ident) }
        })
        .collect();

    // Generate info() match arms
    let info_arms: Vec<_> = com_objects
        .iter()
        .map(|obj| {
            let name = to_camel_case(&obj.ident.to_string());
            let variant_ident = syn::Ident::new(&name, obj.ident.span());
            let field_ident = &obj.ident;
            quote! {
                Index::#variant_ident => zweidraehte_device::objects::comm::ComObjectInfo {
                    status: &self.#field_ident.status,
                    value: self.#field_ident.value.as_ref(),
                }
            }
        })
        .collect();

    // Generate info_mut() match arms
    let info_mut_arms: Vec<_> = com_objects
        .iter()
        .map(|obj| {
            let name = to_camel_case(&obj.ident.to_string());
            let variant_ident = syn::Ident::new(&name, obj.ident.span());
            let field_ident = &obj.ident;
            quote! {
                Index::#variant_ident => zweidraehte_device::objects::comm::ComObjectInfoMut {
                    status: &mut self.#field_ident.status,
                    value: self.#field_ident.value.as_mut(),
                }
            }
        })
        .collect();

    // Generate new() field initializers
    let new_fields: Vec<_> = com_objects
        .iter()
        .map(|obj| {
            let ident = &obj.ident;
            if obj.is_multi_dpt {
                // Multi-DPT objects use ComObjectStorage for runtime type selection
                quote! {
                    #ident: zweidraehte_device::objects::comm::ComObject::new(
                        zweidraehte_device::objects::comm::ComObjectStorage::new()
                    )
                }
            } else if let Some(initial) = &obj.attrs.initial {
                // Explicit `#[ets(initial = …)]` seed value.
                quote! {
                    #ident: zweidraehte_device::objects::comm::ComObject::new(#initial)
                }
            } else {
                // Single-DPT objects (including same-DPT multi-ref) use the declared inner type
                let inner_ty = &obj.inner_ty;
                quote! {
                    #ident: zweidraehte_device::objects::comm::ComObject::new(<#inner_ty>::default())
                }
            }
        })
        .collect();

    // Generate ETS_COMM_OBJECTS const array
    let ets_comm_objects: Vec<_> = com_objects
        .iter()
        .map(|obj| {
            let index = obj.attrs.index.unwrap();
            // Use name override if provided, otherwise use field ident
            let name = obj.attrs.name.clone().unwrap_or_else(|| obj.ident.to_string());
            let display_name = obj.attrs.display.clone().unwrap_or_else(|| to_title_case(&obj.ident.to_string()));
            let function_text = obj.attrs.function.clone().unwrap_or_default();
            let default_flags = obj.attrs.flags.unwrap_or(0xDF);

            // Generate object_size_override expression
            let object_size_override_expr =
                if let Some(ref size) = obj.attrs.object_size { quote!(Some(#size)) } else { quote!(None) };

            // Generate text_template expression
            let text_template_expr =
                if let Some(ref template) = obj.attrs.text_template { quote!(Some(#template)) } else { quote!(None) };

            if obj.has_refs {
                // For objects with refs, use first ref's DPT info as base
                let first_ref_dpt = &obj.refs[0].dpt;
                quote! {
                    zweidraehte_ets_model::EtsCommObjectDef {
                        index: #index,
                        name: #name,
                        display_name: #display_name,
                        function_text: #function_text,
                        dpt_main: <#first_ref_dpt as zweidraehte_ets_model::HasDptInfo>::DPT_MAIN,
                        dpt_sub: <#first_ref_dpt as zweidraehte_ets_model::HasDptInfo>::DPT_SUB,
                        size_bits: <#first_ref_dpt as zweidraehte_ets_model::HasDptInfo>::SIZE_BITS as u8,
                        default_flags: #default_flags,
                        object_size_override: #object_size_override_expr,
                        text_template: #text_template_expr,
                    }
                }
            } else {
                // Use inner_ty to extract DPT info (handles both ComObject<T> and bare T)
                let inner_ty = &obj.inner_ty;
                quote! {
                    zweidraehte_ets_model::EtsCommObjectDef {
                        index: #index,
                        name: #name,
                        display_name: #display_name,
                        function_text: #function_text,
                        dpt_main: <#inner_ty as zweidraehte_ets_model::HasDptInfo>::DPT_MAIN,
                        dpt_sub: <#inner_ty as zweidraehte_ets_model::HasDptInfo>::DPT_SUB,
                        size_bits: <#inner_ty as zweidraehte_ets_model::HasDptInfo>::SIZE_BITS as u8,
                        default_flags: #default_flags,
                        object_size_override: #object_size_override_expr,
                        text_template: #text_template_expr,
                    }
                }
            }
        })
        .collect();

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
                let text_tokens = if let Some(ref text) = ref_attr.text { quote!(Some(#text)) } else { quote!(None) };
                // Only include selector info if the ref has a `when` attribute
                // Refs without `when` are unconditional and should NOT have selector_param
                let (selector_value, selector_value_name, this_ref_selector_param) = match &ref_attr.when {
                    Some(SelectorValue::Path(path)) => {
                        // Cast the enum variant to i64 to get the discriminant value.
                        // Extract the last path segment as the variant name for
                        // translation resolution (e.g., "Switch" from
                        // "ButtonConfigDiscriminant::Switch").
                        let variant_name = path.segments.last().map(|seg| seg.ident.to_string()).unwrap_or_default();
                        (quote!(Some(#path as i64)), quote!(Some(#variant_name)), selector_param_tokens.clone())
                    }
                    Some(SelectorValue::Int(val)) => {
                        (quote!(Some(#val as i64)), quote!(None), selector_param_tokens.clone())
                    }
                    None => {
                        // No `when` = unconditional ref, clear selector_param
                        (quote!(None), quote!(None), quote!(None))
                    }
                };

                // Generate flag overrides
                let flag_overrides = if ref_attr.read.is_some()
                    || ref_attr.write.is_some()
                    || ref_attr.communication.is_some()
                    || ref_attr.transmit.is_some()
                    || ref_attr.update.is_some()
                    || ref_attr.read_on_init.is_some()
                {
                    let read = opt_bool_to_tokens(ref_attr.read);
                    let write = opt_bool_to_tokens(ref_attr.write);
                    let communication = opt_bool_to_tokens(ref_attr.communication);
                    let transmit = opt_bool_to_tokens(ref_attr.transmit);
                    let update = opt_bool_to_tokens(ref_attr.update);
                    let read_on_init = opt_bool_to_tokens(ref_attr.read_on_init);
                    quote! {
                        Some(zweidraehte_ets_model::FlagOverrides {
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
                    zweidraehte_ets_model::EtsCommObjectRefDef {
                        object_index: #index,
                        ref_name: #ref_name,
                        text: #text_tokens,
                        function_text: #function_text,
                        dpt_main: <#ref_dpt as zweidraehte_ets_model::HasDptInfo>::DPT_MAIN,
                        dpt_sub: <#ref_dpt as zweidraehte_ets_model::HasDptInfo>::DPT_SUB,
                        size_bits: <#ref_dpt as zweidraehte_ets_model::HasDptInfo>::SIZE_BITS as u8,
                        flag_overrides: #flag_overrides,
                        selector_value: #selector_value,
                        selector_value_name: #selector_value_name,
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
                zweidraehte_ets_model::EtsCommObjectRefDef {
                    object_index: #index,
                    ref_name: #ref_name,
                    text: None,
                    function_text: #function_text,
                    dpt_main: <#inner_ty as zweidraehte_ets_model::HasDptInfo>::DPT_MAIN,
                    dpt_sub: <#inner_ty as zweidraehte_ets_model::HasDptInfo>::DPT_SUB,
                    size_bits: <#inner_ty as zweidraehte_ets_model::HasDptInfo>::SIZE_BITS as u8,
                    flag_overrides: None,
                    selector_value: None,
                    selector_value_name: None,
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

    // Generate ComObjects impl unless manual_impl is set. Unless the
    // user opted into writing the hook themselves via `#[ets(bus_hook)]`,
    // also emit an empty `ComObjectBusHook` so the generated container
    // satisfies the `StackDefinition::CO: ComObjects + ComObjectBusHook`
    // bound.
    let hook_impl = if struct_attrs.bus_hook {
        // User writes `impl ComObjectBusHook for #struct_name { … }`
        // next to the derive; the standard dispatch is still generated.
        quote!()
    } else {
        quote! {
            impl zweidraehte_device::objects::comm::ComObjectBusHook for #struct_name {}
        }
    };
    let com_objects_impl = if struct_attrs.manual_impl {
        quote!()
    } else {
        quote! {
            impl zweidraehte_device::objects::comm::ComObjects for #struct_name {
                type Index = Index;

                const FIRST_INDEX: u16 = #first_index;

                fn new() -> Self {
                    Self {
                        #(#new_fields),*
                    }
                }

                fn info<'a>(&'a self, idx: u16) -> Option<zweidraehte_device::objects::comm::ComObjectInfo<'a>> {
                    <Index as zweidraehte_device::objects::comm::ComObjectIndex>::from_index(idx).map(|index| match index {
                        #(#info_arms),*
                    })
                }

                fn info_mut<'a>(&'a mut self, idx: u16) -> Option<zweidraehte_device::objects::comm::ComObjectInfoMut<'a>> {
                    <Index as zweidraehte_device::objects::comm::ComObjectIndex>::from_index(idx).map(|index| match index {
                        #(#info_mut_arms),*
                    })
                }
            }

            #hook_impl
        }
    };

    let num_objects = com_objects.len();

    // ── The runtime struct ──────────────────────────────────────────
    //
    // The declaration's field types are plain DPT types; the runtime
    // container wraps them. Multi-DPT objects get a storage sized to
    // the widest DPT any of their refs can configure — computed here,
    // so a declaration cannot under-size a slot.
    let struct_fields: Vec<_> = com_objects
        .iter()
        .map(|obj| {
            let attrs = &obj.passthrough_attrs;
            let vis = &obj.vis;
            let ident = &obj.ident;
            let ty = if obj.is_multi_dpt {
                let sizes: Vec<_> = obj
                    .refs
                    .iter()
                    .map(|r| {
                        let dpt = &r.dpt;
                        quote!(<#dpt as zweidraehte_ets_model::HasDptInfo>::SIZE_BITS)
                    })
                    .collect();
                quote! {
                    zweidraehte_device::objects::comm::ComObject<
                        zweidraehte_device::objects::comm::ComObjectStorage<{
                            let sizes: &[usize] = &[#(#sizes),*];
                            let mut max = 0usize;
                            let mut i = 0;
                            while i < sizes.len() {
                                if sizes[i] > max {
                                    max = sizes[i];
                                }
                                i += 1;
                            }
                            (max + 7) / 8
                        }>,
                    >
                }
            } else {
                let inner_ty = &obj.inner_ty;
                quote!(zweidraehte_device::objects::comm::ComObject<#inner_ty>)
            };
            quote! {
                #(#attrs)*
                #vis #ident: #ty
            }
        })
        .collect();

    let runtime_struct = quote! {
        #(#passthrough_attrs)*
        #struct_vis struct #struct_name {
            #(#struct_fields),*
        }
    };

    // ── Assembly ────────────────────────────────────────────────────
    //
    // The metadata half (Index enum, the ETS_* consts) references only
    // `zweidraehte-ets-model` types and is emitted unconditionally; the
    // runtime half needs `zweidraehte-device` and goes behind the
    // declaration's `runtime_cfg` feature when one is named — with a
    // unit struct standing in so the metadata has a type to hang off.
    let unconditional = quote! {
        /// Enum with all communication object names and their indices
        #[allow(dead_code)]
        #[derive(core::marker::ConstParamTy, Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u16)]
        pub enum Index {
            #(#index_variants),*
        }

        impl #struct_name {
            /// ETS communication object definitions for this module.
            #[allow(dead_code)]
            pub const ETS_COMM_OBJECTS: &'static [zweidraehte_ets_model::EtsCommObjectDef] = &[
                #(#ets_comm_objects),*
            ];

            /// ETS communication object reference definitions.
            #[allow(dead_code)]
            pub const ETS_COMM_OBJECT_REFS: &'static [zweidraehte_ets_model::EtsCommObjectRefDef] = &[
                #(#ets_comm_object_refs),*
            ];

            /// Number of communication objects in this module.
            #[allow(dead_code)]
            pub const NUM_COMM_OBJECTS: usize = #num_objects;
        }

        impl zweidraehte_ets_model::HasModuleCommObjects for #struct_name {
            const ETS_COMM_OBJECTS: &'static [zweidraehte_ets_model::EtsCommObjectDef] = #struct_name::ETS_COMM_OBJECTS;
        }
    };

    let index_trait_impl = quote! {
        #[allow(dead_code)]
        impl zweidraehte_device::objects::comm::ComObjectIndex for Index {
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
    };

    // Per-item runtime pieces, so a cfg attribute can prefix each.
    let runtime_items = [runtime_struct, index_trait_impl, com_objects_impl, selector_impl];

    match runtime_cfg {
        Some(feature) => {
            let gated: Vec<_> = runtime_items
                .iter()
                .filter(|t| !t.is_empty())
                .map(|t| apply_cfg_to_items(t, &feature))
                .collect::<syn::Result<Vec<_>>>()?;
            let unit_docs = &passthrough_attrs;
            Ok(quote! {
                #unconditional

                #(#gated)*

                /// Metadata-only stand-in: the runtime container needs
                /// the device stack, which this build does not carry.
                #(#unit_docs)*
                #[cfg(not(feature = #feature))]
                #struct_vis struct #struct_name;
            })
        }
        None => Ok(quote! {
            #unconditional
            #(#runtime_items)*
        }),
    }
}

/// Re-emit the declaration's struct with the `#[ets]`/`#[ets_ref]`
/// attributes consumed (module-based declarations keep their field
/// types verbatim — the array of module objects is already a runtime
/// type).
fn emit_struct_verbatim(input: &syn::ItemStruct) -> TokenStream2 {
    let attrs = strip_ets_attrs(&input.attrs);
    let vis = &input.vis;
    let ident = &input.ident;
    let fields: Vec<_> = match &input.fields {
        Fields::Named(named) => named
            .named
            .iter()
            .map(|f| {
                let attrs = strip_ets_attrs(&f.attrs);
                let vis = &f.vis;
                let ident = &f.ident;
                let ty = &f.ty;
                quote! { #(#attrs)* #vis #ident: #ty }
            })
            .collect(),
        _ => unreachable!("checked for named fields above"),
    };
    quote! {
        #(#attrs)*
        #vis struct #ident {
            #(#fields),*
        }
    }
}

/// Attach `#[cfg(feature = ...)]` to every top-level item in `tokens`.
///
/// The runtime token streams may hold several items (an impl plus the
/// bus hook, the selector enum plus its accessor impls); a cfg
/// attribute only applies to one item, so the stream is parsed back
/// into items and each gets its own.
fn apply_cfg_to_items(tokens: &TokenStream2, feature: &str) -> syn::Result<TokenStream2> {
    let file: syn::File = syn::parse2(quote!(#tokens))?;
    let items = file.items;
    Ok(quote! {
        #(
            #[cfg(feature = #feature)]
            #items
        )*
    })
}

/// Generate ComObjects implementation for a struct with module fields.
///
/// This generates:
/// - Index enum with variants for each instance's objects
/// - ComObjects impl with flattened indexing
/// - ETS_COMM_OBJECTS referencing the module's definitions
fn generate_module_based_impl(
    struct_name: &syn::Ident,
    struct_attrs: &ComObjectsStructAttrs,
    _regular_objects: &[ComObjectField],
    module_field: &ModuleFieldInfo,
) -> syn::Result<TokenStream2> {
    let field_ident = &module_field.ident;
    let module_type = &module_field.module_type;
    let instance_count = &module_field.instance_count;
    let element_type = &module_field.element_type;

    // Get singular name for prefix (e.g., "channels" -> "Ch")
    let field_name_str = field_ident.to_string();
    let prefix = if field_name_str.ends_with("s") {
        let s = &field_name_str[..field_name_str.len() - 1];
        let mut chars = s.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            None => "Obj".to_string(),
        }
    } else {
        let mut chars = field_name_str.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            None => "Obj".to_string(),
        }
    };

    // Generate code that computes the total object count at compile time
    // using the module's MODULE_COMM_OBJECTS constant
    let objects_per_instance = quote! {
        {
            match <#module_type as zweidraehte_knxprod::definition::module::KnxModule>::MODULE_COMM_OBJECTS {
                Some(objs) => objs.len(),
                None => 0,
            }
        }
    };

    let total_objects = quote! {
        #instance_count * #objects_per_instance
    };

    // For the Index enum, we can't generate named variants at macro time because
    // we don't know the module's object names. Instead, we use a numeric index approach.
    // Users can still use helper methods to get human-readable indices.

    // Generate ComObjects impl that forwards to the array elements.
    // Unless `#[ets(bus_hook)]` says the user writes the hook, also emit
    // an empty `ComObjectBusHook` so the resulting type satisfies the
    // `StackDefinition::CO` bound; manual_impl users must write both.
    let hook_impl = if struct_attrs.bus_hook {
        quote!()
    } else {
        quote! {
            impl zweidraehte_device::objects::comm::ComObjectBusHook for #struct_name {}
        }
    };
    let com_objects_impl = if struct_attrs.manual_impl {
        quote!()
    } else {
        quote! {
            impl zweidraehte_device::objects::comm::ComObjects for #struct_name {
                type Index = Index;

                fn new() -> Self {
                    Self {
                        #field_ident: core::array::from_fn(|_| <#element_type as zweidraehte_device::objects::comm::ComObjects>::new()),
                    }
                }

                fn info<'a>(&'a self, idx: u16) -> Option<zweidraehte_device::objects::comm::ComObjectInfo<'a>> {
                    const OBJS_PER_INSTANCE: usize = #objects_per_instance;
                    let instance = idx as usize / OBJS_PER_INSTANCE;
                    let local_idx = idx as usize % OBJS_PER_INSTANCE;
                    self.#field_ident.get(instance)?.info(local_idx as u16)
                }

                fn info_mut<'a>(&'a mut self, idx: u16) -> Option<zweidraehte_device::objects::comm::ComObjectInfoMut<'a>> {
                    const OBJS_PER_INSTANCE: usize = #objects_per_instance;
                    let instance = idx as usize / OBJS_PER_INSTANCE;
                    let local_idx = idx as usize % OBJS_PER_INSTANCE;
                    self.#field_ident.get_mut(instance)?.info_mut(local_idx as u16)
                }
            }

            #hook_impl
        }
    };

    // Generate Index enum as a simple numeric newtype for module-based structs
    // This allows any valid index within the total object range
    let index_impl = quote! {
        /// Index type for module-based communication objects.
        ///
        /// This is a simple u16 wrapper that validates indices are within range.
        #[allow(dead_code)]
        #[derive(core::marker::ConstParamTy, Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct Index(u16);

        #[allow(dead_code)]
        impl Index {
            /// Create an index from a raw u16 value.
            ///
            /// Returns None if the index is out of range.
            pub const fn from_raw(idx: u16) -> Option<Self> {
                const TOTAL: usize = #total_objects;
                if (idx as usize) < TOTAL {
                    Some(Self(idx))
                } else {
                    None
                }
            }

            /// Get the raw index value.
            pub const fn raw(&self) -> u16 {
                self.0
            }

            /// Get object index for a specific instance and local object.
            ///
            /// # Arguments
            /// * `instance` - Instance number (0-indexed)
            /// * `local_obj` - Local object index within the module (0-indexed)
            pub const fn for_instance(instance: usize, local_obj: usize) -> Option<Self> {
                const OBJS_PER_INSTANCE: usize = #objects_per_instance;
                const TOTAL: usize = #total_objects;
                let idx = instance * OBJS_PER_INSTANCE + local_obj;
                if idx < TOTAL {
                    Some(Self(idx as u16))
                } else {
                    None
                }
            }
        }

        impl zweidraehte_device::objects::comm::ComObjectIndex for Index {
            fn from_index(idx: u16) -> Option<Self> {
                Self::from_raw(idx)
            }

            fn index(&self) -> u16 {
                self.0
            }
        }
    };

    // Generate helper methods on the struct
    let helper_methods = {
        let prefix_lower = prefix.to_lowercase();
        let object_index_fn = syn::Ident::new(&format!("{}_object_index", prefix_lower), field_ident.span());
        let instance_count_const =
            syn::Ident::new(&format!("{}_INSTANCE_COUNT", field_name_str.to_uppercase()), field_ident.span());

        quote! {
            impl #struct_name {
                /// Number of module instances.
                pub const #instance_count_const: usize = #instance_count;

                /// Get the object index for a specific instance and local object.
                ///
                /// # Arguments
                /// * `instance` - Instance number (1-indexed, matching ETS convention)
                /// * `local_obj` - Local object index within the module (0-indexed)
                pub const fn #object_index_fn(instance: usize, local_obj: usize) -> usize {
                    const OBJS_PER_INSTANCE: usize = #objects_per_instance;
                    (instance - 1) * OBJS_PER_INSTANCE + local_obj
                }
            }
        }
    };

    // Generate ETS_COMM_OBJECTS by iterating over the module's definitions
    // and replicating them for each instance (with adjusted indices)
    let ets_impl = quote! {
        impl #struct_name {
            /// ETS communication object definitions for all instances.
            ///
            /// This is derived from the module's `MODULE_COMM_OBJECTS` constant,
            /// replicated for each instance with adjusted indices.
            #[allow(dead_code)]
            pub const ETS_COMM_OBJECTS: &'static [zweidraehte_ets_model::EtsCommObjectDef] =
                <#element_type as zweidraehte_ets_model::HasModuleCommObjects>::ETS_COMM_OBJECTS;

            /// Number of communication objects per module instance.
            pub const OBJECTS_PER_INSTANCE: usize = #objects_per_instance;

            /// Total number of communication objects.
            pub const NUM_COMM_OBJECTS: usize = #total_objects;
        }

        impl zweidraehte_ets_model::HasModuleCommObjects for #struct_name {
            const ETS_COMM_OBJECTS: &'static [zweidraehte_ets_model::EtsCommObjectDef] =
                <#element_type as zweidraehte_ets_model::HasModuleCommObjects>::ETS_COMM_OBJECTS;
        }
    };

    Ok(quote! {
        #index_impl
        #com_objects_impl
        #helper_methods
        #ets_impl
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
        syn::Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.clone())
            .ok_or_else(|| syn::Error::new_spanned(selector_enum, "Invalid selector enum type"))?,
        _ => return Err(syn::Error::new_spanned(selector_enum, "Selector must be a path type")),
    };

    let objs_enum_name = syn::Ident::new(&format!("{}Objs", selector_name), selector_name.span());

    // Find all fields that have refs with `when` clauses matching this selector
    let mut selector_fields: Vec<(&ComObjectField, Vec<&ComObjectRefAttrs>)> = Vec::new();

    for obj in com_objects {
        let matching_refs: Vec<_> = obj
            .refs
            .iter()
            .filter(|r| {
                match &r.when {
                    Some(SelectorValue::Path(path)) => {
                        // Check if the path starts with the selector enum name
                        path.segments.first().map(|s| s.ident == selector_name).unwrap_or(false)
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

    // Collect unique variants from all refs. We keep `variant_order` alongside
    // the map so codegen iterates in source-declaration order: a plain HashMap
    // iterates nondeterministically, which would shuffle the generated enum
    // variants and match arms between builds (non-reproducible output).
    let mut variants_map: std::collections::HashMap<String, Vec<(&ComObjectField, &ComObjectRefAttrs)>> =
        std::collections::HashMap::new();
    let mut variant_order: Vec<String> = Vec::new();

    for (obj, refs) in &selector_fields {
        for ref_attr in refs {
            if let Some(SelectorValue::Path(path)) = &ref_attr.when {
                let variant_name = path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                if !variants_map.contains_key(&variant_name) {
                    variant_order.push(variant_name.clone());
                }
                variants_map.entry(variant_name).or_default().push((obj, ref_attr));
            }
        }
    }

    // Generate enum variants - deduplicate fields by name within each variant
    // (same field may have multiple refs with same `when` but different functions)
    let enum_variants: Vec<_> = variant_order
        .iter()
        .map(|variant_name| {
            let field_refs = &variants_map[variant_name];
            let variant_ident = syn::Ident::new(variant_name, proc_macro2::Span::call_site());

            // Deduplicate by field name, keeping the first ref for each field
            let mut seen_fields = std::collections::HashSet::new();
            let field_defs: Vec<_> = field_refs
                .iter()
                .filter(|(obj, _)| seen_fields.insert(obj.ident.to_string()))
                .map(|(obj, ref_attr)| {
                    let field_ident = &obj.ident;
                    let dpt_type = &ref_attr.dpt;
                    let index = obj.attrs.index.unwrap();
                    quote! {
                        #field_ident: zweidraehte_device::objects::comm::TypedComObj<'a, #dpt_type, #index>
                    }
                })
                .collect();

            quote! {
                #variant_ident {
                    #(#field_defs),*
                }
            }
        })
        .collect();

    // Generate match arms for the accessor method
    let match_arms: Vec<_> = variant_order
        .iter()
        .map(|variant_name| {
            let field_refs = &variants_map[variant_name];
            let variant_ident = syn::Ident::new(variant_name, proc_macro2::Span::call_site());
            let selector_variant = syn::Ident::new(variant_name, proc_macro2::Span::call_site());

            // Deduplicate by field name, keeping the first ref for each field
            let mut seen_fields = std::collections::HashSet::new();
            let field_inits: Vec<_> = field_refs
                .iter()
                .filter(|(obj, _)| seen_fields.insert(obj.ident.to_string()))
                .map(|(obj, _ref_attr)| {
                    let field_ident = &obj.ident;
                    quote! {
                        #field_ident: unsafe {
                            zweidraehte_device::objects::comm::TypedComObj::new(
                                objs.#field_ident.value.as_mut(),
                                &mut objs.#field_ident.status,
                            )
                        }
                    }
                })
                .collect();

            quote! {
                #selector_enum::#selector_variant => #objs_enum_name::#variant_ident {
                    #(#field_inits),*
                }
            }
        })
        .collect();

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

// ============================================================================
// Types and parsers private to EtsComObjects
// ============================================================================

/// Parsed struct-level attributes for EtsComObjects
struct ComObjectsStructAttrs {
    /// Don't generate ComObjects trait impl
    manual_impl: bool,
    /// Generate the ComObjects impl but skip the empty
    /// `ComObjectBusHook` impl — the user writes the hook themselves.
    bus_hook: bool,
    /// Selector enum type for generating variant struct
    selector_enum: Option<syn::Type>,
}

/// Parsed field-level attributes for a comm object
struct ComObjectFieldAttrs {
    /// ASAP index (required for regular fields, ignored for module fields)
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
    /// Text template for module comm objects (e.g., "Ch{{ChNo}} Switch: {{0}}")
    text_template: Option<String>,
    /// Marks this field as containing module instances (array of module comm objects).
    /// The type should be the module type (e.g., DimmerChannelModule).
    module_type: Option<syn::Type>,
    /// Initial value expression used in the generated `ComObjects::new()`
    /// instead of `<inner_ty>::default()` (e.g. a non-zero seed value).
    initial: Option<syn::Expr>,
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
    let mut result = ComObjectsStructAttrs { manual_impl: false, bus_hook: false, selector_enum: None };

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
                } else if ident == "bus_hook" {
                    result.bus_hook = true;
                } else if ident == "selector_enum" {
                    input.parse::<Token![=]>()?;
                    result.selector_enum = Some(input.parse()?);
                } else {
                    return Err(syn::Error::new(ident.span(), format!("unknown `#[ets(...)]` struct key `{ident}`")));
                }

                let _ = input.parse::<Option<Token![,]>>();
            }
            Ok(())
        };

        syn::parse::Parser::parse2(parser, tokens)?;

        if result.manual_impl && result.bus_hook {
            return Err(syn::Error::new(
                attr.span(),
                "`bus_hook` is redundant with `manual_impl` — a manual impl already writes \
                 `ComObjectBusHook` itself",
            ));
        }
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
        text_template: None,
        module_type: None,
        initial: None,
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
                    result.flags = Some(parse_flags_expr(input)?);
                } else if ident == "initial" {
                    input.parse::<Token![=]>()?;
                    result.initial = Some(input.parse()?);
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
                } else if ident == "text_template" {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitStr = input.parse()?;
                    result.text_template = Some(value.value());
                } else if ident == "module" {
                    // Parse: module = ModuleType
                    input.parse::<Token![=]>()?;
                    result.module_type = Some(input.parse()?);
                } else {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown `#[ets(...)]` comm-object key `{ident}`"),
                    ));
                }

                let _ = input.parse::<Option<Token![,]>>();
            }
            Ok(())
        };

        syn::parse::Parser::parse2(parser, tokens)?;
    }

    Ok(result)
}

/// Resolve a comm object flag identifier to its u8 value.
fn resolve_flag_ident(ident: &str) -> Option<u8> {
    match ident {
        "C" | "CE" => Some(0x04), // Communication Enable
        "R" | "RE" => Some(0x08), // Read Enable
        "W" | "WE" => Some(0x10), // Write Enable
        "ROI" => Some(0x20),      // Read on Init
        "T" | "TE" => Some(0x40), // Transmission Enable
        "U" | "UE" => Some(0x80), // Update Enable
        "LOW" => Some(0x03),      // Priority Low
        "HIGH" => Some(0x01),     // Priority High
        "ALARM" => Some(0x02),    // Priority Alarm
        "SYSTEM" => Some(0x00),   // Priority System
        _ => None,
    }
}

/// Parse a flags expression: either a literal integer (e.g. `0x47`) or a bitwise OR
/// of named flag constants (e.g. `CE | T | LOW`).
fn parse_flags_expr(input: ParseStream) -> syn::Result<u8> {
    if input.peek(syn::LitInt) {
        let value: syn::LitInt = input.parse()?;
        return value.base10_parse();
    }

    let mut flags: u8 = 0;
    loop {
        let ident: syn::Ident = input.parse()?;
        let ident_str = ident.to_string();
        match resolve_flag_ident(&ident_str) {
            Some(val) => flags |= val,
            None => {
                return Err(syn::Error::new_spanned(
                    &ident,
                    format!(
                        "unknown flag `{}`. Expected: C/CE, R/RE, W/WE, T/TE, U/UE, ROI, LOW, HIGH, ALARM, SYSTEM",
                        ident_str
                    ),
                ));
            }
        }
        // If next token is `|`, consume it and continue; otherwise stop
        if input.peek(Token![|]) {
            input.parse::<Token![|]>()?;
        } else {
            break;
        }
    }
    Ok(flags)
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
                } else {
                    return Err(syn::Error::new(ident.span(), format!("unknown `#[ets_ref(...)]` key `{ident}`")));
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
    /// Field attributes minus the consumed `#[ets]`/`#[ets_ref]` ones,
    /// forwarded onto the emitted runtime struct's field.
    passthrough_attrs: Vec<Attribute>,
    /// Field visibility, forwarded likewise.
    vis: syn::Visibility,
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
    if let syn::Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "ComObject"
        && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
    {
        return inner.clone();
    }
    ty.clone()
}

/// Array length info - either a literal value or an expression.
#[derive(Clone)]
enum ArrayLen {
    /// Literal array length (e.g., `4`)
    Literal(usize),
    /// Expression for array length (e.g., `NUM_CHANNELS`)
    Expr(syn::Expr),
}

impl quote::ToTokens for ArrayLen {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        match self {
            ArrayLen::Literal(n) => {
                tokens.extend(quote! { #n });
            }
            ArrayLen::Expr(expr) => {
                tokens.extend(quote! { #expr });
            }
        }
    }
}

/// Extract array information from a type like `[T; N]`.
/// Returns (element_type, array_length) if successful.
fn extract_array_info(ty: &syn::Type) -> Option<(syn::Type, ArrayLen)> {
    if let syn::Type::Array(arr) = ty {
        let elem = (*arr.elem).clone();
        // Try to parse the length expression as a literal first
        if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(lit_int), .. }) = &arr.len
            && let Ok(len) = lit_int.base10_parse::<usize>()
        {
            return Some((elem, ArrayLen::Literal(len)));
        }
        // Otherwise, keep the expression (could be a const like NUM_CHANNELS)
        return Some((elem, ArrayLen::Expr(arr.len.clone())));
    }
    None
}

/// Information about a module field in the comm objects struct
struct ModuleFieldInfo {
    /// Field identifier (e.g., "channels")
    ident: syn::Ident,
    /// Module type (e.g., DimmerChannelModule)
    module_type: syn::Type,
    /// Number of instances - either a literal or expression
    instance_count: ArrayLen,
    /// Element type of the array (e.g., DimmerChannelRuntimeObjects)
    element_type: syn::Type,
}
