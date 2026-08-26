//! Code generation for the `InterfaceObject` derive.
//!
//! Emits a `const PROPERTY_DESCRIPTORS: &'static [PropertyDescriptor]`,
//! a `new(...)` constructor, and the four `InterfaceObject` trait methods
//! (`object_type`, `property_count`, `property_descriptor_by_index`,
//! `property_descriptor_by_id`, `read_property`, `write_property`,
//! `property_element_count`).
//!
//! State-backed fields (`backing = state`) are erased from the generated
//! struct and dispatch through the user-supplied `read` / `write` closures
//! against `self.state: &'a S`. The macro auto-injects the `state` field
//! when at least one property is state-backed.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::ItemStruct;

use crate::parse::{Access, Backing, LevelAttr, ObjectAttrs, PropertyAttrs};

/// `props` is parallel to `item.fields` — `None` entries are non-property
/// struct fields kept verbatim, `Some(_)` entries are property metadata.
pub(crate) fn gen_object(
    item: &ItemStruct,
    obj_attrs: &ObjectAttrs,
    props: &[Option<PropertyAttrs>],
) -> syn::Result<TokenStream> {
    let object_type = obj_attrs.object_type.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(&item.ident, "missing `object_type = ...` argument on #[interface_object(...)]")
    })?;

    let ident = &item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();
    let vis = &item.vis;
    // Forward `#[derive(...)]`, doc comments, etc. from the user's struct.
    let outer_attrs = item
        .attrs
        .iter()
        .filter(|a| !a.path().is_ident("interface_object") && !a.path().is_ident("interface_object_augment"));

    // Re-emit the user's struct verbatim except: virtual properties (unit-
    // typed fields with `read`/`write` closures) are stripped because they
    // have no runtime storage. Real fields keep their original type, vis,
    // attributes, and visibility — they survive untouched.
    //
    // Field-level `#[io(...)]` attributes are stripped from the output to
    // avoid the compiler complaining about an unknown attribute.
    let kept_fields = item.fields.iter().zip(props.iter()).filter_map(|(field, p)| {
        // Drop virtual properties (unit-typed placeholders) from the emitted
        // struct. Plain struct fields (`p == None`) and field-backed
        // properties survive — keep their attributes (doc comments etc.)
        // but strip our own `#[io(...)]`.
        let drop = matches!(p, Some(prop) if matches!(prop.backing, Backing::Virtual));
        if drop {
            None
        } else {
            let attrs = field.attrs.iter().filter(|a| !a.path().is_ident("io"));
            let vis = &field.vis;
            let name = field.ident.as_ref().unwrap();
            let ty = &field.ty;
            Some(quote! {
                #( #attrs )*
                #vis #name: #ty,
            })
        }
    });

    // PROPERTY_DESCRIPTORS const slice. Always starts with OBJECT_TYPE
    // (PID 1) at index 0; user-declared properties follow in declaration
    // order. Non-property struct fields (None) are skipped.
    let property_props: Vec<&PropertyAttrs> = props.iter().filter_map(|p| p.as_ref()).collect();
    // Lift the path-typed `object_type` to an expression so the shared
    // `descriptor_for` helper (also used by the augment path, which
    // passes an `Expr`) can take a uniform parameter.
    let object_type_expr: syn::Expr = syn::parse_quote!(#object_type);
    // An interface object belongs to exactly one profile, so its named
    // access levels resolve here, at const-evaluation time. `levels = 16`
    // on a System 7 object is what turns `Runtime` into 15.
    let levels = match &obj_attrs.levels {
        Some(e) => quote! { ((#e) as u8) },
        None => quote! { 4u8 },
    };
    let object_type_rl = match &obj_attrs.object_type_rl {
        Some(level) => {
            let ident = &level.0;
            quote! { ::zweidraehte_proto::access::AccessLevel::#ident }
        }
        None => quote! { ::zweidraehte_proto::access::AccessLevel::Runtime },
    };
    let descriptor_entries = property_props.iter().map(|p| descriptor_for(p, &object_type_expr, &levels));

    let read_arms = property_props.iter().map(|p| read_arm(p));
    let write_arms = property_props.iter().map(|p| write_arm(p));

    // ------------------------------------------------------------------
    // Final emission
    // ------------------------------------------------------------------
    Ok(quote! {
        #( #outer_attrs )*
        #vis struct #ident #impl_generics #where_clause {
            #( #kept_fields )*
        }

        impl #impl_generics #ident #ty_generics #where_clause {
            /// Property descriptors for this interface object.
            ///
            /// Index 0 is always OBJECT_TYPE (PID 1); user-defined properties
            /// follow in declaration order.
            pub const PROPERTY_DESCRIPTORS: &'static [
                ::zweidraehte_proto::properties::PropertyDescriptor
            ] = &[
                // OBJECT_TYPE (PID 1) — always first and ReadOnly. Its
                // audience defaults to Runtime but a mask-specific object
                // can override it at the struct level.
                // Mandated by the KNX spec for every interface object.
                ::zweidraehte_proto::properties::PropertyDescriptor::new(
                    ::zweidraehte_device::objects::interface::pid::OBJECT_TYPE,
                    <::zweidraehte_proto::dpt::PDT_UnsignedInt
                        as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
                    1,
                    ::zweidraehte_proto::properties::PropertyAccess::ReadOnly,
                    (#object_type_rl).for_levels(#levels),
                    ::zweidraehte_proto::access::AccessLevel::SystemManufacturer.for_levels(#levels),
                    ::zweidraehte_proto::access::AccessPolicy::READ_OPEN_WRITE_TOOL,
                ),
                #( #descriptor_entries , )*
            ];
        }

        impl #impl_generics ::zweidraehte_device::objects::interface::InterfaceObject
            for #ident #ty_generics #where_clause
        {
            fn object_type(&self) -> ::zweidraehte_proto::dpt::InterfaceObjectType {
                #object_type
            }

            fn property_count(&self) -> u16 {
                Self::PROPERTY_DESCRIPTORS.len() as u16
            }

            fn property_descriptor_by_index(
                &self,
                prop_idx: u16,
            ) -> ::core::option::Option<
                ::zweidraehte_proto::properties::PropertyDescriptor
            > {
                Self::PROPERTY_DESCRIPTORS.get(prop_idx as usize).copied()
            }

            fn property_descriptor_by_id(
                &self,
                pid: u16,
            ) -> ::core::option::Option<(
                u16,
                ::zweidraehte_proto::properties::PropertyDescriptor,
            )> {
                Self::PROPERTY_DESCRIPTORS
                    .iter()
                    .enumerate()
                    .find(|(_, d)| d.pid == pid)
                    .map(|(i, d)| (i as u16, *d))
            }

            fn read_property(
                &self,
                req: ::zweidraehte_device::objects::interface::PropertyReadRequest,
                buf: &mut [u8],
            ) -> ::core::result::Result<
                usize,
                ::zweidraehte_device::objects::interface::PropertyError,
            > {
                match req.pid {
                    ::zweidraehte_device::objects::interface::pid::OBJECT_TYPE => {
                        let obj_type: u16 =
                            <::zweidraehte_proto::dpt::InterfaceObjectType
                                as ::core::convert::Into<u16>>::into(#object_type);
                        ::zweidraehte_device::objects::interface::PropertyRead::read_property(
                            &obj_type.to_be_bytes(),
                            req.start_idx,
                            req.count,
                            buf,
                        )
                    }
                    #( #read_arms )*
                    _ => Err(::zweidraehte_device::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn write_property(
                &mut self,
                req: ::zweidraehte_device::objects::interface::PropertyWriteRequest<'_>,
            ) -> ::core::result::Result<
                ::zweidraehte_device::objects::interface::WriteResponse,
                ::zweidraehte_device::objects::interface::PropertyError,
            > {
                match req.pid {
                    ::zweidraehte_device::objects::interface::pid::OBJECT_TYPE => {
                        Err(::zweidraehte_device::objects::interface::PropertyError::WriteNotAllowed)
                    }
                    #( #write_arms )*
                    _ => Err(::zweidraehte_device::objects::interface::PropertyError::InvalidPropertyId),
                }
            }

            fn property_element_count(
                &self,
                pid: u16,
            ) -> ::core::result::Result<
                u16,
                ::zweidraehte_device::objects::interface::PropertyError,
            > {
                if let Some(d) = Self::PROPERTY_DESCRIPTORS.iter().find(|d| d.pid == pid) {
                    // Single-element properties report 1; array properties
                    // report the static `max_elements` from the descriptor.
                    // (Computed-max sites override this method themselves.)
                    Ok(if d.max_elements == 0 { 1 } else { d.max_elements })
                } else {
                    Err(::zweidraehte_device::objects::interface::PropertyError::InvalidPropertyId)
                }
            }
        }
    })
}

// ===========================================================================
// `#[interface_object_augment]` codegen
// ===========================================================================
//
// Augments are different beasts from `InterfaceObject` impls:
//
//  - The trait is `Augment<D: StackDefinition>` (in
//    `zweidraehte_device::service`) and every dispatch method takes
//    `(&self, ctx: &ServiceCtx<'_, D>, ...)`.
//  - Every method returns `Option<...>` so the container can fall
//    through to the next augment in the chain (named-field
//    `#[derive(ServiceRegistry)]` struct).
//  - One augment can touch multiple object types (`DiagnosticsAugment`
//    targets both `ApplicationProgram` and `GroupObjectTable`), so the
//    macro accepts `target_objects = [...]` and per-field `target = ...`.
//  - Augments may *add* whole new objects (`additional_objects = [...]`)
//    on top of the base IO list.
//  - The macro emits one `Augment<D>` impl per augment so it
//    can be used directly as an `#[service(augment)]` field in a
//    services struct without further work.
//
// The codegen mirrors these shapes. For each property field, the macro
// emits a descriptor entry (always) and a dispatch arm in the appropriate
// trait method (depending on which closure attributes are set). Fields
// marked `manual` skip the dispatch arm and route the unhandled PIDs to
// a fallback method on the user's struct (`handle_extra_pid*`), where
// the user supplies whatever bespoke logic the macro can't express.

pub(crate) fn gen_augment(
    item: &ItemStruct,
    obj_attrs: &ObjectAttrs,
    props: &[Option<PropertyAttrs>],
) -> syn::Result<TokenStream> {
    // For an additive augment, `additional_objects = [X]` implies the
    // augment also dispatches PIDs to those types — entries from
    // `additional_objects` are auto-included in the effective
    // `target_objects` list (deduped). The user only needs to list extra
    // intercepted base objects explicitly.
    let mut effective_targets: Vec<syn::Expr> = obj_attrs.target_objects.clone();
    for add in &obj_attrs.additional_objects {
        if !effective_targets.iter().any(|t| exprs_equal(t, add)) {
            effective_targets.push(add.clone());
        }
    }
    if effective_targets.is_empty() {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "`#[interface_object_augment]` requires `target_objects = [InterfaceObjectType::X, ...]` \
             or `additional_objects = [...]` with at least one entry",
        ));
    }

    let ident = &item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();
    let vis = &item.vis;
    let outer_attrs = item
        .attrs
        .iter()
        .filter(|a| !a.path().is_ident("interface_object") && !a.path().is_ident("interface_object_augment"));

    // For the augment trait impl we need to add a `D: StackDefinition`
    // parameter on top of the user's existing generics. Construct a fresh
    // `Generics` clone with `D` appended so we can split it cleanly.
    let mut augment_generics = item.generics.clone();
    augment_generics.params.push(syn::parse_quote! {
        D: ::zweidraehte_device::StackDefinition
    });
    // If the user supplied `where_bounds(...)`, splice them into the
    // generics' where clause so they survive `split_for_impl`.
    if let Some(extra) = &obj_attrs.extra_where {
        // `make_where_clause` returns the existing or a fresh empty
        // `Where` so we can extend it.
        let where_clause = augment_generics.make_where_clause();
        let parsed: syn::WhereClause = if where_clause.predicates.is_empty() {
            syn::parse_quote! { where #extra }
        } else {
            // Append: prefix with a comma so the existing predicates and
            // the extras compose into a single comma-separated list.
            syn::parse_quote! { where #extra, }
        };
        for pred in parsed.predicates {
            where_clause.predicates.push(pred);
        }
    }
    let (augment_impl_generics, _, augment_where_clause) = augment_generics.split_for_impl();

    // ----------------------------------------------------------------------
    // Re-emit the struct verbatim. Augments rarely use unit-typed virtual
    // fields the way `InterfaceObject` impls do (the closures usually live
    // on real struct fields), but we still strip `#[io(...)]` from the
    // output so rustc doesn't complain about an unknown attribute.
    // ----------------------------------------------------------------------
    let kept_fields: Vec<TokenStream> = item
        .fields
        .iter()
        .zip(props.iter())
        .filter_map(|(field, p)| {
            let drop = matches!(p, Some(prop) if matches!(prop.backing, Backing::Virtual));
            if drop {
                None
            } else {
                let attrs = field.attrs.iter().filter(|a| !a.path().is_ident("io"));
                let vis = &field.vis;
                let name = field.ident.as_ref().unwrap();
                let ty = &field.ty;
                Some(quote! {
                    #( #attrs )*
                    #vis #name: #ty,
                })
            }
        })
        .collect();
    // If every field was stripped (the augment is purely virtual — e.g.
    // `EasterEggAugment` with one function-only PID), emit a unit struct
    // so callers can construct it as `Foo` rather than `Foo {}`.
    let struct_body = if kept_fields.is_empty() {
        quote! { ; }
    } else {
        quote! { { #( #kept_fields )* } }
    };

    // ----------------------------------------------------------------------
    // Resolve per-PID target object. With a single declared target every
    // PID defaults to it; with multiple targets the parser-validated
    // `target = ...` attribute is required per field.
    // ----------------------------------------------------------------------
    let property_props: Vec<&PropertyAttrs> = props.iter().filter_map(|p| p.as_ref()).collect();
    let multi_target = effective_targets.len() > 1;
    let default_target = effective_targets[0].clone();
    for p in &property_props {
        if multi_target && p.target.is_none() {
            return Err(syn::Error::new(
                p.field_span,
                "augment declares multiple `target_objects`; this property must specify \
                 `target = InterfaceObjectType::...` to disambiguate",
            ));
        }
        // Field-backed augment writes are not implemented: augments are
        // dispatched through `&self`, so a write would need interior
        // mutability on the field plus a non-`&mut self` write trait.
        // Reject up front rather than emit a runtime `WriteNotAllowed`,
        // which used to compile silently and only fail at request time.
        if !p.manual
            && !matches!(p.access, Access::Ro)
            && matches!(p.backing, Backing::Field)
            && p.write_fn.is_none()
            && p.write_with_ctx.is_none()
        {
            return Err(syn::Error::new(
                p.field_span,
                "field-backed property write is not implemented; \
                 supply `write = |this, data| { ... }` (typically with a `Cell` or `RefCell` field) \
                 or mark the property `access = RO`",
            ));
        }
    }
    let pid_target =
        |p: &PropertyAttrs| -> syn::Expr { p.target.as_ref().cloned().unwrap_or_else(|| default_target.clone()) };

    // ----------------------------------------------------------------------
    // Descriptor table — single flat const slice across all targets. The
    // dispatch methods filter by object type at runtime; the descriptor
    // lookup (property_descriptor) does the same.
    // ----------------------------------------------------------------------
    let descriptor_entries = property_props.iter().map(|p| {
        let target = pid_target(p);
        let desc = descriptor_spec_for(p);
        // Pair each descriptor with its target so `property_descriptor`
        // can filter. We encode the pair as `(target, descriptor)` in a
        // separate const so DESCRIPTORS itself stays a flat
        // `&[PropertyDescriptor]`, matching the hand-written augments.
        quote! { (#target, #desc) }
    });

    // Build the per-target arms used inside `if object_type == X { ... }`
    // blocks for property_value_read / write / function_*.
    //
    // For each target, collect (pid, dispatch_token_stream) for arms.
    let pid_field_value: syn::Ident = syn::parse_quote!(pid);
    let pid_field_function: syn::Ident = syn::parse_quote!(prop_id);
    let read_arms_per_target =
        build_per_target_arms(&property_props, &effective_targets, &pid_target, &pid_field_value, |p| {
            augment_read_arm(p)
        });
    let write_arms_per_target =
        build_per_target_arms(&property_props, &effective_targets, &pid_target, &pid_field_value, |p| {
            augment_write_arm(p)
        });
    let fn_cmd_arms_per_target =
        build_per_target_arms(&property_props, &effective_targets, &pid_target, &pid_field_function, |p| {
            augment_function_command_arm(p)
        });
    let fn_state_arms_per_target =
        build_per_target_arms(&property_props, &effective_targets, &pid_target, &pid_field_function, |p| {
            augment_function_state_arm(p)
        });

    // additional_objects → count + type_at
    let additional_count = obj_attrs.additional_objects.len() as u16;
    let additional_type_arms = obj_attrs.additional_objects.iter().enumerate().map(|(i, t)| {
        let i = i as u16;
        quote! { #i => Some(#t), }
    });

    // Per-hook fallback gating. The macro emits a call into a user-defined
    // `handle_extra_pid_*` method only when at least one `manual` PID
    // actually needs that hook. PIDs are partitioned by PDT: function-
    // property PIDs (`pdt = PDT_Function`) flow exclusively through
    // `FunctionPropertyCommand` / `FunctionPropertyStateRead`; all other
    // manual PIDs flow through value read/write.
    //
    // The descriptor hook is the one exception — it's enabled whenever any
    // PID is `manual`, since dynamic descriptor lookup is universally
    // applicable (e.g. const-generic array sizing, runtime-conditional
    // PIDs).
    //
    // When a flag is true the user **must** supply the matching
    // `handle_extra_pid_*` impl on the augment struct.
    let manual_descriptor = property_props.iter().any(|p| p.manual);
    let manual_read = property_props.iter().any(|p| p.manual && !is_function_pdt(p) && !matches!(p.access, Access::Wo));
    let manual_write =
        property_props.iter().any(|p| p.manual && !is_function_pdt(p) && !matches!(p.access, Access::Ro));
    let manual_fn_cmd =
        property_props.iter().any(|p| p.manual && is_function_pdt(p) && !matches!(p.access, Access::Ro));
    let manual_fn_state = property_props.iter().any(|p| p.manual && is_function_pdt(p));
    // Fallbacks are *only* dispatched when the request's `object_type`
    // matches one of this augment's effective targets. Without this
    // guard, a `manual` PID like `LOAD_STATE_CONTROL` would steal writes
    // destined for unrelated objects (e.g. an Association Table's LSM
    // would be silently shadowed by SecurityAugment's LSM cascade
    // because both expose PID 5 LOAD_STATE_CONTROL).
    let target_matches: TokenStream = {
        let preds = effective_targets.iter().map(|t| quote! { object_type == #t });
        quote! { #( #preds )||* }
    };
    let gated_call = |enabled: bool, call: TokenStream| -> TokenStream {
        if enabled {
            quote! {
                if #target_matches {
                    #call
                } else {
                    None
                }
            }
        } else {
            quote! { None }
        }
    };
    let descriptor_fallback = gated_call(
        manual_descriptor,
        // User-supplied dynamic descriptor lookup (e.g. for runtime-
        // conditional or const-generic-sized array PIDs).
        quote! { self.handle_extra_pid_descriptor(object_type, prop_id) },
    );
    let read_fallback = gated_call(manual_read, quote! { self.handle_extra_pid_read(ctx, object_type, req, buf) });
    let write_fallback = gated_call(manual_write, quote! { self.handle_extra_pid_write(ctx, object_type, req) });
    let fn_cmd_fallback =
        gated_call(manual_fn_cmd, quote! { self.handle_extra_pid_function_command(ctx, object_type, req) });
    let fn_state_fallback =
        gated_call(manual_fn_state, quote! { self.handle_extra_pid_function_state_read(ctx, object_type, req) });

    Ok(quote! {
        #( #outer_attrs )*
        #vis struct #ident #impl_generics #where_clause #struct_body

        impl #impl_generics #ident #ty_generics #where_clause {
            /// Property descriptor table (paired with the target object
            /// type for each PID — the augment can target multiple types).
            ///
            /// This `const` is the single source of truth for descriptor
            /// lookups. `property_descriptor` and
            /// `property_description_read` route through it.
            #[allow(clippy::type_complexity)]
            pub const DESCRIPTORS: &'static [(
                ::zweidraehte_proto::dpt::InterfaceObjectType,
                ::zweidraehte_proto::properties::PropertyDescriptorSpec,
            )] = &[
                #( #descriptor_entries , )*
            ];

        }

        impl #augment_impl_generics ::zweidraehte_device::service::Augment<D>
            for #ident #ty_generics #augment_where_clause
        {
            fn property_descriptor(
                &self,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                prop_id: u16,
            ) -> ::core::option::Option<::zweidraehte_proto::properties::PropertyDescriptor> {
                if let Some(d) = Self::DESCRIPTORS
                    .iter()
                    .find(|(t, d)| *t == object_type && d.pid == prop_id)
                    .map(|(_, d)| d.for_levels(<<D as ::zweidraehte_device::StackDefinition>::State as ::zweidraehte_device::HasAuthorization>::MAX_ACCESS_LEVELS))
                {
                    return Some(d);
                }
                #descriptor_fallback
            }

            fn property_description_read(
                &self,
                _ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                object_idx: u16,
                lookup: ::zweidraehte_device::objects::interface::PropertyLookup,
            ) -> ::core::option::Option<::core::result::Result<
                ::zweidraehte_device::objects::interface::PropertyDescriptionResponse,
                ::zweidraehte_device::objects::interface::PropertyError,
            >> {
                use ::zweidraehte_device::objects::interface::{PropertyDescriptionResponse, PropertyLookup};
                // Only descriptors for `object_type` are visible to the
                // index-based scan used by `A_PropertyDescription_Read`.
                let mut filtered = Self::DESCRIPTORS.iter().filter(|(t, _)| *t == object_type);
                match lookup {
                    PropertyLookup::ByPid(pid) => filtered
                        .enumerate()
                        .find(|(_, (_, d))| d.pid == pid)
                        .map(|(idx, (_, d))| {
                            let d = d.for_levels(<<D as ::zweidraehte_device::StackDefinition>::State as ::zweidraehte_device::HasAuthorization>::MAX_ACCESS_LEVELS);
                            Ok(PropertyDescriptionResponse::from_descriptor(object_idx, idx as u16, &d))
                        }),
                    PropertyLookup::ByIndex(idx) => filtered
                        .nth(idx as usize)
                        .map(|(_, d)| {
                            let d = d.for_levels(<<D as ::zweidraehte_device::StackDefinition>::State as ::zweidraehte_device::HasAuthorization>::MAX_ACCESS_LEVELS);
                            Ok(PropertyDescriptionResponse::from_descriptor(object_idx, idx, &d))
                        }),
                }
            }

            fn property_value_read(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &::zweidraehte_device::objects::interface::FullPropertyReadRequest,
                buf: &mut [u8],
            ) -> ::core::option::Option<::core::result::Result<
                usize,
                ::zweidraehte_device::objects::interface::PropertyError,
            >> {
                #( #read_arms_per_target )*
                #read_fallback
            }

            fn property_value_write(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &::zweidraehte_device::objects::interface::FullPropertyWriteRequest<'_>,
            ) -> ::core::option::Option<::core::result::Result<
                ::zweidraehte_device::objects::interface::WriteResponse,
                ::zweidraehte_device::objects::interface::PropertyError,
            >> {
                #( #write_arms_per_target )*
                #write_fallback
            }

            fn function_property_command(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &::zweidraehte_device::objects::interface::FunctionPropertyRequest<'_>,
            ) -> ::core::option::Option<::zweidraehte_device::objects::interface::FunctionPropertyResult> {
                #( #fn_cmd_arms_per_target )*
                #fn_cmd_fallback
            }

            fn function_property_state_read(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &::zweidraehte_device::objects::interface::FunctionPropertyRequest<'_>,
            ) -> ::core::option::Option<::zweidraehte_device::objects::interface::FunctionPropertyResult> {
                #( #fn_state_arms_per_target )*
                #fn_state_fallback
            }

            fn additional_object_count(&self) -> u16 {
                #additional_count
            }

            fn additional_object_type_at(
                &self,
                index: u16,
            ) -> ::core::option::Option<::zweidraehte_proto::dpt::InterfaceObjectType> {
                match index {
                    #( #additional_type_arms )*
                    _ => None,
                }
            }

            fn descriptor_count_for(
                &self,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
            ) -> u16 {
                // Count of this augment's descriptors for `object_type` — the
                // same filter the index-based `property_description_read` scan
                // uses. The `ServiceRegistry` aggregator sums this across the
                // augments preceding a field so a second augment contributing
                // to the same object type is reachable by index.
                Self::DESCRIPTORS.iter().filter(|(t, _)| *t == object_type).count() as u16
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Augment per-target arm builder
// ---------------------------------------------------------------------------
//
// For each declared target, builds a block of:
//
//     if object_type == <target> {
//         match req.pid {
//             pid::FOO => <gen-arm>,
//             pid::BAR => <gen-arm>,
//             _ => {} // fall through to handle_extra_pid*
//         }
//     }
//
// PIDs marked `manual` produce no arm — they fall through to
// `handle_extra_pid_*`.

/// Builds per-target dispatch blocks. `pid_field` is the field name on
/// the request struct holding the property id (`pid` for value reads,
/// `prop_id` for function-property requests).
fn build_per_target_arms<F>(
    props: &[&PropertyAttrs],
    targets: &[syn::Expr],
    pid_target: &dyn Fn(&PropertyAttrs) -> syn::Expr,
    pid_field: &syn::Ident,
    arm_for: F,
) -> Vec<TokenStream>
where
    F: Fn(&PropertyAttrs) -> Option<TokenStream>,
{
    targets
        .iter()
        .map(|target| {
            let arms: Vec<TokenStream> = props
                .iter()
                .filter(|p| {
                    let pt = pid_target(p);
                    exprs_equal(&pt, target)
                })
                .filter_map(|p| arm_for(p))
                .collect();
            if arms.is_empty() {
                quote! {}
            } else {
                quote! {
                    if object_type == #target {
                        match req.#pid_field {
                            #( #arms )*
                            _ => {}
                        }
                    }
                }
            }
        })
        .collect()
}

/// True when the property's PDT is `PDT_Function` (matched by the path's
/// last segment). Function-property PIDs flow through
/// `FunctionPropertyCommand` / `FunctionPropertyStateRead` rather than
/// value reads/writes; we use this to gate which `handle_extra_pid_*`
/// hooks the macro calls into. PIDs declared via `pdt_raw = ...` always
/// answer `false` and land in the value-side bucket — no in-tree augment
/// uses `pdt_raw` for a function PID, and the parser's mutual-exclusivity
/// rule keeps `pdt`/`pdt_raw` from coexisting.
fn is_function_pdt(p: &PropertyAttrs) -> bool {
    p.pdt.as_ref().and_then(|path| path.segments.last()).is_some_and(|seg| seg.ident == "PDT_Function")
}

fn exprs_equal(a: &syn::Expr, b: &syn::Expr) -> bool {
    // Compare by token stream — not robust against `Foo::Bar` vs `crate::x::Foo::Bar`
    // but the user is expected to be consistent within a single
    // `#[interface_object_augment(...)]` invocation.
    quote! { #a }.to_string() == quote! { #b }.to_string()
}

// ---------------------------------------------------------------------------
// Augment dispatch arms
// ---------------------------------------------------------------------------
//
// Each `arm_for` function returns:
//  - `Some(TokenStream)` for a generated match arm (`pid::X => return ...`).
//  - `None` if this PID has nothing to contribute to that dispatch path
//    (e.g. PID with only `read_fn` contributes nothing to `function_property_command`).
//
// Field-backed augment properties (`Backing::Field`) dispatch through the
// usual `PropertyRead` / `PropertyWrite` traits on the struct field, just
// like `InterfaceObject` does. Virtual properties dispatch through the
// user's closures.
//
// `manual` skips arm generation for *every* dispatch path. The descriptor
// is still emitted. Routing falls through to `handle_extra_pid_*`.

fn augment_read_arm(p: &PropertyAttrs) -> Option<TokenStream> {
    if p.manual {
        return None;
    }
    if matches!(p.access, Access::Wo) {
        let pid = &p.pid;
        return Some(quote! {
            #pid => return Some(Err(::zweidraehte_device::objects::interface::PropertyError::ReadNotAllowed)),
        });
    }

    let pid = &p.pid;
    if let Some(read_with_ctx) = &p.read_with_ctx {
        Some(quote! {
            #pid => {
                let __c = #read_with_ctx;
                let data = __c(self, ctx);
                return Some(::zweidraehte_device::objects::interface::PropertyRead::read_property(
                    &data, req.start_idx, req.count, buf,
                ));
            }
        })
    } else if let Some(read_fn) = &p.read_fn {
        Some(quote! {
            #pid => {
                let __c = #read_fn;
                let data = __c(self);
                return Some(::zweidraehte_device::objects::interface::PropertyRead::read_property(
                    &data, req.start_idx, req.count, buf,
                ));
            }
        })
    } else if matches!(p.backing, Backing::Field) {
        let name = &p.field_ident;
        Some(quote! {
            #pid => return Some(::zweidraehte_device::objects::interface::PropertyRead::read_property(
                &self.#name, req.start_idx, req.count, buf,
            )),
        })
    } else {
        // Virtual property without a read closure → nothing to do here.
        None
    }
}

fn augment_write_arm(p: &PropertyAttrs) -> Option<TokenStream> {
    if p.manual {
        return None;
    }
    if matches!(p.access, Access::Ro) {
        let pid = &p.pid;
        return Some(quote! {
            #pid => return Some(Err(::zweidraehte_device::objects::interface::PropertyError::WriteNotAllowed)),
        });
    }

    let pid = &p.pid;
    if let Some(write_with_ctx) = &p.write_with_ctx {
        // Pass the full write request, not just `req.data`, so closures
        // can inspect `start_idx` / `count` for array-index writes and
        // see any future request fields without another macro change.
        return Some(quote! {
            #pid => {
                let __c = #write_with_ctx;
                return Some(__c(self, ctx, req));
            }
        });
    }

    let Some(write_fn) = &p.write_fn else {
        // Field-backed writes are rejected up front in `gen_augment`
        // (see the validation pass before arm generation), so a
        // writable field-backed property never reaches this branch.
        return None;
    };

    Some(quote! {
        #pid => {
            let __c = #write_fn;
            return Some(__c(self, req.data));
        }
    })
}

fn augment_function_command_arm(p: &PropertyAttrs) -> Option<TokenStream> {
    let function_command = p.function_command.as_ref()?;
    let pid = &p.pid;
    Some(quote! {
        #pid => {
            let __c = #function_command;
            return Some(__c(self, ctx, req));
        }
    })
}

fn augment_function_state_arm(p: &PropertyAttrs) -> Option<TokenStream> {
    let function_state_read = p.function_state_read.as_ref()?;
    let pid = &p.pid;
    Some(quote! {
        #pid => {
            let __c = #function_state_read;
            return Some(__c(self, ctx, req));
        }
    })
}

// ---------------------------------------------------------------------------
// Per-property descriptor entry
// ---------------------------------------------------------------------------

/// The two access levels of a property, as `AccessLevel` expressions.
///
/// Defaults follow the KNX convention for the access mode: a readable
/// property is readable at runtime, a writable one is writable by a
/// controller, and the unreachable half of a read-only or write-only
/// property sits at the most privileged level. Spelling those defaults
/// as audiences rather than numbers is what lets a shared object be
/// hosted by either authorisation model — see
/// `zweidraehte_proto::access::AccessLevel`.
fn level_specs(p: &PropertyAttrs) -> (TokenStream, TokenStream) {
    let audience = |name: &str| -> TokenStream {
        let ident = syn::Ident::new(name, Span::call_site());
        quote! { ::zweidraehte_proto::access::AccessLevel::#ident }
    };
    let render = |lvl: &LevelAttr| -> TokenStream {
        let ident = &lvl.0;
        quote! { ::zweidraehte_proto::access::AccessLevel::#ident }
    };

    let (default_rl, default_wl) = match p.access {
        Access::Ro => (audience("Runtime"), audience("SystemManufacturer")),
        Access::Rw => (audience("Runtime"), audience("Controller")),
        Access::Wo => (audience("SystemManufacturer"), audience("Controller")),
    };
    let rl = p.rl.as_ref().map(render).unwrap_or(default_rl);
    let wl = p.wl.as_ref().map(render).unwrap_or(default_wl);
    (rl, wl)
}

fn descriptor_for(p: &PropertyAttrs, _object_type: &syn::Expr, levels: &TokenStream) -> TokenStream {
    let pid = &p.pid;
    let policy = &p.policy;
    // PDT is either a named type (`pdt = PDT_Foo`, takes `::ID`) or a raw
    // u8 escape (`pdt_raw = 0xNN`). Parser already guarantees exactly one
    // is set.
    let pdt_id = if let Some(raw) = p.pdt_raw {
        quote! { #raw u8 }
    } else {
        let pdt = p.pdt.as_ref().expect("parser checked exactly one of pdt/pdt_raw");
        quote! { <#pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID }
    };

    let access = match p.access {
        Access::Ro => quote! { ::zweidraehte_proto::properties::PropertyAccess::ReadOnly },
        Access::Rw => quote! { ::zweidraehte_proto::properties::PropertyAccess::ReadWrite },
        Access::Wo => quote! { ::zweidraehte_proto::properties::PropertyAccess::WriteOnly },
    };

    let (rl, wl) = level_specs(p);

    let max_elements = if let Some(n) = &p.array_max {
        // `array(max = <expr>)` — `<expr>` is forwarded verbatim and
        // must evaluate to `u16`. The `as u16` cast covers the common
        // `array(max = N)` case where `N` is a `usize` const generic.
        quote! { (#n) as u16 }
    } else if p.computed_max.is_some() {
        // Sentinel; patched at lookup time by the user's `computed_max` site.
        quote! { 0u16 }
    } else {
        quote! { 1u16 }
    };

    quote! {
        ::zweidraehte_proto::properties::PropertyDescriptor::new(
            #pid,
            #pdt_id,
            #max_elements,
            #access,
            (#rl).for_levels(#levels),
            (#wl).for_levels(#levels),
            #policy,
        )
    }
}

/// The augment form of [`descriptor_for`]: levels stay symbolic.
///
/// An augment can be composed onto either authorisation model — the
/// Security Interface Object is composed onto both — so it publishes
/// specs and the generated `Augment<D>` methods resolve them against the
/// device's own `MAX_ACCESS_LEVELS`.
fn descriptor_spec_for(p: &PropertyAttrs) -> TokenStream {
    let pid = &p.pid;
    let policy = &p.policy;
    let pdt_id = if let Some(raw) = p.pdt_raw {
        quote! { #raw u8 }
    } else {
        let pdt = p.pdt.as_ref().expect("parser checked exactly one of pdt/pdt_raw");
        quote! { <#pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID }
    };
    let access = match p.access {
        Access::Ro => quote! { ::zweidraehte_proto::properties::PropertyAccess::ReadOnly },
        Access::Rw => quote! { ::zweidraehte_proto::properties::PropertyAccess::ReadWrite },
        Access::Wo => quote! { ::zweidraehte_proto::properties::PropertyAccess::WriteOnly },
    };
    let (rl, wl) = level_specs(p);
    let max_elements = if let Some(n) = &p.array_max {
        quote! { (#n) as u16 }
    } else if p.computed_max.is_some() {
        quote! { 0u16 }
    } else {
        quote! { 1u16 }
    };

    quote! {
        ::zweidraehte_proto::properties::PropertyDescriptorSpec::new(
            #pid,
            #pdt_id,
            #max_elements,
            #access,
            #rl, #wl,
            #policy,
        )
    }
}

// ---------------------------------------------------------------------------
// read_property match arm per property
// ---------------------------------------------------------------------------

fn read_arm(p: &PropertyAttrs) -> TokenStream {
    let pid = &p.pid;

    // Every arm ends with a trailing comma so block-bodied and expression-bodied
    // arms compose cleanly when concatenated.
    match (p.access, p.backing, &p.read_fn) {
        (Access::Wo, _, _) => quote! {
            #pid => Err(::zweidraehte_device::objects::interface::PropertyError::ReadNotAllowed),
        },
        (_, Backing::Field, _) => {
            // Field-backed: read directly from the struct field via PropertyRead.
            let name = &p.field_ident;
            quote! {
                #pid => ::zweidraehte_device::objects::interface::PropertyRead::read_property(
                    &self.#name, req.start_idx, req.count, buf,
                ),
            }
        }
        (_, Backing::Virtual, Some(read_fn)) => {
            // Virtual: invoke the user's `read = |this| …` closure with `&self`.
            // The closure returns a value implementing `PropertyRead` (commonly
            // `[u8; N]`) which is then sliced into `buf` via the standard
            // start_idx/count protocol.
            quote! {
                #pid => {
                    let __read_closure = #read_fn;
                    let data = __read_closure(self);
                    ::zweidraehte_device::objects::interface::PropertyRead::read_property(
                        &data, req.start_idx, req.count, buf,
                    )
                },
            }
        }
        (_, Backing::Virtual, None) => quote! {
            #pid => Err(::zweidraehte_device::objects::interface::PropertyError::ReadNotAllowed),
        },
    }
}

// ---------------------------------------------------------------------------
// write_property match arm per property
// ---------------------------------------------------------------------------

fn write_arm(p: &PropertyAttrs) -> TokenStream {
    let pid = &p.pid;

    match (p.access, p.backing, &p.write_fn) {
        (Access::Ro, _, _) => quote! {
            #pid => Err(::zweidraehte_device::objects::interface::PropertyError::WriteNotAllowed),
        },
        (_, Backing::Field, _) => {
            let name = &p.field_ident;
            quote! {
                #pid => {
                    ::zweidraehte_device::objects::interface::PropertyWrite::write_property(
                        &mut self.#name, req.start_idx, req.data,
                    )?;
                    Ok(::zweidraehte_device::objects::interface::WriteResponse::Echo)
                },
            }
        }
        (_, Backing::Virtual, Some(write_fn)) => {
            // The user's closure takes `&mut Self` and the request data; it
            // must return the full `Result<WriteResponse, PropertyError>` so
            // it can choose between `Echo` and `Data(...)` (e.g. LSM/RSM
            // writes that echo back the new state byte).
            quote! {
                #pid => {
                    let __write_closure = #write_fn;
                    __write_closure(self, req.data)
                },
            }
        }
        (_, Backing::Virtual, None) => quote! {
            #pid => Err(::zweidraehte_device::objects::interface::PropertyError::WriteNotAllowed),
        },
    }
}
