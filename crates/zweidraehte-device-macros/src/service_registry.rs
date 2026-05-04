//! `#[derive(ServiceRegistry)]` — emits `LayerRegistry<D>` and
//! `AugmentRegistry<D>` impls on a device's services struct.
//!
//! The derive walks the struct's named fields and partitions them by
//! `#[service(...)]` attribute:
//!
//! - `#[service(handler)]` — field implements
//!   [`Layer<D>`](::zweidraehte_device::service::Layer). Contributes
//!   to the const dispatch table and the layer-side lifecycle
//!   aggregation.
//! - `#[service(augment)]` — field implements
//!   [`Augment<D>`](::zweidraehte_device::service::Augment). Joins
//!   the property-hook chain, IO-list contribution sum, and
//!   augment-side lifecycle aggregation.
//!
//! Both impls are generic over `D: ::zweidraehte_device::StackDefinition`,
//! so a single services struct can be reused across multiple
//! `StackDefinition` types provided every field's trait impl is also
//! generic (or already covers the concrete `D`).

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

/// Per-field role parsed from the `#[service(...)]` attribute.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ServiceFieldRole {
    Handler,
    Augment,
    /// `#[service(flatten)]` — the field is itself a struct that
    /// implements `AugmentRegistry<D>` (typically another
    /// `#[derive(ServiceRegistry)]` struct or a pre-bundled augment
    /// bundle). The outer registry's augment chain delegates each
    /// method through to this field's `AugmentRegistry` impl, so the
    /// inner struct's augments participate in the property hook
    /// chain, IO list aggregation, and lifecycle as if they were
    /// declared directly on the outer struct.
    ///
    /// Flattened structs may **not** also expose `Layer<D>` handler
    /// fields today: the const dispatch table is keyed on a single
    /// outer field index and would need a 2D mapping to forward into
    /// a flattened sub-table. Devices that need to compose layer
    /// stacks list their handler fields directly on the outer
    /// struct.
    Flatten,
}

/// Parsed field with its role and identifier. The field's type is
/// kept around because the dispatch-table builder needs it as a path
/// to call `<FieldTy as Layer<D>>::HANDLES`.
struct ServiceField<'a> {
    role: ServiceFieldRole,
    ident: &'a syn::Ident,
    ty: &'a syn::Type,
}

pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_name = &input.ident;

    // Inject `D: StackDefinition` as an extra generic parameter on the
    // emitted impl, on top of whatever generics the struct already
    // carries. `split_for_impl()` returns the struct's own generics,
    // and we splice `D` into the impl-side parameter list separately.
    //
    // Rust requires lifetime parameters to come before type and const
    // parameters in `impl<...>` lists. So we partition the struct's
    // own generics: lifetimes first, then `D`, then everything else.
    let (_, ty_generics, where_clause) = input.generics.split_for_impl();
    let struct_lifetimes: Vec<_> = input
        .generics
        .params
        .iter()
        .filter(|p| matches!(p, syn::GenericParam::Lifetime(_)))
        .collect();
    let struct_non_lifetime_params: Vec<_> = input
        .generics
        .params
        .iter()
        .filter(|p| !matches!(p, syn::GenericParam::Lifetime(_)))
        .collect();
    let struct_lifetime_separator = if struct_lifetimes.is_empty() { quote! {} } else { quote! { , } };
    let struct_non_lifetime_separator = if struct_non_lifetime_params.is_empty() { quote! {} } else { quote! { , } };

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "ServiceRegistry can only be derived for structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(input, "ServiceRegistry can only be derived for structs"));
        }
    };

    // -----------------------------------------------------------------
    // Parse #[service(...)] annotations.
    //
    // Every field must carry exactly one `#[service(role)]` attribute
    // where `role` is `handler` or `augment`. Unannotated fields are
    // a hard error — silent acceptance would lose track of state we
    // need to aggregate.
    // -----------------------------------------------------------------
    let mut service_fields: Vec<ServiceField<'_>> = Vec::with_capacity(fields.len());

    for field in fields {
        let ident = field.ident.as_ref().expect("named-field struct guaranteed by check above");

        let mut role: Option<ServiceFieldRole> = None;
        for attr in &field.attrs {
            if !attr.path().is_ident("service") {
                continue;
            }

            attr.parse_nested_meta(|meta| {
                let new_role = if meta.path.is_ident("handler") {
                    ServiceFieldRole::Handler
                } else if meta.path.is_ident("augment") {
                    ServiceFieldRole::Augment
                } else if meta.path.is_ident("flatten") {
                    ServiceFieldRole::Flatten
                } else {
                    return Err(meta.error("expected `handler`, `augment`, or `flatten`"));
                };

                if role.is_some() {
                    return Err(meta.error("duplicate role on this field"));
                }
                role = Some(new_role);
                Ok(())
            })?;
        }

        let role = role.ok_or_else(|| {
            syn::Error::new_spanned(
                field,
                "every field of a `#[derive(ServiceRegistry)]` struct must carry one of \
                 `#[service(handler)]`, `#[service(augment)]`, or `#[service(flatten)]`",
            )
        })?;

        service_fields.push(ServiceField { role, ident, ty: &field.ty });
    }

    let handlers: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| f.role == ServiceFieldRole::Handler).collect();
    let augments: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| f.role == ServiceFieldRole::Augment).collect();
    let flattens: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| f.role == ServiceFieldRole::Flatten).collect();

    // `#[service(flatten)]` only forwards into the inner struct's
    // `AugmentRegistry<D>` impl. The const dispatch table is keyed
    // on a single outer field index per `Layer`, which can't route
    // through a flattened sub-table without a 2D mapping. Reject
    // mixing handlers and flattens here so the failure is a clear
    // macro-time error instead of a confusing trait-resolution one
    // later.
    if !handlers.is_empty() && !flattens.is_empty() {
        return Err(syn::Error::new_spanned(
            input,
            "`#[service(flatten)]` cannot be combined with `#[service(handler)]` fields on the \
             same struct: the const dispatch table cannot route through a flattened sub-table. \
             Declare handler fields directly on the outer struct.",
        ));
    }

    // -----------------------------------------------------------------
    // LayerRegistry impl — const dispatch table + lifecycle aggregator
    // for every #[service(handler)] field.
    // -----------------------------------------------------------------

    let dispatch_table_body = if handlers.is_empty() {
        quote! { ::zweidraehte_device::router::DispatchTable::empty() }
    } else {
        // For each handler at positional index `idx`, generate a const
        // loop that registers all of its `HANDLES` entries. The
        // `.into()` call works inside a const context thanks to the
        // device crate's `feature(const_trait_impl) +
        // feature(const_convert)`.
        let registrations = handlers.iter().enumerate().map(|(idx, h)| {
            let ty = h.ty;
            let idx_u8 = idx as u8;
            quote! {
                {
                    let handles = <#ty as ::zweidraehte_device::service::Layer<D>>::HANDLES;
                    let mut i = 0;
                    while i < handles.len() {
                        let st: u8 = handles[i].into();
                        table.register(st, #idx_u8);
                        i += 1;
                    }
                }
            }
        });

        quote! {
            {
                let mut table = ::zweidraehte_device::router::DispatchTable::empty();
                #( #registrations )*
                table
            }
        }
    };

    let dispatch_arms = handlers.iter().enumerate().map(|(idx, h)| {
        let ident = h.ident;
        let idx_u8 = idx as u8;
        quote! {
            #idx_u8 => ::zweidraehte_device::service::Layer::<D>::process(&mut self.#ident, msg, ctx),
        }
    });

    let init_layer_calls = handlers.iter().map(|h| {
        let ident = h.ident;
        quote! { ::zweidraehte_device::service::Layer::<D>::init(&mut self.#ident, ctx); }
    });

    let poll_layer_calls = handlers.iter().map(|h| {
        let ident = h.ident;
        quote! { ::zweidraehte_device::service::Layer::<D>::poll(&mut self.#ident, ctx); }
    });

    let next_layer_deadline_merges = handlers.iter().map(|h| {
        let ident = h.ident;
        quote! {
            if let Some(d) = ::zweidraehte_device::service::Layer::<D>::next_deadline(&self.#ident) {
                earliest = Some(match earliest {
                    Some(e) if e < d => e,
                    _ => d,
                });
            }
        }
    });

    let layer_registry_impl = quote! {
        impl<#(#struct_lifetimes),* #struct_lifetime_separator D #struct_non_lifetime_separator #(#struct_non_lifetime_params),*>
            ::zweidraehte_device::service::LayerRegistry<D> for #struct_name #ty_generics
        where
            D: ::zweidraehte_device::StackDefinition,
            #where_clause
        {
            const DISPATCH_TABLE: ::zweidraehte_device::router::DispatchTable = #dispatch_table_body;

            fn dispatch_wire(
                &mut self,
                idx: u8,
                msg: ::zweidraehte_device::__macro_support::messages::knx::KnxMessageBuffer<
                    ::zweidraehte_device::__macro_support::messages::buffers::Buffer<'static>,
                >,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
            ) {
                match idx {
                    #( #dispatch_arms )*
                    _ => ::core::unreachable!(
                        "dispatch_wire called with idx={} not registered in DISPATCH_TABLE",
                        idx,
                    ),
                }
            }

            fn init_layers(&mut self, ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>) {
                #( #init_layer_calls )*
            }

            fn poll_layers(&mut self, ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>) {
                #( #poll_layer_calls )*
            }

            fn next_layer_deadline(&self) -> ::core::option::Option<::embassy_time::Instant> {
                let mut earliest: ::core::option::Option<::embassy_time::Instant> =
                    ::core::option::Option::None;
                #( #next_layer_deadline_merges )*
                earliest
            }
        }
    };

    // -----------------------------------------------------------------
    // AugmentRegistry impl — property-hook chain, IO list aggregation,
    // and augment-side lifecycle for every #[service(augment)] field.
    // -----------------------------------------------------------------

    let augment_idents: Vec<&syn::Ident> = augments.iter().map(|a| a.ident).collect();
    let flatten_idents: Vec<&syn::Ident> = flattens.iter().map(|f| f.ident).collect();
    let any_aug_or_flatten = !augments.is_empty() || !flattens.is_empty();

    // Property-hook chains. Each method walks fields left-to-right
    // (`#[service(augment)]` then `#[service(flatten)]`); the first
    // to return `Some` claims the request. Augment-marked fields
    // forward through the `Augment<D>` trait; flatten-marked fields
    // forward through the `AugmentRegistry<D>` trait so a nested
    // services struct's chain participates in full.
    //
    // The `&mut [u8]` borrow on `property_value_read` rules out the
    // closure-based `.or_else()` chain; that path uses explicit
    // if-let arms instead.
    let prop_chain_get_descriptor = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let aug_calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::get_property_descriptor(
                    &self.#id, object_type, prop_id))
            }
        });
        let flat_calls = flatten_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::AugmentRegistry::<D>::get_property_descriptor(
                    &self.#id, object_type, prop_id))
            }
        });
        quote! { ::core::option::Option::None #( #aug_calls )* #( #flat_calls )* }
    };

    let prop_chain_description_read = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let aug_calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::property_description_read(
                    &self.#id, ctx, object_type, object_idx, lookup))
            }
        });
        let flat_calls = flatten_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::AugmentRegistry::<D>::property_description_read(
                    &self.#id, ctx, object_type, object_idx, lookup))
            }
        });
        quote! { ::core::option::Option::None #( #aug_calls )* #( #flat_calls )* }
    };

    let prop_chain_value_read = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let aug_arms = augment_idents.iter().map(|id| {
            quote! {
                if let r @ ::core::option::Option::Some(_) =
                    ::zweidraehte_device::service::Augment::<D>::property_value_read(
                        &self.#id, ctx, object_type, req, buf,
                    )
                {
                    return r;
                }
            }
        });
        let flat_arms = flatten_idents.iter().map(|id| {
            quote! {
                if let r @ ::core::option::Option::Some(_) =
                    ::zweidraehte_device::service::AugmentRegistry::<D>::property_value_read(
                        &self.#id, ctx, object_type, req, buf,
                    )
                {
                    return r;
                }
            }
        });
        quote! {
            #( #aug_arms )*
            #( #flat_arms )*
            ::core::option::Option::None
        }
    };

    let prop_chain_value_write = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let aug_calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::property_value_write(
                    &self.#id, ctx, object_type, req))
            }
        });
        let flat_calls = flatten_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::AugmentRegistry::<D>::property_value_write(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #aug_calls )* #( #flat_calls )* }
    };

    let prop_chain_func_command = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let aug_calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::function_property_command(
                    &self.#id, ctx, object_type, req))
            }
        });
        let flat_calls = flatten_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::AugmentRegistry::<D>::function_property_command(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #aug_calls )* #( #flat_calls )* }
    };

    let prop_chain_func_state_read = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let aug_calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::function_property_state_read(
                    &self.#id, ctx, object_type, req))
            }
        });
        let flat_calls = flatten_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::AugmentRegistry::<D>::function_property_state_read(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #aug_calls )* #( #flat_calls )* }
    };

    // IO list contribution: sum + walk-by-index. Augment fields go
    // first (Augment::additional_object_count), then flatten fields
    // (AugmentRegistry::additional_object_count) — same order as the
    // hook chain so the index space stays consistent.
    let aug_io_count_terms = augment_idents.iter().map(|id| {
        quote! { ::zweidraehte_device::service::Augment::<D>::additional_object_count(&self.#id) }
    });
    let flat_io_count_terms = flatten_idents.iter().map(|id| {
        quote! { ::zweidraehte_device::service::AugmentRegistry::<D>::additional_object_count(&self.#id) }
    });
    let io_count_body = quote! { 0u16 #( + #aug_io_count_terms )* #( + #flat_io_count_terms )* };

    let aug_io_at_arms = augment_idents.iter().map(|id| {
        quote! {
            let n = ::zweidraehte_device::service::Augment::<D>::additional_object_count(&self.#id);
            if index < n {
                return ::zweidraehte_device::service::Augment::<D>::additional_object_type_at(&self.#id, index);
            }
            index -= n;
        }
    });
    let flat_io_at_arms = flatten_idents.iter().map(|id| {
        quote! {
            let n = ::zweidraehte_device::service::AugmentRegistry::<D>::additional_object_count(&self.#id);
            if index < n {
                return ::zweidraehte_device::service::AugmentRegistry::<D>::additional_object_type_at(&self.#id, index);
            }
            index -= n;
        }
    });

    // Augment-side lifecycle. Augments use Augment::poll (&mut self),
    // flattens use AugmentRegistry::poll_augments (&mut self) which
    // delegates further into its own fields.
    let poll_augment_calls = augment_idents.iter().map(|id| {
        quote! { ::zweidraehte_device::service::Augment::<D>::poll(&mut self.#id, ctx); }
    });
    let poll_flatten_calls = flatten_idents.iter().map(|id| {
        quote! { ::zweidraehte_device::service::AugmentRegistry::<D>::poll_augments(&mut self.#id, ctx); }
    });

    let next_augment_deadline_merges = augment_idents.iter().map(|id| {
        quote! {
            if let Some(d) = ::zweidraehte_device::service::Augment::<D>::next_deadline(&self.#id) {
                earliest = Some(match earliest {
                    Some(e) if e < d => e,
                    _ => d,
                });
            }
        }
    });
    let next_flatten_deadline_merges = flatten_idents.iter().map(|id| {
        quote! {
            if let Some(d) = ::zweidraehte_device::service::AugmentRegistry::<D>::next_augment_deadline(&self.#id) {
                earliest = Some(match earliest {
                    Some(e) if e < d => e,
                    _ => d,
                });
            }
        }
    });

    // For each `#[service(augment)]` field, the impl requires the
    // field's type to satisfy `Augment<D>`. Same idea for
    // `#[service(flatten)]` fields, which need `AugmentRegistry<D>`.
    // These are explicit `where` bounds in the emitted impl so any
    // additional state-trait bounds on the field type (e.g. a
    // `DiagnosticsAugment` requiring `D::State: HasExtensionState`)
    // get inferred from the field's own trait impl, without the
    // user having to spell them out on the outer struct.
    let augment_field_bounds = augments.iter().map(|a| {
        let ty = a.ty;
        quote! { #ty: ::zweidraehte_device::service::Augment<D> }
    });
    let flatten_field_bounds = flattens.iter().map(|f| {
        let ty = f.ty;
        quote! { #ty: ::zweidraehte_device::service::AugmentRegistry<D> }
    });

    let augment_registry_impl = quote! {
        impl<#(#struct_lifetimes),* #struct_lifetime_separator D #struct_non_lifetime_separator #(#struct_non_lifetime_params),*>
            ::zweidraehte_device::service::AugmentRegistry<D> for #struct_name #ty_generics
        where
            D: ::zweidraehte_device::StackDefinition,
            #( #augment_field_bounds, )*
            #( #flatten_field_bounds, )*
            #where_clause
        {
            fn get_property_descriptor(
                &self,
                object_type: ::zweidraehte_device::__macro_support::dpt::InterfaceObjectType,
                prop_id: u16,
            ) -> ::core::option::Option<::zweidraehte_device::objects::interface::PropertyDescriptor> {
                #prop_chain_get_descriptor
            }

            fn property_description_read(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_device::__macro_support::dpt::InterfaceObjectType,
                object_idx: u16,
                lookup: ::zweidraehte_device::objects::interface::PropertyLookup,
            ) -> ::core::option::Option<::core::result::Result<
                ::zweidraehte_device::objects::interface::PropertyDescriptionResponse,
                ::zweidraehte_device::objects::interface::PropertyError,
            >> {
                #prop_chain_description_read
            }

            fn property_value_read(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_device::__macro_support::dpt::InterfaceObjectType,
                req: &::zweidraehte_device::objects::interface::FullPropertyReadRequest,
                buf: &mut [u8],
            ) -> ::core::option::Option<::core::result::Result<
                usize,
                ::zweidraehte_device::objects::interface::PropertyError,
            >> {
                #prop_chain_value_read
            }

            fn property_value_write(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_device::__macro_support::dpt::InterfaceObjectType,
                req: &::zweidraehte_device::objects::interface::FullPropertyWriteRequest<'_>,
            ) -> ::core::option::Option<::core::result::Result<
                ::zweidraehte_device::objects::interface::WriteResponse,
                ::zweidraehte_device::objects::interface::PropertyError,
            >> {
                #prop_chain_value_write
            }

            fn function_property_command(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_device::__macro_support::dpt::InterfaceObjectType,
                req: &::zweidraehte_device::objects::interface::FunctionPropertyRequest<'_>,
            ) -> ::core::option::Option<::zweidraehte_device::objects::interface::FunctionPropertyResult> {
                #prop_chain_func_command
            }

            fn function_property_state_read(
                &self,
                ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_device::__macro_support::dpt::InterfaceObjectType,
                req: &::zweidraehte_device::objects::interface::FunctionPropertyRequest<'_>,
            ) -> ::core::option::Option<::zweidraehte_device::objects::interface::FunctionPropertyResult> {
                #prop_chain_func_state_read
            }

            fn additional_object_count(&self) -> u16 {
                #io_count_body
            }

            fn additional_object_type_at(
                &self,
                index: u16,
            ) -> ::core::option::Option<::zweidraehte_device::__macro_support::dpt::InterfaceObjectType> {
                let mut index = index;
                #( #aug_io_at_arms )*
                #( #flat_io_at_arms )*
                ::core::option::Option::None
            }

            fn poll_augments(&mut self, ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>) {
                #( #poll_augment_calls )*
                #( #poll_flatten_calls )*
            }

            fn next_augment_deadline(&self) -> ::core::option::Option<::embassy_time::Instant> {
                let mut earliest: ::core::option::Option<::embassy_time::Instant> =
                    ::core::option::Option::None;
                #( #next_augment_deadline_merges )*
                #( #next_flatten_deadline_merges )*
                earliest
            }
        }
    };

    Ok(quote! {
        #layer_registry_impl
        #augment_registry_impl
    })
}
