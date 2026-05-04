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
                } else {
                    return Err(meta.error("expected `handler` or `augment`"));
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
                 `#[service(handler)]` or `#[service(augment)]`",
            )
        })?;

        service_fields.push(ServiceField { role, ident, ty: &field.ty });
    }

    let handlers: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| f.role == ServiceFieldRole::Handler).collect();
    let augments: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| f.role == ServiceFieldRole::Augment).collect();

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
        // feature(const_convert)`, matching today's
        // `impl_layer_stack!` macro.
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

    // Property-hook chains. Each method walks the augment fields
    // left-to-right; the first to return `Some` claims the request.
    // The methods that don't take `&mut [u8]` chain via
    // `Option::or_else`; `property_value_read` takes a `&mut [u8]`
    // and so it has to use explicit if-let arms to avoid moving the
    // buffer reference into the closure.
    let prop_chain_get_descriptor = if augments.is_empty() {
        quote! { ::core::option::Option::None }
    } else {
        let calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::get_property_descriptor(
                    &self.#id, object_type, prop_id))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    let prop_chain_description_read = if augments.is_empty() {
        quote! { ::core::option::Option::None }
    } else {
        let calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::property_description_read(
                    &self.#id, ctx, object_type, object_idx, lookup))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    let prop_chain_value_read = if augments.is_empty() {
        quote! { ::core::option::Option::None }
    } else {
        let arms = augment_idents.iter().map(|id| {
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
        quote! {
            #( #arms )*
            ::core::option::Option::None
        }
    };

    let prop_chain_value_write = if augments.is_empty() {
        quote! { ::core::option::Option::None }
    } else {
        let calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::property_value_write(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    let prop_chain_func_command = if augments.is_empty() {
        quote! { ::core::option::Option::None }
    } else {
        let calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::function_property_command(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    let prop_chain_func_state_read = if augments.is_empty() {
        quote! { ::core::option::Option::None }
    } else {
        let calls = augment_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::function_property_state_read(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    // IO list contribution: sum + walk-by-index.
    let io_count_terms = augment_idents.iter().map(|id| {
        quote! { ::zweidraehte_device::service::Augment::<D>::additional_object_count(&self.#id) }
    });
    let io_count_body = quote! { 0u16 #( + #io_count_terms )* };

    let io_at_arms = augment_idents.iter().map(|id| {
        quote! {
            let n = ::zweidraehte_device::service::Augment::<D>::additional_object_count(&self.#id);
            if index < n {
                return ::zweidraehte_device::service::Augment::<D>::additional_object_type_at(&self.#id, index);
            }
            index -= n;
        }
    });

    // Augment-side lifecycle.
    let poll_augment_calls = augment_idents.iter().map(|id| {
        quote! { ::zweidraehte_device::service::Augment::<D>::poll(&mut self.#id, ctx); }
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

    let augment_registry_impl = quote! {
        impl<#(#struct_lifetimes),* #struct_lifetime_separator D #struct_non_lifetime_separator #(#struct_non_lifetime_params),*>
            ::zweidraehte_device::service::AugmentRegistry<D> for #struct_name #ty_generics
        where
            D: ::zweidraehte_device::StackDefinition,
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
                #( #io_at_arms )*
                ::core::option::Option::None
            }

            fn poll_augments(&mut self, ctx: &::zweidraehte_device::service::ServiceCtx<'_, D>) {
                #( #poll_augment_calls )*
            }

            fn next_augment_deadline(&self) -> ::core::option::Option<::embassy_time::Instant> {
                let mut earliest: ::core::option::Option<::embassy_time::Instant> =
                    ::core::option::Option::None;
                #( #next_augment_deadline_merges )*
                earliest
            }
        }
    };

    Ok(quote! {
        #layer_registry_impl
        #augment_registry_impl
    })
}
