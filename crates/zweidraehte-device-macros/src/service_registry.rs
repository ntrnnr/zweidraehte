//! `#[derive(ServiceRegistry)]` — emits `LayerRegistry<D>` and
//! `Augment<D>` impls on a device's services struct.
//!
//! The derive walks the struct's named fields and partitions them by
//! `#[service(...)]` attribute:
//!
//! - `#[service(handler)]` — field implements
//!   [`Layer<D>`](::zweidraehte_device::service::Layer). Contributes
//!   to the const dispatch table and the layer-side lifecycle
//!   aggregation.
//! - `#[service(augment)]` — field implements
//!   [`Augment<D>`](::zweidraehte_device::service::Augment).
//!   Joins the property-hook chain, IO-list contribution sum, and
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
#[derive(Clone)]
enum ServiceFieldRole {
    Handler,
    Augment,
    /// `#[service(flatten)]` — the field is itself a struct that
    /// implements `Augment<D>` (typically another
    /// `#[derive(ServiceRegistry)]` struct or a pre-bundled augment
    /// bundle). The outer registry's augment chain delegates each
    /// method through to this field's `Augment` impl, so the
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
    /// `#[service(lifecycle)]` — non-`Layer` field that implements
    /// [`LifecycleHook<D>`](::zweidraehte_device::service::LifecycleHook).
    /// The macro emits `LifecycleHook::init` calls before the handler
    /// inits in `init_layers`, and `LifecycleHook::drain_events` calls
    /// inside a generated `drain_events` override.
    Lifecycle,
    /// `#[service(channel(dispatch = |this, payload| body))]` — async
    /// input field whose `.receive()` future feeds
    /// `recv_service_input`. The macro generates a hidden
    /// `ServiceInput` enum (one variant per channel), wires
    /// `embassy_futures::select::select{N}` over the receive futures,
    /// and runs the user's dispatch closure in `handle_service_input`.
    Channel {
        dispatch: syn::ExprClosure,
    },
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
    //
    // If the struct already declares its own `D` parameter (e.g.
    // because field types directly reference `D`), don't inject a
    // second one — emit the struct's generics verbatim and rely on
    // the user's bound (or the where-clause we always add for
    // `D: StackDefinition`).
    let (_, ty_generics, where_clause) = input.generics.split_for_impl();
    let struct_has_own_d = input.generics.params.iter().any(|p| match p {
        syn::GenericParam::Type(t) => t.ident == "D",
        _ => false,
    });
    let struct_lifetimes: Vec<_> =
        input.generics.params.iter().filter(|p| matches!(p, syn::GenericParam::Lifetime(_))).collect();
    // Type and const parameters may carry a default on the struct
    // (`const FREE: u8 = 3`), but defaults are a declaration-site feature
    // — repeating one in the `impl<...>` list we emit is a hard error.
    // Strip them here rather than forbidding defaults on registry structs.
    let struct_non_lifetime_params: Vec<syn::GenericParam> = input
        .generics
        .params
        .iter()
        .filter(|p| !matches!(p, syn::GenericParam::Lifetime(_)))
        .cloned()
        .map(|p| match p {
            syn::GenericParam::Type(mut t) => {
                t.eq_token = None;
                t.default = None;
                syn::GenericParam::Type(t)
            }
            syn::GenericParam::Const(mut c) => {
                c.eq_token = None;
                c.default = None;
                syn::GenericParam::Const(c)
            }
            other => other,
        })
        .collect();
    let struct_lifetime_separator = if struct_lifetimes.is_empty() {
        quote! {}
    } else {
        quote! { , }
    };
    let struct_non_lifetime_separator = if struct_non_lifetime_params.is_empty() {
        quote! {}
    } else {
        quote! { , }
    };
    // Empty when the struct already provides `D`, otherwise injects
    // `D` between the struct's lifetimes and its non-lifetime params.
    let injected_d = if struct_has_own_d {
        quote! {}
    } else {
        quote! { D }
    };
    // The injected-`D` separator only matters when we're actually
    // injecting; otherwise it falls out via the empty `injected_d`.
    let injected_d_separator = if struct_has_own_d {
        quote! {}
    } else {
        // Need a separator after `D` only if there are non-lifetime
        // params following; before `D` only if there are lifetimes.
        struct_non_lifetime_separator.clone()
    };
    let pre_d_separator = if struct_has_own_d {
        // Stitch lifetimes and non-lifetimes directly.
        struct_non_lifetime_separator.clone()
    } else {
        struct_lifetime_separator.clone()
    };
    // The struct's where-clause predicates (without the `where`
    // keyword), so we can splice them after our own `D: StackDefinition`
    // bound. `split_for_impl` returns `Option<&WhereClause>`, which
    // includes the `where` keyword when used directly — that breaks
    // the emitted impl when the struct already has its own where.
    let user_where_predicates = match &input.generics.where_clause {
        Some(wc) => {
            let preds = wc.predicates.iter();
            quote! { #( #preds, )* }
        }
        None => quote! {},
    };

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
                } else if meta.path.is_ident("lifecycle") {
                    ServiceFieldRole::Lifecycle
                } else if meta.path.is_ident("channel") {
                    // `channel(dispatch = |stack, payload| body)`.
                    // The inner content is parsed as `dispatch = <closure>`.
                    let mut dispatch: Option<syn::ExprClosure> = None;
                    meta.parse_nested_meta(|inner| {
                        if inner.path.is_ident("dispatch") {
                            dispatch = Some(inner.value()?.parse()?);
                            Ok(())
                        } else {
                            Err(inner.error("expected `dispatch = |stack, payload| body`"))
                        }
                    })?;
                    let dispatch = dispatch.ok_or_else(|| {
                        meta.error("`#[service(channel(...))]` requires `dispatch = |stack, payload| body`")
                    })?;
                    ServiceFieldRole::Channel { dispatch }
                } else {
                    return Err(meta
                        .error("expected `handler`, `augment`, `flatten`, `lifecycle`, or `channel(dispatch = ...)`"));
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
                 `#[service(handler)]`, `#[service(augment)]`, `#[service(flatten)]`, \
                 `#[service(lifecycle)]`, or `#[service(channel(dispatch = ...))]`",
            )
        })?;

        service_fields.push(ServiceField { role, ident, ty: &field.ty });
    }

    let handlers: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| matches!(f.role, ServiceFieldRole::Handler)).collect();
    let augments: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| matches!(f.role, ServiceFieldRole::Augment)).collect();
    let flattens: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| matches!(f.role, ServiceFieldRole::Flatten)).collect();
    let lifecycles: Vec<&ServiceField<'_>> =
        service_fields.iter().filter(|f| matches!(f.role, ServiceFieldRole::Lifecycle)).collect();
    // For channels, keep the dispatch closure paired with the field —
    // the codegen below pairs each enum variant with its dispatch.
    let channels: Vec<(&ServiceField<'_>, &syn::ExprClosure)> = service_fields
        .iter()
        .filter_map(|f| match &f.role {
            ServiceFieldRole::Channel { dispatch } => Some((f, dispatch)),
            _ => None,
        })
        .collect();

    // Whether the struct has any field role that participates in the
    // router's dispatch surface. Augment-only structs (no handler /
    // lifecycle / channel) get `Augment<D>` but no `LayerRegistry<D>`
    // — the latter would be vestigial: empty dispatch table, no-op
    // init / poll / next_deadline, an `unreachable!()`-bodied
    // `dispatch_wire`. Gating on this also drops the empty
    // `service_input_enum` for those structs.
    let has_dispatch_fields = !handlers.is_empty() || !lifecycles.is_empty() || !channels.is_empty();

    // `#[service(flatten)]` only forwards into the inner struct's
    // `Augment<D>` impl. The const dispatch table is keyed
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
            #idx_u8 => ::zweidraehte_device::service::Layer::<D>::process(&mut self.#ident, msg),
        }
    });

    // Lifecycle inits run *before* handler inits so the device model
    // can establish initial run-state-machine state before the layers
    // start polling.
    let lifecycle_init_calls = lifecycles.iter().map(|l| {
        let ident = l.ident;
        quote! { ::zweidraehte_device::service::LifecycleHook::<D>::init(&mut self.#ident); }
    });
    let init_layer_calls = handlers.iter().map(|h| {
        let ident = h.ident;
        quote! { ::zweidraehte_device::service::Layer::<D>::init(&mut self.#ident); }
    });

    let poll_layer_calls = handlers.iter().map(|h| {
        let ident = h.ident;
        quote! { ::zweidraehte_device::service::Layer::<D>::poll(&mut self.#ident); }
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

    // -----------------------------------------------------------------
    // drain_events override — only emitted when there's at least one
    // lifecycle field. Otherwise fall through to the trait default
    // (no-op).
    // -----------------------------------------------------------------
    let drain_events_override = if lifecycles.is_empty() {
        quote! {}
    } else {
        let drain_calls = lifecycles.iter().map(|l| {
            let ident = l.ident;
            quote! {
                ::zweidraehte_device::service::LifecycleHook::<D>::drain_events(&mut self.#ident);
            }
        });
        quote! {
            fn drain_events(&mut self) {
                #( #drain_calls )*
            }
        }
    };

    // -----------------------------------------------------------------
    // ServiceInput machinery — only emitted when there's at least one
    // channel field. With zero channels the trait defaults
    // (`type ServiceInput = !`, `recv_service_input` pends forever)
    // apply.
    // -----------------------------------------------------------------
    if channels.len() > 6 {
        return Err(syn::Error::new_spanned(
            input,
            "`#[derive(ServiceRegistry)]` supports up to 6 `#[service(channel)]` fields \
             (the limit of `embassy_futures::select`); add a custom `LayerRegistry` impl \
             for stacks needing more",
        ));
    }

    // Hidden enum used as `LayerRegistry::ServiceInput`. One variant per
    // channel field, payload type extracted from the field's last
    // generic argument (e.g. `DynamicReceiver<'a, T>` → `T`).
    let service_input_variants: Vec<TokenStream2> = channels
        .iter()
        .map(|(field, _)| {
            let variant = pascal_case_ident(field.ident);
            let payload = last_generic_argument(field.ty)?;
            Ok(quote! { #variant(#payload) })
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let service_input_enum_ident =
        syn::Ident::new(&format!("__{}ServiceInput", struct_name), proc_macro2::Span::call_site());

    // The hidden enum carries the same generics as the parent struct,
    // since channel payload types may reference them (e.g. `Request<'a, ...>`).
    // A hidden `__Phantom` variant consumes any parent generic that
    // none of the channel payloads happen to reference, preventing
    // E0392 ("unused lifetime parameter") on enums whose payloads
    // don't transitively use every parent generic.
    let phantom_variant = if input.generics.params.is_empty() {
        quote! {}
    } else {
        let phantom_ty = input.generics.params.iter().map(|p| match p {
            syn::GenericParam::Lifetime(l) => {
                let lt = &l.lifetime;
                quote! { &#lt () }
            }
            syn::GenericParam::Type(t) => {
                let id = &t.ident;
                quote! { #id }
            }
            syn::GenericParam::Const(_) => quote! { () },
        });
        quote! {
            #[doc(hidden)]
            __Phantom(::core::convert::Infallible, ::core::marker::PhantomData<( #( #phantom_ty ),* )>),
        }
    };

    // Inherit the parent struct's visibility on the hidden enum so the
    // enum can carry payload types of the same visibility as the
    // parent's fields without rustc warning about private interfaces.
    let struct_vis = &input.vis;
    let service_input_enum = if channels.is_empty() {
        quote! {}
    } else {
        quote! {
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            #struct_vis enum #service_input_enum_ident #ty_generics #where_clause {
                #( #service_input_variants, )*
                #phantom_variant
            }
        }
    };

    // recv_service_input body. Branches on channel count.
    let recv_service_input_body = match channels.len() {
        0 => quote! {},
        1 => {
            let (field, _) = &channels[0];
            let ident = field.ident;
            let variant = pascal_case_ident(field.ident);
            quote! {
                async move {
                    #service_input_enum_ident::#variant(self.#ident.receive().await)
                }
            }
        }
        n => {
            let select_name = if n == 2 { "select".to_string() } else { format!("select{n}") };
            let either_name = if n == 2 { "Either".to_string() } else { format!("Either{n}") };
            let select_fn = syn::Ident::new(&select_name, proc_macro2::Span::call_site());
            let either_ty = syn::Ident::new(&either_name, proc_macro2::Span::call_site());
            let receive_calls: Vec<_> = channels
                .iter()
                .map(|(f, _)| {
                    let ident = f.ident;
                    quote! { self.#ident.receive() }
                })
                .collect();
            let either_arms: Vec<_> = channels
                .iter()
                .enumerate()
                .map(|(i, (f, _))| {
                    let arm = either_arm_name(n, i);
                    let variant = pascal_case_ident(f.ident);
                    quote! {
                        #either_ty::#arm(payload) =>
                            #service_input_enum_ident::#variant(payload),
                    }
                })
                .collect();
            quote! {
                async move {
                    use ::zweidraehte_device::__macro_support::embassy_futures::select::{#select_fn, #either_ty};
                    match #select_fn(#( #receive_calls ),*).await {
                        #( #either_arms )*
                    }
                }
            }
        }
    };

    // handle_service_input body — match on the variant, run the
    // user-supplied dispatch closure with `(self, payload)`.
    let handle_service_input_arms: Vec<TokenStream2> = channels
        .iter()
        .map(|(field, dispatch)| {
            let variant = pascal_case_ident(field.ident);
            let payload_ty = last_generic_argument(field.ty)?;
            // Pin the closure to `fn(&mut Self, Payload)` via a typed
            // local. This gives the closure body a known type for its
            // first parameter (`&mut Self`), so users don't have to
            // annotate `stack:` in their dispatch attribute. The
            // closure can't capture (it's a `fn`), but the dispatch
            // closure is by design a small forwarder — it doesn't need
            // captures.
            Ok::<_, syn::Error>(quote! {
                #service_input_enum_ident::#variant(payload) => {
                    let __dispatch: fn(&mut Self, #payload_ty) = #dispatch;
                    __dispatch(self, payload)
                }
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;

    // When the parent struct has generics, the hidden enum carries a
    // `__Phantom` variant that's uninhabited (`Infallible`); the match
    // arm pattern `__Phantom(never, _)` is wired through so rustc can
    // see exhaustiveness and the runtime never actually constructs it.
    let phantom_match_arm = if input.generics.params.is_empty() {
        quote! {}
    } else {
        quote! {
            #service_input_enum_ident::__Phantom(never, _) => match never {},
        }
    };

    let service_input_impl_items = if channels.is_empty() {
        quote! {}
    } else {
        quote! {
            type ServiceInput = #service_input_enum_ident #ty_generics;

            fn recv_service_input(&self)
                -> impl ::core::future::Future<Output = Self::ServiceInput> + '_
            {
                #recv_service_input_body
            }

            fn handle_service_input(&mut self, input: Self::ServiceInput) {
                match input {
                    #( #handle_service_input_arms )*
                    #phantom_match_arm
                }
            }
        }
    };

    let layer_registry_impl = if has_dispatch_fields {
        quote! {
            #service_input_enum

            impl<#(#struct_lifetimes),* #pre_d_separator #injected_d #injected_d_separator #(#struct_non_lifetime_params),*>
                ::zweidraehte_device::service::LayerRegistry<D> for #struct_name #ty_generics
            where
                D: ::zweidraehte_device::StackDefinition,
                #user_where_predicates
            {
                const DISPATCH_TABLE: ::zweidraehte_device::router::DispatchTable = #dispatch_table_body;

                fn dispatch_wire(
                    &mut self,
                    idx: u8,
                    msg: ::zweidraehte_device::__macro_support::messages::knx::KnxMessageBuffer<
                        ::zweidraehte_device::__macro_support::messages::buffers::Buffer<'static>,
                    >,
                ) {
                    match idx {
                        #( #dispatch_arms )*
                        _ => ::core::unreachable!(
                            "dispatch_wire called with idx={} not registered in DISPATCH_TABLE",
                            idx,
                        ),
                    }
                }

                fn init_layers(&mut self) {
                    #( #lifecycle_init_calls )*
                    #( #init_layer_calls )*
                }

                fn poll_layers(&mut self) {
                    #( #poll_layer_calls )*
                }

                fn next_layer_deadline(&self) -> ::core::option::Option<::embassy_time::Instant> {
                    let mut earliest: ::core::option::Option<::embassy_time::Instant> =
                        ::core::option::Option::None;
                    #( #next_layer_deadline_merges )*
                    earliest
                }

                #drain_events_override

                #service_input_impl_items
            }
        }
    } else {
        quote! {}
    };

    // -----------------------------------------------------------------
    // Augment impl — property-hook chain, IO list aggregation,
    // and augment-side lifecycle for every #[service(augment)] field.
    // -----------------------------------------------------------------

    let augment_idents: Vec<&syn::Ident> = augments.iter().map(|a| a.ident).collect();
    let flatten_idents: Vec<&syn::Ident> = flattens.iter().map(|f| f.ident).collect();
    let any_aug_or_flatten = !augments.is_empty() || !flattens.is_empty();

    // Property-hook chains. Each method walks fields left-to-right
    // (`#[service(augment)]` then `#[service(flatten)]`); the first
    // to return `Some` claims the request.
    //
    // Both annotations dispatch through `Augment<D>`. The
    // single-augment case uses the impl that
    // `#[interface_object_augment]` emits on the augment type (or
    // the explicit `()` / `&A` impls); the nested-bundle case uses
    // the macro-derived `Augment<D>` impl on the inner
    // services struct. The two annotations differ only in semantic
    // intent — `augment` says "this field IS a single augment",
    // `flatten` says "this field has nested augments" — but both
    // call sites are identical.
    //
    // The `&mut [u8]` borrow on `property_value_read` rules out the
    // closure-based `.or_else()` chain; that path uses explicit
    // if-let arms instead.
    let all_aug_idents: Vec<&syn::Ident> = augment_idents.iter().chain(flatten_idents.iter()).copied().collect();

    let prop_chain_get_descriptor = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let calls = all_aug_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::property_descriptor(
                    &self.#id, object_type, prop_id))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    let prop_chain_description_read = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        // `A_PropertyDescription_Read` comes in two flavours (see `PropertyLookup`):
        //
        // - `ByPid`: a property id is unique within an object type, so whichever
        //   augment owns it claims the request — a plain left-to-right
        //   `.or_else()` chain is correct.
        //
        // - `ByIndex`: the index is *into the object type's merged descriptor
        //   table*. When two augments contribute to the same object type, the
        //   second augment's descriptors live at indices *after* the first's, but
        //   each leaf augment numbers its own descriptors from 0. So we walk the
        //   augments in declaration order, carrying the index down and subtracting
        //   each augment's `descriptor_count_for(object_type)` until we reach the
        //   augment whose range covers it — then delegate with the rebased index.
        //   This is what lets e.g. the RF Medium Object's PIDs be split across the
        //   base RF augment and a retransmitter augment.
        let by_pid_calls = all_aug_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::property_description_read(
                    &self.#id, ctx, object_type, object_idx, lookup))
            }
        });
        let by_index_arms = all_aug_idents.iter().map(|id| {
            quote! {
                {
                    let n = ::zweidraehte_device::service::Augment::<D>::descriptor_count_for(
                        &self.#id, object_type);
                    if __rebased_idx < n {
                        return ::zweidraehte_device::service::Augment::<D>::property_description_read(
                            &self.#id, ctx, object_type, object_idx,
                            ::zweidraehte_device::objects::interface::PropertyLookup::ByIndex(__rebased_idx));
                    }
                    __rebased_idx -= n;
                }
            }
        });
        quote! {
            match lookup {
                ::zweidraehte_device::objects::interface::PropertyLookup::ByPid(_) => {
                    ::core::option::Option::None #( #by_pid_calls )*
                }
                ::zweidraehte_device::objects::interface::PropertyLookup::ByIndex(__req_idx) => {
                    let mut __rebased_idx = __req_idx;
                    #( #by_index_arms )*
                    ::core::option::Option::None
                }
            }
        }
    };

    // `descriptor_count_for` aggregation: sum the count across every augment /
    // flatten field so a parent registry exposes the merged total (and so a
    // nested registry's index offsets are computed against the right base).
    let descriptor_count_terms = all_aug_idents.iter().map(|id| {
        quote! { + ::zweidraehte_device::service::Augment::<D>::descriptor_count_for(&self.#id, object_type) }
    });
    let descriptor_count_body = if !any_aug_or_flatten {
        quote! { 0u16 }
    } else {
        quote! { 0u16 #( #descriptor_count_terms )* }
    };

    let prop_chain_value_read = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let arms = all_aug_idents.iter().map(|id| {
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

    let prop_chain_value_write = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let calls = all_aug_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::property_value_write(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    let prop_chain_func_command = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let calls = all_aug_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::function_property_command(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    let prop_chain_func_state_read = if !any_aug_or_flatten {
        quote! { ::core::option::Option::None }
    } else {
        let calls = all_aug_idents.iter().map(|id| {
            quote! {
                .or_else(|| ::zweidraehte_device::service::Augment::<D>::function_property_state_read(
                    &self.#id, ctx, object_type, req))
            }
        });
        quote! { ::core::option::Option::None #( #calls )* }
    };

    // IO list contribution: sum + walk-by-index. All fields
    // dispatch through `Augment::additional_object_count` /
    // `additional_object_type_at`. Order matches the hook chain
    // above so the index space stays consistent.
    let io_count_terms = all_aug_idents.iter().map(|id| {
        quote! { ::zweidraehte_device::service::Augment::<D>::additional_object_count(&self.#id) }
    });
    let io_count_body = quote! { 0u16 #( + #io_count_terms )* };

    let io_at_arms = all_aug_idents.iter().map(|id| {
        quote! {
            let n = ::zweidraehte_device::service::Augment::<D>::additional_object_count(&self.#id);
            if index < n {
                return ::zweidraehte_device::service::Augment::<D>::additional_object_type_at(&self.#id, index);
            }
            index -= n;
        }
    });

    // Every `#[service(augment)]` and `#[service(flatten)]` field
    // type must satisfy `Augment<D>`. This is one explicit
    // `where` bound per field in the emitted impl so any additional
    // state-trait bounds on the field type (e.g. a
    // `DiagnosticsAugment` requiring `D::State: HasExtensionState`)
    // get inferred from the field's own trait impl, without the
    // user having to spell them out on the outer struct.
    let augment_field_bounds = augments.iter().map(|a| {
        let ty = a.ty;
        quote! { #ty: ::zweidraehte_device::service::Augment<D> }
    });
    let flatten_field_bounds = flattens.iter().map(|f| {
        let ty = f.ty;
        quote! { #ty: ::zweidraehte_device::service::Augment<D> }
    });

    let augment_registry_impl = quote! {
        impl<#(#struct_lifetimes),* #pre_d_separator #injected_d #injected_d_separator #(#struct_non_lifetime_params),*>
            ::zweidraehte_device::service::Augment<D> for #struct_name #ty_generics
        where
            D: ::zweidraehte_device::StackDefinition,
            #( #augment_field_bounds, )*
            #( #flatten_field_bounds, )*
            #user_where_predicates
        {
            fn property_descriptor(
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

            fn descriptor_count_for(
                &self,
                object_type: ::zweidraehte_device::__macro_support::dpt::InterfaceObjectType,
            ) -> u16 {
                #descriptor_count_body
            }
        }
    };

    Ok(quote! {
        #layer_registry_impl
        #augment_registry_impl
    })
}

// =============================================================================
// Helpers
// =============================================================================

/// `app_rx` → `AppRx`. Field-ident → enum-variant pascal case, splitting
/// on underscores.
fn pascal_case_ident(field: &syn::Ident) -> syn::Ident {
    let s = field.to_string();
    let mut out = String::with_capacity(s.len());
    let mut upper_next = true;
    for c in s.chars() {
        if c == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(c.to_uppercase());
            upper_next = false;
        } else {
            out.push(c);
        }
    }
    syn::Ident::new(&out, field.span())
}

/// Pull the last generic-argument type out of a path-typed field.
/// e.g. `DynamicReceiver<'a, Foo>` → `Foo`. Returns an error if the
/// field type isn't a path with at least one type-position generic
/// argument.
fn last_generic_argument(ty: &syn::Type) -> syn::Result<&syn::Type> {
    let path = match ty {
        syn::Type::Path(p) => p,
        _ => {
            return Err(syn::Error::new_spanned(
                ty,
                "`#[service(channel)]` field must have a path-typed type with a generic payload \
                 (e.g. `DynamicReceiver<'a, Payload>`)",
            ));
        }
    };
    let last = path
        .path
        .segments
        .last()
        .ok_or_else(|| syn::Error::new_spanned(ty, "`#[service(channel)]` field type has no path segments"))?;
    let args = match &last.arguments {
        syn::PathArguments::AngleBracketed(a) => a,
        _ => {
            return Err(syn::Error::new_spanned(
                ty,
                "`#[service(channel)]` field type must carry a generic payload \
                 (e.g. `DynamicReceiver<'a, Payload>`)",
            ));
        }
    };
    args.args
        .iter()
        .rev()
        .find_map(|a| match a {
            syn::GenericArgument::Type(t) => Some(t),
            _ => None,
        })
        .ok_or_else(|| {
            syn::Error::new_spanned(
                ty,
                "`#[service(channel)]` field type must include at least one type-position \
                 generic argument (the payload)",
            )
        })
}

/// Map a 0-based channel index to the corresponding `EitherN::*` arm
/// name. `select` returns `Either::First`/`Second`; `select3..6` use
/// `First`/`Second`/`Third`/`Fourth`/`Fifth`/`Sixth`.
fn either_arm_name(channel_count: usize, idx: usize) -> syn::Ident {
    let name = match (channel_count, idx) {
        (2, 0) => "First",
        (2, 1) => "Second",
        (3, 0) | (4, 0) | (5, 0) | (6, 0) => "First",
        (3, 1) | (4, 1) | (5, 1) | (6, 1) => "Second",
        (3, 2) | (4, 2) | (5, 2) | (6, 2) => "Third",
        (4, 3) | (5, 3) | (6, 3) => "Fourth",
        (5, 4) | (6, 4) => "Fifth",
        (6, 5) => "Sixth",
        _ => unreachable!("either_arm_name called with invalid count/idx pair"),
    };
    syn::Ident::new(name, proc_macro2::Span::call_site())
}
