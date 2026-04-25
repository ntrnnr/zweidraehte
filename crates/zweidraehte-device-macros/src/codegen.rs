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

use proc_macro2::TokenStream;
use quote::quote;
use syn::ItemStruct;

use crate::parse::{Access, Backing, ObjectAttrs, PropertyAttrs};

pub(crate) fn gen_object(
    item: &ItemStruct,
    obj_attrs: &ObjectAttrs,
    props: &[PropertyAttrs],
) -> syn::Result<TokenStream> {
    let object_type = obj_attrs.object_type.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(
            &item.ident,
            "missing `object_type = ...` argument on #[interface_object(...)]",
        )
    })?;

    let ident = &item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();
    let vis = &item.vis;
    // Forward `#[derive(...)]`, doc comments, etc. from the user's struct.
    let outer_attrs = item.attrs.iter().filter(|a| !a.path().is_ident("interface_object"));

    // The struct that the user wrote contains both real fields (backing=field)
    // and placeholder unit fields (backing=state). Re-emit the struct with the
    // placeholder fields stripped, and inject `state: &'a S` if any property
    // is state-backed.
    let real_fields = props
        .iter()
        .filter(|p| matches!(p.backing, Backing::Field))
        .map(|p| {
            let name = &p.field_ident;
            let ty = &p.field_ty;
            quote! { pub #name: #ty, }
        });

    let needs_state = props.iter().any(|p| matches!(p.backing, Backing::State));
    if needs_state {
        // The macro doesn't synthesise the lifetime/state bound — the user
        // already wrote them on the struct (e.g. `<'a, S: StackState>`). We
        // just inject a `state: &'a S` field at the end. To know which
        // lifetime and state type to use, we lift them straight out of the
        // generics list: first lifetime + first type parameter, by convention.
    }

    // Inject `state: &'a S` field when needed. We look up the first lifetime
    // and the first type parameter on the struct generics.
    let state_field = if needs_state {
        let lt = item
            .generics
            .lifetimes()
            .next()
            .ok_or_else(|| {
                syn::Error::new_spanned(
                    ident,
                    "state-backed properties require a lifetime parameter on the struct",
                )
            })?
            .lifetime
            .clone();
        let state_ty = item
            .generics
            .type_params()
            .next()
            .ok_or_else(|| {
                syn::Error::new_spanned(
                    ident,
                    "state-backed properties require a type parameter on the struct \
                     (the state type, e.g. `S: StackState`)",
                )
            })?
            .ident
            .clone();
        Some(quote! { state: & #lt #state_ty, })
    } else {
        None
    };

    // ------------------------------------------------------------------
    // PROPERTY_DESCRIPTORS const slice. Always starts with OBJECT_TYPE
    // (PID 1) at index 0; user properties follow in declaration order.
    // ------------------------------------------------------------------
    let descriptor_entries = props.iter().map(|p| descriptor_for(p, object_type));

    // ------------------------------------------------------------------
    // read_property / write_property match arms
    // ------------------------------------------------------------------
    let read_arms = props.iter().map(|p| read_arm(p));
    let write_arms = props.iter().map(|p| write_arm(p));

    // ------------------------------------------------------------------
    // new() constructor — only takes &'a S if state-backed
    // ------------------------------------------------------------------
    let constructor_args = if needs_state {
        let lt = item.generics.lifetimes().next().unwrap().lifetime.clone();
        let state_ty = item.generics.type_params().next().unwrap().ident.clone();
        quote! { state: & #lt #state_ty }
    } else {
        quote! {}
    };
    let constructor_body_fields = props
        .iter()
        .filter(|p| matches!(p.backing, Backing::Field))
        .map(|p| {
            let name = &p.field_ident;
            let ty = &p.field_ty;
            if let Some(default) = &p.default_value {
                quote! { #name: #default, }
            } else {
                // Fall back to `<T as Default>::default()` to match the legacy
                // macro's behaviour (which uses `Default::default()` when no
                // explicit `= default` is given).
                quote! { #name: <#ty as ::core::default::Default>::default(), }
            }
        });
    let constructor_state = if needs_state {
        Some(quote! { state, })
    } else {
        None
    };

    // ------------------------------------------------------------------
    // Final emission
    // ------------------------------------------------------------------
    Ok(quote! {
        #( #outer_attrs )*
        #vis struct #ident #impl_generics #where_clause {
            #( #real_fields )*
            #state_field
        }

        impl #impl_generics #ident #ty_generics #where_clause {
            /// Property descriptors for this interface object.
            ///
            /// Index 0 is always OBJECT_TYPE (PID 1); user-defined properties
            /// follow in declaration order.
            pub const PROPERTY_DESCRIPTORS: &'static [
                ::zweidraehte_proto::properties::PropertyDescriptor
            ] = &[
                // OBJECT_TYPE (PID 1) — always first, ReadOnly, level 3/0,
                // policy READ_OPEN_WRITE_TOOL. This is mandated by KNX spec
                // for every interface object.
                ::zweidraehte_proto::properties::PropertyDescriptor::with_policy(
                    ::zweidraehte_device::objects::interface::pid::OBJECT_TYPE,
                    <::zweidraehte_proto::dpt::PDT_UnsignedInt
                        as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
                    1,
                    ::zweidraehte_proto::properties::PropertyAccess::ReadOnly,
                    3, 0,
                    ::zweidraehte_proto::access::AccessPolicy::READ_OPEN_WRITE_TOOL,
                ),
                #( #descriptor_entries , )*
            ];

            #[allow(clippy::new_without_default)]
            pub fn new(#constructor_args) -> Self {
                Self {
                    #( #constructor_body_fields )*
                    #constructor_state
                }
            }
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

// ---------------------------------------------------------------------------
// Per-property descriptor entry
// ---------------------------------------------------------------------------

fn descriptor_for(
    p: &PropertyAttrs,
    _object_type: &syn::Path,
) -> TokenStream {
    let pid = &p.pid;
    let pdt = &p.pdt;
    let policy = &p.policy;

    let access = match p.access {
        Access::Ro => quote! { ::zweidraehte_proto::properties::PropertyAccess::ReadOnly },
        Access::Rw => quote! { ::zweidraehte_proto::properties::PropertyAccess::ReadWrite },
        Access::Wo => quote! { ::zweidraehte_proto::properties::PropertyAccess::WriteOnly },
    };

    // Default access levels follow KNX convention: RO=3/0, RW=3/3, WO=0/3.
    // Explicit `rl=` / `wl=` attributes override.
    let (default_rl, default_wl) = match p.access {
        Access::Ro => (3u8, 0u8),
        Access::Rw => (3u8, 3u8),
        Access::Wo => (0u8, 3u8),
    };
    let rl = p.rl.unwrap_or(default_rl);
    let wl = p.wl.unwrap_or(default_wl);

    let max_elements = if let Some(n) = p.array_max {
        quote! { #n }
    } else if p.computed_max.is_some() {
        // Sentinel; patched at lookup time by the user's `computed_max` site.
        quote! { 0u16 }
    } else {
        quote! { 1u16 }
    };

    quote! {
        ::zweidraehte_proto::properties::PropertyDescriptor::with_policy(
            #pid,
            <#pdt as ::zweidraehte_proto::dpt::PropertyDataDefinition>::ID,
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
            let name = &p.field_ident;
            quote! {
                #pid => ::zweidraehte_device::objects::interface::PropertyRead::read_property(
                    &self.#name, req.start_idx, req.count, buf,
                ),
            }
        }
        (_, Backing::State, Some(read_fn)) => quote! {
            #pid => {
                let __read_closure = #read_fn;
                let data = __read_closure(self.state);
                ::zweidraehte_device::objects::interface::PropertyRead::read_property(
                    &data, req.start_idx, req.count, buf,
                )
            },
        },
        (_, Backing::State, None) => quote! {
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
        (_, Backing::State, Some(write_fn)) => quote! {
            #pid => {
                let __write_closure = #write_fn;
                __write_closure(self.state, req.data)?;
                Ok(::zweidraehte_device::objects::interface::WriteResponse::Echo)
            },
        },
        (_, Backing::State, None) => quote! {
            #pid => Err(::zweidraehte_device::objects::interface::PropertyError::WriteNotAllowed),
        },
    }
}
