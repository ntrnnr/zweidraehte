//! The `#[ets_params]` attribute macro.
//!
//! # Why this is an attribute and not a derive
//!
//! Same reason as [`ets_union`](crate::ets_union): a params struct is
//! reinterpreted wholesale — as the `<Data>` defaults blob ETS reads back, and
//! as the live parameter memory `ApplicationImpl::data_ref` serves to
//! `A_Memory_Read`. Any byte the layout does not name is read uninitialized,
//! which is UB and produces a product database whose defaults change between
//! builds.
//!
//! `#[repr(C)]` inserts a hole wherever a field's alignment exceeds the running
//! offset, plus trailing padding to the struct's own alignment. Naming those
//! bytes means *adding fields*, which a derive cannot do to its own item.
//!
//! Before this macro existed the fillers were hand-placed: `MdtParams` needed
//! three, at offsets 3, 435 and 547, and locating them took a purpose-built
//! probe because zerocopy reports only a total ("3 total byte(s) of padding"),
//! never where. Now they are generated.
//!
//! # Relationship to the metadata
//!
//! The parameter offsets in the generated ETS metadata come from
//! `core::mem::offset_of!`, so they track the real layout and are unaffected by
//! inserting fillers. The fillers carry `#[ets(skip)]` and a leading
//! underscore, so no ETS parameter is emitted for them.

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, parse_quote};

use crate::ets_params::derive_ets_params_impl;

pub(crate) fn ets_params_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_name = &input.ident;

    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(input, "#[ets_params] can only be applied to structs"));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new_spanned(&data.fields, "#[ets_params] requires named fields"));
    };

    // The macro owns the representation; see the `#[ets_union]` note on why a
    // stray `repr` is rejected rather than merged.
    if let Some(attr) = input.attrs.iter().find(|a| a.path().is_ident("repr")) {
        return Err(syn::Error::new_spanned(
            attr,
            "#[ets_params] sets the representation itself — remove this `repr`. It emits `#[repr(C)]`.",
        ));
    }

    // ========================================================================
    // Offset chain
    // ========================================================================
    //
    // Computed as `const` expressions over the real `size_of` / `align_of`
    // rather than at expansion time, so the fillers stay correct no matter how
    // a field's type is later defined:
    //
    //   end₀ = 0
    //   offⱼ = align_up(endⱼ₋₁, align_of::<Tⱼ>())
    //   endⱼ = offⱼ + size_of::<Tⱼ>()
    //   TOTAL = align_up(endₙ, ALIGN)
    let mut layout_consts = Vec::new();

    let align_ident = format_ident!("__ETS_PARAMS_{}_ALIGN", struct_name);
    let mut align_expr: TokenStream2 = quote!(1usize);
    for field in &named.named {
        let ty = &field.ty;
        align_expr = quote! {
            zweidraehte_device::ets::union_max(#align_expr, core::mem::align_of::<#ty>())
        };
    }
    layout_consts.push(quote! {
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        const #align_ident: usize = #align_expr;
    });

    let mut end_ident = format_ident!("__ETS_PARAMS_{}_END0", struct_name);
    layout_consts.push(quote! {
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        const #end_ident: usize = 0;
    });

    let originals: Vec<_> = named.named.iter().cloned().collect();
    for (j, field) in originals.iter().enumerate() {
        let ty = &field.ty;
        let off_ident = format_ident!("__ETS_PARAMS_{}_OFF{}", struct_name, j);
        let next_end = format_ident!("__ETS_PARAMS_{}_END{}", struct_name, j + 1);
        layout_consts.push(quote! {
            #[doc(hidden)]
        #[allow(non_upper_case_globals)]
            const #off_ident: usize =
                zweidraehte_device::ets::union_align_up(#end_ident, core::mem::align_of::<#ty>());
            #[doc(hidden)]
        #[allow(non_upper_case_globals)]
            const #next_end: usize = #off_ident + core::mem::size_of::<#ty>();
        });
        end_ident = next_end;
    }

    let total_ident = format_ident!("__ETS_PARAMS_{}_TOTAL", struct_name);
    layout_consts.push(quote! {
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        const #total_ident: usize = zweidraehte_device::ets::union_align_up(#end_ident, #align_ident);
    });

    // ========================================================================
    // Rewrite the fields with their fillers
    // ========================================================================
    let mut padded = syn::punctuated::Punctuated::new();
    for (j, field) in originals.iter().enumerate() {
        let off_ident = format_ident!("__ETS_PARAMS_{}_OFF{}", struct_name, j);
        let prev_end = format_ident!("__ETS_PARAMS_{}_END{}", struct_name, j);
        let pad_name = format_ident!("_pad_before_{}", field.ident.as_ref().expect("named"));
        let vis = &field.vis;
        // Zero-length in the common case; a ZST field costs nothing and keeps
        // the emitted shape uniform.
        padded.push(parse_quote! {
            #[ets(skip)]
            #[serde(skip)]
            #vis #pad_name: [u8; #off_ident - #prev_end]
        });
        padded.push(field.clone());
    }
    let last_vis = originals.last().map(|f| f.vis.clone()).unwrap_or(syn::Visibility::Inherited);
    padded.push(parse_quote! {
        #[ets(skip)]
        #[serde(skip)]
        #last_vis _pad_tail: [u8; #total_ident - #end_ident]
    });

    let mut rewritten = data.clone();
    rewritten.fields = Fields::Named(syn::FieldsNamed { brace_token: named.brace_token, named: padded });

    // ========================================================================
    // Emit
    // ========================================================================
    let mut derive_input = input.clone();
    derive_input.data = Data::Struct(rewritten.clone());
    derive_input.attrs.push(parse_quote!(#[repr(C)]));
    let metadata = derive_ets_params_impl(&derive_input)?;

    // `#[ets(...)]` is a derive-helper attribute and must not survive into the
    // emitted item — see the equivalent note in `ets_union_attr`.
    let mut emitted = rewritten;
    if let Fields::Named(f) = &mut emitted.fields {
        for field in &mut f.named {
            field.attrs.retain(|a| !a.path().is_ident("ets"));
        }
    }

    let mut outer_attrs = input.attrs.clone();
    outer_attrs.retain(|a| !a.path().is_ident("ets"));
    let vis = &input.vis;
    let fields = match &emitted.fields {
        Fields::Named(f) => &f.named,
        _ => unreachable!("rewritten above"),
    };

    Ok(quote! {
        #(#layout_consts)*

        #(#outer_attrs)*
        #[repr(C)]
        #[derive(::zerocopy::IntoBytes, ::zerocopy::KnownLayout, ::zerocopy::Immutable)]
        #vis struct #struct_name {
            #fields
        }

        #metadata
    })
}
