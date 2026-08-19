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
//!
//! # Tool-only parameters
//!
//! `#[ets(no_memory)]` marks a parameter ETS displays and stores in the project
//! but never downloads — the high-level structural choices ("Single-button
//! function") that only decide which stored parameters are shown. Since this
//! struct is the download image, such a field is **removed from the emitted
//! struct**: keeping it would put bytes in the image at an offset ETS was never
//! told about.
//!
//! The consequence is that the field does not exist on the resulting Rust type.
//! That is intended — a tool-only parameter is not device state — but it means
//! reading or assigning one is a compile error, and the struct cannot be built
//! by literal. Use the generated `Default` / `ConstDefault` impl.

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, parse_quote};

use crate::ets_params::derive_ets_params_impl;
use crate::parse::parse_field_attrs;

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
    // Tool-only fields
    // ========================================================================
    //
    // `#[ets(no_memory)]` marks a parameter ETS shows and persists in the
    // project but never downloads. Because this struct *is* the device memory
    // image, such a field must not occupy bytes here — otherwise the offsets
    // published to ETS and the physical layout drift apart, the exact failure
    // this macro exists to prevent. So the field is dropped from the emitted
    // struct: it contributes no bytes, no alignment and no filler, and survives
    // only as metadata (its declared type still supplies the width and enum
    // variants, which needs no field to exist).
    let originals: Vec<_> = named.named.iter().cloned().collect();
    let mut no_memory_fields = Vec::new();
    for field in &originals {
        let attrs = parse_field_attrs(&field.attrs)?;
        if !attrs.no_memory {
            continue;
        }

        // Combinations that cannot mean anything, rejected at the point of
        // declaration rather than producing subtly wrong XML.
        if attrs.union_field {
            return Err(syn::Error::new_spanned(
                field,
                "`#[ets(no_memory)]` cannot be combined with `union`: a union always occupies device memory",
            ));
        }
        if attrs.skip {
            return Err(syn::Error::new_spanned(
                field,
                "`#[ets(no_memory)]` cannot be combined with `skip`: `skip` emits no parameter at all, \
                 while `no_memory` emits one without device memory",
            ));
        }
        if attrs.module_type.is_some() {
            return Err(syn::Error::new_spanned(
                field,
                "`#[ets(no_memory)]` cannot be combined with `module`: module instances occupy device memory",
            ));
        }
        // With no bytes in the defaults blob there is nothing to read a default
        // from, and offset 0 would read the first byte of an unrelated
        // parameter. `ets_enum` fields derive theirs from `ConstDefault`, so
        // only inline variants need to say it explicitly.
        if attrs.enum_variants.is_some() && attrs.default_value.is_none() {
            return Err(syn::Error::new_spanned(
                field,
                "`#[ets(no_memory)]` with inline `enum_variants` requires an explicit `#[ets(default = N)]`: \
                 a tool-only parameter has no bytes in the defaults blob to read one from",
            ));
        }

        no_memory_fields.push(field.ident.clone().expect("named"));
    }
    let is_no_memory = |field: &syn::Field| {
        field.ident.as_ref().is_some_and(|ident| no_memory_fields.iter().any(|skipped| skipped == ident))
    };

    // Only these take part in the layout; everything below is indexed over this
    // subset, never over `originals`.
    let layout_fields: Vec<_> = originals.iter().filter(|f| !is_no_memory(f)).cloned().collect();

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
    //
    // `j` indexes `layout_fields`, so the chain stays contiguous when a
    // tool-only field is dropped from the middle of the struct.
    let mut layout_consts = Vec::new();

    let align_ident = format_ident!("__ETS_PARAMS_{}_ALIGN", struct_name);
    let mut align_expr: TokenStream2 = quote!(1usize);
    for field in &layout_fields {
        let ty = &field.ty;
        align_expr = quote! {
            zweidraehte_ets_model::union_max(#align_expr, core::mem::align_of::<#ty>())
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

    for (j, field) in layout_fields.iter().enumerate() {
        let ty = &field.ty;
        let off_ident = format_ident!("__ETS_PARAMS_{}_OFF{}", struct_name, j);
        let next_end = format_ident!("__ETS_PARAMS_{}_END{}", struct_name, j + 1);
        layout_consts.push(quote! {
            #[doc(hidden)]
        #[allow(non_upper_case_globals)]
            const #off_ident: usize =
                zweidraehte_ets_model::union_align_up(#end_ident, core::mem::align_of::<#ty>());
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
        const #total_ident: usize = zweidraehte_ets_model::union_align_up(#end_ident, #align_ident);
    });

    // ========================================================================
    // Rewrite the fields with their fillers
    // ========================================================================
    //
    // Tool-only fields are carried through in declaration order but without a
    // filler, so the metadata pass still sees them where the author wrote them.
    // They are removed again before the struct is emitted.
    let mut padded = syn::punctuated::Punctuated::new();
    let mut layout_j = 0usize;
    for field in &originals {
        if is_no_memory(field) {
            padded.push(field.clone());
            continue;
        }

        let off_ident = format_ident!("__ETS_PARAMS_{}_OFF{}", struct_name, layout_j);
        let prev_end = format_ident!("__ETS_PARAMS_{}_END{}", struct_name, layout_j);
        // Trim the field's own leading underscores so a `_anchor` field
        // yields `_pad_before_anchor`, not the double-underscore
        // spelling the non_snake_case lint rejects.
        let field_ident = field.ident.as_ref().expect("named");
        let pad_name = format_ident!("_pad_before_{}", field_ident.to_string().trim_start_matches('_'));
        let vis = &field.vis;
        // Zero-length in the common case; a ZST field costs nothing and keeps
        // the emitted shape uniform.
        padded.push(parse_quote! {
            #[ets(skip)]
            #[serde(skip)]
            #vis #pad_name: [u8; #off_ident - #prev_end]
        });
        padded.push(field.clone());
        layout_j += 1;
    }
    let last_vis = layout_fields.last().map(|f| f.vis.clone()).unwrap_or(syn::Visibility::Inherited);
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
    // emitted item — see the equivalent note in `ets_union_attr`. Tool-only
    // fields drop out here, after the metadata pass has seen them: they are
    // parameters, not device state, so the struct must not carry their bytes.
    let mut emitted = rewritten;
    if let Fields::Named(f) = &mut emitted.fields {
        f.named = f.named.iter().filter(|field| !is_no_memory(field)).cloned().collect();
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
