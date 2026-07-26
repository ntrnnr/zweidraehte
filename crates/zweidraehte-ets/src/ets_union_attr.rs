//! The `#[ets_union]` attribute macro.
//!
//! # Why this is an attribute and not a derive
//!
//! A union's bytes are reinterpreted wholesale — as the `<Data>` defaults blob
//! the generators emit, and as the live parameter memory
//! `ApplicationImpl::data_ref` serves to `A_Memory_Read`. Any byte the layout
//! does not name is read uninitialized: UB, and observably a product database
//! whose defaults change between builds.
//!
//! `zerocopy::IntoBytes` is what decides whether a type is safe to read that
//! way, and its derive handles data-carrying enums under a bare `#[repr(u8)]`
//! (adding `C` makes rustc reject the tag enum the derive generates). But a
//! tagged union is padded by construction in two places:
//!
//! 1. **after the tag**, whenever a payload field needs alignment > 1; and
//! 2. **at the tail** of any variant narrower than the widest one.
//!
//! Both are fixable only by adding fields — which a derive macro cannot do to
//! the item it is attached to. Hence an attribute macro: it rewrites the enum,
//! inserting exactly the `_pad` fields the layout requires, then hands the
//! result to zerocopy's derive to check. Device authors declare only real
//! parameters and write no `unsafe`.
//!
//! # How the padding is sized
//!
//! Deliberately *not* at macro-expansion time. The `ets` type table assumes
//! every `#[ets(ets_enum)]` field is one byte, which is wrong for the
//! `#[repr(u16)]` enums — precisely the fields whose alignment creates the
//! holes. So the generated array lengths are `const` expressions over the real
//! `size_of` / `align_of` of each field type, emitted as named consts:
//!
//! ```text
//! end₀ = 1                                    // just past the tag
//! offⱼ = align_up(endⱼ₋₁, align_of::<Tⱼ>())   // where field j must start
//! endⱼ = offⱼ + size_of::<Tⱼ>()
//! TOTAL = align_up(max over variants of endₙ, ALIGN)
//! ```
//!
//! A filler of `offⱼ - endⱼ₋₁` bytes goes before field *j*, and one of
//! `TOTAL - endₙ` bytes closes the variant. If a type's size ever changes, the
//! padding follows it; if the arithmetic here were ever wrong, zerocopy's
//! derive rejects the result rather than emitting a bad blob.

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, FieldsNamed, parse_quote};

use crate::ets_union::derive_ets_union_impl;

pub(crate) fn ets_union_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let enum_name = &input.ident;

    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(input, "#[ets_union] can only be applied to enums"));
    };

    // The author supplies no `repr`: this macro owns it. A hand-written
    // `#[repr(C, u8)]` is the one thing that would silently defeat the whole
    // mechanism (it blocks zerocopy's derive), so reject any repr outright
    // rather than trying to reconcile it.
    if let Some(attr) = input.attrs.iter().find(|a| a.path().is_ident("repr")) {
        return Err(syn::Error::new_spanned(
            attr,
            "#[ets_union] sets the representation itself — remove this `repr`.\n\
             It emits `#[repr(u8)]`, which gives the same tag-then-payload image as \
             `#[repr(C, u8)]` (RFC 2195) while still allowing `#[derive(zerocopy::IntoBytes)]`, \
             the check that proves the union has no uninitialized bytes.",
        ));
    }

    // ========================================================================
    // Per-variant layout consts
    // ========================================================================
    //
    // Names are prefixed with the enum so several unions can coexist in one
    // module. They are `#[doc(hidden)]` implementation detail, not API.
    let mut layout_consts = Vec::new();
    let mut variant_end_idents = Vec::new();

    // The enum's alignment is the largest alignment among all payload fields
    // of all variants (1 if every variant is empty).
    let align_ident = format_ident!("__ETS_UNION_{}_ALIGN", enum_name);
    let mut align_expr: TokenStream2 = quote!(1usize);
    for variant in &data.variants {
        for field in variant.fields.iter() {
            let ty = &field.ty;
            align_expr = quote! {
                zweidraehte_device::ets::union_max(#align_expr, core::mem::align_of::<#ty>())
            };
        }
    }
    layout_consts.push(quote! {
        #[doc(hidden)]
        const #align_ident: usize = #align_expr;
    });

    // Walk each variant's fields, emitting the running offset chain.
    for variant in &data.variants {
        let vname = &variant.ident;
        // `end` starts at 1: the tag occupies byte 0 of every variant.
        let mut end_ident = format_ident!("__ETS_UNION_{}_{}_END0", enum_name, vname);
        layout_consts.push(quote! {
            #[doc(hidden)]
            const #end_ident: usize = 1;
        });

        for (j, field) in variant.fields.iter().enumerate() {
            let ty = &field.ty;
            let off_ident = format_ident!("__ETS_UNION_{}_{}_OFF{}", enum_name, vname, j);
            let next_end = format_ident!("__ETS_UNION_{}_{}_END{}", enum_name, vname, j + 1);
            layout_consts.push(quote! {
                #[doc(hidden)]
                const #off_ident: usize =
                    zweidraehte_device::ets::union_align_up(#end_ident, core::mem::align_of::<#ty>());
                #[doc(hidden)]
                const #next_end: usize = #off_ident + core::mem::size_of::<#ty>();
            });
            end_ident = next_end;
        }
        variant_end_idents.push(end_ident);
    }

    // TOTAL: the widest variant, rounded up to the enum's alignment. Every
    // variant is tail-padded to exactly this, so no variant leaves a gap.
    let total_ident = format_ident!("__ETS_UNION_{}_TOTAL", enum_name);
    let mut widest: TokenStream2 = quote!(1usize);
    for end in &variant_end_idents {
        widest = quote! { zweidraehte_device::ets::union_max(#widest, #end) };
    }
    layout_consts.push(quote! {
        #[doc(hidden)]
        const #total_ident: usize = zweidraehte_device::ets::union_align_up(#widest, #align_ident);
    });

    // ========================================================================
    // Rewrite the variants with their fillers
    // ========================================================================
    //
    // Alongside the rewrite we collect a constructor per variant. Without them
    // the padding would leak into the DSL: every construction site would have
    // to name `_pad_before_x` / `_pad_tail` explicitly, since Rust has no
    // functional-update syntax for enum variants. `Union::variant(field, ..)`
    // keeps call sites reading exactly as they did before the padding existed.
    let mut constructors = Vec::new();
    let mut rewritten = data.clone();
    for (variant, end_ident) in rewritten.variants.iter_mut().zip(&variant_end_idents) {
        let vname = variant.ident.clone();

        // Tuple variants would force positional fillers, which read as noise at
        // every construction site; named fields keep `_pad_*` self-describing.
        if matches!(variant.fields, Fields::Unnamed(_)) {
            return Err(syn::Error::new_spanned(
                &variant.fields,
                "#[ets_union] variants must use named fields (or none) so generated padding stays readable",
            ));
        }

        let mut fields: FieldsNamed = match &variant.fields {
            Fields::Named(named) => named.clone(),
            // A unit variant still occupies the union's full width, so it needs
            // a body to hold the filler. This is the one case where the macro
            // changes how a variant is written at its construction sites.
            Fields::Unit => parse_quote!({}),
            Fields::Unnamed(_) => unreachable!("rejected above"),
        };

        let originals: Vec<_> = fields.named.iter().cloned().collect();
        let mut padded = syn::punctuated::Punctuated::new();

        for (j, field) in originals.iter().enumerate() {
            let off_ident = format_ident!("__ETS_UNION_{}_{}_OFF{}", enum_name, vname, j);
            let prev_end = format_ident!("__ETS_UNION_{}_{}_END{}", enum_name, vname, j);
            let pad_name = format_ident!("_pad_before_{}", field.ident.as_ref().expect("named"));
            // Zero-length in the common case; a ZST field costs nothing and
            // keeps the emitted shape uniform.
            padded.push(parse_quote! {
                #[ets(skip)]
                #[serde(skip)]
                #pad_name: [u8; #off_ident - #prev_end]
            });
            padded.push(field.clone());
        }

        padded.push(parse_quote! {
            #[ets(skip)]
            #[serde(skip)]
            _pad_tail: [u8; #total_ident - #end_ident]
        });

        fields.named = padded;
        variant.fields = Fields::Named(fields.clone());

        // `Union::snake_case_variant(real_fields..)`, with every generated
        // filler zeroed. `const` so it can build a `ConstDefault` value.
        let ctor_name = syn::Ident::new(&to_snake_case(&vname.to_string()), vname.span());
        let args = originals.iter().map(|f| {
            let name = f.ident.as_ref().expect("named");
            let ty = &f.ty;
            quote!(#name: #ty)
        });
        let inits = fields.named.iter().map(|f| {
            let name = f.ident.as_ref().expect("named");
            if name.to_string().starts_with('_') {
                let ty = &f.ty;
                quote!(#name: [0u8; { core::mem::size_of::<#ty>() }])
            } else {
                quote!(#name)
            }
        });
        let doc = format!("Construct [`{enum_name}::{vname}`], zeroing the generated padding.");
        constructors.push(quote! {
            #[doc = #doc]
            #[allow(clippy::too_many_arguments)]
            pub const fn #ctor_name(#(#args),*) -> Self {
                Self::#vname { #(#inits),* }
            }
        });
    }

    // ========================================================================
    // Emit
    // ========================================================================
    //
    // The metadata half is produced by the existing `EtsUnion` derive logic,
    // run over the *rewritten* enum so its variant sizes match what is actually
    // laid out.
    let mut derive_input = input.clone();
    derive_input.data = Data::Enum(rewritten.clone());
    derive_input.attrs.push(parse_quote!(#[repr(u8)]));
    let metadata = derive_ets_union_impl(&derive_input)?;

    // `#[ets(...)]` is a *derive helper* attribute: it only exists while a
    // derive that declares it is being expanded. The metadata call above has
    // already consumed every one of them, so they must not survive into the
    // emitted item or rustc rejects them as unknown attributes.
    let mut emitted = rewritten;
    for variant in &mut emitted.variants {
        strip_ets_attrs(&mut variant.attrs);
        for field in variant.fields.iter_mut() {
            strip_ets_attrs(&mut field.attrs);
        }
    }

    let mut outer_attrs = input.attrs.clone();
    strip_ets_attrs(&mut outer_attrs);
    let vis = &input.vis;
    let variants = &emitted.variants;

    Ok(quote! {
        #(#layout_consts)*

        #(#outer_attrs)*
        #[repr(u8)]
        #[derive(::zerocopy::IntoBytes, ::zerocopy::KnownLayout, ::zerocopy::Immutable)]
        #vis enum #enum_name {
            #variants
        }

        impl #enum_name {
            #(#constructors)*
        }

        #metadata
    })
}

/// `CamelCase` -> `snake_case`, for deriving a constructor name from a variant.
fn to_snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, ch) in name.trim_start_matches('_').chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn strip_ets_attrs(attrs: &mut Vec<syn::Attribute>) {
    attrs.retain(|a| !a.path().is_ident("ets"));
}
