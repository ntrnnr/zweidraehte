//! Proc-macros for KNX interface object metadata.
//!
//! Provides two attribute macros:
//!
//! - `#[interface_object(object_type = ...)]` — applied to a struct, rewrites
//!   it to strip `backing = state` placeholder fields, injects `state: &'a S`
//!   when needed, and emits a `const PROPERTY_DESCRIPTORS` plus a full
//!   `InterfaceObject` impl.
//! - `#[interface_object_augment(augment_for = ...)]` — same DSL for
//!   `InterfaceObjectAugment` impls.
//!
//! Every audit-relevant attribute (`pid`, `pdt`, `access`, `policy`) is
//! mandatory at parse time — missing fields raise a `syn::Error` pointing
//! at the offending field rather than a runtime panic or silent default.
//!
//! Attribute macros are used (not derive) because deriving cannot strip
//! fields from the input struct, and the form-A DSL relies on stripping
//! unit-typed placeholders for state-backed properties.

use proc_macro::TokenStream;
use syn::{ItemStruct, parse_macro_input};

mod codegen;
mod parse;

use parse::{ObjectAttrs, PropertyAttrs};

#[proc_macro_attribute]
pub fn interface_object(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemStruct);
    let obj_attrs = match ObjectAttrs::from_attribute_args(attr.into()) {
        Ok(o) => o,
        Err(err) => return err.to_compile_error().into(),
    };
    match expand(&item, obj_attrs, Mode::Object) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

#[proc_macro_attribute]
pub fn interface_object_augment(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemStruct);
    let obj_attrs = match ObjectAttrs::from_attribute_args(attr.into()) {
        Ok(o) => o,
        Err(err) => return err.to_compile_error().into(),
    };
    match expand(&item, obj_attrs, Mode::Augment) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Object,
    Augment,
}

fn expand(
    item: &ItemStruct,
    obj_attrs: ObjectAttrs,
    mode: Mode,
) -> syn::Result<proc_macro2::TokenStream> {
    let fields = match &item.fields {
        syn::Fields::Named(f) => &f.named,
        _ => {
            return Err(syn::Error::new(
                item.ident.span(),
                "#[interface_object] requires a struct with named fields",
            ));
        }
    };

    // Parse every field's #[io(...)] attribute. Mandatory-field diagnostics
    // fire here, before any codegen runs, so the user gets one error per
    // missing attribute, attached to the right field.
    let mut props = Vec::with_capacity(fields.len());
    for field in fields {
        props.push(PropertyAttrs::from_field(field)?);
    }

    match mode {
        Mode::Object => codegen::gen_object(item, &obj_attrs, &props),
        Mode::Augment => Err(syn::Error::new(
            item.ident.span(),
            "interface_object_augment codegen not yet implemented",
        )),
    }
}
