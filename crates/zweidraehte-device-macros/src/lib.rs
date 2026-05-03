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
use syn::{DeriveInput, ItemStruct, parse_macro_input};

mod codegen;
mod parse;
mod service_registry;

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

/// Derive [`LayerRegistry<D>`](::zweidraehte_device::service::LayerRegistry) and
/// [`AugmentRegistry<D>`](::zweidraehte_device::service::AugmentRegistry) for a
/// device's services struct.
///
/// # Field annotations
///
/// Each field of the struct must carry exactly one `#[service(...)]`
/// annotation describing its role:
///
/// - `#[service(handler)]` — the field implements
///   [`Layer<D>`](::zweidraehte_device::service::Layer). It contributes its
///   `Layer::HANDLES` to the const dispatch table and participates in
///   `init_layers` / `poll_layers` / `next_layer_deadline`.
///
/// - `#[service(augment)]` — the field implements
///   [`Augment<D>`](::zweidraehte_device::service::Augment). It joins the
///   property-hook chain, contributes to `additional_object_count` /
///   `additional_object_type_at`, and participates in `poll_augments` /
///   `next_augment_deadline`.
///
/// Field annotations are checked at compile time; an un-annotated
/// field or one with an unknown annotation produces a clear compile
/// error.
///
/// # Generics
///
/// The macro emits impls generic over `<D: ::zweidraehte_device::StackDefinition>`,
/// so a single services struct can be reused across multiple
/// `StackDefinition` types provided every field is also generic
/// (or already covers the concrete `D`).
///
/// # Example
///
/// ```rust,ignore
/// #[derive(ServiceRegistry)]
/// pub struct MyDeviceServices {
///     #[service(handler)] pub nl:   NetworkLayer,
///     #[service(handler)] pub tl:   TransportLayer,
///     #[service(handler)] pub al:   ApplicationLayer<(Memory, Authorization)>,
///     #[service(augment)] pub sec:  StdSecurity,
///     #[service(augment)] pub diag: StdDiagnostics,
/// }
/// ```
#[proc_macro_derive(ServiceRegistry, attributes(service))]
pub fn derive_service_registry(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match service_registry::derive(&input) {
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
        Mode::Augment => codegen::gen_augment(item, &obj_attrs, &props),
    }
}
