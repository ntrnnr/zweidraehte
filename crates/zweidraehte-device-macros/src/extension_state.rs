//! `#[derive(ExtensionState)]` — generate the persisted `*Config` mirror
//! and the `ExtensionState` glue from a runtime `*State` struct.
//!
//! For a leaf extension the persisted config is *literally* the runtime
//! state with every `Cell<T>` / `RefCell<T>` unwrapped to `T`, and
//! `from_config` / `to_config` / `on_erase` are mechanical. This derive
//! treats the `*State` struct as the single source of truth and generates:
//!
//! 1. `struct <Config> { … }` — the unwrapped, `Serialize + Deserialize`
//!    mirror, with each field's serde defaults carried through.
//! 2. `impl Default for <Config>`.
//! 3. `impl ExtensionConfig for <Config>`.
//! 4. `impl ExtensionState for <State>` — `Config` / `Resources` assoc
//!    types, field-by-field `from_config` / `to_config`, and the shared
//!    factory-reset `on_erase` guard.
//!
//! # Struct attribute
//!
//! `#[extension_state(config = <Ident> [, resources = <Type>]
//!   [, on_erase = manual] [, default = manual])]`
//! — `config` (mandatory) names the generated config type; `resources`
//! (default `()`) is the `ExtensionState::Resources` associated type;
//! `on_erase = manual` suppresses the generated factory-reset method so the
//! extension can hand-write `on_erase` when a field reset needs a side-effect
//! the field-mapping can't express (e.g. the IP extension also pushes the
//! reset multicast group onto its rebind channel); `default = manual`
//! suppresses the generated `impl Default for <Config>` so the extension can
//! keep a hand-written `Default` when the factory values are not the per-field
//! `Default::default()` (e.g. the IP config's DHCP/multicast defaults).
//!
//! # Field attributes
//!
//! - `#[runtime_only]` / `#[runtime_only(init = <expr>)]` — the field is
//!   pure runtime: it is omitted from the config, initialised from `init`
//!   (default `Default::default()`) in `from_config`, and skipped by
//!   `to_config` and `on_erase`.
//! - `#[config(...)]` — control the config-side representation:
//!   - `serde_default = "<path>"` — emits `#[serde(default = "<path>")]`
//!     on the config field (matches the hand-written structs).
//!   - `ty = <Type>` — the config field uses `<Type>` instead of the
//!     unwrapped runtime type (e.g. `Cell<Ipv4Addr>` persisted as
//!     `[u8; 4]`). Requires `from`/`to`.
//!   - `from = |c| <expr>` — build the *inner* runtime value from the
//!     config field value `c` (before re-wrapping in `Cell`/`RefCell`).
//!   - `to = |s| <expr>` — build the config field value from the *inner*
//!     runtime value `s` (after unwrapping the `Cell`/`RefCell`).
//! - `#[erase(default = <expr>)]` — the value the field resets to on a
//!   factory reset. Defaults to `Default::default()` for the inner type.
//!
//! The `#[io(...)]` virtual placeholder fields used by
//! `#[interface_object_augment]` are unit-typed (`()`); on TP1 (where the
//! same struct carries both attributes) the attribute macro strips them
//! before this derive runs, so they never reach the field walk. As a
//! belt-and-braces measure the derive also skips any unit-typed field.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Expr, Field, Fields, Ident, Type, spanned::Spanned};

// ===========================================================================
// Parsed model
// ===========================================================================

/// How a runtime field is wrapped, which dictates the unwrap/rewrap code.
enum Wrapper {
    /// `Cell<T>` — `Cell::new(v)` / `self.f.get()`.
    Cell(Type),
    /// `RefCell<T>` — `RefCell::new(v)` / `self.f.borrow().clone()`.
    RefCell(Type),
    /// Plain `T` — moved directly.
    Plain(Type),
}

impl Wrapper {
    /// The inner runtime type `T` (what `from`/`to` converters see).
    fn inner_ty(&self) -> &Type {
        match self {
            Wrapper::Cell(t) | Wrapper::RefCell(t) | Wrapper::Plain(t) => t,
        }
    }
}

/// A persisted field: contributes a config field and conversion code.
struct PersistedField {
    ident: Ident,
    wrapper: Wrapper,
    /// Config-side type override (`#[config(ty = …)]`); falls back to the
    /// unwrapped inner type.
    config_ty: Option<Type>,
    /// `#[config(serde_default = "<path>")]`.
    serde_default: Option<syn::LitStr>,
    /// `#[config(from = |c| …)]` — config value → inner runtime value.
    from_fn: Option<Expr>,
    /// `#[config(to = |s| …)]` — inner runtime value → config value.
    to_fn: Option<Expr>,
    /// `#[erase(default = <expr>)]` — factory-reset value for the inner type.
    erase_default: Option<Expr>,
}

/// A runtime-only field: never persisted.
struct RuntimeField {
    ident: Ident,
    /// `#[runtime_only(init = <expr>)]` for `from_config`; default
    /// `Default::default()`.
    init: Option<Expr>,
}

enum FieldModel {
    Persisted(PersistedField),
    Runtime(RuntimeField),
}

// ===========================================================================
// Entry point
// ===========================================================================

pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let state_ident = &input.ident;

    let StructAttr { config_ident, resources_ty, manual_on_erase, manual_default } = parse_struct_attr(input)?;

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "`#[derive(ExtensionState)]` requires a struct with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(input, "`#[derive(ExtensionState)]` can only be derived for structs"));
        }
    };

    // Parse each field into the persisted/runtime model, skipping unit-typed
    // virtual placeholders left over from `#[interface_object_augment]`.
    let mut models: Vec<FieldModel> = Vec::with_capacity(fields.len());
    for field in fields {
        if is_unit_field(field) {
            continue;
        }
        models.push(parse_field(field)?);
    }

    // The derive only makes sense on a non-generic state struct: the config
    // mirror is a concrete persisted type. (`IpExtensionState<CAPS>` is the
    // one generic case; its `CAPS` is firmware-compiled and contributes
    // nothing to the config, so the config type is non-generic and the
    // `ExtensionState` impl carries the generic header.)
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let config_struct = gen_config_struct(&config_ident, &models, input.vis.clone(), manual_default);
    let extension_state_impl = gen_extension_state_impl(
        state_ident,
        &impl_generics,
        &ty_generics,
        where_clause,
        &config_ident,
        &resources_ty,
        &models,
        manual_on_erase,
    );

    Ok(quote! {
        #config_struct
        #extension_state_impl
    })
}

// ===========================================================================
// Struct-attribute parsing: #[extension_state(config = …, resources = …)]
// ===========================================================================

struct StructAttr {
    config_ident: Ident,
    resources_ty: Type,
    /// `on_erase = manual` — caller hand-writes `on_erase` (the derive forwards
    /// the trait method to an inherent `on_erase_manual`).
    manual_on_erase: bool,
    /// `default = manual` — caller keeps a hand-written `impl Default for
    /// <Config>`; the derive omits its own.
    manual_default: bool,
}

fn parse_struct_attr(input: &DeriveInput) -> syn::Result<StructAttr> {
    let attr = input.attrs.iter().find(|a| a.path().is_ident("extension_state")).ok_or_else(|| {
        syn::Error::new_spanned(
            &input.ident,
            "`#[derive(ExtensionState)]` requires `#[extension_state(config = <Ident>)]`",
        )
    })?;

    let mut config: Option<Ident> = None;
    let mut resources: Option<Type> = None;
    let mut manual_on_erase = false;
    let mut manual_default = false;

    // Shared parser for the `on_erase = manual` / `default = manual` flags:
    // both accept only the literal `manual`.
    fn require_manual(meta: &syn::meta::ParseNestedMeta, what: &str) -> syn::Result<bool> {
        let value: Ident = meta.value()?.parse()?;
        if value == "manual" {
            Ok(true)
        } else {
            Err(meta.error(format!("unknown `{what}` value — the only option is `manual`")))
        }
    }

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("config") {
            config = Some(meta.value()?.parse()?);
            Ok(())
        } else if meta.path.is_ident("resources") {
            resources = Some(meta.value()?.parse()?);
            Ok(())
        } else if meta.path.is_ident("on_erase") {
            manual_on_erase = require_manual(&meta, "on_erase")?;
            Ok(())
        } else if meta.path.is_ident("default") {
            manual_default = require_manual(&meta, "default")?;
            Ok(())
        } else {
            Err(meta.error(
                "unknown `extension_state` attribute — expected `config`, `resources`, `on_erase`, or `default`",
            ))
        }
    })?;

    let config_ident =
        config.ok_or_else(|| syn::Error::new_spanned(attr, "`extension_state` requires `config = <Ident>`"))?;
    let resources_ty = resources.unwrap_or_else(|| syn::parse_quote!(()));
    Ok(StructAttr { config_ident, resources_ty, manual_on_erase, manual_default })
}

// ===========================================================================
// Field parsing
// ===========================================================================

fn is_unit_field(field: &Field) -> bool {
    matches!(&field.ty, Type::Tuple(t) if t.elems.is_empty())
}

fn parse_field(field: &Field) -> syn::Result<FieldModel> {
    let ident = field.ident.clone().expect("named field");

    // `#[runtime_only]` short-circuits — the field never persists.
    if let Some(rt) = field.attrs.iter().find(|a| a.path().is_ident("runtime_only")) {
        let mut init: Option<Expr> = None;
        // `#[runtime_only]` (bare) or `#[runtime_only(init = <expr>)]`.
        if !matches!(rt.meta, syn::Meta::Path(_)) {
            rt.parse_nested_meta(|meta| {
                if meta.path.is_ident("init") {
                    init = Some(meta.value()?.parse()?);
                    Ok(())
                } else {
                    Err(meta.error("unknown `runtime_only` attribute — expected `init`"))
                }
            })?;
        }
        return Ok(FieldModel::Runtime(RuntimeField { ident, init }));
    }

    let wrapper = classify_wrapper(&field.ty)?;

    let mut config_ty: Option<Type> = None;
    let mut serde_default: Option<syn::LitStr> = None;
    let mut from_fn: Option<Expr> = None;
    let mut to_fn: Option<Expr> = None;

    if let Some(cfg) = field.attrs.iter().find(|a| a.path().is_ident("config")) {
        cfg.parse_nested_meta(|meta| {
            if meta.path.is_ident("ty") {
                config_ty = Some(meta.value()?.parse()?);
                Ok(())
            } else if meta.path.is_ident("serde_default") {
                serde_default = Some(meta.value()?.parse()?);
                Ok(())
            } else if meta.path.is_ident("from") {
                from_fn = Some(meta.value()?.parse()?);
                Ok(())
            } else if meta.path.is_ident("to") {
                to_fn = Some(meta.value()?.parse()?);
                Ok(())
            } else {
                Err(meta.error("unknown `config` attribute — expected `ty`, `serde_default`, `from`, or `to`"))
            }
        })?;
    }

    let erase_default = field
        .attrs
        .iter()
        .find(|a| a.path().is_ident("erase"))
        .map(|erase| {
            let mut default: Option<Expr> = None;
            erase.parse_nested_meta(|meta| {
                if meta.path.is_ident("default") {
                    default = Some(meta.value()?.parse()?);
                    Ok(())
                } else {
                    Err(meta.error("unknown `erase` attribute — expected `default`"))
                }
            })?;
            default.ok_or_else(|| syn::Error::new_spanned(erase, "`erase` requires `default = <expr>`"))
        })
        .transpose()?;

    // A custom config type requires explicit converters: the derive can't
    // know how to bridge two arbitrary types.
    if config_ty.is_some() && (from_fn.is_none() || to_fn.is_none()) {
        return Err(syn::Error::new(
            field.span(),
            "`#[config(ty = …)]` requires both `from = |c| …` and `to = |s| …` converters",
        ));
    }

    Ok(FieldModel::Persisted(PersistedField {
        ident,
        wrapper,
        config_ty,
        serde_default,
        from_fn,
        to_fn,
        erase_default,
    }))
}

/// Recognise `Cell<T>` / `RefCell<T>` / plain `T`. Only the last path
/// segment is inspected, so both `core::cell::Cell<T>` and a bare `Cell<T>`
/// match.
fn classify_wrapper(ty: &Type) -> syn::Result<Wrapper> {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            let name = seg.ident.to_string();
            if name == "Cell" || name == "RefCell" {
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                        return Ok(if name == "Cell" {
                            Wrapper::Cell(inner.clone())
                        } else {
                            Wrapper::RefCell(inner.clone())
                        });
                    }
                }
                return Err(syn::Error::new(ty.span(), format!("`{name}` field must have a single type argument")));
            }
        }
    }
    Ok(Wrapper::Plain(ty.clone()))
}

// ===========================================================================
// Config struct generation
// ===========================================================================

fn gen_config_struct(
    config_ident: &Ident,
    models: &[FieldModel],
    vis: syn::Visibility,
    manual_default: bool,
) -> TokenStream {
    let mut config_fields = Vec::new();
    let mut default_fields = Vec::new();

    for model in models {
        let FieldModel::Persisted(p) = model else { continue };
        let ident = &p.ident;
        let cfg_ty = p.config_ty.clone().unwrap_or_else(|| p.wrapper.inner_ty().clone());

        let serde_attr = p.serde_default.as_ref().map(|path| {
            quote! { #[serde(default = #path)] }
        });
        config_fields.push(quote! {
            #serde_attr
            pub #ident: #cfg_ty,
        });

        // `Default` mirrors serde's: prefer the named serde-default fn (so the
        // two agree exactly), else fall back to `Default::default()`.
        let default_expr = match &p.serde_default {
            Some(path_lit) => {
                let path: syn::Path = path_lit.parse().expect("serde_default is a path literal");
                quote! { #path() }
            }
            None => quote! { ::core::default::Default::default() },
        };
        default_fields.push(quote! { #ident: #default_expr, });
    }

    // `default = manual` keeps a hand-written `impl Default for <Config>` when
    // the factory values aren't the per-field defaults (e.g. the IP config's
    // DHCP method / multicast group). Otherwise the derive synthesises one from
    // each field's serde default (or `Default::default()`), so it agrees with
    // what `#[serde(default = …)]` fills in for a missing field.
    let default_impl = if manual_default {
        quote! {}
    } else {
        quote! {
            impl ::core::default::Default for #config_ident {
                fn default() -> Self {
                    Self {
                        #( #default_fields )*
                    }
                }
            }
        }
    };

    quote! {
        #[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]
        #vis struct #config_ident {
            #( #config_fields )*
        }

        #default_impl

        impl ::zweidraehte_device::bcus::system_b::ExtensionConfig for #config_ident {}
    }
}

// ===========================================================================
// ExtensionState impl generation
// ===========================================================================

#[allow(clippy::too_many_arguments)]
fn gen_extension_state_impl(
    state_ident: &Ident,
    impl_generics: &syn::ImplGenerics<'_>,
    ty_generics: &syn::TypeGenerics<'_>,
    where_clause: Option<&syn::WhereClause>,
    config_ident: &Ident,
    resources_ty: &Type,
    models: &[FieldModel],
    manual_on_erase: bool,
) -> TokenStream {
    let mut from_config_fields = Vec::new();
    let mut to_config_fields = Vec::new();
    let mut erase_stmts = Vec::new();

    for model in models {
        match model {
            FieldModel::Persisted(p) => {
                let ident = &p.ident;

                // from_config: config field → inner value (via `from` if any)
                // → rewrapped in Cell/RefCell.
                let inner_from = match &p.from_fn {
                    Some(f) => quote! { (#f)(config.#ident) },
                    None => quote! { config.#ident },
                };
                let rewrapped = match &p.wrapper {
                    Wrapper::Cell(_) => quote! { ::core::cell::Cell::new(#inner_from) },
                    Wrapper::RefCell(_) => quote! { ::core::cell::RefCell::new(#inner_from) },
                    Wrapper::Plain(_) => inner_from,
                };
                from_config_fields.push(quote! { #ident: #rewrapped, });

                // to_config: unwrap Cell/RefCell → inner value → config field
                // (via `to` if any).
                let unwrapped = match &p.wrapper {
                    Wrapper::Cell(_) => quote! { self.#ident.get() },
                    Wrapper::RefCell(_) => quote! { self.#ident.borrow().clone() },
                    Wrapper::Plain(_) => quote! { self.#ident.clone() },
                };
                let cfg_value = match &p.to_fn {
                    Some(f) => quote! { (#f)(#unwrapped) },
                    None => unwrapped,
                };
                to_config_fields.push(quote! { #ident: #cfg_value, });

                // on_erase: reset the inner value to its factory default.
                let erase_value = match &p.erase_default {
                    Some(e) => quote! { #e },
                    None => quote! { ::core::default::Default::default() },
                };
                let erase_stmt = match &p.wrapper {
                    Wrapper::Cell(_) => quote! { self.#ident.set(#erase_value); },
                    Wrapper::RefCell(_) => quote! { *self.#ident.borrow_mut() = #erase_value; },
                    // A plain (non-interior-mutable) field can't be reset
                    // through `&self`; require interior mutability for
                    // erasable fields. If someone hits this, they should wrap
                    // the field in a Cell/RefCell or mark it `#[runtime_only]`.
                    Wrapper::Plain(_) => quote! {
                        compile_error!(
                            "plain (non-Cell/RefCell) field cannot be reset by `on_erase` through `&self`; \
                             wrap it in `Cell`/`RefCell` or mark it `#[runtime_only]`"
                        );
                    },
                };
                erase_stmts.push(erase_stmt);
            }
            FieldModel::Runtime(r) => {
                let ident = &r.ident;
                let init = match &r.init {
                    Some(e) => quote! { #e },
                    None => quote! { ::core::default::Default::default() },
                };
                from_config_fields.push(quote! { #ident: #init, });
                // runtime-only fields are absent from config and untouched by
                // on_erase.
            }
        }
    }

    // `on_erase` has no default on the `ExtensionState` trait, and Rust won't
    // let one trait impl span two blocks, so the derive must always emit the
    // method. `on_erase = manual` forwards it to a user-written inherent
    // `on_erase_manual(&self, code)` — the escape hatch for a reset that needs
    // a side-effect the field-mapping can't express (e.g. the IP extension
    // pushes the reset multicast group onto its rebind channel). Otherwise the
    // derive generates the standard factory-reset guard from the fields.
    let on_erase_method = if manual_on_erase {
        quote! {
            fn on_erase(&self, code: ::zweidraehte_device::restart::EraseCode) {
                self.on_erase_manual(code);
            }
        }
    } else {
        quote! {
            fn on_erase(&self, code: ::zweidraehte_device::restart::EraseCode) {
                if ::core::matches!(
                    code,
                    ::zweidraehte_device::restart::EraseCode::FactoryReset
                        | ::zweidraehte_device::restart::EraseCode::FactoryResetKeepIA
                ) {
                    #( #erase_stmts )*
                }
            }
        }
    };

    quote! {
        impl #impl_generics ::zweidraehte_device::bcus::system_b::ExtensionState
            for #state_ident #ty_generics #where_clause
        {
            type Config = #config_ident;
            type Resources = #resources_ty;

            fn from_config(config: Self::Config, _resources: Self::Resources) -> Self {
                Self {
                    #( #from_config_fields )*
                }
            }

            fn to_config(&self) -> Self::Config {
                #config_ident {
                    #( #to_config_fields )*
                }
            }

            #on_erase_method
        }
    }
}
