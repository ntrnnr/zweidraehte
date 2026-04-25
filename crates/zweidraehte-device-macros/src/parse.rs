//! Attribute parsing for `#[io(...)]` on structs and fields.
//!
//! All audit-relevant fields (`pid`, `pdt`, `access`, `policy`) are mandatory
//! and validated here. Errors are attached to the offending span so the user
//! sees the diagnostic at the right field, not at the derive site.

use proc_macro2::{Span, TokenStream};
use syn::{Expr, Field, Path, spanned::Spanned};

// ---------------------------------------------------------------------------
// Struct-level attributes: #[io(object_type = ..., augment_for = ...)]
// ---------------------------------------------------------------------------

pub(crate) struct ObjectAttrs {
    pub object_type: Option<Path>,
    pub augment_for: Option<Path>,
}

impl ObjectAttrs {
    /// Parse `#[interface_object(object_type = ..., augment_for = ...)]`
    /// arguments. The token stream is the `attr` input from the proc-macro,
    /// so it does not include the surrounding `#[interface_object(...)]`.
    pub fn from_attribute_args(args: TokenStream) -> syn::Result<Self> {
        let mut object_type: Option<Path> = None;
        let mut augment_for: Option<Path> = None;

        // `meta::ParseNestedMeta` handles the comma-separated key=value list
        // that lives inside the attribute parens.
        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("object_type") {
                object_type = Some(meta.value()?.parse()?);
                Ok(())
            } else if meta.path.is_ident("augment_for") {
                augment_for = Some(meta.value()?.parse()?);
                Ok(())
            } else {
                Err(meta.error("unknown attribute (expected `object_type` or `augment_for`)"))
            }
        });
        syn::parse::Parser::parse2(parser, args)?;

        Ok(Self {
            object_type,
            augment_for,
        })
    }
}

// ---------------------------------------------------------------------------
// Field-level attributes: #[io(pid=..., pdt=..., access=..., policy=..., ...)]
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Ro,
    Rw,
    Wo,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backing {
    /// Property value lives in the struct field itself (default).
    Field,
    /// Property value lives behind a `state: &S` reference. The annotated
    /// field is unit-typed (`()`) and erased from the generated struct.
    State,
}

pub(crate) struct PropertyAttrs {
    pub field_ident: syn::Ident,
    pub field_ty: syn::Type,
    pub field_span: Span,

    // Mandatory ----------------------------------------------------------
    pub pid: Path,
    pub pdt: Path,
    pub access: Access,
    pub policy: Expr,

    // Optional -----------------------------------------------------------
    pub rl: Option<u8>,
    pub wl: Option<u8>,
    pub array_max: Option<u16>,
    pub computed_max: Option<Expr>,
    pub backing: Backing,
    pub read_fn: Option<Expr>,
    pub write_fn: Option<Expr>,
    pub default_value: Option<Expr>,
}

impl PropertyAttrs {
    pub fn from_field(field: &Field) -> syn::Result<Self> {
        let field_ident = field
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new(field.span(), "expected named field"))?;
        let field_span = field.span();

        let io_attrs: Vec<_> = field
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("io"))
            .collect();
        if io_attrs.is_empty() {
            return Err(syn::Error::new(
                field_span,
                "missing #[io(...)] attribute on field — every InterfaceObject \
                 field must declare its property metadata",
            ));
        }

        let mut pid: Option<Path> = None;
        let mut pdt: Option<Path> = None;
        let mut access: Option<Access> = None;
        let mut policy: Option<Expr> = None;
        let mut rl: Option<u8> = None;
        let mut wl: Option<u8> = None;
        let mut array_max: Option<u16> = None;
        let mut computed_max: Option<Expr> = None;
        let mut backing = Backing::Field;
        let mut read_fn: Option<Expr> = None;
        let mut write_fn: Option<Expr> = None;
        let mut default_value: Option<Expr> = None;

        for attr in io_attrs {
            attr.parse_nested_meta(|meta| {
                let key = &meta.path;
                if key.is_ident("pid") {
                    pid = Some(meta.value()?.parse()?);
                } else if key.is_ident("pdt") {
                    pdt = Some(meta.value()?.parse()?);
                } else if key.is_ident("access") {
                    let ident: syn::Ident = meta.value()?.parse()?;
                    access = Some(match ident.to_string().as_str() {
                        "RO" => Access::Ro,
                        "RW" => Access::Rw,
                        "WO" => Access::Wo,
                        other => {
                            return Err(syn::Error::new(
                                ident.span(),
                                format!("expected RO, RW, or WO; got `{other}`"),
                            ));
                        }
                    });
                } else if key.is_ident("policy") {
                    policy = Some(meta.value()?.parse()?);
                } else if key.is_ident("rl") {
                    let lit: syn::LitInt = meta.value()?.parse()?;
                    rl = Some(lit.base10_parse()?);
                } else if key.is_ident("wl") {
                    let lit: syn::LitInt = meta.value()?.parse()?;
                    wl = Some(lit.base10_parse()?);
                } else if key.is_ident("array") {
                    // array(max = N)
                    meta.parse_nested_meta(|inner| {
                        if inner.path.is_ident("max") {
                            let lit: syn::LitInt = inner.value()?.parse()?;
                            array_max = Some(lit.base10_parse()?);
                            Ok(())
                        } else {
                            Err(inner.error("unknown array attribute (expected `max`)"))
                        }
                    })?;
                } else if key.is_ident("computed_max") {
                    computed_max = Some(meta.value()?.parse()?);
                } else if key.is_ident("backing") {
                    let ident: syn::Ident = meta.value()?.parse()?;
                    backing = match ident.to_string().as_str() {
                        "field" => Backing::Field,
                        "state" => Backing::State,
                        other => {
                            return Err(syn::Error::new(
                                ident.span(),
                                format!("expected `field` or `state`; got `{other}`"),
                            ));
                        }
                    };
                } else if key.is_ident("read") {
                    read_fn = Some(meta.value()?.parse()?);
                } else if key.is_ident("write") {
                    write_fn = Some(meta.value()?.parse()?);
                } else if key.is_ident("default") {
                    default_value = Some(meta.value()?.parse()?);
                } else {
                    return Err(meta.error("unknown #[io(...)] field attribute"));
                }
                Ok(())
            })?;
        }

        // Mandatory checks: each missing attribute gets its own error pointing
        // at the field, so the user can fix all of them in one pass.
        let pid = require(pid, field_span, "pid")?;
        let pdt = require(pdt, field_span, "pdt")?;
        let access = require(access, field_span, "access")?;
        let policy = require(policy, field_span, "policy")?;

        // Cross-field consistency:
        // - `array(max=N)` and `computed_max=...` are mutually exclusive
        // - `backing = state` requires `read_fn`; `write_fn` only if access != RO
        if array_max.is_some() && computed_max.is_some() {
            return Err(syn::Error::new(
                field_span,
                "`array(max = ...)` and `computed_max = ...` are mutually exclusive",
            ));
        }
        if matches!(backing, Backing::State) && read_fn.is_none() {
            return Err(syn::Error::new(
                field_span,
                "`backing = state` requires `read = |s| ...`",
            ));
        }
        if matches!(access, Access::Wo) && read_fn.is_some() {
            return Err(syn::Error::new(
                field_span,
                "WriteOnly property cannot have a `read` closure",
            ));
        }
        if matches!(access, Access::Ro) && write_fn.is_some() {
            return Err(syn::Error::new(
                field_span,
                "ReadOnly property cannot have a `write` closure",
            ));
        }

        Ok(Self {
            field_ident,
            field_ty: field.ty.clone(),
            field_span,
            pid,
            pdt,
            access,
            policy,
            rl,
            wl,
            array_max,
            computed_max,
            backing,
            read_fn,
            write_fn,
            default_value,
        })
    }
}

fn require<T>(value: Option<T>, span: Span, name: &str) -> syn::Result<T> {
    value.ok_or_else(|| {
        syn::Error::new(
            span,
            format!(
                "missing required #[io({name} = ...)] attribute — \
                 every property must declare {name} explicitly (no defaults)"
            ),
        )
    })
}
