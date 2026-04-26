//! Attribute parsing for `#[io(...)]` on structs and fields.
//!
//! All audit-relevant fields (`pid`, `pdt`, `access`, `policy`) are mandatory
//! and validated here. Errors are attached to the offending span so the user
//! sees the diagnostic at the right field, not at the derive site.

use proc_macro2::{Span, TokenStream};
use syn::{Expr, Field, Path, parse::Parse, spanned::Spanned};

// ---------------------------------------------------------------------------
// Struct-level attributes
// ---------------------------------------------------------------------------
//
// `#[interface_object(object_type = ...)]` — used by `InterfaceObject` impls
// (single object type per IO).
//
// `#[interface_object_augment(target_objects = [...], additional_objects = [...])]`
//  — used by `InterfaceObjectAugment` impls. `target_objects` is the list of
// object types the augment touches (intercepts and/or owns); per-field
// `target = ...` selects which one a PID belongs to (defaults to the first
// when the list has one entry, mandatory otherwise). `additional_objects`
// drives `additional_object_count` / `additional_object_type_at` for
// augments that *add* an object to the device's IO list.

pub(crate) struct ObjectAttrs {
    /// Set on `#[interface_object]` only. The augment macro uses
    /// `target_objects` instead.
    pub object_type: Option<Path>,

    /// Set on `#[interface_object_augment]` only. Empty for an
    /// `InterfaceObject` derive.
    pub target_objects: Vec<Path>,

    /// Set on `#[interface_object_augment]` only. Drives
    /// `additional_object_count` / `additional_object_type_at`.
    pub additional_objects: Vec<Path>,

    /// Set on `#[interface_object_augment]` only. Extra `where`-clause
    /// predicates appended to the generated `impl InterfaceObjectAugment<D>`.
    /// Use to express bounds on the augment's `D::State`, e.g. on the
    /// state having `HasApplication`, `HasSecurityState`, etc.
    ///
    /// Syntax: `where_bounds(__AugmentD::State: HasApplication + ...)`.
    /// Multiple predicates are comma-separated.
    pub extra_where: Option<TokenStream>,
}

impl ObjectAttrs {
    /// Parse the attribute arguments inside the parentheses of the
    /// `#[interface_object(...)]` or `#[interface_object_augment(...)]`
    /// invocation.
    pub fn from_attribute_args(args: TokenStream) -> syn::Result<Self> {
        let mut object_type: Option<Path> = None;
        let mut target_objects: Vec<Path> = Vec::new();
        let mut additional_objects: Vec<Path> = Vec::new();
        let mut extra_where: Option<TokenStream> = None;

        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("object_type") {
                object_type = Some(meta.value()?.parse()?);
                Ok(())
            } else if meta.path.is_ident("target_objects") {
                target_objects = parse_path_list(&meta)?;
                Ok(())
            } else if meta.path.is_ident("additional_objects") {
                additional_objects = parse_path_list(&meta)?;
                Ok(())
            } else if meta.path.is_ident("where_bounds") {
                // Parenthesised raw token group — the macro emits these
                // verbatim into the augment impl's `where` clause.
                let content;
                syn::parenthesized!(content in meta.input);
                extra_where = Some(content.parse::<TokenStream>()?);
                Ok(())
            } else {
                Err(meta.error(
                    "unknown attribute — expected `object_type`, \
                     `target_objects = [...]`, `additional_objects = [...]`, \
                     or `where_bounds(...)`",
                ))
            }
        });
        syn::parse::Parser::parse2(parser, args)?;

        Ok(Self {
            object_type,
            target_objects,
            additional_objects,
            extra_where,
        })
    }
}

/// Parse a bracketed list of paths: `[Foo::Bar, Baz::Qux]`.
fn parse_path_list(meta: &syn::meta::ParseNestedMeta) -> syn::Result<Vec<Path>> {
    let value = meta.value()?;
    let content;
    syn::bracketed!(content in value);
    let punctuated: syn::punctuated::Punctuated<Path, syn::Token![,]> =
        content.parse_terminated(Path::parse, syn::Token![,])?;
    Ok(punctuated.into_iter().collect())
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
    /// Property value lives in the struct field itself. Reads dispatch
    /// through `PropertyRead::read_property(&self.field, …)`; writes
    /// through `PropertyWrite::write_property(&mut self.field, …)`.
    Field,
    /// Virtual property — has no struct field. The annotated source field
    /// is unit-typed (`()`) and erased from the generated struct. Reads
    /// invoke the user's `read = |this| …` closure; writes invoke
    /// `write = |this, data| …`. Closures take `&Self` / `&mut Self` so
    /// they can reach any other struct field (e.g. `&'a RefCell<T>`,
    /// `&'a dyn DeviceModelNotifier`, …).
    Virtual,
}

pub(crate) struct PropertyAttrs {
    pub field_ident: syn::Ident,
    pub field_ty: syn::Type,
    pub field_span: Span,

    // Mandatory ----------------------------------------------------------
    pub pid: Path,
    /// `pdt = Foo` parses as a `Path`. For escape-hatch raw IDs the user
    /// writes `pdt_raw = 0xNN` instead — see `pdt_raw` below.
    pub pdt: Option<Path>,
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

    // Augment-only fields (None / unused on InterfaceObject impls) -------
    /// Closure invoked from `property_value_read`; signature
    /// `|this: &Self, ctx: &AugmentContext<'_, D>| -> impl PropertyRead`.
    /// Mutually exclusive with `read_fn`.
    pub read_with_ctx: Option<Expr>,
    /// Closure invoked from `property_value_write`; signature
    /// `|this: &mut Self, ctx: &AugmentContext<'_, D>, data: &[u8]| -> Result<WriteResponse, PropertyError>`.
    /// Mutually exclusive with `write_fn`.
    pub write_with_ctx: Option<Expr>,
    /// Closure invoked from `function_property_command`.
    pub function_command: Option<Expr>,
    /// Closure invoked from `function_property_state_read`.
    pub function_state_read: Option<Expr>,
    /// Raw PDT ID escape — `pdt_raw = 0x24` — for PDTs lacking a named type.
    /// When present, takes priority over `pdt` in codegen. Currently unused
    /// by any in-tree augment (kept as a documented future-proofing hatch).
    pub pdt_raw: Option<u8>,
    /// Marks a PID as having no macro-generated dispatch arm. The macro
    /// emits the descriptor entry but routes the dispatch to a user-defined
    /// fallback method (see codegen / handle_extra_pid mechanism).
    pub manual: bool,
    /// Documentation flag: PID extends a base object rather than living on
    /// an augment-owned additive object. No codegen effect today.
    pub intercepts: bool,
    /// Selects which target object this PID belongs to, when the augment
    /// declares multiple `target_objects`. Defaults to the single declared
    /// target when there's only one.
    pub target: Option<Path>,
}

impl PropertyAttrs {
    /// Returns `Ok(None)` for non-property struct fields (no `#[io(...)]`),
    /// `Ok(Some(_))` for property fields, and `Err` for malformed metadata.
    pub fn from_field(field: &Field) -> syn::Result<Option<Self>> {
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
            // Plain struct field — kept verbatim by codegen.
            return Ok(None);
        }

        let mut pid: Option<Path> = None;
        let mut pdt: Option<Path> = None;
        let mut access: Option<Access> = None;
        let mut policy: Option<Expr> = None;
        let mut rl: Option<u8> = None;
        let mut wl: Option<u8> = None;
        let mut array_max: Option<u16> = None;
        let mut computed_max: Option<Expr> = None;
        let mut read_fn: Option<Expr> = None;
        let mut write_fn: Option<Expr> = None;
        let mut default_value: Option<Expr> = None;
        let mut read_with_ctx: Option<Expr> = None;
        let mut write_with_ctx: Option<Expr> = None;
        let mut function_command: Option<Expr> = None;
        let mut function_state_read: Option<Expr> = None;
        let mut pdt_raw: Option<u8> = None;
        let mut manual: bool = false;
        let mut intercepts: bool = false;
        let mut target: Option<Path> = None;

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
                } else if key.is_ident("read") {
                    read_fn = Some(meta.value()?.parse()?);
                } else if key.is_ident("write") {
                    write_fn = Some(meta.value()?.parse()?);
                } else if key.is_ident("default") {
                    default_value = Some(meta.value()?.parse()?);
                } else if key.is_ident("read_with_ctx") {
                    read_with_ctx = Some(meta.value()?.parse()?);
                } else if key.is_ident("write_with_ctx") {
                    write_with_ctx = Some(meta.value()?.parse()?);
                } else if key.is_ident("function_command") {
                    function_command = Some(meta.value()?.parse()?);
                } else if key.is_ident("function_state_read") {
                    function_state_read = Some(meta.value()?.parse()?);
                } else if key.is_ident("pdt_raw") {
                    let lit: syn::LitInt = meta.value()?.parse()?;
                    pdt_raw = Some(lit.base10_parse()?);
                } else if key.is_ident("manual") {
                    // Bare flag: `manual` (no `= ...` value).
                    manual = true;
                } else if key.is_ident("intercepts") {
                    // Bare flag.
                    intercepts = true;
                } else if key.is_ident("target") {
                    target = Some(meta.value()?.parse()?);
                } else {
                    return Err(meta.error("unknown #[io(...)] field attribute"));
                }
                Ok(())
            })?;
        }

        // Mandatory checks: each missing attribute gets its own error pointing
        // at the field, so the user can fix all of them in one pass.
        let pid = require(pid, field_span, "pid")?;
        let access = require(access, field_span, "access")?;
        let policy = require(policy, field_span, "policy")?;
        // PDT is mandatory but accepts either `pdt = TypeName` or
        // `pdt_raw = 0xNN` (escape hatch for PDTs without a named type).
        if pdt.is_none() && pdt_raw.is_none() {
            return Err(syn::Error::new(
                field_span,
                "missing required #[io(pdt = ...)] (or `pdt_raw = 0xNN` for PDTs without a named type)",
            ));
        }
        if pdt.is_some() && pdt_raw.is_some() {
            return Err(syn::Error::new(
                field_span,
                "`pdt` and `pdt_raw` are mutually exclusive",
            ));
        }

        // Cross-field consistency:
        // - `array(max=N)` and `computed_max=...` are mutually exclusive
        // - `backing = state` requires `read_fn`; `write_fn` only if access != RO
        if array_max.is_some() && computed_max.is_some() {
            return Err(syn::Error::new(
                field_span,
                "`array(max = ...)` and `computed_max = ...` are mutually exclusive",
            ));
        }
        // Determine backing from the field type and the presence of closures.
        // A unit-typed (`()`) field signals a virtual property; the macro
        // strips it from the generated struct and dispatches via the user's
        // `read`/`write` closures. Anything else is a real struct field whose
        // type implements `PropertyRead`/`PropertyWrite`.
        let is_unit = matches!(&field.ty, syn::Type::Tuple(t) if t.elems.is_empty());
        let backing = if is_unit { Backing::Virtual } else { Backing::Field };
        // Virtual property requires *some* dispatch attached to it. RO with a
        // `function_command` / `function_state_read` is fine (function-property
        // only properties have no value reads). WO is fine because it has no
        // read at all. Otherwise we need a read closure.
        let has_function = function_command.is_some() || function_state_read.is_some();
        if matches!(backing, Backing::Virtual)
            && read_fn.is_none()
            && read_with_ctx.is_none()
            && !matches!(access, Access::Wo)
            && !has_function
            && !manual
        {
            return Err(syn::Error::new(
                field_span,
                "virtual property (unit-typed field) requires `read = |this| ...`, \
                 `read_with_ctx = ...`, `function_command = ...`, `manual`, or `access = WO`",
            ));
        }
        if matches!(backing, Backing::Field) && (read_fn.is_some() || write_fn.is_some()) {
            return Err(syn::Error::new(
                field_span,
                "non-unit field cannot have `read`/`write` closures — \
                 use a unit-typed (`()`) field for virtual properties",
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

        // `read` / `read_with_ctx` and `write` / `write_with_ctx` are
        // mutually exclusive: a property has at most one read closure
        // (with or without `ctx`) and at most one write closure.
        if read_fn.is_some() && read_with_ctx.is_some() {
            return Err(syn::Error::new(
                field_span,
                "`read` and `read_with_ctx` are mutually exclusive",
            ));
        }
        if write_fn.is_some() && write_with_ctx.is_some() {
            return Err(syn::Error::new(
                field_span,
                "`write` and `write_with_ctx` are mutually exclusive",
            ));
        }

        Ok(Some(Self {
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
            read_with_ctx,
            write_with_ctx,
            function_command,
            function_state_read,
            pdt_raw,
            manual,
            intercepts,
            target,
        }))
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
