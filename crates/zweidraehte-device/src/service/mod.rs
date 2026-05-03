//! Unified service abstractions: [`Layer`], [`ApciHandler`], [`Augment`].
//!
//! Three focused traits — each one owns a single responsibility:
//!
//! - [`Layer`] — wire-message handlers (NL / TL / AL / SecureAL). Holds
//!   `&mut self` for plain-field state, plus its own lifecycle methods
//!   (`init` / `poll` / `next_deadline`).
//! - [`ApciHandler`] — APCI fall-through extensions composed into the
//!   AL via [`StackDefinition::Services`](crate::StackDefinition::Services).
//!   `&self`, no lifecycle.
//! - [`Augment`] — interface-object property hooks plus optional
//!   IO-list contribution. `&self` for hooks, opt-in `&mut self`
//!   lifecycle for augments with temporal behaviour (Security rekey
//!   timer, Diagnostics auto-revert).
//!
//! All three share [`ServiceCtx`] — a single context type covering
//! state, IO objects, memory map, layer-context (outbox / buffer
//! manager / channels), and the request's [`AccessContext`].
//!
//! # Coexistence with the legacy `Layer` trait
//!
//! Wire-message handlers (NL/TL/AL/SecureAL) currently implement
//! both this module's [`Layer`] trait and the older
//! [`router::Layer`](crate::router::Layer) trait so the runner can
//! pick either dispatch path. Once the runner switches to the new
//! [`LayerRegistry`]-driven dispatch, the old `router::Layer` trait
//! and its `LayerStack` machinery delete.

mod apci_tuple;
mod ctx;
mod registry;
mod traits;

pub use ctx::ServiceCtx;
pub use registry::{AugmentRegistry, LayerRegistry};
pub use traits::{ApciHandler, Augment, Layer};

/// Derive [`LayerRegistry<D>`] and [`AugmentRegistry<D>`] for a
/// device's services struct from `#[service(handler | augment)]`
/// field annotations. See the macro documentation for usage.
pub use zweidraehte_device_macros::ServiceRegistry;

/// Generate an [`Augment<D>`] impl that forwards to a type's
/// existing [`InterfaceObjectAugment<D>`](crate::objects::interface::InterfaceObjectAugment) body.
///
/// During the migration to the new trait surface, every system-B
/// augment uses this to gain a parallel `Augment` impl with zero
/// behaviour change. The shim builds a transient
/// [`AugmentContext`](crate::objects::interface::AugmentContext)
/// from the new [`ServiceCtx`] and dispatches through the legacy
/// trait. Once every consumer has moved to the new trait,
/// `InterfaceObjectAugment` deletes and each augment's body folds
/// into a direct `Augment` impl.
///
/// # Forms
///
/// All invocations specify the augment's own impl-generic
/// parameters in square brackets (possibly empty), then the
/// concrete `Self` type, then an optional `where` clause. Square
/// brackets sidestep the macro_rules `:ty` / angle-bracket parsing
/// ambiguity.
///
/// ```rust,ignore
/// // No augment-side generics, no extra bounds:
/// augment_via_interface_object_augment!([], MyAug);
///
/// // Augment-side generics + bounds:
/// augment_via_interface_object_augment!(
///     ['a, S, const N: usize], MyAug<'a, S, N>,
///     where S: HasSomething,
/// );
/// ```
///
/// The bracketed list is spliced verbatim into the emitted
/// `impl<D, …augment-params…>` block; the `where` predicates land
/// on that impl alongside the standard `D: StackDefinition` and
/// `Self: InterfaceObjectAugment<D>` bounds.
#[macro_export]
macro_rules! augment_via_interface_object_augment {
    // Square-bracket-delimited augment-side generics + the `Self`
    // type + optional `where`. The brackets sidestep the
    // macro_rules `:ty` / angle-bracket ambiguity that arises when
    // trying to splice `$($g:tt)*` between the start of a `:ty` and
    // the comma that follows.
    ([], $self_ty:ty $(,)?) => {
        $crate::augment_via_interface_object_augment!(@impl_no_generics $self_ty, where);
    };
    ([], $self_ty:ty, where $($extra:tt)*) => {
        $crate::augment_via_interface_object_augment!(@impl_no_generics $self_ty, where $($extra)*);
    };
    ([$($g:tt)*], $self_ty:ty $(,)?) => {
        $crate::augment_via_interface_object_augment!(@impl [$($g)*] $self_ty, where);
    };
    ([$($g:tt)*], $self_ty:ty, where $($extra:tt)*) => {
        $crate::augment_via_interface_object_augment!(@impl [$($g)*] $self_ty, where $($extra)*);
    };
    // Internal: no augment-side generics → emit `impl<D>` directly
    // without a leading empty parameter list.
    (@impl_no_generics $self_ty:ty, where $($extra:tt)*) => {
        $crate::augment_via_interface_object_augment!(@impl_body
            impl_decl: { impl<D> },
            self_ty:   { $self_ty },
            extra:     { $($extra)* }
        );
    };
    // Internal: with augment-side generics. Splice them in front of
    // `D` so any user-supplied lifetimes precede the type parameters,
    // satisfying Rust's lifetimes-before-types ordering rule.
    (@impl [$($g:tt)*] $self_ty:ty, where $($extra:tt)*) => {
        $crate::augment_via_interface_object_augment!(@impl_body
            impl_decl: { impl<$($g)*, D> },
            self_ty:   { $self_ty },
            extra:     { $($extra)* }
        );
    };
    // Internal: emit the actual trait impl body. The two `@impl*`
    // arms above differ only in the `impl<…>` declaration; everything
    // else lives here once.
    (@impl_body
        impl_decl: { $($impl_decl:tt)* },
        self_ty:   { $self_ty:ty },
        extra:     { $($extra:tt)* }
    ) => {
        $($impl_decl)* $crate::service::Augment<D> for $self_ty
        where
            D: $crate::StackDefinition,
            Self: $crate::objects::interface::InterfaceObjectAugment<D>,
            $($extra)*
        {
            #[inline]
            fn additional_object_count(&self) -> u16 {
                <Self as $crate::objects::interface::InterfaceObjectAugment<D>>::additional_object_count(self)
            }

            #[inline]
            fn additional_object_type_at(
                &self,
                index: u16,
            ) -> ::core::option::Option<::zweidraehte_proto::dpt::InterfaceObjectType> {
                <Self as $crate::objects::interface::InterfaceObjectAugment<D>>::additional_object_type_at(self, index)
            }

            #[inline]
            fn get_property_descriptor(
                &self,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                prop_id: u16,
            ) -> ::core::option::Option<$crate::objects::interface::PropertyDescriptor> {
                <Self as $crate::objects::interface::InterfaceObjectAugment<D>>::get_property_descriptor(
                    self, object_type, prop_id,
                )
            }

            #[inline]
            fn property_description_read(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                object_idx: u16,
                lookup: $crate::objects::interface::PropertyLookup,
            ) -> ::core::option::Option<::core::result::Result<
                $crate::objects::interface::PropertyDescriptionResponse,
                $crate::objects::interface::PropertyError,
            >> {
                let legacy = $crate::objects::interface::AugmentContext::<'_, D>::from_service_ctx(ctx);
                <Self as $crate::objects::interface::InterfaceObjectAugment<D>>::property_description_read(
                    self, &legacy, object_type, object_idx, lookup,
                )
            }

            #[inline]
            fn property_value_read(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &$crate::objects::interface::FullPropertyReadRequest,
                buf: &mut [u8],
            ) -> ::core::option::Option<::core::result::Result<usize, $crate::objects::interface::PropertyError>> {
                let legacy = $crate::objects::interface::AugmentContext::<'_, D>::from_service_ctx(ctx);
                <Self as $crate::objects::interface::InterfaceObjectAugment<D>>::property_value_read(
                    self, &legacy, object_type, req, buf,
                )
            }

            #[inline]
            fn property_value_write(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &$crate::objects::interface::FullPropertyWriteRequest<'_>,
            ) -> ::core::option::Option<::core::result::Result<
                $crate::objects::interface::WriteResponse,
                $crate::objects::interface::PropertyError,
            >> {
                let legacy = $crate::objects::interface::AugmentContext::<'_, D>::from_service_ctx(ctx);
                <Self as $crate::objects::interface::InterfaceObjectAugment<D>>::property_value_write(
                    self, &legacy, object_type, req,
                )
            }

            #[inline]
            fn function_property_command(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &$crate::objects::interface::FunctionPropertyRequest<'_>,
            ) -> ::core::option::Option<$crate::objects::interface::FunctionPropertyResult> {
                let legacy = $crate::objects::interface::AugmentContext::<'_, D>::from_service_ctx(ctx);
                <Self as $crate::objects::interface::InterfaceObjectAugment<D>>::function_property_command(
                    self, &legacy, object_type, req,
                )
            }

            #[inline]
            fn function_property_state_read(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &$crate::objects::interface::FunctionPropertyRequest<'_>,
            ) -> ::core::option::Option<$crate::objects::interface::FunctionPropertyResult> {
                let legacy = $crate::objects::interface::AugmentContext::<'_, D>::from_service_ctx(ctx);
                <Self as $crate::objects::interface::InterfaceObjectAugment<D>>::function_property_state_read(
                    self, &legacy, object_type, req,
                )
            }

            // `next_deadline` and `poll` keep their `Augment` defaults
            // (no timer, no-op poll). The legacy `InterfaceObjectAugment`
            // trait has no lifecycle methods to forward to.
        }
    };
}

#[cfg(test)]
mod derive_smoke;
