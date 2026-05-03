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

pub use ctx::{AlCtx, ServiceCtx};
pub use registry::{AugmentRegistry, LayerRegistry};
pub use traits::{ApciHandler, Augment, Layer};

/// Derive [`LayerRegistry<D>`] and [`AugmentRegistry<D>`] for a
/// device's services struct from `#[service(handler | augment)]`
/// field annotations. See the macro documentation for usage.
pub use zweidraehte_device_macros::ServiceRegistry;


#[cfg(test)]
mod derive_smoke;
