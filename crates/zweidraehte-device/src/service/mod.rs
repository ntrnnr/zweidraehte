//! Unified service abstractions: [`Layer`], [`ApciHandler`],
//! [`Augment`].
//!
//! Three focused traits — each one owns a single responsibility:
//!
//! - [`Layer`] — wire-message handlers (NL / TL / AL / SecureAL). Holds
//!   `&mut self` for plain-field state, plus its own lifecycle methods
//!   (`init` / `poll` / `next_deadline`).
//! - [`ApciHandler`] — APCI fall-through extensions composed into the
//!   AL via [`StackDefinition::Services`](crate::StackDefinition::Services).
//!   `&self`, no lifecycle.
//! - [`Augment`] — interface-object property hooks plus
//!   optional IO-list contribution. Used both for individual augments
//!   (e.g. `IpAugment`, `SecurityAugment`) and for the aggregating
//!   bundle on a services struct. All methods carry sensible defaults
//!   so leaf augments override only the hooks they actually service;
//!   `&self` for hooks, opt-in `&mut self` lifecycle for augments
//!   with temporal behaviour (Security rekey timer, Diagnostics
//!   auto-revert).
//!
//! All three share [`ServiceCtx`] — a single context type covering
//! state, IO objects, memory map, layer-context (outbox / buffer
//! manager / channels), and the request's [`AccessContext`].
//!

mod apci_tuple;
mod ctx;
mod registry;
mod traits;

pub use ctx::{AlCtx, ServiceCtx};
pub use registry::{LayerRegistry, LifecycleHook};
pub use traits::{ApciHandler, Augment, Layer};

/// Derive [`LayerRegistry<D>`] and [`Augment<D>`] for a
/// device's services struct from `#[service(handler | augment)]`
/// field annotations. See the macro documentation for usage.
pub use zweidraehte_device_macros::ServiceRegistry;

#[cfg(test)]
mod derive_smoke;
