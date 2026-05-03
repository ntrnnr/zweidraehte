//! Unified service abstractions: [`Layer`], [`ApciHandler`], [`Augment`].
//!
//! Three focused traits replace the legacy
//! [`router::Layer`](crate::router::Layer) +
//! [`AlService`](crate::layers::application::services::AlService) +
//! [`InterfaceObjectAugment`](crate::objects::interface::InterfaceObjectAugment)
//! triad. Each trait owns one responsibility:
//!
//! - [`Layer`] — wire-message handlers (NL / TL / AL / SecureAL). Holds
//!   `&mut self` for plain-field state, plus its own lifecycle methods
//!   (`init` / `poll` / `next_deadline`).
//! - [`ApciHandler`] — APCI fall-through extensions consumed inside the
//!   AL's `Ext` parameter. `&self`, no lifecycle.
//! - [`Augment`] — interface-object property hooks plus optional
//!   IO-list contribution. `&self` for hooks, opt-in `&mut self`
//!   lifecycle for augments with temporal behaviour (Security rekey
//!   timer, Diagnostics auto-revert).
//!
//! All three share [`ServiceCtx`] — a single context type covering
//! state, IO objects, memory map, layer-context (outbox / buffer
//! manager / channels), and the request's [`AccessContext`].
//!
//! # Coexistence with the legacy traits
//!
//! This module currently lives alongside the legacy `router::Layer` /
//! `AlService` / `InterfaceObjectAugment`. Migration happens layer by
//! layer; the legacy traits delete once every consumer is on the new
//! ones. Until then, you can refer to the new traits as
//! `crate::service::{Layer, ApciHandler, Augment}` to disambiguate.

mod apci_tuple;
mod ctx;
mod registry;
mod traits;

pub use ctx::ServiceCtx;
pub use registry::{AugmentRegistry, LayerRegistry};
pub use traits::{ApciHandler, Augment, Layer};
