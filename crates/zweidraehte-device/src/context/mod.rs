//! Stack context: trait interfaces + runtime bundles.
//!
//! This module groups three related pieces:
//!
//! - [`traits`]: small abstract trait interfaces that layers depend on
//!   (buffer management, APDU length, property service dispatch, ...).
//!   Layers declare only the traits they need, keeping them decoupled from
//!   the full [`StackDefinition`](crate::StackDefinition).
//! - [`layer`]: the persistent [`LayerContext<D>`](layer::LayerContext)
//!   runtime bundle (outbox, buffer manager, inter-component channels).
//!   Owned by [`StackResources`](crate::StackResources), passed to every
//!   layer at construction.
//! - [`stack`]: the transient [`StackContext<'a, D>`](stack::StackContext)
//!   assembled at [`Runner::run`](crate::Runner::run) scope. Bundles
//!   references to [`Inner`](crate::inner::Inner) and the interface
//!   objects for link-layer builders. See [`stack`] for why this is
//!   transient.
//!
//! Everything from `traits` is re-exported at this module's root for
//! ergonomic `crate::context::BufferManagerContext` access.

pub mod layer;
pub mod stack;
pub mod traits;

pub use layer::{HasOutbox, LayerContext};
pub use stack::StackContext;
pub use traits::*;
