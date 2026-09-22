//! Shared address geometry, bit ownership, and resolved image facts.
//!
//! These values describe bytes and their meaning independently of the stage
//! that constructed them or the backend that will transfer them.

mod fingerprint;
mod ownership;
mod storage;

pub(crate) use fingerprint::{fingerprint_image, fingerprint_product};
pub use ownership::ImageOwnership;
pub use storage::{ImageLocation, ImageSegment, ImageSpace, NativeImageRegion, SparseDeviceImage};

/// Exact desired-image bytes consumed by one normalized procedure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequiredImageRange {
    pub location: ImageLocation,
    pub length: u32,
}
