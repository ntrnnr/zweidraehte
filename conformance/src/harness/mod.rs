//! Test harnesses for conformance testing
//!
//! Provides infrastructure to run the full KNX stack with MockLinkLayer
//! for injecting and capturing telegrams.

pub mod mock;
pub mod stack;

pub use mock::{
    CapturedLinkLayerMessage, MockLinkLayer, MockLinkLayerBuilder, MockLinkLayerHandle,
    MockLinkLayerResources,
};
pub use stack::{ConformanceTestStack, FullStackHarness};
