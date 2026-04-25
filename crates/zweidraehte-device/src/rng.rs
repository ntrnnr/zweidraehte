//! Cryptographic byte source for KNX Data Secure.
//!
//! [`Rng`] is implemented on a ZST and plugged into the stack via
//! [`StackDefinition::Rng`](crate::StackDefinition::Rng). It is
//! stateless by design: both real implementations (libc `getrandom`,
//! `critical_section`-guarded PRNG statics) are ambient globals, so
//! threading `&self` would force a fabricated singleton that buys
//! nothing.
//!
//! Non-secure stacks inherit the [`NoRng`] default and never call
//! into it. The secure composition builder forbids [`NoRng`] via the
//! [`SecureRng`] marker, so forgetting to set
//! `type Rng = …` on a secure [`StackDefinition`](crate::StackDefinition)
//! is a compile-time error rather than a runtime panic on the first
//! `S-A_Sync`.

/// Random byte source used by the Secure Application Layer to fill
/// `S-A_Sync` challenge and nonce buffers.
///
/// Implementations must produce cryptographically suitable bytes.
/// Firmware targets without a hardware TRNG should document their
/// entropy source and its limitations at the impl site.
pub trait Rng {
    /// Fill `buf` with random bytes.
    fn fill(buf: &mut [u8]);
}

/// Marker trait gating the secure composition builder.
///
/// Implemented by every real [`Rng`] but *not* by [`NoRng`], so the
/// `where D::Rng: SecureRng` bound on
/// [`SecureDeviceBuilder`](crate::SecureDeviceBuilder) rejects stack
/// definitions that never overrode the default.
pub trait SecureRng: Rng {}

/// Default [`Rng`] for non-secure stacks.
///
/// Panics if `fill` is ever invoked. The secure builder's
/// [`SecureRng`] bound prevents this from happening in well-formed
/// stacks; a panic here therefore indicates a misconfigured stack
/// that bypassed the builder, not a runtime condition to handle.
pub struct NoRng;

impl Rng for NoRng {
    fn fill(_buf: &mut [u8]) {
        panic!("StackDefinition::Rng is NoRng — secure stacks must set a real Rng via `type Rng = …;`");
    }
}
