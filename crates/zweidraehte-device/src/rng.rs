//! Cryptographic byte source for KNX Data Secure and IP Secure.
//!
//! [`Rng`] is implemented on a ZST and plugged into the stack via
//! [`StackDefinition::Rng`](crate::StackDefinition::Rng). Data Secure uses it
//! directly; IP Secure receives the same type through its context. It is
//! stateless by design: both real implementations (libc `getrandom`,
//! `critical_section`-guarded PRNG statics) are ambient globals, so
//! threading `&self` would force a fabricated singleton that buys
//! nothing.
//!
//! Non-secure stacks inherit the [`NoRng`] default and never call into it.
//! Every composition that needs key material — the Data Secure builders and
//! a KNX/IP link layer with IP Secure — asserts [`Rng::SECURE`] through
//! [`require_secure_rng`] or an equivalent const guard, so forgetting to set
//! `type Rng = …` on a secure [`StackDefinition`](crate::StackDefinition)
//! fails the build rather than panicking on the first `S-A_Sync` or IP
//! Secure handshake. The guards are const assertions, like the IP Secure TCP
//! rule, so they fire when the composition is monomorphized: `cargo build`
//! reports them, `cargo check` does not.

/// Random bytes for Data Secure challenges/nonces and IP Secure session
/// keys, multicast tags and delays.
///
/// Implementations must produce cryptographically suitable bytes.
/// Firmware targets without a hardware TRNG should document their
/// entropy source and its limitations at the impl site.
pub trait Rng {
    /// Whether this source may supply key material.
    ///
    /// Every real source keeps the default; only [`NoRng`] opts out, which
    /// is what the secure compositions check.
    const SECURE: bool = true;

    /// Fill `buf` with random bytes.
    fn fill(buf: &mut [u8]);
}

/// Default [`Rng`] for non-secure stacks.
///
/// Panics if `fill` is ever invoked. Secure compositions refuse to build with
/// it (see [`require_secure_rng`]); a panic indicates a stack that bypassed
/// them.
pub struct NoRng;

impl Rng for NoRng {
    const SECURE: bool = false;

    fn fill(_buf: &mut [u8]) {
        panic!("Rng is NoRng — secure stacks must set a real Rng via `type Rng = …;`");
    }
}

/// Fail the build when `R` cannot supply key material.
///
/// Call it where a secure composition is assembled for its concrete `R`.
/// A real source passes:
///
/// ```
/// use zweidraehte_device::rng::{Rng, require_secure_rng};
///
/// struct HardwareRng;
/// impl Rng for HardwareRng {
///     fn fill(buf: &mut [u8]) {
///         buf.fill(0x5A); // stand-in for a TRNG read
///     }
/// }
///
/// require_secure_rng::<HardwareRng>();
/// ```
///
/// The default [`NoRng`] does not: its `SECURE` is `false`, so the const
/// assertion fails when this call is monomorphized:
///
/// ```compile_fail
/// zweidraehte_device::rng::require_secure_rng::<zweidraehte_device::rng::NoRng>();
/// ```
pub fn require_secure_rng<R: Rng>() {
    let () = SecureRngGuard::<R>::CHECK;
}

/// Carries the assertion for [`require_secure_rng`]. An associated const is
/// evaluated once per concrete `R` when it is referenced; the crate's
/// `generic_const_exprs` does not allow the assertion in an inline `const`
/// block of a generic function.
struct SecureRngGuard<R>(core::marker::PhantomData<R>);

impl<R: Rng> SecureRngGuard<R> {
    const CHECK: () = core::assert!(
        R::SECURE,
        "secure stacks need a real random source: set `type Rng` on the device definition, not `NoRng`"
    );
}
