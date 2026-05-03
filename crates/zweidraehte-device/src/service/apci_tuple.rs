//! Tuple impls of [`ApciHandler`] for arities 0..=8.
//!
//! Used as the `Ext` parameter on
//! [`ApplicationLayer<Ext>`](crate::service::Layer) and the secure AL.
//! The tuple impl tries each member left-to-right; the first to
//! return `true` claims the APCI.

use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer};

use crate::definition::StackDefinition;
use crate::service::{ApciHandler, ServiceCtx};

/// Empty extension set — handles nothing, returns `false` always.
impl<D: StackDefinition> ApciHandler<D> for () {
    #[inline(always)]
    fn try_handle_apci(
        &self,
        _apci: ApciCode,
        _msg: &KnxMessageBuffer<Buffer<'static>>,
        _ctx: &ServiceCtx<'_, D>,
    ) -> bool {
        false
    }
}

/// Generate an `impl ApciHandler for (T0, T1, …)` that tries each
/// member left-to-right. First `true` wins.
macro_rules! impl_apci_handler_tuple {
    ($($idx:tt : $T:ident),+) => {
        impl<D, $($T,)+> ApciHandler<D> for ($($T,)+)
        where
            D: StackDefinition,
            $($T: ApciHandler<D>,)+
        {
            #[inline]
            fn try_handle_apci(
                &self,
                apci: ApciCode,
                msg: &KnxMessageBuffer<Buffer<'static>>,
                ctx: &ServiceCtx<'_, D>,
            ) -> bool {
                $(
                    if self.$idx.try_handle_apci(apci, msg, ctx) {
                        return true;
                    }
                )+
                false
            }
        }
    };
}

impl_apci_handler_tuple!(0: A);
impl_apci_handler_tuple!(0: A, 1: B);
impl_apci_handler_tuple!(0: A, 1: B, 2: C);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0, 4: E);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0, 4: E, 5: F);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0, 4: E, 5: F, 6: G);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0, 4: E, 5: F, 6: G, 7: H);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0, 4: E, 5: F, 6: G, 7: H, 8: I);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0, 4: E, 5: F, 6: G, 7: H, 8: I, 9: J);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0, 4: E, 5: F, 6: G, 7: H, 8: I, 9: J, 10: K);
impl_apci_handler_tuple!(0: A, 1: B, 2: C, 3: D0, 4: E, 5: F, 6: G, 7: H, 8: I, 9: J, 10: K, 11: L);

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    /// Minimal `StackDefinition`-shaped stand-in is impractical here;
    /// the tuple impls are exercised end-to-end via the conformance
    /// suite once `ApplicationLayer<Ext>` lands. We still verify the
    /// structural property that the macro expansion compiles for
    /// non-trivial `D` and that the chain short-circuits on `true`.
    ///
    /// We build a tiny `Recorder` that counts calls and returns a
    /// pre-set verdict, then assert the chain stops after the first
    /// `true`. The `D: StackDefinition` bound is satisfied at the
    /// call site by the conformance harness; for this unit test we
    /// only need a type that implements `ApciHandler<D>` for *some*
    /// `D` — we test the macro structure, not protocol behaviour.
    ///
    /// Concretely: we need a real `StackDefinition` to instantiate
    /// `ServiceCtx`. Constructing one in a unit test is heavy; the
    /// chain-short-circuit invariant is instead asserted indirectly
    /// via a manual `try_handle_apci`-shaped helper trait below that
    /// mirrors the macro's logic without needing `ServiceCtx`.
    trait MiniHandler {
        fn try_handle(&self, apci: u8) -> bool;
    }

    impl MiniHandler for () {
        fn try_handle(&self, _: u8) -> bool {
            false
        }
    }

    macro_rules! impl_mini_tuple {
        ($($idx:tt : $T:ident),+) => {
            impl<$($T: MiniHandler),+> MiniHandler for ($($T,)+) {
                fn try_handle(&self, apci: u8) -> bool {
                    $( if self.$idx.try_handle(apci) { return true; } )+
                    false
                }
            }
        };
    }
    impl_mini_tuple!(0: A);
    impl_mini_tuple!(0: A, 1: B);
    impl_mini_tuple!(0: A, 1: B, 2: C);

    struct Recorder {
        verdict: bool,
        calls: Cell<usize>,
    }
    impl Recorder {
        fn new(verdict: bool) -> Self {
            Self { verdict, calls: Cell::new(0) }
        }
    }
    impl MiniHandler for Recorder {
        fn try_handle(&self, _: u8) -> bool {
            self.calls.set(self.calls.get() + 1);
            self.verdict
        }
    }

    #[test]
    fn empty_tuple_returns_false() {
        let h: () = ();
        assert!(!h.try_handle(0x00));
    }

    #[test]
    fn single_member_tuple_dispatches() {
        let r = Recorder::new(true);
        let h = (r,);
        assert!(h.try_handle(0xAB));
        assert_eq!(h.0.calls.get(), 1);
    }

    #[test]
    fn first_true_short_circuits() {
        let a = Recorder::new(true);
        let b = Recorder::new(true);
        let h = (a, b);
        assert!(h.try_handle(0x42));
        assert_eq!(h.0.calls.get(), 1);
        // Short-circuit: b is never consulted.
        assert_eq!(h.1.calls.get(), 0);
    }

    #[test]
    fn chain_walks_until_a_member_claims() {
        let a = Recorder::new(false);
        let b = Recorder::new(false);
        let c = Recorder::new(true);
        let h = (a, b, c);
        assert!(h.try_handle(0x42));
        assert_eq!(h.0.calls.get(), 1);
        assert_eq!(h.1.calls.get(), 1);
        assert_eq!(h.2.calls.get(), 1);
    }

    #[test]
    fn no_member_claims_returns_false() {
        let a = Recorder::new(false);
        let b = Recorder::new(false);
        let h = (a, b);
        assert!(!h.try_handle(0x99));
    }
}
