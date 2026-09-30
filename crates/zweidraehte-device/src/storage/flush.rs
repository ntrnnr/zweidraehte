//! The router's hook for write-through configuration storage.
//!
//! A device whose storage handle keeps its configuration in an
//! [`NvStore`](zweidraehte_nv::NvStore) persists every change before the
//! response to it leaves the device: the router asks the handle to flush
//! after dispatch, ahead of each frame it passes to the link layer (see
//! `runner.rs`). A handle without a configuration store (`()`, test
//! fixtures) keeps [`ENABLED`](ConfigFlush::ENABLED) false, and the router
//! and storage-task code compiles away.

use crate::storage::definition::NoStore;
use crate::storage::{ConfigStorage, SecureIpStorage, SecureStorage};

/// Write-through persistence of a device state, driven by the router.
pub trait ConfigFlush<State> {
    /// Whether this handle persists through [`flush_config`](Self::flush_config).
    /// While false neither the router nor the storage task calls it, and the
    /// state's dirty flag is never cleared.
    const ENABLED: bool = false;

    /// Make every pending change of `state` durable. `Err` leaves the
    /// changes pending; the router retries on its next pass.
    // The router only needs "not persisted": it counts the failure and
    // retries. The medium's own error stays with the store.
    #[allow(clippy::result_unit_err)]
    fn flush_config(&self, _state: &State) -> Result<(), ()> {
        Ok(())
    }

    /// Whether the store would like a [`compact`](Self::compact) soon. The
    /// storage task checks it on every tick and compacts under its
    /// `SaveGuard`, so the long flash operation happens with the bus held
    /// busy rather than inside a later flush.
    fn needs_compaction(&self) -> bool {
        false
    }

    /// Rewrite the whole of `state` and drop the store's history.
    #[allow(clippy::result_unit_err)]
    fn compact(&self, _state: &State) -> Result<(), ()> {
        Ok(())
    }
}

/// Forward every `ConfigFlush` item to `$inner`.
macro_rules! forward_config_flush {
    ($inner:ident => |$this:ident| $target:expr) => {
        const ENABLED: bool = $inner::ENABLED;

        fn flush_config(&self, state: &State) -> Result<(), ()> {
            let $this = self;
            $target.flush_config(state)
        }

        fn needs_compaction(&self) -> bool {
            let $this = self;
            $target.needs_compaction()
        }

        fn compact(&self, state: &State) -> Result<(), ()> {
            let $this = self;
            $target.compact(state)
        }
    };
}

// A device's storage handle is a `&'static` to its stores struct, so the
// capability forwards through the reference, as the other capabilities do.
impl<T: ConfigFlush<State>, State> ConfigFlush<State> for &T {
    forward_config_flush!(T => |this| (**this));
}

// The stores structs flush through their config store: write-through with
// an `NvConfig`, compiled away with `NoStore`. The bound names only
// the config field, as the structs' other capabilities do (see
// `SecureStorage`), and `State` stays free for the same reason.
impl<C: ConfigFlush<State>, State> ConfigFlush<State> for ConfigStorage<C> {
    forward_config_flush!(C => |this| this.config.borrow());
}

impl<C: ConfigFlush<State>, S, State> ConfigFlush<State> for SecureStorage<C, S> {
    forward_config_flush!(C => |this| this.config.borrow());
}

impl<C: ConfigFlush<State>, S, M, State> ConfigFlush<State> for SecureIpStorage<C, S, M> {
    forward_config_flush!(C => |this| this.config.borrow());
}

// The storage-less `()` and the `NoStore` sentinel: nothing to flush.
impl<State> ConfigFlush<State> for () {}
impl<State> ConfigFlush<State> for NoStore {}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::Cell;

    use embassy_futures::select::{Either, select};
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::channel::Channel;
    use std::boxed::Box;
    use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};
    use zweidraehte_proto::messages::buffers::BufferManager;
    use zweidraehte_proto::messages::knx::ServiceType;

    use super::ConfigFlush;
    use crate::bcus::system_b::{SystemBStateInit, Tp1};
    use crate::layers::linklayers::mock::{CapturedLinkLayerMessage, InjectedFrame, MockLinkLayerBuilder};
    use crate::objects::comm::NoComObjects;
    use crate::storage::StaticIdentity;
    use crate::{DeviceDefinition, NoParams, StackResources};

    const DEVICE: DeviceDescriptor =
        DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00FA, [0; 6], 0xF001, 0x01, 1, 1, 1, 0);

    type Capture = Channel<NoopRawMutex, CapturedLinkLayerMessage, 4>;

    /// Write-through enabled; records how many frames the link layer had
    /// already taken when the first flush ran.
    struct FlushProbe {
        capture: &'static Capture,
        captured_at_first_flush: Cell<Option<usize>>,
    }

    impl<S> ConfigFlush<S> for FlushProbe {
        const ENABLED: bool = true;

        fn flush_config(&self, _state: &S) -> Result<(), ()> {
            if self.captured_at_first_flush.get().is_none() {
                self.captured_at_first_flush.set(Some(self.capture.len()));
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct TestDefinition;

    impl DeviceDefinition for TestDefinition {
        type Buffers = BufferManager<4>;
        const DEVICE: &'static DeviceDescriptor = &DEVICE;

        type Params = NoParams;
        type ComObjects = NoComObjects;
        type LinkLayer = MockLinkLayerBuilder<1, 4>;
        type Storage = &'static FlushProbe;
    }

    type TestStack = Tp1<TestDefinition>;

    /// A_DeviceDescriptor_Read, connectionless, from 1.1.1 to the factory
    /// address 15.15.255: TP1 frame without checksum.
    const DEVICE_DESCRIPTOR_READ: [u8; 8] = [0xBC, 0x11, 0x01, 0xFF, 0xFF, 0x61, 0x03, 0x00];

    /// A pending change is flushed before the response to the frame that
    /// arrives next reaches the link layer.
    ///
    /// The runner and this test are polled as one task, so what the test
    /// sees afterwards cannot tell a flush before the send from one at the
    /// end of the dispatch pass. The probe looks at the capture channel from
    /// inside the flush instead: before the send it is still empty.
    #[test]
    fn the_router_flushes_before_the_response_reaches_the_link_layer() {
        let resources = Box::leak(Box::new(StackResources::<TestStack>::new()));
        let injection = Box::leak(Box::new(Channel::<NoopRawMutex, InjectedFrame, 1>::new()));
        let capture: &'static Capture = Box::leak(Box::new(Channel::new()));
        let probe: &'static FlushProbe =
            Box::leak(Box::new(FlushProbe { capture, captured_at_first_flush: Cell::new(None) }));
        let (link, handle) = MockLinkLayerBuilder::with_capture(injection, capture);
        let (stack, runner) = crate::new(
            resources,
            link,
            SystemBStateInit::new(StaticIdentity::new([0; 6])),
            (),
            TestStack::memory_map(),
            probe,
        );

        stack.state().mark_dirty();

        embassy_futures::block_on(async {
            let driver = async {
                handle.inject_bytes(&DEVICE_DESCRIPTOR_READ).await;
                loop {
                    let message = handle.receive_captured().await.expect("capture enabled");
                    if message.service_type == ServiceType::L_Data_Req {
                        return;
                    }
                }
            };
            match select(runner.run(), driver).await {
                Either::Second(()) => {}
            }
        });

        assert_eq!(
            probe.captured_at_first_flush.get(),
            Some(0),
            "the response reached the link layer before the pending change was flushed"
        );
        assert!(!stack.state().is_dirty(), "a successful flush clears the dirty flag");
    }
}
