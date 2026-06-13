//! Persistent shared runtime infrastructure for all layers.
//!
//! [`LayerContext`] holds the outbox, buffer manager, and inter-component
//! channels that layers and augments need during message processing. It
//! lives in [`StackResources`](crate::StackResources) and is passed
//! directly to layers at construction time.

use core::cell::RefCell;

use embassy_sync::{
    channel::Channel,
    pubsub::{PubSubBehavior, PubSubChannel},
};

use crate::{
    actor::Request,
    definition::StackDefinition,
    layers::application::{ApplicationLayerService, ApplicationLayerServiceResponse, group_data::GroupDataState},
    lifecycle::LifecycleEvent,
    objects::comm::{ComObjectEvent, ComObjects},
    persist::PersistRequest,
    restart,
    router::Outbox,
};
use zweidraehte_proto::messages::{
    buffers::{Buffer, DynBufferManager},
    knx::KnxMessageBuffer,
};

// ============================================================================
// LayerContext
// ============================================================================

/// Shared runtime infrastructure for the KNX protocol stack — the
/// outbox, buffer manager, and inter-component channels.
///
/// Despite the name, this serves more than the protocol layers: augments,
/// the IO container, per-call [`ServiceCtx`](crate::service::ServiceCtx)
/// bundles, and the user-facing [`Stack`](crate::Stack) handle all hold a
/// reference to it. It is completely decoupled from `StackState` and is
/// created *before* the state (see [`new()`](crate::new)) so
/// `D::create_state` has working infrastructure from birth.
pub struct LayerContext<D: StackDefinition> {
    pub buffer_manager: DynBufferManager<'static>,
    pub outbox: RefCell<Outbox>,
    pub event_channel:
        PubSubChannel<D::Mutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 4, 1>,
    pub lifecycle_channel: PubSubChannel<D::Mutex, LifecycleEvent, 4, 4, 1>,
    pub restart_channel: Channel<D::Mutex, restart::RestartRequest, 1>,
    pub app_service_channel: Channel<D::Mutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,

    /// On-demand persistence requests towards user code's storage task.
    /// Gated requests (03/08/09 §2.2.4.2 mc_timer watermark) embed a
    /// reply the sender awaits; advisory notifications (ETS download
    /// complete) are [`Request::fire_and_forget`] — same channel, and
    /// the replier's `reply(())` is a no-op for them. Capacity 2: one
    /// gated + one advisory in flight without blocking either sender.
    pub persist_channel: Channel<D::Mutex, Request<PersistRequest, ()>, 2>,

    /// Bookkeeping shared between the application layer's built-in
    /// group-data handler and the
    /// [`GroupDataProvider`](crate::layers::application::group_data::GroupDataProvider)
    /// capability used by augments. The struct holds all its fields
    /// behind [`Cell`](core::cell::Cell), so a provider built from a
    /// shared reference can still advance the state.
    pub(crate) group_data: GroupDataState,
}

impl<D: StackDefinition> LayerContext<D> {
    pub fn new(buffer_manager: DynBufferManager<'static>) -> Self {
        Self {
            buffer_manager,
            outbox: RefCell::new(Outbox::new()),
            event_channel: PubSubChannel::new(),
            lifecycle_channel: PubSubChannel::new(),
            restart_channel: Channel::new(),
            app_service_channel: Channel::new(),
            persist_channel: Channel::new(),
            group_data: GroupDataState::new(),
        }
    }
}

// ============================================================================
// Inherent helpers (outbox, event publish, restart — no trait soup)
// ============================================================================

impl<D: StackDefinition> LayerContext<D> {
    /// Push a wire message onto the outbox for the next router drain pass.
    pub fn push_outbox(&self, msg: KnxMessageBuffer<Buffer<'static>>) {
        self.outbox.borrow_mut().push(msg);
    }

    /// Publish a communication object event to subscribed user code.
    pub fn publish_event(&self, index: <<D as StackDefinition>::CO as ComObjects>::Index, event: ComObjectEvent) {
        self.event_channel.publish_immediate((index, event));
    }

    /// Try sending a restart request to user code. Returns `true` if sent.
    pub fn try_send_restart_request(&self, request: restart::RestartRequest) -> bool {
        self.restart_channel.try_send(request).is_ok()
    }

    /// Try sending an advisory (fire-and-forget) persistence
    /// notification to user code. Returns `true` if sent. Losing one
    /// (channel full) is acceptable — the dirty flag still gets the
    /// data saved on the next poll/restart.
    pub fn try_send_persist_request(&self, request: PersistRequest) -> bool {
        self.persist_channel.try_send(Request::fire_and_forget(request)).is_ok()
    }
}
