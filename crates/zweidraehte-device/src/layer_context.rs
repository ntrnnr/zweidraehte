//! Persistent shared runtime infrastructure for all layers.
//!
//! [`LayerContext`] holds the outbox, buffer manager, and inter-component
//! channels that layers and augments need during message processing. It
//! lives in [`StackResources`](crate::StackResources) and is passed
//! directly to layers at construction time.

use core::cell::{Cell, RefCell};

use embassy_sync::{channel::Channel, pubsub::{PubSubChannel, PubSubBehavior}};

use crate::messages::buffers::DynBufferManager;
use crate::{
    actor::Request,
    definition::StackDefinition,
    layers::application::{
        ApplicationLayerService, ApplicationLayerServiceResponse,
        group_data::{PendingGroupSend, ReadOnInitState},
    },
    objects::comm::{ComObjectEvent, ComObjects, LifecycleEvent},
    restart,
    router::Outbox,
};

// ============================================================================
// LayerContext
// ============================================================================

/// Shared runtime infrastructure for the KNX protocol stack.
///
/// Contains message queues, event channels, buffer managers, and shared
/// group-data bookkeeping. This is completely decoupled from `StackState`.
/// Layers that need to publish events, send messages, or allocate buffers
/// take a reference to this context.
pub struct LayerContext<D: StackDefinition> {
    pub buffer_manager: DynBufferManager<'static>,
    pub outbox: RefCell<Outbox>,
    pub event_channel: PubSubChannel<D::Mutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,
    pub lifecycle_channel: PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,
    pub restart_channel: Channel<D::Mutex, restart::RestartRequest, 1>,
    pub app_service_channel: Channel<D::Mutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,

    // ------------------------------------------------------------------------
    // Group-data bookkeeping
    //
    // Shared across the application layer's built-in group-data handler and
    // the [`GroupDataProvider`](crate::layers::application::group_data::GroupDataProvider)
    // capability used by augments. Interior mutability keeps these reachable
    // via shared references so an augment running inside a property-dispatch
    // call can still request group sends.
    // ------------------------------------------------------------------------

    /// Read-on-init scan cursor. Advanced by the AL poll loop; restarted
    /// when the application transitions from stopped to running.
    pub(crate) read_on_init: Cell<ReadOnInitState>,

    /// Pending group value send awaiting TL confirmation. When populated,
    /// the next TL confirmation resolves the matching communication object
    /// status.
    pub(crate) pending_group_send: Cell<Option<PendingGroupSend>>,
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
            read_on_init: Cell::new(ReadOnInitState::Idle),
            pending_group_send: Cell::new(None),
        }
    }
}

// ============================================================================
// Context Trait Implementations
// ============================================================================

pub trait HasOutbox {
    fn push_outbox(&self, msg: crate::messages::knx::KnxMessageBuffer<crate::messages::buffers::Buffer<'static>>);
    fn push_deferred_outbox(&self, msg: crate::messages::knx::KnxMessageBuffer<crate::messages::buffers::Buffer<'static>>);
}

impl<D: StackDefinition> HasOutbox for LayerContext<D> {
    fn push_outbox(&self, msg: crate::messages::knx::KnxMessageBuffer<crate::messages::buffers::Buffer<'static>>) {
        self.outbox.borrow_mut().push(msg);
    }

    fn push_deferred_outbox(&self, msg: crate::messages::knx::KnxMessageBuffer<crate::messages::buffers::Buffer<'static>>) {
        self.outbox.borrow_mut().push_deferred(msg);
    }
}

impl<D: StackDefinition> crate::context::EventPublisherContext<<<D as StackDefinition>::CO as ComObjects>::Index> for LayerContext<D> {
    fn publish_event(&self, index: <<D as StackDefinition>::CO as ComObjects>::Index, event: ComObjectEvent) {
        self.event_channel.publish_immediate((index, event));
    }
}

impl<D: StackDefinition> crate::context::RestartPublisherContext for LayerContext<D> {
    fn try_send_restart_request(&self, request: restart::RestartRequest) -> bool {
        self.restart_channel.try_send(request).is_ok()
    }
}

impl<D: StackDefinition> crate::context::OutboxContext for LayerContext<D> {
    fn outbox(&self) -> &core::cell::RefCell<crate::router::Outbox> {
        &self.outbox
    }
}

impl<D: StackDefinition> crate::context::BufferManagerContext for LayerContext<D> {
    fn buffer_manager(&self) -> &DynBufferManager<'static> {
        &self.buffer_manager
    }
}
