//! Persistent shared runtime infrastructure for all layers.
//!
//! [`LayerContext`] holds the outbox, buffer manager, and inter-component
//! channels that layers and augments need during message processing. It
//! lives in [`StackResources`](crate::StackResources) and is referenced
//! by both the device state (via [`HasLayerContext`]) and individual layers.
//!
//! This replaces the ad-hoc parameter threading of `&mut Outbox` and
//! `&DynBufferManager` through layer function signatures.

use core::cell::RefCell;

use embassy_sync::{blocking_mutex::raw::RawMutex, channel::Channel, pubsub::PubSubChannel};

use crate::messages::buffers::DynBufferManager;
use crate::{
    actor::Request,
    definition::StackDefinition,
    layers::application::{ApplicationLayerService, ApplicationLayerServiceResponse},
    objects::comm::{ComObjectEvent, ComObjectIndex, ComObjects, LifecycleEvent},
    restart,
    router::Outbox,
};

// ============================================================================
// LayerContext
// ============================================================================

/// Shared runtime infrastructure for the KNX protocol stack.
///
/// All layers and augments access this through a shared `&LayerContext`
/// reference. The device state provides access via the [`HasLayerContext`]
/// trait, so any component with `&State` can reach these resources.
///
/// # Contents
///
/// - **Buffer manager** — allocates message buffers for outgoing telegrams
/// - **Outbox** — inter-layer message queue (layers push outgoing messages)
/// - **Event channel** — publishes communication object events to user code
/// - **Lifecycle channel** — publishes application start/stop events
/// - **Restart channel** — sends restart requests from AL to user code
/// - **App service channel** — receives GroupValue requests from user code
pub struct LayerContext<D: StackDefinition> {
    /// Buffer allocator for building outgoing messages.
    pub buffer_manager: DynBufferManager<'static>,

    /// Shared outbox — layers push outgoing messages here, the router drains.
    pub outbox: RefCell<Outbox>,

    /// Comm object event channel: AL publishes, user code subscribes.
    pub event_channel:
        PubSubChannel<D::Mutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,

    /// Lifecycle event channel: device model publishes, user code subscribes.
    pub lifecycle_channel: PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,

    /// Restart request channel: AL sends, user code receives.
    pub restart_channel: Channel<D::Mutex, restart::RestartRequest, 1>,

    /// App service channel: user code sends GroupValue requests, AL receives.
    pub app_service_channel: Channel<D::Mutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,
}

impl<D: StackDefinition> LayerContext<D> {
    /// Create a new LayerContext with the given buffer manager.
    ///
    /// The outbox starts empty. Channels are initialized with default
    /// (empty) state.
    pub fn new(buffer_manager: DynBufferManager<'static>) -> Self {
        Self {
            buffer_manager,
            outbox: RefCell::new(Outbox::new()),
            event_channel: PubSubChannel::new(),
            lifecycle_channel: PubSubChannel::new(),
            restart_channel: Channel::new(),
            app_service_channel: Channel::new(),
        }
    }
}

// ============================================================================
// HasLayerContext trait
// ============================================================================

/// Trait for device states that provide access to the layer context.
///
/// Implemented on `SystemBDeviceState` and forwarded by wrapper types.
/// Any component with `&State` can access runtime infrastructure through
/// this trait.
pub trait HasLayerContext {
    /// The stack definition type (needed for channel generics).
    type Definition: StackDefinition;

    /// Get a reference to the shared layer context.
    fn layer_context(&self) -> &LayerContext<Self::Definition>;
}
