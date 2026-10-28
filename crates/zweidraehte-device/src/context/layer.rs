//! Persistent shared runtime infrastructure for all layers.
//!
//! [`LayerContext`] holds the outbox, buffer manager, and inter-component
//! channels that layers and augments need during message processing. It
//! lives in [`StackResources`](crate::StackResources) and is passed
//! directly to layers at construction time.

use core::cell::{Cell, RefCell};

use embassy_sync::{
    channel::Channel,
    pubsub::{PubSubBehavior, PubSubChannel},
    signal::Signal,
};

use crate::buffers::{Buffer, DynBufferManager};
use crate::{
    actor::Request,
    definition::StackDefinition,
    layers::application::{ApplicationLayerService, ApplicationLayerServiceResponse, group_data::GroupDataState},
    lifecycle::LifecycleEvent,
    objects::comm::{ComObjectEvent, ComObjects},
    restart,
    router::Outbox,
};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::messages::{
    builder::{MessageBuilder, direction, state},
    knx::{ApciCode, DestinationAddress, KnxMessageBuffer, ServiceType},
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
///
/// The channel fields are `pub(crate)` on purpose. Their types spell out
/// their capacities (`PubSubChannel<.., 4, 4, 1>`, `Channel<.., 2>`), so
/// exposing them would make every capacity part of the public API and turn
/// "raise the subscriber limit" into a breaking change. Reach them through
/// the methods below and on [`Stack`](crate::Stack) instead.
pub struct LayerContext<D: StackDefinition> {
    pub(crate) buffer_manager: DynBufferManager<'static>,
    pub(crate) outbox: RefCell<Outbox>,
    pub(crate) event_channel:
        PubSubChannel<D::Mutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 4, 1>,
    pub(crate) lifecycle_channel: PubSubChannel<D::Mutex, LifecycleEvent, 4, 4, 1>,
    pub(crate) restart_channel: Channel<D::Mutex, restart::RestartRequest, 1>,
    pub(crate) app_service_channel:
        Channel<D::Mutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,

    /// Bookkeeping shared between the application layer's built-in
    /// group-data handler and the
    /// [`GroupDataProvider`](crate::layers::application::group_data::GroupDataProvider)
    /// capability used by augments. The struct holds all its fields
    /// behind [`Cell`](core::cell::Cell), so a provider built from a
    /// shared reference can still advance the state.
    pub(crate) group_data: GroupDataState,

    /// The device's storage (`()` when no stack component needs the
    /// stores — see [`StackDefinition::Storage`]).
    /// Lives here so consumers bounding on the storage capabilities (e.g.
    /// `D::Storage: HasSeqStore`) reach the stores without going through
    /// `D::State`.
    pub storage: &'static D::Storage,

    pub(crate) status: embassy_sync::watch::Watch<D::Mutex, crate::status::DeviceStatus, 4>,
    /// Failed write-through flushes (router or storage task), for status.
    pub(crate) save_failures: Cell<u32>,
    /// Raised by a flush that leaves the store asking for compaction: the
    /// storage task compacts under its guard. Its only wake-up besides a
    /// restart request.
    pub(crate) maintenance: Signal<D::Mutex, ()>,
    pub(crate) restarting: Cell<bool>,
    /// What [`new`](crate::new) found in the storage at boot, for status.
    pub(crate) loaded: Cell<zweidraehte_nv::Loaded>,
}

impl<D: StackDefinition> LayerContext<D> {
    pub fn new(buffer_manager: DynBufferManager<'static>, storage: &'static D::Storage) -> Self {
        Self {
            buffer_manager,
            outbox: RefCell::new(Outbox::new()),
            event_channel: PubSubChannel::new(),
            lifecycle_channel: PubSubChannel::new(),
            restart_channel: Channel::new(),
            app_service_channel: Channel::new(),
            group_data: GroupDataState::new(),
            storage,
            status: embassy_sync::watch::Watch::new(),
            save_failures: Cell::new(0),
            maintenance: Signal::new(),
            restarting: Cell::new(false),
            loaded: Cell::new(zweidraehte_nv::Loaded::Fresh),
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
    ///
    /// `#[must_use]` because a dropped restart request is not recoverable
    /// from elsewhere: the remote-reset server reports the failure back to
    /// the client (see `knxip::services::remote_config`), so a caller that
    /// silently ignored a `false` would strand the request.
    #[must_use = "a dropped restart request is silently lost; report or retry it"]
    pub fn try_send_restart_request(&self, request: restart::RestartRequest) -> bool {
        self.restart_channel.try_send(request).is_ok()
    }
}

// ============================================================================
// Responses
// ============================================================================
//
// Most application services answer an indication the same way: allocate a
// buffer, frame the response from the indication (which carries its priority
// and security context over), write the payload, queue it. `respond` is that
// sequence. It is generic over the payload writer and therefore instantiated
// once per call site, so everything that does not depend on the writer lives
// in `begin_response`, out of line.

/// Where a response goes, relative to the indication it answers.
#[derive(Clone, Copy)]
pub(crate) enum ResponseTarget {
    /// Back to the requester, on the request service matching the
    /// indication's.
    Requester,
    /// A broadcast to every device: the answer of the addressing services
    /// (individual address, domain address, and their serial-number
    /// variants). On the wire the destination is group address 0/0/0.
    ///
    /// `Some(service)` fixes the broadcast service (`T_Broadcast_Req` or
    /// `T_SystemBroadcast_Req`); `None` answers in the mode the request
    /// came in.
    Broadcast(Option<ServiceType>),
}

impl<D: StackDefinition> LayerContext<D> {
    /// Answer `ind` with an `apci` response of `len` frame octets, whose
    /// payload `write` fills in, and queue it.
    ///
    /// Without a free buffer the response is dropped with a warning — the
    /// requester's retry is the recovery, as for a lost frame.
    pub(crate) fn respond(
        &self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        apci: ApciCode,
        len: usize,
        write: impl FnOnce(&mut [u8]),
    ) {
        self.respond_to(ind, ResponseTarget::Requester, apci, len, write);
    }

    /// [`respond`](Self::respond), addressed to `target`.
    pub(crate) fn respond_to(
        &self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        target: ResponseTarget,
        apci: ApciCode,
        len: usize,
        write: impl FnOnce(&mut [u8]),
    ) {
        if let Some(builder) = self.begin_response(ind, target, apci, len) {
            self.push_outbox(builder.with_data(write).into_inner());
        }
    }

    /// Allocate and frame a response; everything of
    /// [`respond_to`](Self::respond_to) but the payload.
    ///
    /// `respond_to` inherits the indication's security stamps (level,
    /// tool-access flag, TL sequence), so the Secure Application Layer wraps
    /// the response as it unwrapped the request — a broadcast target
    /// overrides only service and destination.
    #[inline(never)]
    fn begin_response(
        &self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        target: ResponseTarget,
        apci: ApciCode,
        len: usize,
    ) -> Option<MessageBuilder<Buffer<'static>, direction::Request, state::ApplicationRequest>> {
        let Some(buffer) = self.buffer_manager.try_alloc_with_size(len) else {
            warn!("AL no buffer for {:?}", apci);
            return None;
        };

        let mut builder = MessageBuilder::respond_to(buffer, ind);
        if let ResponseTarget::Broadcast(service) = target {
            if let Some(service) = service {
                builder = builder.with_service_type(service);
            }
            builder = builder.with_destination(DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])));
        }

        Some(builder.with_application(apci))
    }
}
