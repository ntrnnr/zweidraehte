//! On-demand persistence requests from the stack to user code.
//!
//! The stack marks ordinary configuration changes via
//! [`HasPersistence::mark_dirty`](crate::HasPersistence::mark_dirty) and
//! relies on user code to save at safe moments (restart handler, periodic
//! poll). Some events, however, need a save *now* rather than eventually:
//!
//! - The KNX IP Secure multicast timer watermark (03/08/09 §2.2.4.2) must
//!   be durable **before** any frame carrying a timer value beyond it is
//!   sent — otherwise a power loss could make the device reuse timer
//!   values, breaking replay protection for the whole multicast group.
//! - The end of an ETS download is a natural moment to save the freshly
//!   written configuration without waiting for the trailing restart.
//!
//! Both travel one channel on
//! [`LayerContext`](crate::context::layer::LayerContext) as
//! [`Request<PersistRequest, ()>`](crate::actor::Request): gated
//! requests embed a reply the sender awaits; advisory notifications are
//! [`Request::fire_and_forget`](crate::actor::Request::fire_and_forget),
//! whose reply methods are no-ops. User code drains them via
//! [`Stack::receive_persist_request()`](crate::Stack::receive_persist_request)
//! and, after attempting the save, **must** call
//! [`Request::reply`](crate::actor::Request::reply)`(())` — gated
//! senders are blocked until then. Reply even when the save fails (log
//! and continue): wedging secure routing forever on a broken storage
//! backend is worse than the bounded replay-window risk.

/// Why the stack is asking for an on-demand save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistRequest {
    /// The IP Secure multicast timer watermark advanced (03/08/09
    /// §2.2.4.2). Delivered gated: the KNX/IP link layer holds back the
    /// frame that would exceed the previously persisted watermark until
    /// user code confirms the save via
    /// [`Request::reply`](crate::actor::Request::reply).
    McTimerWatermark,
    /// The load state machines completed an ETS download
    /// (`LS_LOADING` → `LS_LOADED`). Advisory (fire-and-forget) — a
    /// convenient moment to save; the dirty flag still gates the
    /// actual write.
    EtsDownloadComplete,
}

#[cfg(test)]
mod tests {
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::channel::Channel;

    use crate::actor::{ActorRequest, Request};

    use super::*;

    /// Advisory and gated requests share one channel; the replier
    /// treats both uniformly, and a gated sender unblocks on `reply`.
    #[test]
    fn one_channel_carries_both_flavours() {
        static CH: Channel<CriticalSectionRawMutex, Request<PersistRequest, ()>, 2> = Channel::new();

        // Advisory: fire-and-forget enqueue, reply is a no-op.
        assert!(CH.try_send(Request::fire_and_forget(PersistRequest::EtsDownloadComplete)).is_ok());
        embassy_futures::block_on(async {
            let req = CH.receive().await;
            assert_eq!(*req.get(), PersistRequest::EtsDownloadComplete);
            req.reply(()).await; // must not block or panic
        });

        // Gated: the requester completes only after reply.
        embassy_futures::block_on(async {
            let requester = async {
                ActorRequest::<CriticalSectionRawMutex, _, _>::request(
                    &CH.dyn_sender(),
                    PersistRequest::McTimerWatermark,
                )
                .await;
                true
            };
            let storage_side = async {
                let req = CH.receive().await;
                assert_eq!(*req.get(), PersistRequest::McTimerWatermark);
                req.reply(()).await;
            };
            let (unblocked, ()) = embassy_futures::join::join(requester, storage_side).await;
            assert!(unblocked);
        });
    }
}
