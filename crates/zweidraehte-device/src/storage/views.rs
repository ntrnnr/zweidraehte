//! The Data Secure sequence state, with the IP Secure multicast-timer
//! watermark (03/08/09 §2.2.4.2) kept next to its counters: [`SiatStore`] for
//! flash and the packed byte-medium store for FRAM and shared memory. Both
//! live in `zweidraehte-nv`, where the micro stack can use them too, and are
//! re-exported here.
//!
//! The seam they sit on — [`KeyValueStore`](super::kv::KeyValueStore), the
//! namespaces, the seq codec helpers — lives in [`kv`](super::kv); the
//! backends implementing it live in [`backends`](super::backends).

pub use zweidraehte_nv::{McTimerWatermark, SiatStore};
pub use zweidraehte_proto::security::SiatAccess;
