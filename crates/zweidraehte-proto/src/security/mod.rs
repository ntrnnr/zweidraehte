//! KNX Data Secure state and policy (03/03/07 §5, 03/05/01 §6.3).
//!
//! This module holds the *stateful and decision-making* part of the Data
//! Secure profile module, in the same spirit as [`transport`](crate::transport)
//! holds the pure transport state machine: no I/O, no clock, no buffer pool,
//! and no assumption about how a device stores anything. The cryptography it
//! is paired with lives in [`crypto`](crate::crypto) and the wire codecs in
//! [`messages::apdu::secure`](crate::messages::apdu::secure); both already
//! operate on plain byte slices, so nothing here needs to own a frame.
//!
//! It lives in `zweidraehte-proto` rather than in a device stack because KNX
//! Data Security is a *profile module* (06 Profiles v02.02.01 §9.1 "Profile
//! Module S-AL") composed onto a base profile — it belongs to no BCU family,
//! and the same tables, sequence rules and admission decisions serve the
//! full async stack, the polling BCU-era stack, and a management client
//! checking its own writes.
//!
//! # What a device supplies
//!
//! Two seams, both in [`seq`]:
//!
//! - [`SequenceNumberStorage`] — the durable sending counter and the
//!   receiving counters. Sequence numbers change on every secure frame, so the
//!   backend is a wear-resistant medium the device chooses (FRAM,
//!   battery-backed RAM, a wear-levelled flash region, a file).
//! - [`SiatAccess`] — the Security Individual Address Table as an addressable
//!   array, which is what `PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE` (54) serves.
//!   A SIAT element *is* a sender IA plus its Last Valid SeqNr, so one store
//!   implements both traits and there is no second copy to keep in step.
//!
//! Everything else — [`SecurityState`] with its key tables, the failures log,
//! and the [`policy`] decisions — is plain data and pure functions.

pub mod failures;
pub mod policy;
pub mod seq;
pub mod state;
pub mod tables;

pub use failures::{SecurityFailureEntry, SecurityFailureType, SecurityFailuresLog};
pub use policy::{GO_FLAG_SECURITY_MASK, go_flags_accept, restart_access_policy, restart_required_level};
pub use seq::{
    DEFAULT_SENDING, SEQ_EXHAUSTION_THRESHOLD, SEQ_REINIT_VALUE, SEQ6_MAX, SeqVerdict, SequenceNumberStorage,
    SiatAccess, check_receiving_seq, erase_seq_on_factory_reset, reserve_next_seq_nr, seq6_to_u64, u64_to_seq6,
};
pub use state::{FunctionPropertyAnswer, SecurityConfig, SecurityState};
pub use tables::SecurityTable;
