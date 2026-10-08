//! The four kinds of data this crate persists, one module each.
//!
//! Each module owns everything that identifies its data on a medium: the
//! magic a fresh or foreign medium is told apart by, the key/value
//! namespaces of its records, and its layout constants. The shared machinery
//! underneath (the medium seams, [`AppendLog`](crate::AppendLog),
//! [`WearLeveledKv`](crate::WearLeveledKv)) knows none of them.
//!
//! - [`config`]: the device configuration as persistent sections (`"KNXC"`).
//! - [`sequence`]: the Data Secure sending and tool counters and the SIAT
//!   (`"KNXR"`).
//! - [`mc_timer`]: the KNX IP Secure multicast-timer watermark (`"KNXW"`).
//! - [`provisioning`]: the factory record of serial, FDSK and MAC (`"KNXP"`).

pub mod config;
pub mod mc_timer;
pub mod provisioning;
pub mod sequence;

/// The key/value namespaces of every store, which must stay distinct: two
/// stores may share one [`WearLeveledKv`](crate::WearLeveledKv) log, and
/// equal namespaces would then overwrite each other's records.
const NAMESPACES: [u8; 4] = [sequence::NS_SIAT, sequence::NS_SENDING, sequence::NS_TOOL, mc_timer::NS_MC_TIMER];

const _: () = {
    let mut i = 0;
    while i < NAMESPACES.len() {
        let mut j = i + 1;
        while j < NAMESPACES.len() {
            assert!(NAMESPACES[i] != NAMESPACES[j], "every key/value namespace is distinct");
            j += 1;
        }
        i += 1;
    }
};
