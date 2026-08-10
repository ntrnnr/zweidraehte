//! Every augment's access levels, resolved for both authorisation models.
//!
//! An augment is profile-generic: its `DESCRIPTORS` const holds
//! [`AccessLevel`]s and the generated `Augment<D>` impl resolves them
//! against the hosting device's `HasAuthorization::MAX_ACCESS_LEVELS`.
//! That makes the same table answer differently on a 4-level System B
//! device and a 16-level System 7 one, and the difference is invisible
//! at the declaration site — which is exactly the kind of thing a
//! snapshot is for.
//!
//! Two things to read out of the snapshot:
//!
//! - **The 4-level column is a regression fence.** It is what System B
//!   devices answer today, and no refactor of how levels are *written*
//!   may move it.
//! - **The 16-level column is the design decision.** It is what these
//!   augments would answer if composed onto a System 7 profile, and it
//!   is the thing to review when 2705h/5705h arrive — as a diff rather
//!   than a re-derivation. Note that agreeing with it is necessary but
//!   not sufficient: a mask's Annex A column may also list a different
//!   *number* for a property, as 0705h does for PID_DEVICE_CONTROL, and
//!   no audience can express that.
//!
//! Run with the IP features on, which is what the snapshot was taken
//! with:
//!
//! ```text
//! cargo test -p zweidraehte-device --features "knxip,ip-secure,rf,tp1,std" --test augment_access_levels
//! ```
//!
//! `SecurityAugment` is deliberately absent: it needs a
//! `SequenceNumberStorage + SiatAccess` backing store to name its type,
//! and its levels are already pinned property-by-property by
//! `security_io_access_levels.rs`.

#![cfg(all(feature = "knxip", feature = "ip-secure"))]

use core::fmt::Write as _;
use core::net::Ipv4Addr;

use zweidraehte_device::bcus::system_b::{
    DiagnosticsAugment, GroupObjectTableAugment, IpAugment, IpSecureAugment, NoSecureGoSend, RfAugment,
    RfRetransmitterAugment, Tp1Augment, TunnellingAugment,
};
use zweidraehte_platform::{IpConfig, NetworkConfig, NetworkInfo};
use zweidraehte_proto::properties::PropertyDescriptorSpec;

/// `IpAugment` is generic over the platform it reads the live network
/// state from. The descriptor table does not depend on it, but naming
/// the type does.
struct StubPlatform;

impl NetworkInfo for StubPlatform {
    fn current_ip_address(&self) -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }
    fn current_subnet_mask(&self) -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }
    fn current_default_gateway(&self) -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }
    fn mac_address(&self) -> [u8; 6] {
        [0; 6]
    }
    fn current_ip_assignment_method(&self) -> u8 {
        0
    }
    fn ip_capabilities(&self) -> u8 {
        0
    }
}

impl NetworkConfig for StubPlatform {
    type Error = core::convert::Infallible;

    fn apply_ip_config(&self, _config: &IpConfig) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// One augment's rows: its name and the descriptor table it declares.
type Table = (&'static str, &'static [(zweidraehte_proto::dpt::InterfaceObjectType, PropertyDescriptorSpec)]);

fn tables() -> Vec<Table> {
    vec![
        ("Tp1Augment", Tp1Augment::DESCRIPTORS),
        ("RfAugment", RfAugment::DESCRIPTORS),
        ("RfRetransmitterAugment", RfRetransmitterAugment::DESCRIPTORS),
        // The const generics pick nothing the descriptors depend on;
        // any concrete value names the same table.
        ("IpAugment", IpAugment::<'_, StubPlatform, 0>::DESCRIPTORS),
        ("TunnellingAugment", TunnellingAugment::<'_, 4>::DESCRIPTORS),
        ("IpSecureAugment", IpSecureAugment::<'_, 4, 4>::DESCRIPTORS),
        ("DiagnosticsAugment", DiagnosticsAugment::<'_, NoSecureGoSend>::DESCRIPTORS),
        ("GroupObjectTableAugment", GroupObjectTableAugment::DESCRIPTORS),
    ]
}

#[test]
fn augment_levels_resolve_the_same_in_both_models() {
    let mut out = String::new();
    writeln!(out, "{:<24} {:<19} {:>4}  {:<9} {}", "augment", "object", "pid", "4 levels", "16 levels")
        .expect("write to a String cannot fail");

    for (name, descriptors) in tables() {
        for (object_type, spec) in descriptors {
            let four = spec.for_levels(4);
            let sixteen = spec.for_levels(16);
            writeln!(
                out,
                "{:<24} {:<19} {:>4}  {:<9} {}",
                name,
                format!("{object_type:?}"),
                spec.pid,
                format!("{}/{}", four.read_level, four.write_level),
                format!("{}/{}", sixteen.read_level, sixteen.write_level),
            )
            .expect("write to a String cannot fail");
        }
    }

    insta::assert_snapshot!(out);
}
