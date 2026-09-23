pub mod mock;

/// Open-medium system broadcasts must not deliver S-A_Data with SBC cleared
/// (03/03/07 §5.2.1.3). The link adapter knows the actual communication mode;
/// IP in particular must use its routing service, not just the cEMI flags.
/// Keep this separate from S-A_Sync's rules and TP1's optional rejection.
#[cfg(any(feature = "rf", feature = "knxip"))]
fn is_secure_data_without_sbc(frame: &[u8]) -> bool {
    use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
    use zweidraehte_proto::messages::{
        apdu::secure,
        knx::{ApciCode, KnxMessageBuffer},
    };

    if KnxMessageBuffer::from_buffer(frame).get_apci_code() != ApciCode::SecureService {
        return false;
    }
    // The communication-mode check needs only the SCF. Even a truncated
    // payload with this mismatch must be ignored before S-AL diagnostics.
    frame
        .get(secure::SCF)
        .and_then(|&scf| SecurityControlField::parse(scf).ok())
        .is_some_and(|scf| scf.service == SecureServiceType::Data && !scf.system_broadcast)
}

#[cfg(all(test, any(feature = "rf", feature = "knxip")))]
mod test_support;

// Each medium filters incoming frames using the same live destination policy.
#[cfg(any(feature = "tp1", feature = "rf", feature = "knxip"))]
pub mod address_check;

#[cfg(feature = "knxip")]
pub mod knxip;

#[cfg(feature = "tp1")]
pub mod tpuart;

#[cfg(feature = "rf")]
pub mod knxrf;

#[cfg(feature = "ip-interface")]
pub mod ip_interface;

#[cfg(feature = "usb")]
pub mod usb;
