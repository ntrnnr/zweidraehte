//! Domain address AL service extension.
//!
//! Handles `A_DomainAddressSerialNumber_Read/Write/Response` for devices
//! that store a domain address (KNX/IP, RF). TP1 devices don't need this
//! extension since their domain address length is 0.
//!
//! # Usage
//!
//! Set `type AlExtensions = DomainAddressService;` in your
//! [`StackDefinition`] impl. The device's `State` type must implement
//! [`HasDomainAddress`].

use crate::buffers::Buffer;
use crate::context::layer::ResponseTarget;
use crate::{
    HasSecurityMode, StackState,
    definition::StackDefinition,
    objects::interface::{HasDomainAddress, SECURE_DOMAIN_ADDRESS_LENGTH},
    service::{AlCtx, ApciHandler},
};
use zweidraehte_proto::messages::{
    apdu::device::{DomainAddressSerialNumberRead, DomainAddressSerialNumberResponse, DomainAddressSerialNumberWrite},
    knx::{ApciCode, KnxMessageBuffer, ServiceType},
};

use crate::logging::{debug, error, trace, warn};

// ============================================================================
// Extension Type
// ============================================================================

/// AL service extension for domain address serial number services.
///
/// Handles:
/// - `A_DomainAddressSerialNumber_Read` — respond with serial + domain address
/// - `A_DomainAddressSerialNumber_Write` — update individual address and domain address
/// - `A_DomainAddressSerialNumber_Response` — ignored (we send these)
///
/// This service does **not** handle the broadcast
/// `A_DomainAddress_Read/Write/Response` services — those are
/// programming-mode-selected and medium-specific, owned by
/// [`RfDomainAddressService`](super::rf_domain_addr::RfDomainAddressService)
/// for KNX-RF. The two services have disjoint APCI sets and may be composed
/// together in any order.
///
/// Requires `D::State: HasDomainAddress`.
#[derive(Default)]
pub struct DomainAddressService;

impl<D> ApciHandler<D> for DomainAddressService
where
    D: StackDefinition,
    D::State: HasDomainAddress,
{
    fn try_handle_apci(&self, apci: ApciCode, msg: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) -> bool {
        match apci {
            ApciCode::DomainAddressSerialNumberRead => {
                handle_domain_address_serial_number_read::<D>(msg, ctx);
                true
            }
            ApciCode::DomainAddressSerialNumberWrite => {
                handle_domain_address_serial_number_write::<D>(msg, ctx);
                true
            }
            // Response APCI — we are the responder, ignore if received.
            ApciCode::DomainAddressSerialNumberResponse => {
                debug!("AL ignoring DomainAddressSerialNumberResponse (response APCI)");
                true
            }

            // `A_DomainAddress_Read/Write/Response` (the broadcast,
            // programming-mode-selected variants) are NOT handled here. They
            // belong to the medium-specific service that owns the on-wire
            // Domain Address — `RfDomainAddressService` for KNX-RF. Returning
            // `false` lets them fall through to that service in the
            // `AlExtensions` tuple regardless of declaration order; claiming
            // them here (even as a no-op) would silently shadow it.
            _ => false,
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================
//
// Both domain-address serial-number services accept **either** broadcast mode
// (`T_SystemBroadcast_Ind` or `T_Broadcast_Ind`): per 03/02/06 KNX IP
// §4.3.5.3.1 the device handles IP System Broadcast Frames and plain broadcast
// Frames uniformly, and 03/03/07 Table 1 marks these services mandatory on both
// `T_Data_Broadcast` and `T_Data_SystemBroadcast`. ETS assigns the routing
// multicast address over plain broadcast (cEMI SB bit 0), which must be
// accepted; responses go out in the same mode as the request.

/// Handle `A_DomainAddressSerialNumber_Read.ind`.
///
/// Matches on serial number and responds with the device's serial number
/// and current domain address. On media where the service is void (KNX/IP,
/// see
/// [`LinkLayerBuilderBase::ANSWERS_DOMAIN_ADDRESS_SERIAL_NUMBER_READ`](crate::layers::LinkLayerBuilderBase::ANSWERS_DOMAIN_ADDRESS_SERIAL_NUMBER_READ))
/// the device claims the request and stays silent.
///
/// Wire format (incoming): APCI(2) + serial(6)
/// Wire format (response): APCI(2) + serial(6) + domain_address(N)
fn handle_domain_address_serial_number_read<D>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>)
where
    D: StackDefinition,
    D::State: HasDomainAddress,
{
    // Accept either broadcast mode; the response mirrors the request's mode
    // (03/02/06 §4.3.5.3.1). See the handlers-section note above.
    if !matches!(ind.service_type(), ServiceType::T_SystemBroadcast_Ind | ServiceType::T_Broadcast_Ind) {
        warn!("AL DomainAddressSerialNumberRead with unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(received_serial) = DomainAddressSerialNumberRead::serial_number(ind.buf()) else {
        error!("DomainAddressSerialNumberRead message too short: {}", ind.len());
        return;
    };

    if received_serial != ctx.base.state.serial_number() {
        trace!("AL DomainAddressSerialNumberRead ignored (serial mismatch)");
        return;
    }

    if !<D::LLB as crate::layers::LinkLayerBuilderBase>::ANSWERS_DOMAIN_ADDRESS_SERIAL_NUMBER_READ {
        debug!("AL DomainAddressSerialNumberRead: void on this medium, not answering");
        return;
    }

    let doa_len = <D::State as HasDomainAddress>::DOMAIN_ADDRESS_LENGTH;

    debug!("AL DomainAddressSerialNumberRead: serial matches, sending response");

    let resp_len = DomainAddressSerialNumberResponse::MSG_LEN_NO_DOA + doa_len;

    let serial: &[u8; 6] = ctx.base.state.serial_number();
    let mut doa_buf = [0u8; 6]; // Max domain address size (RF = 6)
    ctx.base.state.domain_address(&mut doa_buf[..doa_len]);

    // No fixed service: the response goes out in the indication's mode
    // (`T_Broadcast_Ind → T_Broadcast_Req`, `T_SystemBroadcast_Ind →
    // T_SystemBroadcast_Req`), as 03/02/06 §4.3.5.3.1 requires.
    ctx.respond_to(
        ind,
        ResponseTarget::Broadcast(None),
        ApciCode::DomainAddressSerialNumberResponse,
        resp_len,
        |buf| {
            DomainAddressSerialNumberResponse::write_serial(buf, serial);
            // The domain address (if any) follows the serial number.
            DomainAddressSerialNumberResponse::write_domain_address(buf, &doa_buf[..doa_len]);
        },
    );
}

/// Handle `A_DomainAddressSerialNumber_Write.ind`.
///
/// Matches on serial number and updates the device's domain address.
/// This service does NOT set the individual address — that's done by
/// `A_IndividualAddressSerialNumber_Write` instead.
///
/// Wire format: APCI(2) + serial(6) + domain_address(N)
///
/// For KNX/IP, the domain address is the 4-byte routing multicast address
/// (see KNX IP Communication Medium spec, section 4.3.5.3.4).
///
/// # KNX IP Secure
///
/// KNX IP Secure adds a 21-byte form (03/03/07 §3.3.7 Figure 32):
///
/// ```text
/// multicast(4) + routing_security_version(1) + backbone_key(16)
/// ```
///
/// ETS commissions a factory-new device for a secure backbone with it,
/// before it switches to secure routing itself, so a device that drops the
/// key is unreachable afterwards. The form "shall always be sent wrapped as
/// S-A_Data-PDU with authentication and confidentiality"; AN193 §2.2.4.1
/// gives it `00C/00C`: only the Tool with A+C, in either security mode.
/// Devices without IP Secure storage keep the plain behaviour and use only
/// the multicast address.
fn handle_domain_address_serial_number_write<D>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>)
where
    D: StackDefinition,
    D::State: HasDomainAddress,
{
    // Accept either broadcast mode (03/02/06 §4.3.5.3.4 with §4.3.5.3.1). ETS
    // assigns the routing multicast address over plain broadcast, so insisting
    // on system broadcast alone would silently drop it. See the note above.
    if !matches!(ind.service_type(), ServiceType::T_SystemBroadcast_Ind | ServiceType::T_Broadcast_Ind) {
        warn!("AL DomainAddressSerialNumberWrite with unexpected service type: {:?}", ind.service_type());
        return;
    }

    let buf = ind.buf();

    let Some(received_serial) = DomainAddressSerialNumberWrite::serial_number(buf) else {
        error!("DomainAddressSerialNumberWrite message too short: {}", ind.len());
        return;
    };

    if received_serial != ctx.base.state.serial_number() {
        trace!("AL DomainAddressSerialNumberWrite ignored (serial mismatch)");
        return;
    }

    use zweidraehte_proto::access::AccessPolicy;
    let security_on = ctx.base.state.security_mode_enabled();
    let doa = DomainAddressSerialNumberWrite::domain_address(buf);

    // The 21-octet form carries the backbone key: Tool with A+C only, in
    // either security mode (AN193 §2.2.4.1 `00C/00C`). The device applies
    // what it can store (see `HasDomainAddress::set_domain_address`).
    if doa.len() == SECURE_DOMAIN_ADDRESS_LENGTH {
        if !AccessPolicy::TOOL_ONLY.can_write(&ctx.base.access, security_on) {
            debug!("AL DomainAddressSerialNumberWrite (IP Secure) denied: needs the Tool Key with A+C");
            return;
        }

        debug!("AL DomainAddressSerialNumberWrite: setting IP Secure domain address");
        ctx.base.state.set_domain_address(doa);

        return;
    }

    // Access policy 3FF/00C: everyone can write when security mode is off;
    // when security mode is on, only Tool A+C can write.
    if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&ctx.base.access, security_on) {
        debug!("AL DomainAddressSerialNumberWrite denied by access policy");
        return;
    }

    let doa_len = <D::State as HasDomainAddress>::DOMAIN_ADDRESS_LENGTH;
    if doa.len() >= doa_len {
        debug!("AL DomainAddressSerialNumberWrite: setting domain address ({} bytes)", doa_len);
        ctx.base.state.set_domain_address(&doa[..doa_len]);
    } else {
        warn!("AL DomainAddressSerialNumberWrite: domain address too short ({} < {})", doa.len(), doa_len);
    }
}
