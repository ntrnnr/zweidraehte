//! KNX-RF domain-address AL service extension (broadcast `A_DomainAddress_*`).
//!
//! Implements the programming-mode-selected domain-address management services
//! (KNX 03/03/07 §3.3.3–3.3.4) that ETS uses to assign and read back an RF
//! device's 6-octet RF Domain Address:
//!
//! - `A_DomainAddress_Write` — the device, *if in programming mode*, stores the
//!   new domain address (RF Medium Object PID 56).
//! - `A_DomainAddress_Read` — the device, *if in programming mode*, responds
//!   with `A_DomainAddress_Response` carrying its domain address.
//! - `A_DomainAddress_Response` — ignored (we are the responder).
//!
//! All three run on **system broadcast** communication mode (the device has no
//! domain address yet during configuration). They are gated on
//! [`HasRfDomainAddress`], so this extension only compiles into RF devices —
//! TP1 / KNX-IP devices, whose state does not implement that trait, cannot
//! include it. Compose it into an RF device's `type AlExtensions`, e.g.
//!
//! ```rust,ignore
//! type AlExtensions = (StandardAlServices, DomainAddressService, RfDomainAddressService);
//! ```

use crate::{
    HasSecurityMode, StackState,
    definition::StackDefinition,
    objects::interface::HasRfDomainAddress,
    service::{AlCtx, ApciHandler},
};
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::messages::{
    apdu::device::{DomainAddressResponse, DomainAddressWrite},
    buffers::Buffer,
    builder::MessageBuilder,
    knx::{ApciCode, DestinationAddress, KnxMessageBuffer, ServiceType},
};

use crate::logging::{debug, trace, warn};

/// Length of an RF Domain Address.
const RF_DOA_LEN: usize = 6;

/// AL service extension for the broadcast `A_DomainAddress_Read/Write/Response`
/// services. RF-only by construction (requires `D::State: HasRfDomainAddress`).
#[derive(Default)]
pub struct RfDomainAddressService;

impl<D> ApciHandler<D> for RfDomainAddressService
where
    D: StackDefinition,
    D::State: HasRfDomainAddress,
{
    fn try_handle_apci(&self, apci: ApciCode, msg: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) -> bool {
        match apci {
            ApciCode::DomainAddressWrite => {
                handle_domain_address_write::<D>(msg, ctx);
                true
            }
            ApciCode::DomainAddressRead => {
                handle_domain_address_read::<D>(msg, ctx);
                true
            }
            // Response APCI — we are the responder, ignore if received.
            ApciCode::DomainAddressResponse => {
                debug!("AL ignoring DomainAddressResponse (response APCI)");
                true
            }
            _ => false,
        }
    }
}

/// Handle `A_DomainAddress_Write.ind`: store the new RF Domain Address if this
/// device is in programming mode and the access policy permits.
fn handle_domain_address_write<D>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>)
where
    D: StackDefinition,
    D::State: HasRfDomainAddress,
{
    if ind.service_type() != ServiceType::T_SystemBroadcast_Ind {
        warn!("AL DomainAddressWrite with unexpected service type: {:?}", ind.service_type());
        return;
    }

    // Programming-mode selection (KNX 03/03/07 §3.3.3): only the device whose
    // button is pressed accepts the write; all others ignore it.
    if !ctx.base.state.is_programming_mode() {
        trace!("AL DomainAddressWrite ignored (not in programming mode)");
        return;
    }

    // Access policy 3FF/00C: open when security mode is off, Tool A+C only when on.
    let security_on = ctx.base.state.security_mode_enabled();
    if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&ctx.base.access, security_on) {
        debug!("AL DomainAddressWrite denied by access policy");
        return;
    }

    let doa = DomainAddressWrite::domain_address(ind.buf());
    if doa.len() < RF_DOA_LEN {
        warn!("AL DomainAddressWrite: domain address too short ({} < {})", doa.len(), RF_DOA_LEN);
        return;
    }

    let mut new_doa = [0u8; RF_DOA_LEN];
    new_doa.copy_from_slice(&doa[..RF_DOA_LEN]);
    debug!("AL DomainAddressWrite: setting RF domain address");
    ctx.base.state.set_rf_domain_address(&new_doa);
}

/// Handle `A_DomainAddress_Read.ind`: respond with `A_DomainAddress_Response`
/// carrying our RF Domain Address, but only if in programming mode.
fn handle_domain_address_read<D>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>)
where
    D: StackDefinition,
    D::State: HasRfDomainAddress,
{
    if ind.service_type() != ServiceType::T_SystemBroadcast_Ind {
        warn!("AL DomainAddressRead with unexpected service type: {:?}", ind.service_type());
        return;
    }

    if !ctx.base.state.is_programming_mode() {
        trace!("AL DomainAddressRead ignored (not in programming mode)");
        return;
    }

    let resp_len = DomainAddressResponse::MSG_LEN_NO_DOA + RF_DOA_LEN;
    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(resp_len) else {
        warn!("AL no buffer for DomainAddressResponse");
        return;
    };

    // Inherit the indication's security stamps via `respond_to`, then override
    // to the system-broadcast framing the spec mandates (§3.3.4).
    let mut msg = MessageBuilder::respond_to(msg_buf, ind)
        .with_service_type(ServiceType::T_SystemBroadcast_Req)
        .with_destination(DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])))
        .with_application(ApciCode::DomainAddressResponse)
        .build();

    let doa = ctx.base.state.rf_domain_address();
    DomainAddressResponse::write_domain_address(msg.buf_mut(), &doa);

    debug!("AL sending DomainAddressResponse");
    ctx.base.lctx.push_outbox(msg.into_inner());
}
