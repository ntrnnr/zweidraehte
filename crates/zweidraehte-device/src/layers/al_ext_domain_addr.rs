//! Domain address AL service extension.
//!
//! Handles `A_DomainAddressSerialNumber_Read/Write/Response` for devices
//! that store a domain address (KNX/IP, RF). TP1 devices don't need this
//! extension since their domain address length is 0.
//!
//! # Usage
//!
//! Set `type AlExtension = DomainAddressExtension;` in your
//! [`StackDefinition`] impl. The device's `State` type must implement
//! [`HasDomainAddress`].

use crate::{
    StackState,
    address::GroupAddress,
    definition::StackDefinition,
    layers::al_extension::{AlExtensionContext, AlServiceExtension},
    messages::{
        apdu::device::{
            DomainAddressSerialNumberRead, DomainAddressSerialNumberResponse, DomainAddressSerialNumberWrite,
        },
        buffers::Buffer,
        builder::MessageBuilder,
        knx::{ApciCode, DestinationAddress, KnxMessageBuffer, ServiceType},
    },
    objects::interface::HasDomainAddress,
    router::Outbox,
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
/// Also recognizes (but does not act on):
/// - `A_DomainAddress_Read/Write/Response` — only relevant for PL/RF media
///
/// Requires `D::State: HasDomainAddress`.
#[derive(Default)]
pub struct DomainAddressExtension;

impl<D> AlServiceExtension<D> for DomainAddressExtension
where
    D: StackDefinition,
    D::State: HasDomainAddress,
{
    fn try_handle(
        &mut self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlExtensionContext<'_, D>,
        outbox: &mut Outbox,
    ) -> bool {
        match apci {
            ApciCode::DomainAddressSerialNumberRead => {
                handle_domain_address_serial_number_read::<D>(msg, ctx, outbox);
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

            // TODO: A_DomainAddress_Read/Write/Response — only applicable for
            // PL (PowerLine, DoA=8) and RF (DoA=48) media. Not implemented yet.
            ApciCode::DomainAddressRead | ApciCode::DomainAddressWrite | ApciCode::DomainAddressResponse => {
                debug!("AL ignoring DomainAddress_{:?} (not implemented for this medium)", apci);
                true
            }

            _ => false,
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Handle `A_DomainAddressSerialNumber_Read.ind`.
///
/// Matches on serial number and responds with the device's serial number
/// and current domain address.
///
/// Wire format (incoming): APCI(2) + serial(6)
/// Wire format (response): APCI(2) + serial(6) + domain_address(N)
fn handle_domain_address_serial_number_read<D>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    outbox: &mut Outbox,
) where
    D: StackDefinition,
    D::State: HasDomainAddress,
{
    if ind.service_type() != ServiceType::T_Broadcast_Ind {
        warn!("AL DomainAddressSerialNumberRead with unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(received_serial) = DomainAddressSerialNumberRead::serial_number(ind.buf()) else {
        error!("DomainAddressSerialNumberRead message too short: {}", ind.len());
        return;
    };

    if received_serial != ctx.state.serial_number() {
        trace!("AL DomainAddressSerialNumberRead ignored (serial mismatch)");
        return;
    }

    debug!("AL DomainAddressSerialNumberRead: serial matches, sending response");

    let doa_len = <D::State as HasDomainAddress>::DOMAIN_ADDRESS_LENGTH;
    let resp_len = DomainAddressSerialNumberResponse::MSG_LEN_NO_DOA + doa_len;

    let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(resp_len) else {
        warn!("AL no buffer for DomainAddressSerialNumberResponse");
        return;
    };

    let mut msg = MessageBuilder::new_request(
        msg_buf,
        ServiceType::T_Broadcast_Req,
        ind.ctrl_field().priority(),
        DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])),
    )
    .with_application(ApciCode::DomainAddressSerialNumberResponse)
    .build();

    let serial: &[u8; 6] = ctx.state.serial_number();
    DomainAddressSerialNumberResponse::write_serial(msg.buf_mut(), serial);

    // Write domain address (if any) after the serial number.
    if doa_len > 0 {
        let mut doa_buf = [0u8; 6]; // Max domain address size (RF = 6)
        ctx.state.domain_address(&mut doa_buf[..doa_len]);
        DomainAddressSerialNumberResponse::write_domain_address(msg.buf_mut(), &doa_buf[..doa_len]);
    }

    outbox.push(msg.into_inner());
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
fn handle_domain_address_serial_number_write<D>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) where
    D: StackDefinition,
    D::State: HasDomainAddress,
{
    if ind.service_type() != ServiceType::T_Broadcast_Ind {
        warn!("AL DomainAddressSerialNumberWrite with unexpected service type: {:?}", ind.service_type());
        return;
    }

    let buf = ind.buf();

    let Some(received_serial) = DomainAddressSerialNumberWrite::serial_number(buf) else {
        error!("DomainAddressSerialNumberWrite message too short: {}", ind.len());
        return;
    };

    if received_serial != ctx.state.serial_number() {
        trace!("AL DomainAddressSerialNumberWrite ignored (serial mismatch)");
        return;
    }

    let doa_len = <D::State as HasDomainAddress>::DOMAIN_ADDRESS_LENGTH;
    let doa = DomainAddressSerialNumberWrite::domain_address(buf);
    if doa.len() >= doa_len {
        debug!("AL DomainAddressSerialNumberWrite: setting domain address ({} bytes)", doa_len);
        ctx.state.set_domain_address(&doa[..doa_len]);
    } else {
        warn!("AL DomainAddressSerialNumberWrite: domain address too short ({} < {})", doa.len(), doa_len);
    }
}
