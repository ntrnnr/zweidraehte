//! Individual address serial number service AL extension.
//!
//! Handles `A_IndividualAddressSerialNumber_Read` and
//! `A_IndividualAddressSerialNumber_Write` — serial-number-based address
//! assignment via broadcast.
//!
//! # Usage
//!
//! ```rust,ignore
//! type AlExtension = IndividualAddressSerialNumberExtension;
//! ```

use crate::{
    StackState,
    address::{GroupAddress, IndividualAddress},
    definition::StackDefinition,
    layer_context::HasOutbox,
    layers::application::extensions::{AlExtensionContext, AlServiceExtension},
    messages::{
        apdu::device::{
            IndividualAddressSerialNumberRead, IndividualAddressSerialNumberResponse,
            IndividualAddressSerialNumberWrite,
        },
        buffers::Buffer,
        builder::MessageBuilder,
        knx::{ApciCode, DestinationAddress, KnxMessageBuffer, ServiceType},
    },
};

use crate::logging::{debug, error, trace, warn};

/// AL service extension for serial-number-based individual address services.
///
/// Handles:
/// - `A_IndividualAddressSerialNumber_Read` — respond if serial matches
/// - `A_IndividualAddressSerialNumber_Write` — set address if serial matches
/// - `A_IndividualAddressSerialNumber_Response` — ignored (we send these)
#[derive(Default)]
pub struct IndividualAddressSerialNumberExtension;

impl<D: StackDefinition> AlServiceExtension<D> for IndividualAddressSerialNumberExtension {
    fn try_handle(
        &mut self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlExtensionContext<'_, D>,
    ) -> bool {
        match apci {
            ApciCode::IndividualAddressSerialNumberRead => {
                handle_read::<D>(msg, ctx);
                true
            }
            ApciCode::IndividualAddressSerialNumberWrite => {
                handle_write::<D>(msg, ctx);
                true
            }
            ApciCode::IndividualAddressSerialNumberResponse => {
                debug!("AL ignoring IndividualAddressSerialNumberResponse (response APCI)");
                true
            }
            _ => false,
        }
    }
}

fn handle_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlExtensionContext<'_, D>) {
    if ind.service_type() != ServiceType::T_Broadcast_Ind {
        warn!("AL IndividualAddressSerialNumberRead with unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(received_serial) = IndividualAddressSerialNumberRead::serial_number(ind.buf()) else {
        error!("IndividualAddressSerialNumberRead message too short: {}", ind.len());
        return;
    };

    if received_serial != ctx.state.serial_number() {
        trace!("AL IndividualAddressSerialNumberRead ignored (serial mismatch)");
        return;
    }

    debug!("AL IndividualAddressSerialNumberRead: serial matches, sending response");

    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(IndividualAddressSerialNumberResponse::MSG_LEN) else {
        warn!("AL no buffer for response");
        return;
    };

    let mut msg = MessageBuilder::new_request(
        msg_buf,
        ServiceType::T_Broadcast_Req,
        ind.ctrl_field().priority(),
        DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])),
    )
    .with_application(ApciCode::IndividualAddressSerialNumberResponse)
    .build();

    let serial: &[u8; 6] = ctx.state.serial_number();
    IndividualAddressSerialNumberResponse::write_serial(msg.buf_mut(), serial);

    ctx.lctx.push_outbox(msg.into_inner());
}

fn handle_write<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlExtensionContext<'_, D>) {
    if ind.service_type() != ServiceType::T_Broadcast_Ind {
        warn!("AL IndividualAddressSerialNumberWrite with unexpected service type: {:?}", ind.service_type());
        return;
    }

    let buf = ind.buf();

    let Some(received_serial) = IndividualAddressSerialNumberWrite::serial_number(buf) else {
        error!("IndividualAddressSerialNumberWrite message too short: {}", ind.len());
        return;
    };

    if received_serial != ctx.state.serial_number() {
        trace!("AL IndividualAddressSerialNumberWrite ignored (serial mismatch)");
        return;
    }

    // Access policy 3FF/00C.
    use crate::access::AccessPolicy;
    let security_on = ctx.state.security_mode_enabled();
    if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&ctx.access_ctx, security_on) {
        debug!("AL IndividualAddressSerialNumberWrite denied by access policy");
        return;
    }

    let new_addr_bytes = IndividualAddressSerialNumberWrite::address_bytes(buf)
        .expect("length already validated by serial_number check");
    let new_addr = IndividualAddress::from_bytes(new_addr_bytes);

    debug!("AL IndividualAddressSerialNumberWrite: setting address to {}", new_addr);
    ctx.state.set_individual_address(new_addr);
}
