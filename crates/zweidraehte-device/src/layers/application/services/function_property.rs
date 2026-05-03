//! Function property service handlers.
//!
//! Handles `A_FunctionPropertyCommand` and `A_FunctionPropertyState_Read`.
//!
//! Per KNX spec 06 Profiles §4.2.6, function property services are
//! **optional** per profile — they are only required when a device's
//! interface objects declare `PDT_Function` or `PDT_Control` properties.
//! Minimal devices with no function properties (e.g. a simple TP1 light
//! switch) can leave this service out of their `Services` tuple; the AL
//! will then respond to the APCIs as unhandled.
//!
//! # Usage
//!
//! ```rust,ignore
//! type Services = (MemoryService, FunctionPropertyService);
//! ```

use crate::{
    context::layer::HasOutbox,
    definition::StackDefinition,
    layers::application::services::{AlService, AlServiceContext},
    objects::interface::{FunctionPropertyRequest, PropertyServiceHandler},
};
use zweidraehte_proto::messages::{
    apdu::function_property::{FunctionPropertyHeader, FunctionPropertyResponse as FpResponseWriter},
    buffers::Buffer,
    builder::IndicationExt,
    knx::{ApciCode, KnxMessageBuffer, ServiceType},
};

use crate::logging::{debug, error, warn};

/// AL service for function property commands and state reads.
///
/// Dispatches to [`PropertyServiceHandler::function_property_command`] /
/// [`PropertyServiceHandler::function_property_state_read`] on the
/// device's interface objects container.
#[derive(Default)]
pub struct FunctionPropertyService;

impl<D: StackDefinition> AlService<D> for FunctionPropertyService {
    fn try_handle(
        &self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlServiceContext<'_, D>,
    ) -> bool {
        match apci {
            ApciCode::FunctionPropertyCommand => {
                handle::<D>(msg, ctx, true);
                true
            }
            ApciCode::FunctionPropertyStateRead => {
                handle::<D>(msg, ctx, false);
                true
            }
            ApciCode::FunctionPropertyStateResponse => {
                debug!("AL ignoring FunctionPropertyStateResponse (response APCI)");
                true
            }
            _ => false,
        }
    }
}

// ApciHandler shim forwarding to the legacy AlService body. The
// shim keeps both trait impls live during the migration so existing
// callers and new `LayerRegistry`-driven dispatch route through the
// same code.
crate::apci_handler_via_alservice!(FunctionPropertyService);

/// Shared implementation for command and state-read. Both share the same
/// wire format and response format and differ only in which trait method
/// is invoked on the interface objects.
fn handle<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlServiceContext<'_, D>,
    is_command: bool,
) {
    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL FunctionProperty unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(hdr) = FunctionPropertyHeader::parse(ind.buf()) else {
        error!("FunctionProperty message too short: {}", ind.len());
        return;
    };
    let service_data = hdr.data(ind.buf());

    let label = if is_command { "Command" } else { "StateRead" };
    debug!(
        "AL FunctionProperty{}: obj={}, prop_id={}, service_data_len={}, access_ctx={:?}",
        label,
        hdr.object_idx,
        hdr.prop_id,
        service_data.len(),
        ctx.access_ctx,
    );

    let req = FunctionPropertyRequest {
        object_idx: hdr.object_idx as u16,
        prop_id: hdr.prop_id,
        service_data,
        ctx: ctx.access_ctx,
    };

    let result = if is_command {
        ctx.interface_objects.function_property_command(&req)
    } else {
        ctx.interface_objects.function_property_state_read(&req)
    };

    let response_data = result.data.as_slice();
    let response_len = FpResponseWriter::msg_len(response_data.len());

    // Plain `A_FunctionPropertyState_Response` has no negative return
    // code for over-budget responses (unlike the extended
    // FunctionPropertyExt family). If the handler produced more data
    // than fits in the wire budget, drop + warn.
    if !ctx.response_fits(response_len) {
        warn!("AL FunctionProperty response too large for APDU budget ({} bytes); dropping", response_len);
        return;
    }

    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(response_len) else {
        warn!("AL no buffer for FunctionProperty response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::FunctionPropertyStateResponse).with_data(|buf| {
        FpResponseWriter::write(buf, hdr.object_idx, hdr.prop_id, result.return_code, response_data);
    });

    debug!(
        "AL sending FunctionPropertyStateResponse: rc=0x{:02X}, data_len={}",
        result.return_code,
        response_data.len()
    );
    ctx.lctx.push_outbox(msg.into_inner());
}
