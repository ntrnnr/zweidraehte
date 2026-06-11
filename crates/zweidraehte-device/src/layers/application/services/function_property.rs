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
//! type AlExtensions = (MemoryService, FunctionPropertyService);
//! ```

use crate::{
    definition::StackDefinition,
    objects::interface::{FunctionPropertyRequest, PropertyServiceHandler},
    service::{AlCtx, ApciHandler},
};
use zweidraehte_proto::dpt::{PDT_Function, PropertyDataDefinition};
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

impl<D: StackDefinition> ApciHandler<D> for FunctionPropertyService {
    fn try_handle_apci(&self, apci: ApciCode, msg: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) -> bool {
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

/// Shared implementation for command and state-read. Both share the same
/// wire format and response format and differ only in which trait method
/// is invoked on the interface objects.
fn handle<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>, is_command: bool) {
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
        ctx.base.access,
    );

    // 03/03/07 §3.4.7.3: the plain function-property services may only
    // address PDT_Function properties. A property that is absent or of
    // any other PDT (including PDT_Control, which is reachable via the
    // *Ext* services only) gets the "empty" response — object/PID
    // echoed back with neither a return_code octet nor data.
    let is_pdt_function = matches!(
        ctx.interface_objects.property_description_read(hdr.object_idx as u16, hdr.prop_id as u16, 0),
        Ok(desc) if desc.pdt == PDT_Function::ID
    );
    if !is_pdt_function {
        debug!("AL FunctionProperty{}: prop {} is not PDT_Function → empty response", label, hdr.prop_id);
        let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(FpResponseWriter::EMPTY_MSG_LEN) else {
            warn!("AL no buffer for FunctionProperty empty response");
            return;
        };
        let msg =
            ind.respond_with(msg_buf).with_application(ApciCode::FunctionPropertyStateResponse).with_data(|buf| {
                FpResponseWriter::write_empty(buf, hdr.object_idx, hdr.prop_id as u16);
            });
        ctx.base.lctx.push_outbox(msg.into_inner());
        return;
    }

    let req = FunctionPropertyRequest {
        object_idx: hdr.object_idx as u16,
        prop_id: hdr.prop_id,
        service_data,
        ctx: ctx.base.access,
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
    if !ctx.base.response_fits(response_len) {
        warn!("AL FunctionProperty response too large for APDU budget ({} bytes); dropping", response_len);
        return;
    }

    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(response_len) else {
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
    ctx.base.lctx.push_outbox(msg.into_inner());
}
