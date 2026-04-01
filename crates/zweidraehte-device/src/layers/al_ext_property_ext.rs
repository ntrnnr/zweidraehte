//! Extended property services AL extension (AN163).
//!
//! Handles `A_PropertyExtValue_Read/WriteCon/WriteUnCon/Response/WriteConRes/InfoReport`
//! services that use `(interface_object_type, object_instance)` addressing
//! instead of flat `object_index`.
//!
//! # Usage
//!
//! Set `type AlExtension = PropertyExtValueExtension;` in your
//! [`StackDefinition`] impl, or compose with other extensions:
//!
//! ```rust,ignore
//! type AlExtension = (PropertyExtValueExtension, DomainAddressExtension);
//! ```

use crate::{
    definition::StackDefinition,
    layers::al_extension::{AlExtensionContext, AlServiceExtension},
    messages::{
        apdu::property_ext::{
            PropertyExtValueHeader, PropertyExtValueResponse, PropertyExtValueWriteConRes,
            return_code,
        },
        buffers::Buffer,
        builder::IndicationExt,
        knx::{ApciCode, KnxMessageBuffer, ServiceType},
    },
    objects::interface::{FullPropertyReadRequest, FullPropertyWriteRequest, PropertyServiceHandler},
    router::Outbox,
};

#[cfg(not(feature = "defmt"))]
use log::{debug, error, warn};

#[cfg(feature = "defmt")]
use defmt::{debug, error, warn};

// ============================================================================
// Extension Type
// ============================================================================

/// AL service extension for AN163 extended property services.
///
/// Handles:
/// - `A_PropertyExtValue_Read` → read property, respond with `Response`
/// - `A_PropertyExtValue_WriteCon` → write property, respond with `WriteConRes`
/// - `A_PropertyExtValue_WriteUnCon` → write property, no response
/// - `A_PropertyExtValue_Response` / `WriteConRes` / `InfoReport` → ignored
#[derive(Default)]
pub struct PropertyExtValueExtension;

impl<D> AlServiceExtension<D> for PropertyExtValueExtension
where
    D: StackDefinition,
{
    fn try_handle(
        &mut self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlExtensionContext<'_, D>,
        outbox: &mut Outbox,
    ) -> bool {
        match apci {
            ApciCode::PropertyExtValueRead => {
                handle_ext_value_read::<D>(msg, ctx, outbox);
                true
            }
            ApciCode::PropertyExtValueWriteCon => {
                handle_ext_value_write_con::<D>(msg, ctx, outbox);
                true
            }
            ApciCode::PropertyExtValueWriteUnCon => {
                handle_ext_value_write_uncon::<D>(msg, ctx);
                true
            }
            // Response APCIs — we are the responder, ignore if received.
            ApciCode::PropertyExtValueResponse
            | ApciCode::PropertyExtValueWriteConRes
            | ApciCode::PropertyExtValueInfoReport => {
                debug!("AL ignoring PropertyExtValue_{:?} (response/report APCI)", apci);
                true
            }
            _ => false,
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Handle `A_PropertyExtValue_Read.ind`.
///
/// Resolves `(IOT, instance)` → flat object index, reads the property,
/// and responds with `A_PropertyExtValue_Response`.
fn handle_ext_value_read<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    outbox: &mut Outbox,
) {
    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL PropertyExtValueRead unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(hdr) = PropertyExtValueHeader::parse(ind.buf()) else {
        error!("PropertyExtValueRead message too short: {}", ind.len());
        return;
    };

    debug!(
        "AL PropertyExtValueRead: iot=0x{:04X}, inst=0x{:04X}, pid={}, count={}, start={}",
        hdr.object_type, hdr.object_instance, hdr.prop_id, hdr.count, hdr.start_idx
    );

    // Resolve (IOT, instance) → flat object index.
    let Some(object_idx) = ctx.interface_objects.resolve_ext_object_index(hdr.object_type, hdr.object_instance) else {
        send_ext_read_error(ind, ctx, outbox, &hdr, return_code::E_ADDRESS_VOID);
        return;
    };

    // Per spec Figure 55: reject reads of PDT_CONTROL and PDT_FUNCTION properties
    // with E_DATA_TYPE_CONFLICT. These must be accessed via FunctionProperty services.
    if let Ok(desc) = ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        if is_function_pdt(desc.pdt) {
            debug!("AL PropertyExtValueRead: PDT_CONTROL/FUNCTION (0x{:02X}) → type conflict", desc.pdt);
            send_ext_read_error(ind, ctx, outbox, &hdr, return_code::E_DATA_TYPE_CONFLICT);
            return;
        }
    }

    const MAX_PROPERTY_DATA: usize = 64;
    let mut data_buf = [0u8; MAX_PROPERTY_DATA];

    let req = FullPropertyReadRequest {
        object_idx,
        pid: hdr.prop_id,
        start_idx: hdr.start_idx,
        count: hdr.count as u16,
        ctx: ctx.access_ctx,
    };
    let result = ctx.interface_objects.property_value_read(&req, &mut data_buf);

    match result {
        Ok(data_len) => {
            let response_len = PropertyExtValueResponse::msg_len(data_len);
            let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(response_len) else {
                warn!("AL no buffer for PropertyExtValueResponse");
                return;
            };

            // Per spec: if start_idx=0 (element count query), response count=1.
            let response_count = if hdr.start_idx == 0 { 1 } else { hdr.count };

            let msg = ind
                .respond_with(msg_buf)
                .with_application(ApciCode::PropertyExtValueResponse)
                .with_data(|buf| {
                    PropertyExtValueResponse::write(
                        buf,
                        hdr.object_type,
                        hdr.object_instance,
                        hdr.prop_id,
                        response_count,
                        hdr.start_idx,
                        &data_buf[..data_len],
                    );
                });

            debug!("AL sending PropertyExtValueResponse: {} bytes", data_len);
            outbox.push(msg.into_inner());
        }
        Err(e) => {
            warn!("AL PropertyExtValueRead failed: {:?}", e);
            send_ext_read_error(ind, ctx, outbox, &hdr, e.to_ext_return_code());
        }
    }
}

/// Handle `A_PropertyExtValue_WriteCon.ind`.
///
/// Confirmed write: resolves, writes, responds with `WriteConRes` carrying
/// a return code.
fn handle_ext_value_write_con<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    outbox: &mut Outbox,
) {
    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL PropertyExtValueWriteCon unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(hdr) = PropertyExtValueHeader::parse(ind.buf()) else {
        error!("PropertyExtValueWriteCon message too short: {}", ind.len());
        return;
    };
    let data = hdr.data(ind.buf());

    debug!(
        "AL PropertyExtValueWriteCon: iot=0x{:04X}, inst=0x{:04X}, pid={}, count={}, start={}, data_len={}",
        hdr.object_type, hdr.object_instance, hdr.prop_id, hdr.count, hdr.start_idx, data.len()
    );

    // Resolve (IOT, instance) → flat object index.
    let Some(object_idx) = ctx.interface_objects.resolve_ext_object_index(hdr.object_type, hdr.object_instance) else {
        send_ext_write_con_error(ind, ctx, outbox, &hdr, return_code::E_ADDRESS_VOID);
        return;
    };

    // Reject writes to PDT_CONTROL/FUNCTION properties (spec Figure 55).
    if let Ok(desc) = ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        if is_function_pdt(desc.pdt) {
            debug!("AL PropertyExtValueWriteCon: PDT_CONTROL/FUNCTION (0x{:02X}) → type conflict", desc.pdt);
            send_ext_write_con_error(ind, ctx, outbox, &hdr, return_code::E_DATA_TYPE_CONFLICT);
            return;
        }
    }

    let req = FullPropertyWriteRequest {
        object_idx,
        pid: hdr.prop_id,
        start_idx: hdr.start_idx,
        data,
        ctx: ctx.access_ctx,
    };
    let result = ctx.interface_objects.property_value_write(&req);

    let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(PropertyExtValueWriteConRes::MSG_LEN) else {
        warn!("AL no buffer for PropertyExtValueWriteConRes");
        return;
    };

    match result {
        Ok(_write_response) => {
            let msg = ind
                .respond_with(msg_buf)
                .with_application(ApciCode::PropertyExtValueWriteConRes)
                .with_data(|buf| {
                    PropertyExtValueWriteConRes::write_success(
                        buf,
                        hdr.object_type,
                        hdr.object_instance,
                        hdr.prop_id,
                        hdr.count,
                        hdr.start_idx,
                        return_code::E_SUCCESS,
                    );
                });
            debug!("AL sending PropertyExtValueWriteConRes: success");
            outbox.push(msg.into_inner());
        }
        Err(e) => {
            warn!("AL PropertyExtValueWriteCon failed: {:?}", e);
            let msg = ind
                .respond_with(msg_buf)
                .with_application(ApciCode::PropertyExtValueWriteConRes)
                .with_data(|buf| {
                    PropertyExtValueWriteConRes::write_error(
                        buf,
                        hdr.object_type,
                        hdr.object_instance,
                        hdr.prop_id,
                        hdr.start_idx,
                        e.to_ext_return_code(),
                    );
                });
            outbox.push(msg.into_inner());
        }
    }
}

/// Handle `A_PropertyExtValue_WriteUnCon.ind`.
///
/// Unconfirmed write: resolves and writes silently. No response is sent.
/// If the object/property doesn't exist, the request is ignored per spec.
fn handle_ext_value_write_uncon<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) {
    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL PropertyExtValueWriteUnCon unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(hdr) = PropertyExtValueHeader::parse(ind.buf()) else {
        error!("PropertyExtValueWriteUnCon message too short: {}", ind.len());
        return;
    };
    let data = hdr.data(ind.buf());

    debug!(
        "AL PropertyExtValueWriteUnCon: iot=0x{:04X}, inst=0x{:04X}, pid={}, count={}, start={}, data_len={}",
        hdr.object_type, hdr.object_instance, hdr.prop_id, hdr.count, hdr.start_idx, data.len()
    );

    // Resolve (IOT, instance) → flat object index. Ignore if not found.
    let Some(object_idx) = ctx.interface_objects.resolve_ext_object_index(hdr.object_type, hdr.object_instance) else {
        debug!("AL PropertyExtValueWriteUnCon: object not found, ignoring");
        return;
    };

    let req = FullPropertyWriteRequest {
        object_idx,
        pid: hdr.prop_id,
        start_idx: hdr.start_idx,
        data,
        ctx: ctx.access_ctx,
    };
    if let Err(e) = ctx.interface_objects.property_value_write(&req) {
        debug!("AL PropertyExtValueWriteUnCon write failed (ignored): {:?}", e);
    }
}

// ============================================================================
// Error Response Helpers
// ============================================================================

/// Send an error `A_PropertyExtValue_Response` with the given return code.
fn send_ext_read_error<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    outbox: &mut Outbox,
    hdr: &PropertyExtValueHeader,
    return_code: u8,
) {
    let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(PropertyExtValueResponse::ERROR_MSG_LEN) else {
        warn!("AL no buffer for PropertyExtValueResponse error");
        return;
    };

    let msg = ind
        .respond_with(msg_buf)
        .with_application(ApciCode::PropertyExtValueResponse)
        .with_data(|buf| {
            PropertyExtValueResponse::write_error(
                buf,
                hdr.object_type,
                hdr.object_instance,
                hdr.prop_id,
                hdr.start_idx,
                return_code,
            );
        });

    outbox.push(msg.into_inner());
}

/// Send an error `A_PropertyExtValue_WriteConRes` with the given return code.
fn send_ext_write_con_error<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    outbox: &mut Outbox,
    hdr: &PropertyExtValueHeader,
    return_code: u8,
) {
    let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(PropertyExtValueWriteConRes::MSG_LEN) else {
        warn!("AL no buffer for PropertyExtValueWriteConRes error");
        return;
    };

    let msg = ind
        .respond_with(msg_buf)
        .with_application(ApciCode::PropertyExtValueWriteConRes)
        .with_data(|buf| {
            PropertyExtValueWriteConRes::write_error(
                buf,
                hdr.object_type,
                hdr.object_instance,
                hdr.prop_id,
                hdr.start_idx,
                return_code,
            );
        });

    outbox.push(msg.into_inner());
}

/// Check whether a PDT code represents a function/control property type
/// that cannot be accessed via regular property read/write services.
fn is_function_pdt(pdt: u8) -> bool {
    use crate::dpt::{PDT_Control, PDT_Function, PropertyDataDefinition};
    pdt == PDT_Control::ID || pdt == PDT_Function::ID
}
