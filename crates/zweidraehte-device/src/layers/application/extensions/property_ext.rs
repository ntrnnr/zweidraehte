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
    layer_context::HasOutbox,
    layers::application::extensions::{AlExtensionContext, AlServiceExtension},
    memory::MemoryMap,
    messages::{
        apdu::property_ext::{
            FunctionPropertyExtHeader, FunctionPropertyExtResponse, PropertyExtValueHeader, PropertyExtValueResponse,
            PropertyExtValueWriteConRes, return_code,
        },
        buffers::Buffer,
        builder::{IndicationExt, MessageBuilder},
        knx::{ApciCode, DestinationAddress, KnxMessageBuffer, Priority, ServiceType, offsets},
    },
    objects::{
        comm::{ComObjects, HasCommObjects},
        interface::{
            FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, PropertyServiceHandler, pid,
        },
        tables::{
            AddressTable, AssociationTable, CommunicationObjectTable, HasAddressTable, HasAssociationTable,
            HasCommunicationObjectTable,
        },
    },
};

use crate::logging::{debug, error, warn};

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
    ) -> bool {
        match apci {
            ApciCode::PropertyExtValueRead => {
                handle_ext_value_read::<D>(msg, ctx);
                true
            }
            ApciCode::PropertyExtValueWriteCon => {
                handle_ext_value_write_con::<D>(msg, ctx);
                true
            }
            ApciCode::PropertyExtValueWriteUnCon => {
                handle_ext_value_write_uncon::<D>(msg, ctx);
                true
            }
            // Extended function property services.
            ApciCode::FunctionPropertyExtCommand => {
                handle_function_property_ext_command::<D>(msg, ctx);
                true
            }
            ApciCode::FunctionPropertyExtStateRead => {
                handle_function_property_ext_state_read::<D>(msg, ctx);
                true
            }
            ApciCode::PropertyExtDescriptionRead => {
                handle_ext_description_read::<D>(msg, ctx);
                true
            }
            // Memory Extended services (24-bit addressing).
            ApciCode::MemoryExtendedWrite => {
                handle_memory_ext_write::<D>(msg, ctx);
                true
            }
            ApciCode::MemoryExtendedRead => {
                handle_memory_ext_read::<D>(msg, ctx);
                true
            }
            // Response APCIs — we are the responder, ignore if received.
            ApciCode::PropertyExtValueResponse
            | ApciCode::PropertyExtValueWriteConRes
            | ApciCode::PropertyExtValueInfoReport
            | ApciCode::FunctionPropertyExtStateResponse
            | ApciCode::PropertyExtDescriptionResponse
            | ApciCode::MemoryExtendedWriteResponse
            | ApciCode::MemoryExtendedReadResponse => {
                debug!("AL ignoring {:?} (response/report APCI)", apci);
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
fn handle_ext_value_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlExtensionContext<'_, D>) {
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
        send_ext_read_error(ind, ctx, &hdr, return_code::E_ADDRESS_VOID);
        return;
    };

    // Validate per spec Figure 55 using the property description.
    if let Ok(desc) = ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        if is_function_pdt(desc.pdt) {
            debug!("AL PropertyExtValueRead: PDT_CONTROL/FUNCTION → type conflict");
            send_ext_read_error(ind, ctx, &hdr, return_code::E_DATA_TYPE_CONFLICT);
            return;
        }
        // Check start_index + count doesn't exceed max_elements (for non-count-query reads).
        if hdr.start_idx > 0 && desc.max_elements > 0 {
            let end = hdr.start_idx as u32 + hdr.count as u32 - 1;
            if end > desc.max_elements as u32 {
                debug!("AL PropertyExtValueRead: range exceeds max_elements");
                send_ext_read_error(ind, ctx, &hdr, return_code::E_ADDRESS_VOID);
                return;
            }
        }
    }

    // Per spec Figure 55: nr_of_elem must be > 0.
    if hdr.count == 0 {
        send_ext_read_error(ind, ctx, &hdr, return_code::E_ADDRESS_VOID);
        return;
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
            let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(response_len) else {
                warn!("AL no buffer for PropertyExtValueResponse");
                return;
            };

            // Per spec: if start_idx=0 (element count query), response count=1.
            let response_count = if hdr.start_idx == 0 { 1 } else { hdr.count };

            let msg = ind.respond_with(msg_buf).with_application(ApciCode::PropertyExtValueResponse).with_data(|buf| {
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
            ctx.lctx.push_outbox(msg.into_inner());
        }
        Err(e) => {
            warn!("AL PropertyExtValueRead failed: {:?}", e);
            send_ext_read_error(ind, ctx, &hdr, e.to_ext_return_code());
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
        hdr.object_type,
        hdr.object_instance,
        hdr.prop_id,
        hdr.count,
        hdr.start_idx,
        data.len()
    );

    // Resolve (IOT, instance) → flat object index.
    let Some(object_idx) = ctx.interface_objects.resolve_ext_object_index(hdr.object_type, hdr.object_instance) else {
        send_ext_write_con_error(ind, ctx, &hdr, return_code::E_ADDRESS_VOID);
        return;
    };

    // Validate per spec Figure 55 using the property description.
    if let Ok(desc) = ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        // PDT_CONTROL and PDT_FUNCTION properties are normally accessed via
        // FunctionPropertyCommand, not PropertyValueWrite. However,
        // LOAD_STATE_CONTROL (PID 5) is a special case — the spec allows
        // writing it via property value services to trigger load state
        // transitions. Allow it through; reject other function PDTs.
        if is_function_pdt(desc.pdt) && hdr.prop_id != crate::objects::interface::pid::LOAD_STATE_CONTROL {
            debug!("AL PropertyExtValueWriteCon: PDT_CONTROL/FUNCTION → type conflict");
            send_ext_write_con_error(ind, ctx, &hdr, return_code::E_DATA_TYPE_CONFLICT);
            return;
        }

        // Check data size matches element count × element size.
        let elem_size = pdt_element_size(desc.pdt);
        if elem_size > 0 && hdr.count > 0 && hdr.start_idx > 0 {
            let expected_data_len = hdr.count as usize * elem_size;
            if data.len() != expected_data_len {
                debug!(
                    "AL PropertyExtValueWriteCon: data size {} != count {} × elem_size {}",
                    data.len(),
                    hdr.count,
                    elem_size
                );
                send_ext_write_con_error(ind, ctx, &hdr, return_code::E_DATA_TYPE_CONFLICT);
                return;
            }
        }

        // Check start_index + count doesn't exceed max_elements.
        if hdr.start_idx > 0 && desc.max_elements > 0 {
            let end = hdr.start_idx as u32 + hdr.count as u32 - 1;
            if end > desc.max_elements as u32 {
                debug!("AL PropertyExtValueWriteCon: range {}..{} > max {}", hdr.start_idx, end, desc.max_elements);
                send_ext_write_con_error(ind, ctx, &hdr, return_code::E_ADDRESS_VOID);
                return;
            }
        }
    }

    // Per spec Figure 55: nr_of_elem must be > 0.
    if hdr.count == 0 {
        send_ext_write_con_error(ind, ctx, &hdr, return_code::E_ADDRESS_VOID);
        return;
    }

    // Element-count write (start_index=0): data must be exactly 2 bytes.
    if hdr.start_idx == 0 && data.len() != 2 {
        debug!("AL PropertyExtValueWriteCon: element-count write with {} data bytes (expected 2)", data.len());
        send_ext_write_con_error(ind, ctx, &hdr, return_code::E_DATA_TYPE_CONFLICT);
        return;
    }

    let req = FullPropertyWriteRequest {
        object_idx,
        pid: hdr.prop_id,
        count: hdr.count as u16,
        start_idx: hdr.start_idx,
        data,
        ctx: ctx.access_ctx,
    };
    let result = ctx.interface_objects.property_value_write(&req);

    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(PropertyExtValueWriteConRes::MSG_LEN) else {
        warn!("AL no buffer for PropertyExtValueWriteConRes");
        return;
    };

    match result {
        Ok(_write_response) => {
            let msg =
                ind.respond_with(msg_buf).with_application(ApciCode::PropertyExtValueWriteConRes).with_data(|buf| {
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
            ctx.lctx.push_outbox(msg.into_inner());
        }
        Err(e) => {
            warn!("AL PropertyExtValueWriteCon failed: {:?}", e);
            let msg =
                ind.respond_with(msg_buf).with_application(ApciCode::PropertyExtValueWriteConRes).with_data(|buf| {
                    PropertyExtValueWriteConRes::write_error(
                        buf,
                        hdr.object_type,
                        hdr.object_instance,
                        hdr.prop_id,
                        hdr.start_idx,
                        e.to_ext_return_code(),
                    );
                });
            ctx.lctx.push_outbox(msg.into_inner());
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
        hdr.object_type,
        hdr.object_instance,
        hdr.prop_id,
        hdr.count,
        hdr.start_idx,
        data.len()
    );

    // Per spec: nr_of_elem must be > 0, otherwise ignore.
    if hdr.count == 0 {
        debug!("AL PropertyExtValueWriteUnCon: count=0, ignoring");
        return;
    }

    // Resolve (IOT, instance) → flat object index. Ignore if not found.
    let Some(object_idx) = ctx.interface_objects.resolve_ext_object_index(hdr.object_type, hdr.object_instance) else {
        debug!("AL PropertyExtValueWriteUnCon: object not found, ignoring");
        return;
    };

    // Validate against property description. Ignore invalid writes.
    if let Ok(desc) = ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        if is_function_pdt(desc.pdt) {
            debug!("AL PropertyExtValueWriteUnCon: PDT_FUNCTION/CONTROL → ignoring");
            return;
        }
        let elem_size = pdt_element_size(desc.pdt);
        if elem_size > 0 && hdr.count > 0 && hdr.start_idx > 0 {
            let expected_data_len = hdr.count as usize * elem_size;
            if data.len() != expected_data_len {
                debug!("AL PropertyExtValueWriteUnCon: data size mismatch, ignoring");
                return;
            }
        }
        if hdr.start_idx > 0 && desc.max_elements > 0 {
            let end = hdr.start_idx as u32 + hdr.count as u32 - 1;
            if end > desc.max_elements as u32 {
                debug!("AL PropertyExtValueWriteUnCon: range exceeds max_elements, ignoring");
                return;
            }
        }
    }

    // Element-count write (start_index=0): data must be exactly 2 bytes.
    if hdr.start_idx == 0 && data.len() != 2 {
        debug!("AL PropertyExtValueWriteUnCon: element-count write with {} bytes (expected 2), ignoring", data.len());
        return;
    }

    let req = FullPropertyWriteRequest {
        object_idx,
        pid: hdr.prop_id,
        count: hdr.count as u16,
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
    hdr: &PropertyExtValueHeader,
    return_code: u8,
) {
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(PropertyExtValueResponse::ERROR_MSG_LEN) else {
        warn!("AL no buffer for PropertyExtValueResponse error");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::PropertyExtValueResponse).with_data(|buf| {
        PropertyExtValueResponse::write_error(
            buf,
            hdr.object_type,
            hdr.object_instance,
            hdr.prop_id,
            hdr.start_idx,
            return_code,
        );
    });

    ctx.lctx.push_outbox(msg.into_inner());
}

/// Send an error `A_PropertyExtValue_WriteConRes` with the given return code.
fn send_ext_write_con_error<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    hdr: &PropertyExtValueHeader,
    return_code: u8,
) {
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(PropertyExtValueWriteConRes::MSG_LEN) else {
        warn!("AL no buffer for PropertyExtValueWriteConRes error");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::PropertyExtValueWriteConRes).with_data(|buf| {
        PropertyExtValueWriteConRes::write_error(
            buf,
            hdr.object_type,
            hdr.object_instance,
            hdr.prop_id,
            hdr.start_idx,
            return_code,
        );
    });

    ctx.lctx.push_outbox(msg.into_inner());
}

/// Check whether a PDT code represents a function/control property type
/// that cannot be accessed via regular property read/write services.
fn is_function_pdt(pdt: u8) -> bool {
    use crate::dpt::{PDT_Control, PDT_Function, PropertyDataDefinition};
    pdt == PDT_Control::ID || pdt == PDT_Function::ID
}

/// Get the element size in bytes for a given PDT code.
///
/// Returns 0 for unknown/variable-size PDTs.
fn pdt_element_size(pdt: u8) -> usize {
    match pdt {
        0x01 => 1,  // PDT_CHAR
        0x02 => 1,  // PDT_UNSIGNED_CHAR
        0x03 => 2,  // PDT_INT
        0x04 => 2,  // PDT_UNSIGNED_INT
        0x06 => 4,  // PDT_FLOAT
        0x07 => 3,  // PDT_DATE
        0x08 => 3,  // PDT_TIME
        0x09 => 4,  // PDT_LONG
        0x0A => 4,  // PDT_UNSIGNED_LONG
        0x0B => 4,  // PDT_FLOAT32
        0x0C => 10, // PDT_CHAR_BLOCK
        0x0E => 5,  // PDT_SHORT_CHAR_BLOCK
        // PDT_GENERIC_xx: code 0x11..0x24 → size = code - 0x10
        c @ 0x11..=0x24 => (c - 0x10) as usize,
        _ => 0,
    }
}

// ============================================================================
// Function Property Extended Handlers
// ============================================================================

/// Handle `A_FunctionPropertyExtCommand.ind`.
///
/// Resolves `(IOT, instance)` → flat object index, delegates to the
/// existing `function_property_command` handler, responds with
/// `A_FunctionPropertyExtState_Response`.
fn handle_function_property_ext_command<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) {
    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL FunctionPropertyExtCommand unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(hdr) = FunctionPropertyExtHeader::parse(ind.buf()) else {
        error!("FunctionPropertyExtCommand message too short: {}", ind.len());
        return;
    };
    let data = hdr.data(ind.buf());

    debug!(
        "AL FunctionPropertyExtCommand: iot=0x{:04X}, inst=0x{:04X}, pid={}, data_len={}",
        hdr.object_type,
        hdr.object_instance,
        hdr.prop_id,
        data.len()
    );

    let Some(object_idx) = ctx.interface_objects.resolve_ext_object_index(hdr.object_type, hdr.object_instance) else {
        send_function_ext_response(ind, ctx, &hdr, return_code::E_ADDRESS_VOID, &[]);
        return;
    };

    // Check PDT: only PDT_FUNCTION and PDT_CONTROL properties can be accessed
    // via function property services. Other PDTs get an empty response (no
    // return_code, no data) per spec 3.4.7.3.
    match ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        Ok(desc) if !is_function_pdt(desc.pdt) => {
            debug!("AL FunctionPropertyExtCommand: PDT 0x{:02X} is not function/control → empty response", desc.pdt);
            send_function_ext_response(ind, ctx, &hdr, return_code::E_DATA_TYPE_CONFLICT, &[]);
            return;
        }
        Err(_) => {
            // PID doesn't exist on this object.
            send_function_ext_response(ind, ctx, &hdr, return_code::E_ADDRESS_VOID, &[]);
            return;
        }
        Ok(_) => {} // PDT_FUNCTION or PDT_CONTROL — proceed.
    }

    let req = FunctionPropertyRequest { object_idx, prop_id: hdr.prop_id, service_data: data, ctx: ctx.access_ctx };
    let result = ctx.interface_objects.function_property_command(&req);

    let response_len = FunctionPropertyExtResponse::msg_len(result.data.len());
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(response_len) else {
        warn!("AL no buffer for FunctionPropertyExtState_Response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::FunctionPropertyExtStateResponse).with_data(|buf| {
        FunctionPropertyExtResponse::write(
            buf,
            hdr.object_type,
            hdr.object_instance,
            hdr.prop_id,
            result.return_code,
            result.data.as_slice(),
        );
    });

    debug!("AL sending FunctionPropertyExtState_Response: rc=0x{:02X}", result.return_code);
    ctx.lctx.push_outbox(msg.into_inner());
}

/// Handle `A_FunctionPropertyExtState_Read.ind`.
///
/// Same pattern as Command but delegates to `function_property_state_read`.
fn handle_function_property_ext_state_read<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) {
    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL FunctionPropertyExtStateRead unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(hdr) = FunctionPropertyExtHeader::parse(ind.buf()) else {
        error!("FunctionPropertyExtStateRead message too short: {}", ind.len());
        return;
    };
    let data = hdr.data(ind.buf());

    debug!(
        "AL FunctionPropertyExtStateRead: iot=0x{:04X}, inst=0x{:04X}, pid={}, data_len={}",
        hdr.object_type,
        hdr.object_instance,
        hdr.prop_id,
        data.len()
    );

    let Some(object_idx) = ctx.interface_objects.resolve_ext_object_index(hdr.object_type, hdr.object_instance) else {
        send_function_ext_response(ind, ctx, &hdr, return_code::E_ADDRESS_VOID, &[]);
        return;
    };

    // Check PDT (same as Command handler).
    match ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        Ok(desc) if !is_function_pdt(desc.pdt) => {
            debug!("AL FunctionPropertyExtStateRead: PDT 0x{:02X} is not function/control → empty response", desc.pdt);
            send_function_ext_response(ind, ctx, &hdr, return_code::E_DATA_TYPE_CONFLICT, &[]);
            return;
        }
        Err(_) => {
            send_function_ext_response(ind, ctx, &hdr, return_code::E_ADDRESS_VOID, &[]);
            return;
        }
        Ok(_) => {}
    }

    let req = FunctionPropertyRequest { object_idx, prop_id: hdr.prop_id, service_data: data, ctx: ctx.access_ctx };
    let result = ctx.interface_objects.function_property_state_read(&req);

    let response_len = FunctionPropertyExtResponse::msg_len(result.data.len());
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(response_len) else {
        warn!("AL no buffer for FunctionPropertyExtState_Response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::FunctionPropertyExtStateResponse).with_data(|buf| {
        FunctionPropertyExtResponse::write(
            buf,
            hdr.object_type,
            hdr.object_instance,
            hdr.prop_id,
            result.return_code,
            result.data.as_slice(),
        );
    });

    debug!("AL sending FunctionPropertyExtState_Response: rc=0x{:02X}", result.return_code);
    ctx.lctx.push_outbox(msg.into_inner());
}

// ============================================================================
// Function Property Extended Response Helpers
// ============================================================================

/// Send a `FunctionPropertyExtState_Response` with return_code and optional data.
fn send_function_ext_response<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    hdr: &FunctionPropertyExtHeader,
    rc: u8,
    data: &[u8],
) {
    let response_len = FunctionPropertyExtResponse::msg_len(data.len());
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(response_len) else {
        warn!("AL no buffer for FunctionPropertyExtState_Response");
        return;
    };
    let msg = ind.respond_with(msg_buf).with_application(ApciCode::FunctionPropertyExtStateResponse).with_data(|buf| {
        FunctionPropertyExtResponse::write(buf, hdr.object_type, hdr.object_instance, hdr.prop_id, rc, data);
    });
    ctx.lctx.push_outbox(msg.into_inner());
}

/// Send an empty `FunctionPropertyExtState_Response` (no return_code, no data).
///
/// Used when the addressed property is not PDT_FUNCTION or PDT_CONTROL
/// (spec 3.4.7.3).
fn send_function_ext_empty_response<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    hdr: &FunctionPropertyExtHeader,
) {
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(FunctionPropertyExtResponse::EMPTY_MSG_LEN) else {
        warn!("AL no buffer for FunctionPropertyExtState_Response");
        return;
    };
    let msg = ind.respond_with(msg_buf).with_application(ApciCode::FunctionPropertyExtStateResponse).with_data(|buf| {
        FunctionPropertyExtResponse::write_empty(buf, hdr.object_type, hdr.object_instance, hdr.prop_id);
    });
    ctx.lctx.push_outbox(msg.into_inner());
}

// ============================================================================
// PropertyExtDescription Handler
// ============================================================================

/// Handle `A_PropertyExtDescription_Read.ind`.
///
/// Wire format request (APDU-relative):
/// ```text
/// [0-1]: APCI (0x01D2)
/// [2-3]: IOT (u16)
/// [4-5]: instance (u16)
/// [6]:   PID (0 = search by prop_index)
/// [7-8]: desc_type (high nibble of [7]) | prop_index (low 12 bits of [7-8])
/// ```
///
/// Response: APCI(2) + IOT(2) + INST(2) + PID(1) + propIdx(2) + descType(1) +
///           PDT+WrEnable(1) + MaxElem(2) + Access(1) = 14 data + 2 APCI = 16 bytes.
/// Error: all descriptor bytes zero.
fn handle_ext_description_read<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) {
    use crate::messages::knx::offsets;

    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL PropertyExtDescriptionRead unexpected service type: {:?}", ind.service_type());
        return;
    }

    let buf = ind.buf();
    // Min length: APCI(2) + IOT(2) + INST(2) + PID(1) + descType_propIdx(2) = 9 bytes from MSG_APCI
    if buf.len() < offsets::MSG_APCI + 9 {
        error!("PropertyExtDescriptionRead too short: {}", ind.len());
        return;
    }

    let base = offsets::MSG_APCI;
    let object_type = u16::from_be_bytes([buf[base + 2], buf[base + 3]]);
    let object_instance = u16::from_be_bytes([buf[base + 4], buf[base + 5]]);
    let pid = buf[base + 6];
    let desc_type_prop_idx_hi = buf[base + 7];
    let prop_idx_lo = buf[base + 8];
    // prop_index is in the lower 12 bits: high nibble of [7] low 4 bits + all of [8]
    let prop_idx = (((desc_type_prop_idx_hi & 0x0F) as u16) << 8) | prop_idx_lo as u16;

    debug!(
        "AL PropertyExtDescriptionRead: iot=0x{:04X}, inst=0x{:04X}, pid={}, prop_idx={}",
        object_type, object_instance, pid, prop_idx
    );

    // Response is always 16 bytes APDU.
    const RESP_LEN: usize = offsets::MSG_APCI + 17;

    // Resolve IOT + instance.
    let object_idx = ctx.interface_objects.resolve_ext_object_index(object_type, object_instance);

    // The service-level access policy is 3FF/3FF (spec 03/03/07 Table 11),
    // so the service itself is never rejected. However, the per-property
    // Data Secure access policy still determines whether the descriptor is
    // visible: properties with restrictive policies (e.g. 00C/00C on
    // Security IO) return all-zero when accessed in plain mode with
    // security mode enabled.
    let desc_result = object_idx.and_then(|idx| {
        let desc_resp = ctx.interface_objects.property_description_read(idx, pid, prop_idx).ok()?;

        // Check per-property access policy via a dummy element-count read.
        // If the property value is access-denied, hide the descriptor too.
        let test_req = FullPropertyReadRequest {
            object_idx: idx,
            pid: desc_resp.prop_id,
            start_idx: 0,
            count: 1,
            ctx: ctx.access_ctx,
        };
        let mut dummy = [0u8; 4];
        match ctx.interface_objects.property_value_read(&test_req, &mut dummy) {
            Err(crate::objects::interface::PropertyError::AccessDenied) => None,
            _ => Some(desc_resp),
        }
    });

    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(RESP_LEN) else {
        warn!("AL no buffer for PropertyExtDescriptionResponse");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::PropertyExtDescriptionResponse).with_data(|buf| {
        // Write IOT + INST + PID header.
        let b = offsets::MSG_APCI;
        buf[b + 2..b + 4].copy_from_slice(&object_type.to_be_bytes());
        buf[b + 4..b + 6].copy_from_slice(&object_instance.to_be_bytes());

        match desc_result {
            Some(desc) => {
                buf[b + 6] = desc.prop_id;
                // PropIdx as 12 bits: desc_type (high nibble of [7]) = 0,
                // prop_idx high nibble in low nibble of [7], low byte in [8].
                buf[b + 7] = (desc.prop_idx >> 8) as u8 & 0x0F;
                buf[b + 8] = desc.prop_idx as u8;
                // PDT + Writeable flag
                buf[b + 9] = if desc.writeable { 0x80 } else { 0x00 } | (desc.pdt & 0x3F);
                // MaxElements (2 bytes, upper 4 bits from PDT)
                let pdt_max = ((desc.pdt as u16 & 0x3F) << 12) | (desc.max_elements & 0x0FFF);
                buf[b + 10] = (pdt_max >> 8) as u8;
                buf[b + 11] = pdt_max as u8;
                // Access levels
                buf[b + 12] = (desc.read_level << 4) | desc.write_level;
                // Remaining bytes zero (padding to 16 bytes APDU).
                for i in (b + 13)..(b + 16) {
                    buf[i] = 0;
                }
            }
            None => {
                // Error: echo PID, zero everything else.
                buf[b + 6] = pid;
                buf[b + 7] = desc_type_prop_idx_hi;
                buf[b + 8] = prop_idx_lo;
                for i in (b + 9)..(b + 16) {
                    buf[i] = 0;
                }
            }
        }
    });

    ctx.lctx.push_outbox(msg.into_inner());
}

// ============================================================================
// MemoryExtended Handlers
// ============================================================================

/// Handle `A_MemoryExtended_Write.ind`.
///
/// Wire format: APCI(2) + count(1) + address(3) + data(count)
/// Response:    APCI(2) + return_code(1) + address(3)
fn handle_memory_ext_write<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) {
    use crate::messages::knx::offsets;

    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        return;
    }

    let buf = ind.buf();
    if buf.len() < offsets::MSG_APCI + 6 {
        error!("MemoryExtendedWrite too short: {}", ind.len());
        return;
    }

    let base = offsets::MSG_APCI;
    let count = buf[base + 2] as usize;
    let addr_hi = buf[base + 3];
    let addr_mid = buf[base + 4];
    let addr_lo = buf[base + 5];
    let address = ((addr_hi as u32) << 16) | ((addr_mid as u32) << 8) | (addr_lo as u32);

    let data_start = base + 6;
    let data_end = data_start + count;

    debug!("AL MemoryExtendedWrite: addr=0x{:06X}, count={}", address, count);

    // Validate count > 0.
    if count == 0 {
        send_memory_ext_write_response(ind, ctx, 0xFD, addr_hi, addr_mid, addr_lo);
        return;
    }

    // Validate data length matches count exactly.
    let actual_data_len = buf.len() - data_start;
    if actual_data_len != count {
        let rc = 0xFEu8; // E_DATA_TYPE_CONFLICT (size mismatch)
        send_memory_ext_write_response(ind, ctx, rc, addr_hi, addr_mid, addr_lo);
        return;
    }

    let data = &buf[data_start..data_end];

    // Use lower 16 bits of address for our memory map.
    let addr16 = (address & 0xFFFF) as u16;
    let result = ctx.memory_map.write(ctx.state, addr16, data, ctx.access_ctx);

    let rc = match result {
        Ok(_) => 0x00,                                         // E_SUCCESS
        Err(crate::memory::MemoryError::AccessDenied) => 0xFC, // E_ILLEGAL_COMMAND
        Err(_) => 0xFD,                                        // E_ADDRESS_VOID
    };

    send_memory_ext_write_response(ind, ctx, rc, addr_hi, addr_mid, addr_lo);
}

/// Handle `A_MemoryExtended_Read.ind`.
///
/// Wire format: APCI(2) + count(1) + address(3)
/// Response:    APCI(2) + return_code(1) + address(3) + data(count)
fn handle_memory_ext_read<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) {
    use crate::messages::knx::offsets;

    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        return;
    }

    let buf = ind.buf();
    if buf.len() < offsets::MSG_APCI + 6 {
        error!("MemoryExtendedRead too short: {}", ind.len());
        return;
    }

    let base = offsets::MSG_APCI;
    let count = buf[base + 2] as usize;
    let addr_hi = buf[base + 3];
    let addr_mid = buf[base + 4];
    let addr_lo = buf[base + 5];
    let address = ((addr_hi as u32) << 16) | ((addr_mid as u32) << 8) | (addr_lo as u32);

    debug!("AL MemoryExtendedRead: addr=0x{:06X}, count={}", address, count);

    if count == 0 {
        // Error: count=0
        let resp_len = offsets::MSG_APCI + 6; // APCI + rc + addr
        let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(resp_len) else { return };
        let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedReadResponse).with_data(|buf| {
            buf[base + 2] = 0xFD;
            buf[base + 3] = addr_hi;
            buf[base + 4] = addr_mid;
            buf[base + 5] = addr_lo;
        });
        ctx.lctx.push_outbox(msg.into_inner());
        return;
    }

    let addr16 = (address & 0xFFFF) as u16;
    let mut data_buf = [0u8; 252]; // Max extended memory read
    let read_len = count.min(data_buf.len());

    let result = ctx.memory_map.read(ctx.state, addr16, &mut data_buf[..read_len], ctx.access_ctx);

    match result {
        Ok(n) => {
            let resp_len = offsets::MSG_APCI + 6 + n;
            let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(resp_len) else { return };
            let msg =
                ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedReadResponse).with_data(|buf| {
                    buf[base + 2] = 0x00; // E_SUCCESS
                    buf[base + 3] = addr_hi;
                    buf[base + 4] = addr_mid;
                    buf[base + 5] = addr_lo;
                    buf[base + 6..base + 6 + n].copy_from_slice(&data_buf[..n]);
                });
            ctx.lctx.push_outbox(msg.into_inner());
        }
        Err(e) => {
            let rc = match e {
                crate::memory::MemoryError::AccessDenied => 0xFC, // E_ILLEGAL_COMMAND
                _ => 0xFD,                                        // E_ADDRESS_VOID
            };
            let resp_len = offsets::MSG_APCI + 6;
            let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(resp_len) else { return };
            let msg =
                ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedReadResponse).with_data(|buf| {
                    buf[base + 2] = rc;
                    buf[base + 3] = addr_hi;
                    buf[base + 4] = addr_mid;
                    buf[base + 5] = addr_lo;
                });
            ctx.lctx.push_outbox(msg.into_inner());
        }
    }
}

fn send_memory_ext_write_response<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    return_code: u8,
    addr_hi: u8,
    addr_mid: u8,
    addr_lo: u8,
) {
    use crate::messages::knx::offsets;
    let resp_len = offsets::MSG_APCI + 6; // APCI(2) + rc(1) + addr(3)
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(resp_len) else { return };
    let base = offsets::MSG_APCI;
    let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedWriteResponse).with_data(|buf| {
        buf[base + 2] = return_code;
        buf[base + 3] = addr_hi;
        buf[base + 4] = addr_mid;
        buf[base + 5] = addr_lo;
    });
    ctx.lctx.push_outbox(msg.into_inner());
}
