//! Extended property services AL extension (AN163).
//!
//! Handles `A_PropertyExtValue_Read/WriteCon/WriteUnCon/Response/WriteConRes/InfoReport`
//! services that use `(interface_object_type, object_instance)` addressing
//! instead of flat `object_index`.
//!
//! # Usage
//!
//! Set `type AlExtensions = PropertyExtValueService;` in your
//! [`StackDefinition`] impl, or compose with other extensions:
//!
//! ```rust,ignore
//! type AlExtensions = (PropertyExtValueService, DomainAddressService);
//! ```

use crate::{
    definition::StackDefinition,
    memory::{MemoryError, MemoryMap},
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, PropertyServiceHandler, pid,
    },
    service::{AlCtx, ApciHandler},
};
use zweidraehte_proto::messages::{
    apdu::property_ext::{
        FunctionPropertyExtHeader, FunctionPropertyExtResponse, PropertyExtValueHeader, PropertyExtValueResponse,
        PropertyExtValueWriteConRes, PropertyReturnCode,
    },
    buffers::Buffer,
    builder::IndicationExt,
    knx::{ApciCode, KnxMessageBuffer, ServiceType},
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
pub struct PropertyExtValueService;

impl<D> ApciHandler<D> for PropertyExtValueService
where
    D: StackDefinition,
{
    fn try_handle_apci(&self, apci: ApciCode, msg: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) -> bool {
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
fn handle_ext_value_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
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
        send_ext_read_error(ind, ctx, &hdr, PropertyReturnCode::AddressVoid);
        return;
    };

    // Validate per spec Figure 55 using the property description.
    if let Ok(desc) = ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        // PDT_FUNCTION must be accessed via FunctionPropertyExt services,
        // never via PropertyExtValue. PDT_CONTROL is normally similar,
        // but the load/run state machines are the canonical exceptions:
        // PID_LOAD_STATE_CONTROL is exposed as a 1-byte readable
        // load-state value via PropertyExtValue_Read (see TSS J §3.8.7.4
        // expected response and AN163 Table 4), and PID_RUN_STATE_CONTROL
        // reads back the run state the same way — both so the MaC can
        // read the current state without invoking a control function.
        if is_function_pdt(desc.pdt) && !is_state_machine_control(hdr.prop_id) {
            debug!("AL PropertyExtValueRead: PDT_CONTROL/FUNCTION → type conflict");
            send_ext_read_error(ind, ctx, &hdr, PropertyReturnCode::DataTypeConflict);
            return;
        }
        // A count that could never fit one APDU is refused F4h before the
        // element-range check gets a say: 03/03/07 §3.3's
        // `E_LENGTH_EXCEEDS_MAX_APDU_LENGTH` describes the *request*, not
        // the property, and TSS J 4.1.8 ("data exceeds Max APDU Length")
        // reads 254 elements of a 245-element property expecting exactly
        // that precedence — FDh would claim the range was the problem.
        let elem_size = pdt_element_size(desc.pdt);
        if hdr.start_idx > 0 && elem_size > 0 {
            let payload_cap = ctx.base.response_payload_cap(PropertyExtValueResponse::msg_len(0));
            if hdr.count as usize * elem_size > payload_cap {
                debug!("AL PropertyExtValueRead: requested count cannot fit an APDU");
                send_ext_read_error(ind, ctx, &hdr, PropertyReturnCode::LengthExceedsMaxApduLength);
                return;
            }
        }
        // A start index past the array is FDh; a count overshooting the
        // end is not — reads clamp to the available elements, the way a
        // MaC discovers an array's actual length (TSS J 3.8.2.1 reads
        // fifteen elements of the ten-character object name and gets the
        // ten). Writes keep their full range check: clamping a write
        // would silently drop data.
        if hdr.start_idx > 0 && desc.max_elements > 0 && hdr.start_idx as u32 > desc.max_elements as u32 {
            debug!("AL PropertyExtValueRead: start index past max_elements");
            send_ext_read_error(ind, ctx, &hdr, PropertyReturnCode::AddressVoid);
            return;
        }
    }

    // Per spec Figure 55: nr_of_elem must be > 0.
    if hdr.count == 0 {
        send_ext_read_error(ind, ctx, &hdr, PropertyReturnCode::AddressVoid);
        return;
    }

    // Local scratch. Sized to the largest APDU the stack can carry, so
    // that `payload_cap` below — derived from the device's advertised
    // `PID_MAX_APDULENGTH` — is what actually limits the answer.
    //
    // It was 64, which silently became the real ceiling: a device
    // advertising a 254-octet APDU still could not return more than 64
    // octets of a property, and a longer read failed with
    // `BufferTooSmall` rather than being served or refused for a reason
    // the requester could act on. Data security 4.1.7 reads exactly as
    // many elements as one APDU holds, which is the case that found it.
    const DATA_SCRATCH: usize = zweidraehte_proto::config::MAX_APDU_LENGTH_EXTENDED as usize;
    let mut data_buf = [0u8; DATA_SCRATCH];

    let payload_cap = ctx.base.response_payload_cap(PropertyExtValueResponse::msg_len(0)).min(DATA_SCRATCH);

    let req = FullPropertyReadRequest {
        object_idx,
        pid: hdr.prop_id,
        start_idx: hdr.start_idx,
        count: hdr.count as u16,
        ctx: ctx.base.access,
    };
    let result = ctx.interface_objects.property_value_read(&req, &mut data_buf[..payload_cap]);

    match result {
        Ok(data_len) if !ctx.base.response_fits(PropertyExtValueResponse::msg_len(data_len)) => {
            // Data read successfully but the full response would exceed
            // the APDU budget — spec 03/03/07 §3.3 dedicated RC.
            warn!("AL PropertyExtValueRead result too large for APDU budget");
            send_ext_read_error(ind, ctx, &hdr, PropertyReturnCode::LengthExceedsMaxApduLength);
        }
        Ok(data_len) => {
            let response_len = PropertyExtValueResponse::msg_len(data_len);
            let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(response_len) else {
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
            ctx.base.lctx.push_outbox(msg.into_inner());
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
fn handle_ext_value_write_con<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
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
        send_ext_write_con_error(ind, ctx, &hdr, PropertyReturnCode::AddressVoid);
        return;
    };

    // Validate per spec Figure 55 using the property description.
    if let Ok(desc) = ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        // PDT_CONTROL and PDT_FUNCTION properties are normally accessed via
        // FunctionPropertyCommand, not PropertyValueWrite. However, the
        // state machines are the exception the spec itself defines: a
        // write access to PID_LOAD_STATE_CONTROL / PID_RUN_STATE_CONTROL
        // *is* the event (03/05/01 §4.23.2.1 Table 93 / §4.24.2.3.2), and
        // DM_LoadStateMachineWrite (03/05/02 §3.31) delivers it as a
        // 10-octet record — event plus additional load information. TSS J
        // 4.2.1 and 6.1.11 write exactly that shape. Allow both through;
        // reject other function PDTs.
        if is_function_pdt(desc.pdt) && !is_state_machine_control(hdr.prop_id) {
            debug!("AL PropertyExtValueWriteCon: PDT_CONTROL/FUNCTION → type conflict");
            send_ext_write_con_error(ind, ctx, &hdr, PropertyReturnCode::DataTypeConflict);
            return;
        }
        // A state-machine-control write must be exactly the 10-octet
        // record DM_LoadStateMachineWrite defines (03/05/02 §3.31: one
        // event octet plus nine octets of event data). 4.2.10 probes 9 and
        // 11 octets and expects FEh — PDT_CONTROL has no fixed element
        // size, so the generic size check below cannot catch it.
        const LOAD_RECORD_LEN: usize = 10;
        if is_function_pdt(desc.pdt) && is_state_machine_control(hdr.prop_id) && data.len() != LOAD_RECORD_LEN {
            debug!("AL PropertyExtValueWriteCon: load record of {} octets (expected 10)", data.len());
            send_ext_write_con_error(ind, ctx, &hdr, PropertyReturnCode::DataTypeConflict);
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
                send_ext_write_con_error(ind, ctx, &hdr, PropertyReturnCode::DataTypeConflict);
                return;
            }
        }

        // Check start_index + count doesn't exceed max_elements.
        if hdr.start_idx > 0 && desc.max_elements > 0 {
            let end = hdr.start_idx as u32 + hdr.count as u32 - 1;
            if end > desc.max_elements as u32 {
                debug!("AL PropertyExtValueWriteCon: range {}..{} > max {}", hdr.start_idx, end, desc.max_elements);
                send_ext_write_con_error(ind, ctx, &hdr, PropertyReturnCode::AddressVoid);
                return;
            }
        }
    }

    // Per spec Figure 55: nr_of_elem must be > 0.
    if hdr.count == 0 {
        send_ext_write_con_error(ind, ctx, &hdr, PropertyReturnCode::AddressVoid);
        return;
    }

    // Element-count write (start_index=0): data must be exactly 2 bytes.
    if hdr.start_idx == 0 && data.len() != 2 {
        debug!("AL PropertyExtValueWriteCon: element-count write with {} data bytes (expected 2)", data.len());
        send_ext_write_con_error(ind, ctx, &hdr, PropertyReturnCode::DataTypeConflict);
        return;
    }

    let req = FullPropertyWriteRequest {
        object_idx,
        pid: hdr.prop_id,
        count: hdr.count as u16,
        start_idx: hdr.start_idx,
        data,
        ctx: ctx.base.access,
    };
    let result = ctx.interface_objects.property_value_write(&req);

    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(PropertyExtValueWriteConRes::MSG_LEN) else {
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
                        PropertyReturnCode::Success,
                    );
                });
            debug!("AL sending PropertyExtValueWriteConRes: success");
            ctx.base.lctx.push_outbox(msg.into_inner());
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
            ctx.base.lctx.push_outbox(msg.into_inner());
        }
    }
}

/// Handle `A_PropertyExtValue_WriteUnCon.ind`.
///
/// Unconfirmed write: resolves and writes silently. No response is sent.
/// If the object/property doesn't exist, the request is ignored per spec.
fn handle_ext_value_write_uncon<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
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
        ctx: ctx.base.access,
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
    ctx: &AlCtx<'_, D>,
    hdr: &PropertyExtValueHeader,
    return_code: PropertyReturnCode,
) {
    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(PropertyExtValueResponse::ERROR_MSG_LEN) else {
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

    ctx.base.lctx.push_outbox(msg.into_inner());
}

/// Send an error `A_PropertyExtValue_WriteConRes` with the given return code.
fn send_ext_write_con_error<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlCtx<'_, D>,
    hdr: &PropertyExtValueHeader,
    return_code: PropertyReturnCode,
) {
    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(PropertyExtValueWriteConRes::MSG_LEN) else {
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

    ctx.base.lctx.push_outbox(msg.into_inner());
}

/// Check whether a PDT code represents a function/control property type
/// that cannot be accessed via regular property read/write services.
fn is_function_pdt(pdt: u8) -> bool {
    use zweidraehte_proto::dpt::{PDT_Control, PDT_Function, PropertyDataDefinition};
    pdt == PDT_Control::ID || pdt == PDT_Function::ID
}

/// Whether a PID is one of the two state-machine control properties that
/// the spec drives through PropertyExtValue services despite their
/// PDT_CONTROL type — see the call sites for the spec references.
fn is_state_machine_control(pid: u16) -> bool {
    pid == pid::LOAD_STATE_CONTROL || pid == pid::RUN_STATE_CONTROL
}

/// Get the element size in bytes for a given PDT code.
///
/// Returns 0 for unknown/variable-size PDTs. Used both within this
/// module and by the standard property write handler in the application
/// layer to validate incoming data lengths before dispatch.
pub fn pdt_element_size(pdt: u8) -> usize {
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
        0x33 => 1,  // PDT_BITSET8
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
    ctx: &AlCtx<'_, D>,
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
        send_function_ext_response(ind, ctx, &hdr, PropertyReturnCode::AddressVoid.into(), &[]);
        return;
    };

    // Check PDT: only PDT_FUNCTION and PDT_CONTROL properties can be
    // accessed via the Ext function property services. Other PDTs get a
    // response with return_code E_DATA_TYPE_CONFLICT and no data per
    // spec 3.4.8.3.
    match ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        Ok(desc) if !is_function_pdt(desc.pdt) => {
            debug!("AL FunctionPropertyExtCommand: PDT 0x{:02X} is not function/control → type conflict", desc.pdt);
            send_function_ext_response(ind, ctx, &hdr, PropertyReturnCode::DataTypeConflict.into(), &[]);
            return;
        }
        Err(_) => {
            // PID doesn't exist on this object.
            send_function_ext_response(ind, ctx, &hdr, PropertyReturnCode::AddressVoid.into(), &[]);
            return;
        }
        Ok(_) => {} // PDT_FUNCTION or PDT_CONTROL — proceed.
    }

    let req = FunctionPropertyRequest { object_idx, prop_id: hdr.prop_id, service_data: data, ctx: ctx.base.access };
    let result = ctx.interface_objects.function_property_command(&req);

    let response_len = FunctionPropertyExtResponse::msg_len(result.data.len());
    if !ctx.base.response_fits(response_len) {
        // Response data exceeds the APDU budget (spec 03/03/07 §3.3 RC 0xF4).
        warn!("AL FunctionPropertyExt result too large for APDU budget ({} bytes)", response_len);
        send_function_ext_response(ind, ctx, &hdr, PropertyReturnCode::LengthExceedsMaxApduLength.into(), &[]);
        return;
    }
    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(response_len) else {
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
    ctx.base.lctx.push_outbox(msg.into_inner());
}

/// Handle `A_FunctionPropertyExtState_Read.ind`.
///
/// Same pattern as Command but delegates to `function_property_state_read`.
fn handle_function_property_ext_state_read<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlCtx<'_, D>,
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
        send_function_ext_response(ind, ctx, &hdr, PropertyReturnCode::AddressVoid.into(), &[]);
        return;
    };

    // Check PDT (same as Command handler; spec 3.4.8.3).
    match ctx.interface_objects.property_description_read(object_idx, hdr.prop_id, 0) {
        Ok(desc) if !is_function_pdt(desc.pdt) => {
            debug!("AL FunctionPropertyExtStateRead: PDT 0x{:02X} is not function/control → type conflict", desc.pdt);
            send_function_ext_response(ind, ctx, &hdr, PropertyReturnCode::DataTypeConflict.into(), &[]);
            return;
        }
        Err(_) => {
            send_function_ext_response(ind, ctx, &hdr, PropertyReturnCode::AddressVoid.into(), &[]);
            return;
        }
        Ok(_) => {}
    }

    let req = FunctionPropertyRequest { object_idx, prop_id: hdr.prop_id, service_data: data, ctx: ctx.base.access };
    let result = ctx.interface_objects.function_property_state_read(&req);

    let response_len = FunctionPropertyExtResponse::msg_len(result.data.len());
    let budget = ctx.base.effective_apdu_budget();
    if response_len > budget {
        warn!("AL FunctionPropertyExt result too large for APDU budget ({} > {})", response_len, budget);
        send_function_ext_response(ind, ctx, &hdr, PropertyReturnCode::LengthExceedsMaxApduLength.into(), &[]);
        return;
    }
    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(response_len) else {
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
    ctx.base.lctx.push_outbox(msg.into_inner());
}

// ============================================================================
// Function Property Extended Response Helpers
// ============================================================================

/// Send a `FunctionPropertyExtState_Response` with return_code and optional data.
fn send_function_ext_response<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlCtx<'_, D>,
    hdr: &FunctionPropertyExtHeader,
    rc: u8,
    data: &[u8],
) {
    let response_len = FunctionPropertyExtResponse::msg_len(data.len());
    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(response_len) else {
        warn!("AL no buffer for FunctionPropertyExtState_Response");
        return;
    };
    let msg = ind.respond_with(msg_buf).with_application(ApciCode::FunctionPropertyExtStateResponse).with_data(|buf| {
        FunctionPropertyExtResponse::write(buf, hdr.object_type, hdr.object_instance, hdr.prop_id, rc, data);
    });
    ctx.base.lctx.push_outbox(msg.into_inner());
}

// NOTE: the *Ext* function-property services never send the "empty"
// (return_code-less) response — that form belongs to the plain
// A_FunctionProperty services only (03/03/07 §3.4.7.3, handled in
// `function_property.rs`). Per §3.4.8.3 the Ext services answer a
// wrong-PDT / absent property with a normal response carrying the
// appropriate return code and no data, which is what the handlers
// above do.

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
fn handle_ext_description_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
    use zweidraehte_proto::messages::apdu::property_ext::{
        PropertyExtDescriptionHeader, PropertyExtDescriptionResponse,
    };

    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL PropertyExtDescriptionRead unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(hdr) = PropertyExtDescriptionHeader::parse(ind.buf()) else {
        error!("PropertyExtDescriptionRead too short: {}", ind.len());
        return;
    };

    debug!(
        "AL PropertyExtDescriptionRead: iot=0x{:04X}, inst=0x{:04X}, pid={}, prop_idx={}",
        hdr.object_type, hdr.object_instance, hdr.prop_id, hdr.prop_idx
    );

    // Resolve IOT + instance.
    let object_idx = ctx.interface_objects.resolve_ext_object_index(hdr.object_type, hdr.object_instance);

    // The service-level access policy is 3FF/3FF (spec 03/03/07 Table 11),
    // so the service itself is never rejected. However, the per-property
    // Data Secure access policy still determines whether the descriptor is
    // visible: properties with restrictive policies (e.g. 00C/00C on
    // Security IO) return all-zero when accessed in plain mode with
    // security mode enabled.
    let desc_result = object_idx.and_then(|idx| {
        let desc_resp = ctx.interface_objects.property_description_read(idx, hdr.prop_id, hdr.prop_idx).ok()?;

        // Mask the descriptor from requesters the per-property policy
        // grants no access at all — read, write, or function alike. Any
        // one of them makes the description visible: a write-only key
        // property must describe itself to the tool that is about to
        // write it (TSS J 3.8.13.7 reads PID_TOOL_KEY's description under
        // the tool key), while a plain scan with security mode on still
        // sees zeros for the tool-only properties.
        if ctx.interface_objects.property_description_visible(idx, desc_resp.prop_id, &ctx.base.access) {
            Some(desc_resp)
        } else {
            None
        }
    });

    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(PropertyExtDescriptionResponse::MSG_LEN) else {
        warn!("AL no buffer for PropertyExtDescriptionResponse");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::PropertyExtDescriptionResponse).with_data(|buf| {
        match &desc_result {
            Some(desc) => PropertyExtDescriptionResponse::write(buf, hdr.object_type, hdr.object_instance, desc),
            None => PropertyExtDescriptionResponse::write_error(
                buf,
                hdr.object_type,
                hdr.object_instance,
                hdr.prop_id,
                hdr.desc_type,
                hdr.prop_idx,
            ),
        }
    });

    ctx.base.lctx.push_outbox(msg.into_inner());
}

// ============================================================================
// MemoryExtended Handlers
// ============================================================================

/// Handle `A_MemoryExtended_Write.ind`.
///
/// Wire format: APCI(2) + count(1) + address(3) + data(count)
/// Response:    APCI(2) + return_code(1) + address(3)
fn handle_memory_ext_write<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
    use zweidraehte_proto::messages::knx::offsets;

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
    let result = ctx.memory_map.write(ctx.base.state, addr16, data, ctx.base.access);

    let rc = match result {
        Ok(_) => 0x00,                            // E_SUCCESS
        Err(MemoryError::AccessDenied) => 0xFC,   // E_ILLEGAL_COMMAND
        Err(MemoryError::WriteProtected) => 0xFB, // E_READ_ONLY
        Err(_) => 0xFD,                           // E_ADDRESS_VOID
    };

    send_memory_ext_write_response(ind, ctx, rc, addr_hi, addr_mid, addr_lo);
}

/// Handle `A_MemoryExtended_Read.ind`.
///
/// Wire format: APCI(2) + count(1) + address(3)
/// Response:    APCI(2) + return_code(1) + address(3) + data(count)
fn handle_memory_ext_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
    use zweidraehte_proto::messages::knx::offsets;

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
        let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(resp_len) else { return };
        let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedReadResponse).with_data(|buf| {
            buf[base + 2] = 0xFD;
            buf[base + 3] = addr_hi;
            buf[base + 4] = addr_mid;
            buf[base + 5] = addr_lo;
        });
        ctx.base.lctx.push_outbox(msg.into_inner());
        return;
    }

    let addr16 = (address & 0xFFFF) as u16;
    let mut data_buf = [0u8; 252]; // Max extended memory read

    // MemoryExtendedReadResponse: APCI(2) + rc(1) + addr(3) + data(n).
    //
    // A read whose count cannot fit the response is refused outright
    // rather than served short. 03/03/07 §3.4.9.1 is explicit: "the
    // Return Code gives details to the indicated an error if the value
    // of the parameter 'number of data octets' is greater than Maximum
    // APDU Length - 4", and Table 3 names that code F4h
    // `E_LENGTH_EXCEEDS_MAX_APDU_LENGTH` — "requested data will not fit
    // into a Frame supported by this server". Figure 68 has the APDU end
    // after the address, with no data field.
    //
    // Truncating instead, which is what this did, is worse than a
    // failure: the requester gets a short read that looks successful and
    // has no way to tell it apart from a region that really is that
    // short.
    let payload_cap = ctx.base.response_payload_cap(offsets::MSG_APCI + 6);
    if count > payload_cap {
        let resp_len = offsets::MSG_APCI + 6; // APCI + rc + addr, no data
        let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(resp_len) else { return };
        let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedReadResponse).with_data(|buf| {
            buf[base + 2] = PropertyReturnCode::LengthExceedsMaxApduLength.into();
            buf[base + 3] = addr_hi;
            buf[base + 4] = addr_mid;
            buf[base + 5] = addr_lo;
        });
        ctx.base.lctx.push_outbox(msg.into_inner());
        return;
    }
    let read_len = count.min(data_buf.len());

    let result = if read_len == 0 {
        Ok(0usize)
    } else {
        ctx.memory_map.read(ctx.base.state, addr16, &mut data_buf[..read_len], ctx.base.access)
    };

    match result {
        Ok(n) => {
            let resp_len = offsets::MSG_APCI + 6 + n;
            let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(resp_len) else { return };
            let msg =
                ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedReadResponse).with_data(|buf| {
                    buf[base + 2] = 0x00; // E_SUCCESS
                    buf[base + 3] = addr_hi;
                    buf[base + 4] = addr_mid;
                    buf[base + 5] = addr_lo;
                    buf[base + 6..base + 6 + n].copy_from_slice(&data_buf[..n]);
                });
            ctx.base.lctx.push_outbox(msg.into_inner());
        }
        Err(e) => {
            let rc = match e {
                MemoryError::AccessDenied => 0xFC,   // E_ILLEGAL_COMMAND
                MemoryError::WriteProtected => 0xFA, // E_WRITE_ONLY (read of write-only region)
                _ => 0xFD,                           // E_ADDRESS_VOID
            };
            let resp_len = offsets::MSG_APCI + 6;
            let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(resp_len) else { return };
            let msg =
                ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedReadResponse).with_data(|buf| {
                    buf[base + 2] = rc;
                    buf[base + 3] = addr_hi;
                    buf[base + 4] = addr_mid;
                    buf[base + 5] = addr_lo;
                });
            ctx.base.lctx.push_outbox(msg.into_inner());
        }
    }
}

fn send_memory_ext_write_response<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlCtx<'_, D>,
    return_code: u8,
    addr_hi: u8,
    addr_mid: u8,
    addr_lo: u8,
) {
    use zweidraehte_proto::messages::knx::offsets;
    let resp_len = offsets::MSG_APCI + 6; // APCI(2) + rc(1) + addr(3)
    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(resp_len) else { return };
    let base = offsets::MSG_APCI;
    let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryExtendedWriteResponse).with_data(|buf| {
        buf[base + 2] = return_code;
        buf[base + 3] = addr_hi;
        buf[base + 4] = addr_mid;
        buf[base + 5] = addr_lo;
    });
    ctx.base.lctx.push_outbox(msg.into_inner());
}
