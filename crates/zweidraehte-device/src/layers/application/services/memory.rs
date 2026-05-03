//! Memory service AL extension.
//!
//! Handles `A_Memory_Read`, `A_Memory_Write`, and `A_MemoryBit_Write` (16-bit
//! addressing). Only needed by devices with a memory map — devices using
//! [`NoMemoryMap`](crate::memory::NoMemoryMap) can omit this extension.
//!
//! # Usage
//!
//! ```rust,ignore
//! type AlExtensions = MemoryService;
//! ```

use crate::{
    HasPersistence,
    context::layer::HasOutbox,
    definition::StackDefinition,
    memory::MemoryMap,
    objects::interface::HasDeviceObject,
    service::{AlCtx, ApciHandler},
};
use zweidraehte_proto::messages::{
    apdu::memory::{MemoryAccess, MemoryBitWrite, MemoryResponse},
    buffers::Buffer,
    builder::IndicationExt,
    knx::{ApciCode, KnxMessageBuffer, ServiceType, offsets},
};

use crate::logging::{debug, error, warn};

// ============================================================================
// Extension Type
// ============================================================================

/// AL service extension for 16-bit memory services.
///
/// Handles:
/// - `A_Memory_Read` — read up to 63 bytes from device memory
/// - `A_Memory_Write` — write up to 63 bytes, optional verify response
/// - `A_MemoryBit_Write` — atomic AND/XOR bit manipulation (1-5 bytes)
/// - `A_Memory_Response` — ignored (we send these, not receive)
#[derive(Default)]
pub struct MemoryService;

impl<D: StackDefinition> ApciHandler<D> for MemoryService {
    fn try_handle_apci(
        &self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlCtx<'_, D>,
    ) -> bool {
        match apci {
            ApciCode::MemoryRead => {
                handle_memory_read::<D>(msg, ctx);
                true
            }
            ApciCode::MemoryWrite => {
                handle_memory_write::<D>(msg, ctx);
                true
            }
            ApciCode::MemoryBitWrite => {
                handle_memorybit_write::<D>(msg, ctx);
                true
            }
            // Response APCI — we are the responder, ignore if received.
            ApciCode::MemoryReadResponse => {
                debug!("AL ignoring MemoryReadResponse (response APCI)");
                true
            }
            _ => false,
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Handle `A_Memory_Read.ind`
///
/// Reads up to 63 bytes from device memory at the specified 16-bit address.
fn handle_memory_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
    if ind.service_type() != ServiceType::T_Data_Ind {
        warn!("AL Memory_Read rejected: connection-oriented only");
        return;
    }

    let Some(acc) = MemoryAccess::parse_read(ind.buf()) else {
        error!("Memory_Read message too short: {}", ind.len());
        return;
    };

    debug!("AL Memory_Read: address=0x{:04X}, count={}", acc.address, acc.count);

    // Cap against the effective APDU budget. Per spec 03/03/07 §3.5.3
    // Error handling: if `number > Maximum APDU Length - 3`, the
    // A_Memory_Response-PDU shall have `number = 0` with no data.
    let payload_cap = ctx.response_payload_cap(MemoryResponse::msg_len(0));

    let mut data = [0u8; 63]; // Max count is 63 (6 bits)
    let request_count = (acc.count as usize).min(data.len()).min(payload_cap);
    let result = if request_count == 0 {
        Ok(0usize)
    } else {
        ctx.memory_map.read(ctx.state, acc.address, &mut data[..request_count], ctx.access)
    };

    let response_count = match result {
        Ok(bytes_read) => bytes_read as u8,
        Err(_) => 0,
    };

    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(MemoryResponse::msg_len(response_count as usize))
    else {
        warn!("AL no buffer for response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryReadResponse).with_data(|buf| {
        MemoryResponse::write(buf, response_count, acc.address, &data[..response_count as usize]);
    });

    debug!("AL sending Memory_Response: address=0x{:04X}, count={}", acc.address, response_count);
    ctx.lctx.push_outbox(msg.into_inner());
}

/// Handle `A_Memory_Write.ind`
///
/// Writes to device memory at the specified 16-bit address. If the Verify
/// flag is set in DEVICE_CONTROL (PID 14), a Memory_Response is sent back.
fn handle_memory_write<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
    if ind.service_type() != ServiceType::T_Data_Ind {
        warn!("AL Memory_Write rejected: connection-oriented only");
        return;
    }

    let Some(acc) = MemoryAccess::parse_write(ind.buf()) else {
        error!("Memory_Write message too short: {}", ind.len());
        return;
    };

    let length_inconsistent = !acc.is_length_consistent(ind.len());
    if length_inconsistent {
        warn!(
            "Memory_Write length inconsistency: expected {} bytes, got {} (count={})",
            offsets::MSG_APCI + 4 + acc.count as usize,
            ind.len(),
            acc.count
        );
    }

    debug!("AL Memory_Write: address=0x{:04X}, count={}", acc.address, acc.count);

    let response_count = if length_inconsistent {
        0
    } else {
        match ctx.memory_map.write(ctx.state, acc.address, acc.data, ctx.access) {
            Ok(bytes_written) => {
                debug!("AL Memory_Write: wrote {} bytes to 0x{:04X}", bytes_written, acc.address);
                ctx.state.mark_dirty();
                bytes_written as u8
            }
            Err(e) => {
                warn!("AL Memory_Write failed: address=0x{:04X}, error={:?}", acc.address, e);
                0
            }
        }
    };

    if !ctx.interface_objects.verify_mode() {
        return;
    }

    // Verify-mode responses are bounded by the same APDU budget; a
    // count that no longer fits is reported as count=0.
    let response_count =
        if ctx.response_fits(MemoryResponse::msg_len(response_count as usize)) { response_count } else { 0 };

    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(MemoryResponse::msg_len(response_count as usize))
    else {
        warn!("AL no buffer for response");
        return;
    };

    // Error responses (count=0) must not include the original request data,
    // which would overflow the buffer sized for zero data bytes.
    let response_data = if response_count > 0 { acc.data } else { &[] };
    let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryReadResponse).with_data(|buf| {
        MemoryResponse::write(buf, response_count, acc.address, response_data);
    });

    debug!("AL sending Memory_Response (verify): address=0x{:04X}, count={}", acc.address, response_count);
    ctx.lctx.push_outbox(msg.into_inner());
}

/// Handle `A_MemoryBit_Write.ind`
///
/// Performs atomic bit-level memory manipulation using AND and XOR masks.
/// Formula: `new_value = (old_value AND and_mask) XOR xor_mask`
///
/// Legal length: count must be 1-5 bytes.
fn handle_memorybit_write<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
    if ind.service_type() != ServiceType::T_Data_Ind {
        warn!("AL MemoryBit_Write rejected: connection-oriented only");
        return;
    }

    // Extract header fields (count + address) before full parse, so we can
    // send an error response even when the message is too short for its
    // declared mask count.
    let raw = ind.buf();
    if raw.len() < MemoryBitWrite::MIN_MSG_LEN {
        error!("MemoryBit_Write message too short: {}", ind.len());
        return;
    }
    let header_count = raw[offsets::MSG_APCI + 2] & 0x0F;
    let header_address = u16::from_be_bytes([raw[offsets::MSG_APCI + 3], raw[offsets::MSG_APCI + 4]]);

    // Reject illegal count (must be 1-5) or truncated messages up front,
    // sending an error response so the remote side isn't left waiting.
    if !(1..=5).contains(&header_count) {
        warn!("MemoryBit_Write illegal count: {}", header_count);
        send_memorybit_response::<D>(ind, ctx, header_address, 0, &[]);
        return;
    }
    let expected_len = MemoryBitWrite::expected_msg_len(header_count as usize);
    if ind.len() != expected_len {
        warn!(
            "MemoryBit_Write length mismatch: expected {} bytes, got {} (count={})",
            expected_len,
            ind.len(),
            header_count
        );
        send_memorybit_response::<D>(ind, ctx, header_address, 0, &[]);
        return;
    }

    // Full parse is safe now — header, count, and mask lengths are validated.
    let mbw = MemoryBitWrite::parse(raw).expect("header and length already validated");

    debug!("AL MemoryBit_Write: address=0x{:04X}, count={}", mbw.address, mbw.count);

    // Read current memory values.
    let mut current_data = [0u8; 5];
    let read_result =
        ctx.memory_map.read(ctx.state, mbw.address, &mut current_data[..mbw.count as usize], ctx.access);

    match read_result {
        Ok(_) => {
            // Apply bit manipulation: new = (old AND and_mask) XOR xor_mask
            let mut new_data = [0u8; 5];
            for i in 0..mbw.count as usize {
                new_data[i] = (current_data[i] & mbw.and_masks[i]) ^ mbw.xor_masks[i];
            }

            match ctx.memory_map.write(ctx.state, mbw.address, &new_data[..mbw.count as usize], ctx.access) {
                Ok(_) => {
                    debug!("AL MemoryBit_Write: wrote {} bytes to 0x{:04X}", mbw.count, mbw.address);
                    send_memorybit_response::<D>(ind, ctx, mbw.address, mbw.count, &new_data[..mbw.count as usize]);
                }
                Err(e) => {
                    warn!("AL MemoryBit_Write write failed: address=0x{:04X}, error={:?}", mbw.address, e);
                    send_memorybit_response::<D>(ind, ctx, mbw.address, 0, &[]);
                }
            }
        }
        Err(e) => {
            warn!("AL MemoryBit_Write read failed: address=0x{:04X}, error={:?}", mbw.address, e);
            send_memorybit_response::<D>(ind, ctx, mbw.address, 0, &[]);
        }
    }
}

/// Send `A_Memory_Response` (in response to `A_MemoryBit_Write`).
///
/// Per KNX spec 3.5.5: "the TSDU is an A_Memory_Response-PDU".
/// Only sends a response if Verify flag is enabled in DEVICE_CONTROL.
fn send_memorybit_response<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlCtx<'_, D>,
    address: u16,
    count: u8,
    data: &[u8],
) {
    if !ctx.interface_objects.verify_mode() {
        return;
    }

    // Same budget guard as A_Memory_Read: truncate to count=0 when the
    // response won't fit.
    let (count, data) =
        if ctx.response_fits(MemoryResponse::msg_len(count as usize)) { (count, data) } else { (0u8, &[][..]) };

    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(MemoryResponse::msg_len(count as usize)) else {
        warn!("AL no buffer for response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryReadResponse).with_data(|buf| {
        MemoryResponse::write(buf, count, address, data);
    });

    debug!("AL sending A_Memory_Response (for MemoryBit_Write): address=0x{:04X}, count={}", address, count);
    ctx.lctx.push_outbox(msg.into_inner());
}
