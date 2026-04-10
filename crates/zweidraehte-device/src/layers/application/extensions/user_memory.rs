//! User memory service AL extension.
//!
//! Handles `A_UserMemory_Read` and `A_UserMemory_Write` (20-bit addressing
//! via 4-bit address extension + 16-bit address). Only needed by devices
//! with DMA on user memory support.
//!
//! # Usage
//!
//! ```rust,ignore
//! type AlExtension = (MemoryServiceExtension, UserMemoryServiceExtension);
//! ```

use crate::{
    HasPersistence,
    definition::StackDefinition,
    layer_context::{HasLayerContext, HasOutbox},
    layers::application::extensions::{AlExtensionContext, AlServiceExtension},
    memory::MemoryMap,
    messages::{
        apdu::memory::{UserMemoryAccess, UserMemoryResponse},
        buffers::Buffer,
        builder::IndicationExt,
        knx::{ApciCode, KnxMessageBuffer, ServiceType, offsets},
    },
    objects::interface::HasDeviceObject,
};

use crate::logging::{debug, error, warn};

// ============================================================================
// Extension Type
// ============================================================================

/// AL service extension for 20-bit user memory services.
///
/// Handles:
/// - `A_UserMemory_Read` — read from 20-bit address space
/// - `A_UserMemory_Write` — write with optional verify response
/// - `A_UserMemory_Response` — ignored (we send these)
#[derive(Default)]
pub struct UserMemoryServiceExtension;

impl<D: StackDefinition> AlServiceExtension<D> for UserMemoryServiceExtension {
    fn try_handle(
        &mut self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlExtensionContext<'_, D>,
    ) -> bool {
        match apci {
            ApciCode::UserMemoryRead => {
                handle_user_memory_read::<D>(msg, ctx);
                true
            }
            ApciCode::UserMemoryWrite => {
                handle_user_memory_write::<D>(msg, ctx);
                true
            }
            ApciCode::UserMemoryResponse => {
                debug!("AL ignoring UserMemoryResponse (response APCI)");
                true
            }
            _ => false,
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Handle `A_UserMemory_Read.ind`
fn handle_user_memory_read<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) {
    if ind.service_type() != ServiceType::T_Data_Ind {
        warn!("AL UserMemory_Read rejected: connection-oriented only");
        return;
    }

    let Some(acc) = UserMemoryAccess::parse_read(ind.buf()) else {
        error!("UserMemory_Read message too short: {}", ind.len());
        return;
    };

    debug!("AL UserMemory_Read: address=0x{:05X}, count={}", acc.full_address(), acc.count);

    let mut data = [0u8; 255];
    let max_read = core::cmp::min(acc.count as usize, data.len());
    let result = ctx.memory_map.read(ctx.state, acc.address_low, &mut data[..max_read], ctx.access_ctx);

    let response_count = match result {
        Ok(bytes_read) => bytes_read as u8,
        Err(_) => 0,
    };

    let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(UserMemoryResponse::msg_len(response_count as usize))
    else {
        warn!("AL no buffer for response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::UserMemoryResponse).with_data(|buf| {
        UserMemoryResponse::write(buf, acc.addr_ext, response_count, acc.address_low, &data[..response_count as usize]);
    });

    debug!("AL sending UserMemory_Response: address=0x{:05X}, count={}", acc.full_address(), response_count);
    ctx.state.push_outbox(msg.into_inner());
}

/// Handle `A_UserMemory_Write.ind`
fn handle_user_memory_write<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
) {
    if ind.service_type() != ServiceType::T_Data_Ind {
        warn!("AL UserMemory_Write rejected: connection-oriented only");
        return;
    }

    let Some(acc) = UserMemoryAccess::parse_write(ind.buf()) else {
        error!("UserMemory_Write message too short: {}", ind.len());
        return;
    };

    let length_inconsistent = !acc.is_length_consistent(ind.len());
    if length_inconsistent {
        warn!(
            "UserMemory_Write length inconsistency: expected {} bytes, got {} (count={})",
            offsets::MSG_APCI + 5 + acc.count as usize,
            ind.len(),
            acc.count
        );
    }

    debug!("AL UserMemory_Write: address=0x{:05X}, count={}", acc.full_address(), acc.count);

    let response_count = if length_inconsistent {
        0
    } else {
        match ctx.memory_map.write(ctx.state, acc.address_low, acc.data, ctx.access_ctx) {
            Ok(bytes_written) => {
                debug!("AL UserMemory_Write: wrote {} bytes to 0x{:05X}", bytes_written, acc.full_address());
                ctx.state.mark_dirty();
                bytes_written as u8
            }
            Err(e) => {
                warn!("AL UserMemory_Write failed: address=0x{:05X}, error={:?}", acc.full_address(), e);
                0
            }
        }
    };

    if !ctx.interface_objects.verify_mode() {
        return;
    }

    let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(UserMemoryResponse::msg_len(response_count as usize))
    else {
        warn!("AL no buffer for response");
        return;
    };

    let response_data = if response_count > 0 { acc.data } else { &[] };
    let msg = ind.respond_with(msg_buf).with_application(ApciCode::UserMemoryResponse).with_data(|buf| {
        UserMemoryResponse::write(buf, acc.addr_ext, response_count, acc.address_low, response_data);
    });

    debug!("AL sending UserMemory_Response (verify): address=0x{:05X}, count={}", acc.full_address(), response_count);
    ctx.state.push_outbox(msg.into_inner());
}
