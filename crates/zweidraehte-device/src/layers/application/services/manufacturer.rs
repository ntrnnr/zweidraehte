//! User manufacturer info service AL extension.
//!
//! Handles `A_UserManufacturerInfo_Read` — returns the 3-byte manufacturer
//! info configured via `StackDefinition::USER_MANUFACTURER_INFO`. Devices
//! without manufacturer info configured can omit this extension.
//!
//! # Usage
//!
//! ```rust,ignore
//! type Services = UserManufacturerInfoService;
//! ```

use crate::{
    definition::StackDefinition,
    layer_context::HasOutbox,
    layers::application::services::{AlServiceContext, AlService},
    messages::{
        buffers::Buffer,
        builder::IndicationExt,
        knx::{ApciCode, KnxMessageBuffer, ServiceType, offsets},
    },
};

use crate::logging::{debug, warn};

/// AL service extension for user manufacturer info.
///
/// Returns the 3-byte `USER_MANUFACTURER_INFO` from the `StackDefinition`.
/// If not configured (`None`), the request is silently ignored.
#[derive(Default)]
pub struct UserManufacturerInfoService;

impl<D: StackDefinition> AlService<D> for UserManufacturerInfoService {
    fn try_handle(
        &self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlServiceContext<'_, D>,
    ) -> bool {
        match apci {
            ApciCode::UserManufacturerInfoRead => {
                handle_read::<D>(msg, ctx);
                true
            }
            ApciCode::UserManufacturerInfoResponse => {
                debug!("AL ignoring UserManufacturerInfoResponse (response APCI)");
                true
            }
            _ => false,
        }
    }
}

fn handle_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlServiceContext<'_, D>) {
    let Some(info) = D::USER_MANUFACTURER_INFO else {
        debug!("AL UserManufacturerInfo_Read: not supported (no USER_MANUFACTURER_INFO configured)");
        return;
    };

    if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
        warn!("AL UserManufacturerInfo_Read unexpected service type: {:?}", ind.service_type());
        return;
    }

    // Response: APCI(2) + Manufacturer ID(2) + Device Type(1) = 5 bytes
    const RESPONSE_LEN: usize = offsets::MSG_APCI + 5;
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(RESPONSE_LEN) else {
        warn!("AL no buffer for response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::UserManufacturerInfoResponse).with_data(|data| {
        data[offsets::MSG_APCI + 2..offsets::MSG_APCI + 5].copy_from_slice(info);
    });

    debug!("AL sending UserManufacturerInfo_Response: {:?}", zweidraehte_util::fmt::Bytes(info));
    ctx.lctx.push_outbox(msg.into_inner());
}
