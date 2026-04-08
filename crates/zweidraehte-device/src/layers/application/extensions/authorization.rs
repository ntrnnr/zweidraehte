//! Authorization service AL extension.
//!
//! Handles `A_Authorize_Request` and `A_Key_Write` for key-based access
//! level management. Only needed by devices that support access-level
//! differentiation.
//!
//! # Usage
//!
//! ```rust,ignore
//! type AlExtension = (MemoryServiceExtension, AuthorizationExtension);
//! ```

use crate::{
    AccessContext, AccessSource, HasAuthorization, HasConnectionAuth, StackState,
    definition::StackDefinition,
    layers::application::extensions::{AlExtensionContext, AlServiceExtension},
    messages::{
        apdu::auth::{AuthorizeRequest, AuthorizeResponse, KeyResponse, KeyWrite},
        buffers::Buffer,
        builder::IndicationExt,
        knx::{ApciCode, KnxMessageBuffer, ServiceType},
    },
    router::Outbox,
};

use crate::logging::{debug, error, warn};

// ============================================================================
// Extension Type
// ============================================================================

/// AL service extension for authorization services.
///
/// Handles:
/// - `A_Authorize_Request` — authenticate with 4-byte key
/// - `A_Key_Write` — write new key for an access level
/// - `A_Authorize_Response`, `A_Key_Response` — ignored (we send these)
#[derive(Default)]
pub struct AuthorizationExtension;

impl<D: StackDefinition> AlServiceExtension<D> for AuthorizationExtension {
    fn try_handle(
        &mut self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlExtensionContext<'_, D>,
        outbox: &mut Outbox,
    ) -> bool {
        match apci {
            ApciCode::AuthorizeRequest => {
                handle_authorize_request::<D>(msg, ctx, outbox);
                true
            }
            ApciCode::KeyWrite => {
                handle_key_write::<D>(msg, ctx, outbox);
                true
            }
            ApciCode::AuthorizeResponse | ApciCode::KeyResponse => {
                debug!("AL ignoring {:?} (response APCI)", apci);
                true
            }
            _ => false,
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Handle `A_Authorize_Request.ind`
fn handle_authorize_request<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    outbox: &mut Outbox,
) {
    let Some(req) = AuthorizeRequest::parse(ind.buf()) else {
        error!("Authorize_Request message too short: {}", ind.len());
        return;
    };

    debug!("AL Authorize_Request: key={:?}", zweidraehte_util::fmt::Bytes(&req.key));

    let access_level = ctx.state.authorize(&req.key);
    debug!("AL Authorize_Request: granted level {}", access_level);

    if ind.service_type() != ServiceType::T_Data_Ind {
        warn!("AL Authorize_Request rejected: connection-oriented only");
        return;
    }

    // Write the granted level directly to the shared access store so it
    // takes effect immediately.
    if let AccessSource::Connection(slot) = ind.access_source() {
        ctx.state.set_connection_access(slot, AccessContext::new(access_level));
    }

    let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(AuthorizeResponse::MSG_LEN) else {
        warn!("AL no buffer for response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::AuthorizeResponse).with_data(|buf| {
        AuthorizeResponse::write(buf, access_level);
    });

    debug!("AL sending Authorize_Response: level={}", access_level);
    outbox.push(msg.into_inner());
}

/// Handle `A_Key_Write.ind`
fn handle_key_write<D: StackDefinition>(
    ind: &KnxMessageBuffer<Buffer<'static>>,
    ctx: &AlExtensionContext<'_, D>,
    outbox: &mut Outbox,
) {
    // Access policy 3FF/0CC: everyone can write when security mode is off;
    // when security mode is on, only Tool A+C can write.
    use crate::access::AccessPolicy;
    let security_on = ctx.state.security_mode_enabled();
    if !AccessPolicy::READ_OPEN_WRITE_TOOL.can_write(&ctx.access_ctx, security_on) {
        debug!("AL Key_Write denied by access policy");
        return;
    }

    let Some(req) = KeyWrite::parse(ind.buf()) else {
        error!("Key_Write message too short: {}", ind.len());
        return;
    };
    debug!(
        "AL Key_Write: level={}, key={:?}, current_ctx={:?}",
        req.level,
        zweidraehte_util::fmt::Bytes(&req.key),
        ctx.access_ctx
    );

    let result_level = ctx.state.key_write(req.level, &req.key, ctx.access_ctx);
    debug!("AL Key_Write: result={}", result_level);

    if ind.service_type() != ServiceType::T_Data_Ind {
        warn!("AL Key_Write rejected: connection-oriented only");
        return;
    }

    let Some(msg_buf) = ctx.buffer_manager.try_alloc_with_size(KeyResponse::MSG_LEN) else {
        warn!("AL no buffer for response");
        return;
    };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::KeyResponse).with_data(|buf| {
        KeyResponse::write(buf, result_level);
    });

    debug!("AL sending Key_Response: level={}", result_level);
    outbox.push(msg.into_inner());
}
