//! ADC service AL extension.
//!
//! Handles `A_ADC_Read` — a legacy service that returns dummy ADC readings.
//! Most real devices don't need this; it exists primarily for conformance.
//!
//! # Usage
//!
//! ```rust,ignore
//! type AlExtensions = (MemoryService, AdcService);
//! ```

use crate::{
    HasSecurityMode,
    definition::StackDefinition,
    service::{AlCtx, ApciHandler},
};
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::messages::{
    apdu::device::{AdcRead, AdcResponse},
    buffers::Buffer,
    knx::{ApciCode, KnxMessageBuffer, ServiceType},
};

use crate::logging::{debug, error};

/// AL service extension for legacy ADC read service.
///
/// Returns dummy sum (0x0000) for channels 0-5, count 0 for others.
#[derive(Default)]
pub struct AdcService;

impl<D: StackDefinition> ApciHandler<D> for AdcService {
    fn try_handle_apci(&self, apci: ApciCode, msg: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) -> bool {
        match apci {
            ApciCode::AdcRead => {
                handle_adc_read::<D>(msg, ctx);
                true
            }
            ApciCode::AdcResponse => {
                debug!("AL ignoring AdcResponse (response APCI)");
                true
            }
            _ => false,
        }
    }
}

fn handle_adc_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
    let Some(req) = AdcRead::parse(ind.buf()) else {
        error!("ADC_Read message too short: {}", ind.len());
        return;
    };

    debug!("AL ADC_Read: channel={}, count={}", req.channel, req.count);

    if ind.service_type() != ServiceType::T_Data_Ind {
        debug!("AL ADC_Read requires connection-oriented mode, got {:?}", ind.service_type());
        return;
    }

    // Access Policy 3FF/00C at service level (03/03/07 Table 11, AN193
    // §2.2.3): anyone while Security Mode is off, only the Tool while it is
    // on. A service-level denial is not answered (03/04/01 §6.2.2).
    let security_on = ctx.base.state.security_mode_enabled();
    if !AccessPolicy::OPEN_OFF_TOOL_ON.can_read(&ctx.base.access, security_on) {
        debug!("AL ADC_Read denied by access policy");
        return;
    }

    // Channels 0-5 are supported; return dummy sum 0x0000.
    let (response_count, sum) = if req.channel <= 5 { (req.count, 0x0000u16) } else { (0u8, 0x0000u16) };

    ctx.respond(ind, ApciCode::AdcResponse, AdcResponse::MSG_LEN, |buf| {
        AdcResponse::write(buf, req.channel, response_count, sum);
    });

    debug!("AL sending ADC_Response: channel={}, count={}, sum={}", req.channel, response_count, sum);
}
