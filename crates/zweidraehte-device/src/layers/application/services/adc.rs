//! ADC service AL extension.
//!
//! Handles `A_ADC_Read` — a legacy service that returns dummy ADC readings.
//! Most real devices don't need this; it exists primarily for conformance.
//!
//! # Usage
//!
//! ```rust,ignore
//! type Services = (MemoryService, AdcService);
//! ```

use crate::{
    definition::StackDefinition,
    layer_context::HasOutbox,
    layers::application::services::{AlServiceContext, AlService}};
use zweidraehte_proto::messages::{
        apdu::device::{AdcRead, AdcResponse},
        buffers::Buffer,
        builder::IndicationExt,
        knx::{ApciCode, KnxMessageBuffer, ServiceType},
    };

use crate::logging::{debug, error, warn};

/// AL service extension for legacy ADC read service.
///
/// Returns dummy sum (0x0000) for channels 0-5, count 0 for others.
#[derive(Default)]
pub struct AdcService;

impl<D: StackDefinition> AlService<D> for AdcService {
    fn try_handle(
        &self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlServiceContext<'_, D>,
    ) -> bool {
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

fn handle_adc_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlServiceContext<'_, D>) {
    let Some(req) = AdcRead::parse(ind.buf()) else {
        error!("ADC_Read message too short: {}", ind.len());
        return;
    };

    debug!("AL ADC_Read: channel={}, count={}", req.channel, req.count);

    if ind.service_type() != ServiceType::T_Data_Ind {
        debug!("AL ADC_Read requires connection-oriented mode, got {:?}", ind.service_type());
        return;
    }

    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(AdcResponse::MSG_LEN) else {
        warn!("AL no buffer for response");
        return;
    };

    // Channels 0-5 are supported; return dummy sum 0x0000.
    let (response_count, sum) = if req.channel <= 5 { (req.count, 0x0000u16) } else { (0u8, 0x0000u16) };

    let msg = ind.respond_with(msg_buf).with_application(ApciCode::AdcResponse).with_data(|buf| {
        AdcResponse::write(buf, req.channel, response_count, sum);
    });

    debug!("AL sending ADC_Response: channel={}, count={}, sum={}", req.channel, response_count, sum);
    ctx.lctx.push_outbox(msg.into_inner());
}
