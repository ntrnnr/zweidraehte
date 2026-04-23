//! `A_SystemNetworkParameter_Read` AL service extension.
//!
//! Implements the `NM_Read_SerialNumber_By_ProgrammingMode` procedure from
//! spec 03/05/02 §2.20.1.3: respond with the KNX Serial Number when the
//! MaC reads `(object_type = Device Object, PID = PID_SERIAL_NUMBER,
//! operand = 0x01)` and the device's Programming Mode is active.
//!
//! Other `A_SystemNetworkParameter_Read` variants are silently ignored.
//!
//! # Usage
//!
//! ```rust,ignore
//! type Services = (SystemBAlServices, SystemNetworkParameterService);
//! ```

use crate::{
    StackState,
    context::layer::HasOutbox,
    definition::StackDefinition,
    layers::application::services::{AlService, AlServiceContext},
    objects::interface::pid,
};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::{
    apdu::system_network_parameter::{SystemNetworkParameterRead, SystemNetworkParameterResponse},
    buffers::Buffer,
    builder::MessageBuilder,
    knx::{ApciCode, DestinationAddress, KnxMessageBuffer, ServiceType},
};

use crate::logging::{debug, error, trace, warn};

/// Operand for `NM_Read_SerialNumber_By_ProgrammingMode` (spec 03/05/02 §2.20.1.4).
// TODO: Implement more modes (PowerReset and ExFactoryState) - spec 03/05/02 §2.20.1.5 & .6
const OPERAND_BY_PROG_MODE: u8 = 0x01;

/// AL service extension for `A_SystemNetworkParameter_Read`.
#[derive(Default)]
pub struct SystemNetworkParameterService;

impl<D: StackDefinition> AlService<D> for SystemNetworkParameterService {
    fn try_handle(
        &self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlServiceContext<'_, D>,
    ) -> bool {
        match apci {
            ApciCode::SystemNetworkParameterRead => {
                handle_read::<D>(msg, ctx);
                true
            }
            ApciCode::SystemNetworkParameterResponse => {
                debug!("AL ignoring SystemNetworkParameterResponse (response APCI)");
                true
            }
            _ => false,
        }
    }
}

fn handle_read<D: StackDefinition>(ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlServiceContext<'_, D>) {
    // The service is only defined on system broadcast per spec 03/05/02 §2.20.
    if ind.service_type() != ServiceType::T_SystemBroadcast_Ind {
        warn!("AL SystemNetworkParameterRead with unexpected service type: {:?}", ind.service_type());
        return;
    }

    let Some(read) = SystemNetworkParameterRead::parse(ind.buf()) else {
        error!("SystemNetworkParameterRead message too short: {}", ind.len());
        return;
    };

    let device_ot: u16 = InterfaceObjectType::Device.into();

    // Only the serial-number-by-programming-mode procedure is supported.
    // Per spec §2.20, unsupported parameter_type/test_info combinations
    // MUST NOT trigger a response.
    if read.object_type != device_ot || read.pid != pid::SERIAL_NUMBER || read.operand != OPERAND_BY_PROG_MODE {
        trace!(
            "AL SystemNetworkParameterRead unsupported: object_type=0x{:04X}, pid={}, operand=0x{:X}",
            read.object_type, read.pid, read.operand
        );
        return;
    }

    if !ctx.state.is_programming_mode() {
        trace!("AL SystemNetworkParameterRead ignored: programming mode off");
        return;
    }

    debug!("AL SystemNetworkParameterRead: programming mode active, sending serial-number response");

    // TODO: spec requires a random wait of 0..1 s before responding to
    // spread out collisions when multiple programming-mode devices are on
    // the bus. With the current AL being fully synchronous we emit
    // immediately; the bus access layer serialises transmissions so no
    // hard collision results, but adding a delay is a conformance nicety.

    // Response tail = test_result = 6-byte KNX Serial Number. The echoed
    // operand lives in the packed PID|operand nibble and is written by
    // `SystemNetworkParameterResponse::write`.
    let resp_len = SystemNetworkParameterResponse::msg_len(6);
    let Some(msg_buf) = ctx.buffer_manager().try_alloc_with_size(resp_len) else {
        warn!("AL no buffer for SystemNetworkParameterResponse");
        return;
    };

    // System broadcast is addressed to the null group address; preserve
    // the request's priority per spec 03/05/02 §2.20.1.2.
    let mut msg = MessageBuilder::new_request(
        msg_buf,
        ServiceType::T_SystemBroadcast_Req,
        ind.ctrl_field().priority(),
        DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])),
    )
    .with_application(ApciCode::SystemNetworkParameterResponse)
    .build();

    let serial: &[u8; 6] = ctx.state.serial_number();
    SystemNetworkParameterResponse::write(msg.buf_mut(), device_ot, pid::SERIAL_NUMBER, OPERAND_BY_PROG_MODE, serial);

    ctx.lctx.push_outbox(msg.into_inner());
}
