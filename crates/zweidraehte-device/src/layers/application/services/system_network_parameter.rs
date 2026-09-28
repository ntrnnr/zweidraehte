//! `A_SystemNetworkParameter_Read` AL service extension.
//!
//! Implements the `NM_Read_SerialNumber_By_ProgrammingMode` procedure from
//! spec 03/05/02 §2.20.1.4: respond with the KNX Serial Number when the
//! MaC reads `(object_type = Device Object, PID = PID_SERIAL_NUMBER,
//! test_info = operand 01h)` and the device's Programming Mode is active.
//! The response follows a random wait of 0–1 s.
//!
//! Other `A_SystemNetworkParameter_Read` variants are silently ignored.
//!
//! # Usage
//!
//! ```rust,ignore
//! type AlExtensions = (StandardAlServices, SystemNetworkParameterService);
//! ```

use core::cell::Cell;

use embassy_time::{Duration, Instant};

use crate::{
    StackState,
    definition::StackDefinition,
    objects::interface::pid,
    service::{AlCtx, ApciHandler},
    timing::time_divisor,
};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::{
    apdu::system_network_parameter::{
        OPERAND_SERIAL_NUMBER_BY_PROGRAMMING_MODE, SystemNetworkParameterRead, SystemNetworkParameterResponse,
        programming_mode_scan_wait_ms,
    },
    buffers::Buffer,
    builder::MessageBuilder,
    knx::{ApciCode, DestinationAddress, KnxMessageBuffer, Priority, RequiredSecurity, ServiceType},
};

use crate::logging::{debug, error, trace, warn};

// TODO: Implement more modes (PowerReset and ExFactoryState) - spec 03/05/02 §2.20.1.5 & .6

/// A serial-number response waiting out its random delay.
///
/// Holds what [`MessageBuilder::respond_to`] would have taken from the
/// request rather than a built response, so no pool buffer is tied up for
/// the up to one second of the wait.
#[derive(Clone, Copy)]
struct PendingScanResponse {
    due: Instant,
    service_type: ServiceType,
    priority: Priority,
    required_security: RequiredSecurity,
    tool_access: bool,
}

/// AL service extension for `A_SystemNetworkParameter_Read`.
#[derive(Default)]
pub struct SystemNetworkParameterService {
    /// At most one response is pending: a repeated scan during the wait
    /// keeps the schedule it already has, so the device answers once.
    pending: Cell<Option<PendingScanResponse>>,
}

impl<D: StackDefinition> ApciHandler<D> for SystemNetworkParameterService {
    fn try_handle_apci(&self, apci: ApciCode, msg: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) -> bool {
        match apci {
            ApciCode::SystemNetworkParameterRead => {
                self.handle_read::<D>(msg, ctx);
                true
            }
            ApciCode::SystemNetworkParameterResponse => {
                debug!("AL ignoring SystemNetworkParameterResponse (response APCI)");
                true
            }
            _ => false,
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.pending.get().map(|pending| pending.due)
    }

    fn poll(&self, ctx: &AlCtx<'_, D>) {
        let Some(pending) = self.pending.get() else { return };
        if Instant::now() < pending.due {
            return;
        }
        self.pending.set(None);

        // The requirement is to reply only while Programming Mode is active
        // (§2.20.1.4). A device taken out of it during the wait is no
        // longer one the Management Client is looking for.
        if !ctx.base.state.is_programming_mode() {
            trace!("AL SystemNetworkParameterRead response dropped: programming mode ended during the wait");
            return;
        }

        send_serial_number_response::<D>(pending, ctx);
    }
}

impl SystemNetworkParameterService {
    fn handle_read<D: StackDefinition>(&self, ind: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) {
        // Per spec 03/05/02 §2.20.1.2, this service is defined *only* on
        // system broadcast. In practice some tools (ETS among them) send
        // `A_SystemNetworkParameter_Read` over plain `T_Broadcast_Ind` on
        // TP1 — the frames look identical on the wire save for one control
        // bit and real devices have historically accepted both. We mirror
        // that behaviour: accept either transport and echo the response
        // back on the same one so the tool sees it on the channel it used.
        let request_service = ind.service_type();
        let response_service = match request_service {
            ServiceType::T_SystemBroadcast_Ind => ServiceType::T_SystemBroadcast_Req,
            ServiceType::T_Broadcast_Ind => ServiceType::T_Broadcast_Req,
            other => {
                warn!("AL SystemNetworkParameterRead with unexpected service type: {:?}", other);
                return;
            }
        };

        let Some(read) = SystemNetworkParameterRead::parse(ind.buf()) else {
            error!("SystemNetworkParameterRead message too short: {}", ind.len());
            return;
        };

        let device_ot: u16 = InterfaceObjectType::Device.into();

        // Only the serial-number-by-programming-mode procedure is supported.
        // Per spec §2.20.1.2, unsupported parameter_type/test_info
        // combinations MUST NOT trigger a response — and for this procedure
        // the test_info "shall consist of a single octet operand 01h"
        // (§2.20.1.4), so trailing octets make it an unsupported one.
        if read.object_type != device_ot
            || read.pid != pid::SERIAL_NUMBER
            || read.operand != OPERAND_SERIAL_NUMBER_BY_PROGRAMMING_MODE
            || !read.test_info_tail(ind.buf()).is_empty()
        {
            trace!(
                "AL SystemNetworkParameterRead unsupported: object_type=0x{:04X}, pid={}, operand=0x{:X}",
                read.object_type, read.pid, read.operand
            );
            return;
        }

        if !ctx.base.state.is_programming_mode() {
            trace!("AL SystemNetworkParameterRead ignored: programming mode off");
            return;
        }

        if self.pending.get().is_some() {
            trace!("AL SystemNetworkParameterRead: a response is already pending");
            return;
        }

        // The response follows a random wait of 0–1 s (§2.20.1.4). The
        // free-running tick counter stands in for the clock that varies
        // the wait between scans; see `programming_mode_scan_wait_ms`.
        let now = Instant::now();
        let wait_ms = programming_mode_scan_wait_ms(ctx.base.state.serial_number(), now.as_ticks() as u32);
        let wait = Duration::from_millis(u64::from(wait_ms) / time_divisor());
        debug!("AL SystemNetworkParameterRead: programming mode active, responding in {}ms", wait.as_millis());

        self.pending.set(Some(PendingScanResponse {
            due: now + wait,
            service_type: response_service,
            priority: ind.ctrl_field().priority(),
            required_security: ind.required_security(),
            tool_access: ind.tool_access_required(),
        }));
    }
}

/// Emit the serial-number response a finished wait was holding back.
fn send_serial_number_response<D: StackDefinition>(pending: PendingScanResponse, ctx: &AlCtx<'_, D>) {
    // Response tail = test_result = 6-byte KNX Serial Number, after the
    // echoed operand octet `SystemNetworkParameterResponse::write` places.
    let resp_len = SystemNetworkParameterResponse::msg_len(6);
    let Some(msg_buf) = ctx.base.buffer_manager().try_alloc_with_size(resp_len) else {
        warn!("AL no buffer for SystemNetworkParameterResponse");
        return;
    };

    // Addressed to the null group address, with the request's priority
    // (§2.20.1.2) and on the transport the request used. The request's
    // security context is restamped so the secure AL wraps the response
    // exactly as a reactive one.
    let mut msg = MessageBuilder::new_request(
        msg_buf,
        pending.service_type,
        pending.priority,
        DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])),
    )
    .with_required_security(pending.required_security)
    .with_tool_access(pending.tool_access)
    .with_application(ApciCode::SystemNetworkParameterResponse)
    .build();

    let device_ot: u16 = InterfaceObjectType::Device.into();
    let serial: &[u8; 6] = ctx.base.state.serial_number();
    SystemNetworkParameterResponse::write(
        msg.buf_mut(),
        device_ot,
        pid::SERIAL_NUMBER,
        OPERAND_SERIAL_NUMBER_BY_PROGRAMMING_MODE,
        serial,
    );

    ctx.base.lctx.push_outbox(msg.into_inner());
}
