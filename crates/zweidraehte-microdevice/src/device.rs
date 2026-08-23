//! The device: one owner struct and one cooperative `poll()`.
//!
//! The application (or the firmware main loop, or the conformance DUT
//! shell) owns a [`Microdevice`] and feeds it one input per call —
//! a complete received frame, or a timer tick. Every call returns the
//! frames the stack wants transmitted. There is no executor, no
//! channel, and no interior mutability: interrupts stop at the byte
//! ring outside this struct, and everything in here is plain
//! `&mut self` code.
//!
//! The core accepts TP1 wire frames without their checksum. Plain profiles
//! select standard-frame capacity; the secure BCU2 profile also admits
//! extended frames. A byte-oriented TPUART driver assembles those frames
//! outside the core; the conformance IPC adapter supplies the same layout
//! directly.
//! Native RF and KNX/IP frame formats are outside this stack's scope.

use core::marker::PhantomData;

use zweidraehte_proto::access::AccessContext;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::memory::memory_regions_valid;
use zweidraehte_proto::messages::apdu::device::{
    IndividualAddressSerialNumberRead, IndividualAddressSerialNumberResponse, IndividualAddressSerialNumberWrite,
};
use zweidraehte_proto::messages::apdu::network_parameter::NetworkParameterInfoReport;
use zweidraehte_proto::messages::apdu::system_network_parameter::{
    SystemNetworkParameterRead, SystemNetworkParameterResponse,
};
use zweidraehte_proto::messages::knx::offsets;
use zweidraehte_proto::pid;
use zweidraehte_proto::transport::TlEvent;

use crate::co_flags;
use crate::eeprom::Tables;
use crate::family::MicroDeviceFamily;
use crate::frame::{self, ApciCode, FrameBuf, FrameView, MAX_FRAME, Tpci, WireBuf};
use crate::management::{ManagementState, ServiceResult};
use crate::sal::RequestContext;
use crate::security::{NoSecurity, SecurityModule};
use crate::transport::{TlOutput, TlState};

/// Sizing ceilings shared by all families this crate will carry (the
/// EEPROM image itself is family-sized through
/// [`MicroDeviceFamily::EepromStore`]; the second RAM window's address
/// and live size are the family's `RAM2_BASE`/`RAM2_SIZE`).
pub const RAM_SIZE: usize = 0x100;
pub const RAM2_CEILING: usize = 0x100;
pub const MAX_AUTH_LEVELS: usize = 16;
pub const MAX_LSM: usize = 4;

/// Page-0 RAM address of the system status byte — a BCU silicon fact:
/// the mask ROM keeps programming mode (bit 0) here and ETS toggles it
/// through plain memory writes.
pub(crate) const SYSTEM_STATUS_ADDR: usize = 0x60;
/// The programming-mode bit of the system status byte.
const PROGMODE_BIT: u8 = 0x01;
/// The parity bit keeping the system status byte's population even.
const PARITY_BIT: u8 = 0x80;

/// Request metadata needed while crossing the optional S-AL boundary.
/// Keeping it together makes the distinction from the mutable frame and
/// output queue explicit at every admission site.
struct Admission {
    now_ms: u32,
    group_key_index: Option<u16>,
    plain_access: AccessContext,
    response_tpci: u8,
    reply_destination: Option<IndividualAddress>,
}

/// Boot-time identity that does not live in the EEPROM image.
#[derive(Debug, Clone, Copy)]
pub struct DeviceIdentity {
    pub serial_number: [u8; 6],
    pub order_info: [u8; 10],
    /// `PID_HARDWARE_TYPE` — the identity a System 7 download
    /// procedure guards on (`LdCtrlCompareProp` against the product's
    /// serial). BCU2 predates the property; its family ignores this.
    pub hardware_type: [u8; 6],
}

/// One input to [`Microdevice::poll`].
pub enum PollInput<'a> {
    /// A complete received TP1 wire frame without checksum.
    Frame(&'a [u8]),
    /// A timer tick — call at least every few milliseconds so TL
    /// timeouts and pending transmissions make progress.
    Timer,
}

/// Frames produced by one poll call, in transmission order, in TP1 wire
/// layout without their checksum — what a link driver transmits.
#[derive(Default)]
pub struct PollOutput<const FRAME_CAP: usize = MAX_FRAME> {
    pub frames: heapless::Vec<WireBuf<FRAME_CAP>, 8>,
    /// The stack accepted an `A_Restart`: the caller must restart the
    /// device (reset the MCU / exit the DUT process) after transmitting
    /// the frames above. The value is the erase code: 0 for a basic
    /// restart, 01h–07h for the master-reset variants.
    pub restart: Option<u8>,
}

impl<const FRAME_CAP: usize> PollOutput<FRAME_CAP> {
    /// Queue one canonical frame, converting it to the wire at the edge.
    ///
    /// This is the stack's only egress point, which is what keeps a
    /// retransmission byte-identical: `to_wire` is a pure function of the
    /// canonical frame the transport layer held on to, so re-pushing that
    /// frame reproduces the octets exactly.
    pub(crate) fn push(&mut self, frame: FrameBuf<FRAME_CAP>) {
        // Dropping a frame beyond the eighth would desynchronize the
        // TL sequence bookkeeping; no legitimate single input produces
        // that many.
        self.frames
            .push(frame::to_wire::<FRAME_CAP>(&frame))
            .expect("one poll input never produces more than 8 frames");
    }
}

/// The device stack, generic over the management-model family and the
/// frame capacity its profile commits to.
///
/// `FRAME_CAP` defaults to the standard-frame width, so a plain BCU1, BCU2
/// or System 7 device spells `Microdevice<Family>` and carries exactly the
/// buffers it did before the parameter existed.
pub struct Microdevice<F: MicroDeviceFamily, const FRAME_CAP: usize = MAX_FRAME, SEC: SecurityModule = NoSecurity> {
    /// The EEPROM image at `F::EEPROM_BASE`. The tables live in here.
    pub(crate) eeprom: F::EepromStore,
    /// Page-0 RAM at 0000h (system status, user RAM, RAM flags,
    /// group object values).
    pub(crate) ram: [u8; RAM_SIZE],
    /// The second RAM area at `F::RAM2_BASE` (ceiling-sized; the
    /// family's `RAM2_SIZE` bounds what is addressable).
    pub(crate) ram2: [u8; RAM2_CEILING],
    pub(crate) identity: DeviceIdentity,
    pub(crate) tl: TlState<FRAME_CAP, F::Transport>,
    /// Public so fixtures (tests, the conformance DUT) can seed load
    /// states and keys the way a factory-programmed device ships.
    pub mgmt: ManagementState,
    /// The profile module's state. `NoSecurity` makes this `()`.
    pub(crate) sec: SEC::State,
    pub(crate) _family: PhantomData<F>,
}

impl<F: MicroDeviceFamily, const FRAME_CAP: usize, SEC: SecurityModule> Microdevice<F, FRAME_CAP, SEC> {
    /// Canonical frame capacity available to the plaintext application PDU.
    /// The security envelope occupies the remainder only after dispatch.
    pub(crate) const fn plaintext_frame_capacity() -> usize {
        FRAME_CAP.saturating_sub(SEC::FRAME_OVERHEAD)
    }

    /// The APDU ceiling reported to management clients.
    pub(crate) const fn max_apdu_length() -> u16 {
        frame::max_apdu(Self::plaintext_frame_capacity())
    }

    /// Longest canonical plaintext frame accepted or constructed. Extended
    /// profiles reserve one additional capacity octet because their TP1 wire
    /// form inserts the extended-control field.
    pub(crate) const fn max_plaintext_frame_len() -> usize {
        7 + Self::max_apdu_length() as usize
    }

    /// Bring up the stack over an EEPROM image (a fresh default image
    /// or one restored from persistent storage).
    ///
    /// `time_divisor` compresses the TL timeouts for the conformance
    /// harness's fast mode; firmware passes 1.
    pub fn new(eeprom: F::EepromStore, identity: DeviceIdentity, time_divisor: u32) -> Self
    where
        SEC::State: Default,
    {
        Self::with_security(eeprom, identity, time_divisor, SEC::State::default())
    }

    /// Bring up the stack with the profile module's state supplied.
    ///
    /// A secure device's module state carries its FDSK and its sequence
    /// store, neither of which can be defaulted into existence, so this is
    /// the constructor a secure profile uses.
    pub fn with_security(eeprom: F::EepromStore, identity: DeviceIdentity, time_divisor: u32, sec: SEC::State) -> Self {
        const {
            assert!(F::RAM2_SIZE <= RAM2_CEILING, "family RAM2 window exceeds the shared ceiling");
            assert!(F::AUTH_LEVELS <= MAX_AUTH_LEVELS, "family authorization levels exceed the shared ceiling");
            assert!(
                memory_regions_valid(F::MEMORY_REGIONS),
                "family memory regions overlap or exceed the address space"
            );
        }
        let mut mgmt = ManagementState::new();
        mgmt.reset_connection_auth::<F>();
        Self {
            eeprom,
            ram: [0; RAM_SIZE],
            ram2: [0; RAM2_CEILING],
            identity,
            tl: TlState::new(time_divisor),
            mgmt,
            sec,
            _family: PhantomData,
        }
    }

    pub(crate) fn tables(&self) -> Tables<'_, F> {
        Tables::new(self.eeprom.as_ref(), &self.mgmt)
    }

    pub fn individual_address(&self) -> IndividualAddress {
        self.tables().individual_address()
    }

    // ── Programming mode (system status at 0060h) ───────────────────
    //
    // Bit 0 is the mode; bit 7 keeps the byte's parity even, which is
    // how the mask firmware guards the byte against corruption.

    pub fn is_programming_mode(&self) -> bool {
        self.ram[SYSTEM_STATUS_ADDR] & PROGMODE_BIT != 0
    }

    pub fn set_programming_mode(&mut self, enabled: bool) {
        let mut value = self.ram[SYSTEM_STATUS_ADDR] & !(PROGMODE_BIT | PARITY_BIT);
        if enabled {
            value |= PROGMODE_BIT;
        }
        if !(value & !PARITY_BIT).count_ones().is_multiple_of(2) {
            value |= PARITY_BIT;
        }
        self.ram[SYSTEM_STATUS_ADDR] = value;
    }

    /// The profile module's state, for fixtures and tests that need to
    /// look at what a management exchange did to it.
    pub fn security_state(&self) -> &SEC::State {
        &self.sec
    }

    /// Mutable profile-module state for provisioning fixtures and storage
    /// adapters. Normal application code should use the management services.
    pub fn security_state_mut(&mut self) -> &mut SEC::State {
        &mut self.sec
    }

    /// The raw EEPROM image, for tests that inspect memory after an
    /// erase or a download.
    pub fn eeprom(&self) -> &[u8] {
        self.eeprom.as_ref()
    }

    /// Whether the application program runs — the family's judgment
    /// (BCU2: RunError byte + load state; System 7: load state alone).
    pub fn is_running(&self) -> bool {
        F::is_app_running(self.eeprom.as_ref(), &self.mgmt)
    }

    // ── The runloop ─────────────────────────────────────────────────

    pub fn poll(&mut self, input: PollInput<'_>, now_ms: u32) -> PollOutput<FRAME_CAP> {
        let mut out = PollOutput::<FRAME_CAP>::default();
        match input {
            PollInput::Frame(raw) => {
                if let Some(mut canonical) = frame::normalize::<FRAME_CAP>(raw) {
                    self.handle_frame(&mut canonical, now_ms, &mut out);
                }
            }
            PollInput::Timer => {
                let timer_outputs = self.tl.check_timers(now_ms);
                for output in timer_outputs {
                    if SEC::ENABLED {
                        self.run_secured_tl_output(output, None, now_ms, &mut out);
                    } else {
                        self.run_plain_tl_output(output, None, now_ms, &mut out);
                    }
                }
                self.scan_transmit_requests(&mut out);
            }
        }
        if let Some(report) = SEC::take_security_report(&self.sec) {
            self.emit_security_report(report, &mut out);
        }
        out
    }

    /// Emit the Security IO's spontaneous failure indication.
    ///
    /// 03/05/01 §6.3.11.4 fixes this as an urgent, plaintext broadcast.
    /// The shared APDU writer owns the object/PID payload layout; this stack
    /// adds only its compact TP1 frame header around it.
    fn emit_security_report(&self, report: u8, out: &mut PollOutput<FRAME_CAP>) {
        const SECURITY_IO_TYPE: u16 = 0x0011;
        const PID_SECURITY_REPORT: u8 = 57;

        let mut message = [0u8; NetworkParameterInfoReport::msg_len(2)];
        NetworkParameterInfoReport::write(&mut message, SECURITY_IO_TYPE, PID_SECURITY_REPORT, &[0x00, report]);
        out.push(frame::data_frame(
            0x08,
            self.individual_address(),
            [0x00, 0x00],
            true,
            Tpci::DataBroadcast,
            ApciCode::NetworkParameterInfoReport,
            0,
            &message[offsets::MSG_APCI + 2..],
        ));
    }

    fn handle_frame(&mut self, frame: &mut FrameBuf<FRAME_CAP>, now_ms: u32, out: &mut PollOutput<FRAME_CAP>) {
        // Security is a compile-time profile choice. Keeping the original
        // one-parse dispatch intact is deliberate: routing every plain frame
        // through the mutable unwrap seam costs several hundred bytes on the
        // G0 even though every `NoSecurity` hook itself folds to nothing.
        if !SEC::ENABLED {
            let Some(view) = FrameView::parse(frame) else { return };
            self.detect_own_individual_address(view.source);
            self.handle_plain_frame(view, now_ms, out);
            return;
        }

        self.handle_secured_frame(frame, now_ms, out);
    }

    fn handle_plain_frame(&mut self, view: FrameView<'_>, now_ms: u32, out: &mut PollOutput<FRAME_CAP>) {
        if view.is_group {
            if view.dest_raw == [0, 0] {
                self.handle_plain_broadcast(view, out);
            } else {
                self.handle_plain_group(view, out);
            }
            return;
        }
        if view.dest_individual() != self.individual_address() {
            return;
        }

        let source = view.source;
        let event = match view.tpci() {
            Some(Tpci::Connect) => TlEvent::ReceivedConnect { source },
            Some(Tpci::Disconnect) => TlEvent::ReceivedDisconnect { source },
            Some(Tpci::DataConnected(seq)) => TlEvent::ReceivedData { source, seq_no: seq },
            Some(Tpci::Ack(seq)) => TlEvent::ReceivedAck { source, seq_no: seq },
            Some(Tpci::Nack(seq)) => TlEvent::ReceivedNack { source, seq_no: seq },
            Some(Tpci::DataIndividual) => {
                if F::CONNECTIONLESS_PROPERTIES || F::CONNECTIONLESS_DEVICE_DESCRIPTOR {
                    self.dispatch_plain_connectionless(view, source, out);
                }
                return;
            }
            _ => return,
        };

        let outputs = self.tl.process(event, now_ms);
        for output in outputs {
            self.run_plain_tl_output(output, Some(view), now_ms, out);
        }
    }

    fn handle_secured_frame(&mut self, frame: &mut FrameBuf<FRAME_CAP>, now_ms: u32, out: &mut PollOutput<FRAME_CAP>) {
        let Some(view) = FrameView::parse(frame) else { return };
        self.detect_own_individual_address(view.source);
        if view.is_group {
            if view.dest_raw == [0, 0] {
                self.dispatch_broadcast(frame, now_ms, out);
            } else {
                self.dispatch_group(frame, now_ms, out);
            }
            return;
        }
        if view.dest_individual() != self.individual_address() {
            return;
        }

        let source = view.source;
        let event = match view.tpci() {
            Some(Tpci::Connect) => TlEvent::ReceivedConnect { source },
            Some(Tpci::Disconnect) => TlEvent::ReceivedDisconnect { source },
            Some(Tpci::DataConnected(seq)) => TlEvent::ReceivedData { source, seq_no: seq },
            Some(Tpci::Ack(seq)) => TlEvent::ReceivedAck { source, seq_no: seq },
            Some(Tpci::Nack(seq)) => TlEvent::ReceivedNack { source, seq_no: seq },
            // Connectionless secure requests enter the S-AL directly here;
            // connection-oriented sync uses the numbered path above. After
            // the S-AL admits ordinary data, the service filter applies the
            // base profile's more precise connectionless obligations.
            Some(Tpci::DataIndividual) => {
                self.dispatch_connectionless_frame(frame, source, now_ms, out);
                return;
            }
            // Reserved TPCI codings and address-type mismatches.
            _ => return,
        };

        let outputs = self.tl.process(event, now_ms);
        for output in outputs {
            self.run_secured_tl_output(output, Some(&mut *frame), now_ms, out);
        }
    }

    #[inline]
    fn detect_own_individual_address(&mut self, source: IndividualAddress) {
        // Volume 6 Profiles §2.3.2 requires this BCU2-specific diagnostic.
        // The TPUART driver consumes our transmit echo, so a frame reaching
        // this boundary with our source address really came from the bus.
        if F::DETECT_OWN_INDIVIDUAL_ADDRESS && source == self.individual_address() {
            self.mgmt.device_control |= zweidraehte_proto::pid::device_control::ADDRESS_DUPLICATION;
        }
    }

    /// Execute one TL obligation without carrying the secure admission seam.
    fn run_plain_tl_output(
        &mut self,
        output: TlOutput,
        frame: Option<FrameView<'_>>,
        now_ms: u32,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        let own = self.individual_address();
        match output {
            TlOutput::SendAck { dest, seq, nak } => {
                out.push(frame::ack_frame(0x00, own, dest, nak, seq));
            }
            TlOutput::SendDisconnect { dest } => {
                out.push(frame::disconnect_frame(own, dest));
            }
            TlOutput::Disconnected => {
                self.mgmt.reset_connection_auth::<F>();
            }
            TlOutput::IndicateData { source } => {
                let Some(view) = frame else { return };
                self.dispatch_plain_management(view, source, now_ms, out);
            }
            TlOutput::Retransmit | TlOutput::TransmitPending => {
                if let Some(pending) = self.tl.pending() {
                    out.push(pending.clone());
                }
            }
            TlOutput::SendData { .. } | TlOutput::QueueSend => {}
        }
    }

    /// Execute one TL obligation. `frame` is the frame that triggered
    /// it, for outputs that consume the received APDU.
    fn run_secured_tl_output(
        &mut self,
        output: TlOutput,
        frame: Option<&mut FrameBuf<FRAME_CAP>>,
        now_ms: u32,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        let own = self.individual_address();
        match output {
            TlOutput::SendAck { dest, seq, nak } => {
                // Transport control PDUs always travel at system
                // priority, whatever the acknowledged data carried.
                out.push(frame::ack_frame(0x00, own, dest, nak, seq));
            }
            TlOutput::SendDisconnect { dest } => {
                out.push(frame::disconnect_frame(own, dest));
            }
            TlOutput::Disconnected => {
                // The state machine already reset the connection; the
                // per-connection authorization dies with it.
                self.mgmt.reset_connection_auth::<F>();
            }
            TlOutput::IndicateData { source } => {
                let Some(frame) = frame else { return };
                self.dispatch_management_frame(frame, source, now_ms, out);
            }
            TlOutput::Retransmit | TlOutput::TransmitPending => {
                if let Some(pending) = self.tl.pending() {
                    out.push(pending.clone());
                }
            }
            TlOutput::SendData { .. } | TlOutput::QueueSend => {
                // Produced by our own RequestData in send_reply(); the
                // frame is built there where the APDU is at hand.
            }
        }
    }

    fn dispatch_plain_management(
        &mut self,
        view: FrameView<'_>,
        source: IndividualAddress,
        now_ms: u32,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        let Some(apci10) = view.apci() else { return };
        let (code, small6) = Self::split_apci(apci10);
        let access = AccessContext::new(self.mgmt.auth_level);
        let mut reply_context = SEC::plain_reply_context();
        match self.handle_service(code, small6, view.payload(), view.frame, access, true, &mut reply_context) {
            ServiceResult::None => {}
            ServiceResult::Reply(reply) => {
                self.send_reply(
                    source,
                    view.priority_bits(),
                    reply.apci,
                    reply.small6,
                    &reply.payload,
                    reply_context,
                    now_ms,
                    out,
                );
            }
            ServiceResult::Restart => {
                out.restart = Some(0);
            }
        }
    }

    fn dispatch_plain_connectionless(
        &mut self,
        view: FrameView<'_>,
        source: IndividualAddress,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        let Some(apci10) = view.apci() else { return };
        let (code, small6) = Self::split_apci(apci10);
        if !Self::connectionless_service_supported(code) {
            return;
        }
        let access = AccessContext::new(self.mgmt.default_access_level::<F>());
        let mut reply_context = SEC::plain_reply_context();
        match self.handle_service(code, small6, view.payload(), view.frame, access, false, &mut reply_context) {
            ServiceResult::None => {}
            ServiceResult::Reply(reply) => {
                let own = self.individual_address();
                out.push(frame::data_frame(
                    view.priority_bits(),
                    own,
                    source.0,
                    false,
                    Tpci::DataIndividual,
                    reply.apci,
                    reply.small6,
                    &reply.payload,
                ));
            }
            ServiceResult::Restart => {
                out.restart = Some(0);
            }
        }
    }

    /// Authenticate and unwrap one frame after its outer transport PDU has
    /// been accepted. For connected traffic this is called only from
    /// `TlOutput::IndicateData`, so an invalid MAC or replay still receives
    /// the transport ACK and never advances its S-AL counter on a TL reject.
    #[inline(always)]
    fn admit_incoming(
        &mut self,
        frame: &mut FrameBuf<FRAME_CAP>,
        admission: Admission,
        out: &mut PollOutput<FRAME_CAP>,
    ) -> Option<RequestContext<SEC::ReplyContext>> {
        let Admission { now_ms, group_key_index, plain_access, response_tpci, reply_destination } = admission;
        if !SEC::ENABLED {
            return Some(RequestContext { access: plain_access, reply: SEC::plain_reply_context() });
        }

        let original_len = frame.len();
        if frame.resize_default(FRAME_CAP).is_err() {
            return None;
        }
        let mut len = original_len;
        let own_ia = u16::from_be_bytes(self.individual_address().0);
        match SEC::process_incoming(
            &mut self.sec,
            frame,
            &mut len,
            now_ms,
            own_ia,
            self.identity.serial_number,
            self.tl.time_divisor(),
            group_key_index,
            response_tpci,
        ) {
            crate::security::SalResult::Passthrough => {
                frame.truncate(original_len);
                // A secure composition reserves room for the S-A_Data
                // envelope, but that extra capacity must not enlarge the
                // device's advertised plaintext APDU. Otherwise a plain
                // management request could use the security headroom to
                // bypass the profile's maximum-frame limit.
                if original_len > Self::max_plaintext_frame_len() {
                    return None;
                }
                Some(RequestContext { access: plain_access, reply: SEC::plain_reply_context() })
            }
            crate::security::SalResult::Decrypted(context) => {
                if len > Self::max_plaintext_frame_len() {
                    frame.truncate(original_len);
                    return None;
                }
                frame.truncate(len);
                Some(context)
            }
            crate::security::SalResult::Dropped => {
                frame.truncate(original_len);
                None
            }
            crate::security::SalResult::Response { len } => {
                frame.truncate(len);
                if let Some(dest) = reply_destination {
                    // Let the TL own the connected response exactly like an
                    // ordinary management reply: this advances its outgoing
                    // sequence, starts TACK, and retains the encrypted frame
                    // byte-for-byte for retransmission.
                    if !self.tl.can_send() {
                        if self.process_busy_send(dest, now_ms, out) {
                            let _ = self.tl.store_queued(frame.clone());
                        }
                    } else if let Some(seq) = self.tl.begin_send(dest, now_ms) {
                        debug_assert_eq!(frame[6] & 0xFC, Tpci::DataConnected(seq).octet());
                        self.tl.store_pending(frame.clone());
                        out.push(frame.clone());
                    }
                } else {
                    out.push(frame.clone());
                }
                None
            }
        }
    }

    /// Split one management APDU into the service code and the short
    /// services' 6-bit in-APCI payload. The other wire families spend
    /// those bits on the service code itself, so they carry no small
    /// data.
    fn split_apci(apci10: u16) -> (ApciCode, u8) {
        let code = ApciCode::from_wire10(apci10);
        let small6 = if u8::from(code) < 0x10 { (apci10 & 0x3F) as u8 } else { 0 };
        (code, small6)
    }

    /// Handle a management APDU and send whatever it answers.
    fn dispatch_management_frame(
        &mut self,
        frame: &mut FrameBuf<FRAME_CAP>,
        source: IndividualAddress,
        now_ms: u32,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        let plain_access = AccessContext::new(self.mgmt.auth_level);
        // S-A_Sync_Res uses the request's communication mode (03/03/07
        // §5.3.2), but a connected response carries the device's next TL
        // sequence. CCM needs that TPCI before the TL sees the response.
        let response_tpci = Tpci::DataConnected(self.tl.reply_seq()).octet();
        let Some(mut request) = self.admit_incoming(
            frame,
            Admission { now_ms, group_key_index: None, plain_access, response_tpci, reply_destination: Some(source) },
            out,
        ) else {
            return;
        };
        let Some(view) = FrameView::parse(frame) else { return };
        let Some(apci10) = view.apci() else { return };
        let (code, small6) = Self::split_apci(apci10);
        match self.handle_service(code, small6, view.payload(), view.frame, request.access, true, &mut request.reply) {
            ServiceResult::None => {}
            ServiceResult::Reply(reply) => {
                self.send_reply(
                    source,
                    view.priority_bits(),
                    reply.apci,
                    reply.small6,
                    &reply.payload,
                    request.reply,
                    now_ms,
                    out,
                );
            }
            ServiceResult::Restart => {
                out.restart = Some(0);
            }
        }
        if SEC::ENABLED
            && let Some(restart) = SEC::take_scheduled_restart(&mut self.sec)
        {
            if let Some(wipe_ia) = restart.wipe_individual_address {
                self.apply_factory_reset(wipe_ia);
            }
            out.restart = Some(restart.erase_code);
        }
    }

    /// Handle a device-oriented connectionless management APDU: the
    /// same service surface, the reply going out unnumbered rather
    /// than through the transport connection. A connectionless
    /// `A_Restart` still restarts.
    fn dispatch_connectionless_frame(
        &mut self,
        frame: &mut FrameBuf<FRAME_CAP>,
        source: IndividualAddress,
        now_ms: u32,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        let plain_access = AccessContext::new(self.mgmt.default_access_level::<F>());
        let Some(mut request) = self.admit_incoming(
            frame,
            Admission {
                now_ms,
                group_key_index: None,
                plain_access,
                response_tpci: Tpci::DataIndividual.octet(),
                reply_destination: None,
            },
            out,
        ) else {
            return;
        };
        let Some(view) = FrameView::parse(frame) else { return };
        let Some(apci10) = view.apci() else { return };
        let (code, small6) = Self::split_apci(apci10);
        if !Self::connectionless_service_supported(code) {
            return;
        }
        // Connectionless plaintext requests are not part of the active
        // transport connection. `plain_access` above gives them the profile's
        // default-key level, never a connected client's authorization.
        match self.handle_service(code, small6, view.payload(), view.frame, request.access, false, &mut request.reply) {
            ServiceResult::None => {}
            ServiceResult::Reply(reply) => {
                self.send_connectionless_reply(
                    source,
                    view.priority_bits(),
                    reply.apci,
                    reply.small6,
                    &reply.payload,
                    request.reply,
                    out,
                );
            }
            ServiceResult::Restart => {
                out.restart = Some(0);
            }
        }
        if SEC::ENABLED
            && let Some(restart) = SEC::take_scheduled_restart(&mut self.sec)
        {
            if let Some(wipe_ia) = restart.wipe_individual_address {
                self.apply_factory_reset(wipe_ia);
            }
            out.restart = Some(restart.erase_code);
        }
    }

    /// Whether one management service is defined on point-to-point
    /// connectionless transport for this composition.
    ///
    /// BCU2 Property procedures are connectionless-capable, but its classic
    /// direct-memory procedure is explicitly `RCo`. A composed Data Secure
    /// module additionally accepts connectionless DD0: this is an optional
    /// base-profile extension used by ETS's secure bootstrap and observed on
    /// the reference MV-0021 device, not a semantic of mask 0021h itself.
    fn connectionless_service_supported(code: ApciCode) -> bool {
        match code {
            ApciCode::DeviceDescriptorRead => F::CONNECTIONLESS_DEVICE_DESCRIPTOR || SEC::ENABLED,
            ApciCode::PropertyValueRead | ApciCode::PropertyValueWrite | ApciCode::PropertyDescriptionRead => {
                F::CONNECTIONLESS_PROPERTIES
            }
            // Extended management comes with an extended plaintext frame
            // budget. The secure BCU2 composition has that budget, while a
            // standard-frame BCU2 image folds these branches away; the gate
            // also preserves the plain extended System 7 test profile.
            ApciCode::PropertyExtValueRead
            | ApciCode::PropertyExtValueWriteCon
            | ApciCode::PropertyExtValueWriteUnCon
            | ApciCode::PropertyExtDescriptionRead
            | ApciCode::MemoryExtendedRead
            | ApciCode::MemoryExtendedWrite
            | ApciCode::FunctionPropertyExtCommand
            | ApciCode::FunctionPropertyExtStateRead => frame::is_extended(Self::plaintext_frame_capacity()),
            // The base profiles make connectionless restart optional. The
            // micro stack only pays for it where a secure composition needs
            // Master Reset over the same unnumbered management channel.
            ApciCode::Restart => SEC::ENABLED,
            _ => false,
        }
    }

    // A reply is exactly these facts; bundling them would only move the
    // argument list one type away.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn send_connectionless_reply(
        &mut self,
        dest: IndividualAddress,
        priority_bits: u8,
        apci: ApciCode,
        small6: u8,
        payload: &[u8],
        reply_context: SEC::ReplyContext,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        let own = self.individual_address();
        let mut frame =
            frame::data_frame(priority_bits, own, dest.0, false, Tpci::DataIndividual, apci, small6, payload);
        if !SEC::protect_reply(&mut self.sec, reply_context, &mut frame) {
            return;
        }
        out.push(frame);
    }

    /// Send one connection-oriented reply APDU through the TL.
    // A reply is exactly these eight facts; bundling them into a
    // struct would just move the argument list one type away.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub(crate) fn send_reply(
        &mut self,
        dest: IndividualAddress,
        priority_bits: u8,
        apci: ApciCode,
        small6: u8,
        payload: &[u8],
        reply_context: SEC::ReplyContext,
        now_ms: u32,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        let own = self.individual_address();
        let can_send = self.tl.can_send();
        let seq = self.tl.reply_seq();
        let mut frame: FrameBuf<FRAME_CAP> =
            frame::data_frame(priority_bits, own, dest.0, false, Tpci::DataConnected(seq), apci, small6, payload);
        // The TL sequence number is part of the inner TPCI and is therefore
        // added before the secure module protects it. Build the complete
        // frame before moving the TL to OPEN_WAIT, so a failed secure wrap
        // leaves the connection able to serve the next request.
        if !SEC::protect_reply(&mut self.sec, reply_context, &mut frame) {
            return;
        }
        if !can_send {
            // The AL has produced E15 while another numbered response is
            // unacknowledged. Style 2/3 retain one complete response; Style 1
            // closes and leaves its zero-sized queue empty.
            if self.process_busy_send(dest, now_ms, out) {
                let _ = self.tl.store_queued(frame);
            }
            return;
        }
        let Some(actual_seq) = self.tl.begin_send(dest, now_ms) else {
            return;
        };
        debug_assert_eq!(actual_seq, seq);
        self.tl.store_pending(frame.clone());
        out.push(frame);
    }

    fn process_busy_send(&mut self, dest: IndividualAddress, now_ms: u32, out: &mut PollOutput<FRAME_CAP>) -> bool {
        let mut queued = false;
        for output in self.tl.process(TlEvent::RequestData { dest }, now_ms) {
            // E15 cannot indicate received data. Reusing the ordinary output
            // path keeps disconnect frames and authorization cleanup exactly
            // aligned with bus-originated TL transitions.
            if output == TlOutput::QueueSend {
                queued = true;
            } else {
                self.run_secured_tl_output(output, None, now_ms, out);
            }
        }
        queued
    }

    // ── Broadcast services (programming mode) ───────────────────────

    /// Serve the serial-number addressing pair shared by the plain and
    /// secure broadcast paths. The secure caller supplies the request's
    /// reply context, so the response is protected exactly like the request;
    /// `NoSecurity` folds that step away in a plain BCU2 image.
    fn handle_serial_number_broadcast(
        &mut self,
        view: FrameView<'_>,
        access: AccessContext,
        reply_context: SEC::ReplyContext,
        out: &mut PollOutput<FRAME_CAP>,
    ) -> bool {
        if !F::SERIAL_NUMBER_ADDRESSING {
            return false;
        }

        let Some(apci10) = view.apci() else { return false };
        match ApciCode::from_wire10(apci10) {
            ApciCode::IndividualAddressSerialNumberRead => {
                let Some(serial) = IndividualAddressSerialNumberRead::serial_number(view.frame) else {
                    return true;
                };
                if serial != self.identity.serial_number {
                    return true;
                }

                // The response carries the six-octet serial followed by four
                // reserved/domain-address octets. The source IA is the value
                // the requester is trying to verify.
                let mut response: FrameBuf<FRAME_CAP> = frame::data_frame(
                    view.priority_bits(),
                    self.individual_address(),
                    [0, 0],
                    true,
                    Tpci::DataBroadcast,
                    ApciCode::IndividualAddressSerialNumberResponse,
                    0,
                    &[0; 10],
                );
                IndividualAddressSerialNumberResponse::write_serial(
                    response.as_mut_slice(),
                    &self.identity.serial_number,
                );
                if SEC::protect_reply(&mut self.sec, reply_context, &mut response) {
                    out.push(response);
                }
                true
            }
            ApciCode::IndividualAddressSerialNumberWrite => {
                if !zweidraehte_proto::access::AccessPolicy::OPEN_OFF_TOOL_ON
                    .can_write(&access, SEC::security_mode_enabled(&self.sec))
                    || !F::individual_address_write_enabled(self.eeprom.as_ref())
                {
                    return true;
                }
                let Some(serial) = IndividualAddressSerialNumberWrite::serial_number(view.frame) else {
                    return true;
                };
                let Some(address) = IndividualAddressSerialNumberWrite::address_bytes(view.frame) else {
                    return true;
                };
                if serial == self.identity.serial_number {
                    let base = F::ia_eeprom_offset();
                    self.eeprom.as_mut()[base..base + 2].copy_from_slice(address);
                }
                true
            }
            _ => false,
        }
    }

    /// Answer ETS's programming-mode serial-number scan.
    ///
    /// Secure commissioning uses the system-broadcast procedure from
    /// 03/05/02 §2.20.1.3 rather than the legacy
    /// `A_IndividualAddress_Read`: Device Object, PID_SERIAL_NUMBER and
    /// operand 01h. Keep it behind the secure composition constant so a
    /// plain BCU2 image does not carry the additional APCI and codec path.
    fn handle_programming_mode_serial_scan(
        &mut self,
        view: FrameView<'_>,
        reply_context: SEC::ReplyContext,
        out: &mut PollOutput<FRAME_CAP>,
    ) -> bool {
        if !SEC::ENABLED || view.apci() != Some(ApciCode::SystemNetworkParameterRead.wire10_base()) {
            return false;
        }

        let Some(request) = SystemNetworkParameterRead::parse(view.frame) else {
            return true;
        };
        if request.object_type != 0
            || request.pid != pid::SERIAL_NUMBER
            || request.operand != 0x01
            || !self.is_programming_mode()
        {
            return true;
        }

        // object_type(2) + PID/reserved(2) + operand(1) + serial(6).
        let mut response: FrameBuf<FRAME_CAP> = frame::data_frame(
            view.priority_bits(),
            self.individual_address(),
            [0, 0],
            true,
            Tpci::DataSystemBroadcast,
            ApciCode::SystemNetworkParameterResponse,
            0,
            &[0; 11],
        );
        SystemNetworkParameterResponse::write(
            response.as_mut_slice(),
            0,
            pid::SERIAL_NUMBER,
            0x01,
            &self.identity.serial_number,
        );
        if SEC::protect_reply(&mut self.sec, reply_context, &mut response) {
            out.push(response);
        }
        true
    }

    fn handle_plain_broadcast(&mut self, view: FrameView<'_>, out: &mut PollOutput<FRAME_CAP>) {
        if view.tpci() != Some(Tpci::DataBroadcast) {
            return;
        }
        let Some(apci10) = view.apci() else { return };
        let access = AccessContext::new(self.mgmt.default_access_level::<F>());
        if self.handle_serial_number_broadcast(view, access, SEC::plain_reply_context(), out) {
            return;
        }
        if self.handle_programming_mode_serial_scan(view, SEC::plain_reply_context(), out) {
            return;
        }
        match ApciCode::from_wire10(apci10) {
            ApciCode::IndividualAddressWrite => {
                let payload = view.payload();
                if F::individual_address_write_enabled(self.eeprom.as_ref())
                    && self.is_programming_mode()
                    && payload.len() == 2
                {
                    let base = F::ia_eeprom_offset();
                    self.eeprom.as_mut()[base..base + 2].copy_from_slice(payload);
                }
            }
            ApciCode::IndividualAddressRead if self.is_programming_mode() => {
                let own = self.individual_address();
                out.push(frame::data_frame(
                    view.priority_bits(),
                    own,
                    [0, 0],
                    true,
                    Tpci::DataBroadcast,
                    ApciCode::IndividualAddressResponse,
                    0,
                    &[],
                ));
            }
            _ => {}
        }
    }

    fn dispatch_broadcast(&mut self, frame: &mut FrameBuf<FRAME_CAP>, now_ms: u32, out: &mut PollOutput<FRAME_CAP>) {
        let plain_access = AccessContext::new(self.mgmt.default_access_level::<F>());
        let Some(request) = self.admit_incoming(
            frame,
            Admission {
                now_ms,
                group_key_index: None,
                plain_access,
                response_tpci: Tpci::DataBroadcast.octet(),
                reply_destination: None,
            },
            out,
        ) else {
            return;
        };
        let Some(view) = FrameView::parse(frame) else { return };
        if view.tpci() != Some(Tpci::DataBroadcast) {
            return;
        }
        let Some(apci10) = view.apci() else { return };
        if self.handle_serial_number_broadcast(view, request.access, request.reply, out) {
            return;
        }
        if self.handle_programming_mode_serial_scan(view, request.reply, out) {
            return;
        }
        match ApciCode::from_wire10(apci10) {
            ApciCode::IndividualAddressWrite => {
                if !zweidraehte_proto::access::AccessPolicy::OPEN_OFF_TOOL_ON
                    .can_write(&request.access, SEC::security_mode_enabled(&self.sec))
                {
                    self.record_access_failure(request.access, view.frame);
                    return;
                }
                if !F::individual_address_write_enabled(self.eeprom.as_ref()) {
                    return;
                }
                let payload = view.payload();
                if self.is_programming_mode() && payload.len() == 2 {
                    let base = F::ia_eeprom_offset();
                    self.eeprom.as_mut()[base..base + 2].copy_from_slice(payload);
                }
            }
            ApciCode::IndividualAddressRead if self.is_programming_mode() => {
                let own = self.individual_address();
                let mut response = frame::data_frame(
                    view.priority_bits(),
                    own,
                    [0, 0],
                    true,
                    Tpci::DataBroadcast,
                    ApciCode::IndividualAddressResponse,
                    0,
                    &[],
                );
                if SEC::protect_reply(&mut self.sec, request.reply, &mut response) {
                    out.push(response);
                }
            }
            _ => {}
        }
    }

    fn dispatch_group(&mut self, frame: &mut FrameBuf<FRAME_CAP>, now_ms: u32, out: &mut PollOutput<FRAME_CAP>) {
        let Some(outer) = FrameView::parse(frame) else { return };
        let Some(tsap) = self.tables().tsap_of(outer.dest_group()) else { return };
        let plain_access = AccessContext::new(self.mgmt.default_access_level::<F>());
        let Some(request) = self.admit_incoming(
            frame,
            Admission {
                now_ms,
                group_key_index: Some(u16::from(tsap)),
                plain_access,
                response_tpci: Tpci::DataGroup.octet(),
                reply_destination: None,
            },
            out,
        ) else {
            return;
        };
        let Some(view) = FrameView::parse(frame) else { return };
        self.handle_group(view, request, out);
    }

    // ── Application API (the classic BCU flag model) ────────────────

    /// RAM address of the flags byte of `asap`, if the tables map one.
    fn flags_addr(&self, asap: u8) -> Option<usize> {
        let tables = self.tables();
        if asap >= tables.co_count() {
            return None;
        }
        let addr = usize::from(tables.ram_flags_ptr()) + usize::from(asap);
        (addr < RAM_SIZE).then_some(addr)
    }

    pub fn object_flags(&self, asap: u8) -> u8 {
        self.flags_addr(asap).map(|a| self.ram[a]).unwrap_or(0)
    }

    pub(crate) fn update_flags(&mut self, asap: u8, f: impl FnOnce(u8) -> u8) {
        if let Some(addr) = self.flags_addr(asap) {
            self.ram[addr] = f(self.ram[addr]);
        }
    }

    /// Request transmission of the object's value (a group write).
    pub fn set_transmit_request(&mut self, asap: u8) {
        self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_REQUEST));
    }

    /// Request a group read for this object.
    pub fn set_read_request(&mut self, asap: u8) {
        self.update_flags(asap, |f| co_flags::set_tx_state(f | co_flags::READ_REQUEST, co_flags::TX_REQUEST));
    }

    pub fn clear_update_flag(&mut self, asap: u8) {
        self.update_flags(asap, |f| f & !(co_flags::UPDATE | co_flags::VALUE_CHANGED));
    }

    /// Copy the object's value bytes out of RAM. Returns the number of
    /// bytes the object's type occupies.
    pub fn read_value(&self, asap: u8, buf: &mut [u8]) -> usize {
        let Some((addr, size)) = self.value_slot(asap) else { return 0 };
        let n = size.min(buf.len());
        buf[..n].copy_from_slice(&self.ram[addr..addr + n]);
        n
    }

    /// Write the object's value bytes into RAM (application side; sets
    /// no flags — pair with [`Self::set_transmit_request`]).
    pub fn write_value(&mut self, asap: u8, data: &[u8]) {
        if let Some((addr, size)) = self.value_slot(asap) {
            let n = size.min(data.len());
            self.ram[addr..addr + n].copy_from_slice(&data[..n]);
        }
    }

    /// Export the EEPROM image (snapshot persistence).
    pub fn eeprom_image(&self) -> &[u8] {
        self.eeprom.as_ref()
    }
}
