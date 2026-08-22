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
//! The core accepts TP1 standard frames without their checksum. A
//! byte-oriented TPUART driver assembles those frames outside the core;
//! the conformance IPC adapter supplies the same layout directly.
//! Native RF and KNX/IP frame formats are outside this stack's scope.

use core::marker::PhantomData;

use zweidraehte_proto::access::AccessContext;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::memory::memory_regions_valid;
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
    /// A complete received frame, TP1 standard layout without checksum.
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
    pub(crate) tl: TlState<FRAME_CAP>,
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
            tl: TlState::new(F::TL_STYLE, time_divisor),
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
        out
    }

    fn handle_frame(&mut self, frame: &mut FrameBuf<FRAME_CAP>, now_ms: u32, out: &mut PollOutput<FRAME_CAP>) {
        // Security is a compile-time profile choice. Keeping the original
        // one-parse dispatch intact is deliberate: routing every plain frame
        // through the mutable unwrap seam costs several hundred bytes on the
        // G0 even though every `NoSecurity` hook itself folds to nothing.
        if !SEC::ENABLED {
            let Some(view) = FrameView::parse(frame) else { return };
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
                if F::CONNECTIONLESS_MANAGEMENT {
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
            // Connectionless data to our individual address: a BCU2
            // serves its management exclusively connection-oriented;
            // System 7 answers device-oriented connectionless services
            // (03/03/07 §3.1) with a connectionless reply.
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
            TlOutput::Retransmit => {
                if let Some(pending) = self.tl.pending() {
                    out.push(pending.clone());
                }
            }
            TlOutput::SendData { .. } => {}
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
            TlOutput::Retransmit => {
                if let Some(pending) = self.tl.pending() {
                    out.push(pending.clone());
                }
            }
            TlOutput::SendData { .. } => {
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
        now_ms: u32,
        group_key_index: Option<u16>,
        plain_access: AccessContext,
        out: &mut PollOutput<FRAME_CAP>,
    ) -> Option<RequestContext<SEC::ReplyContext>> {
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
        ) {
            crate::security::SalResult::Passthrough => {
                frame.truncate(original_len);
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
                out.push(frame.clone());
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
        let Some(mut request) = self.admit_incoming(frame, now_ms, None, plain_access, out) else { return };
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
        let Some(mut request) = self.admit_incoming(frame, now_ms, None, plain_access, out) else { return };
        if request.access.security == zweidraehte_proto::access::SecurityMode::Plain && !F::CONNECTIONLESS_MANAGEMENT {
            return;
        }
        let Some(view) = FrameView::parse(frame) else { return };
        let Some(apci10) = view.apci() else { return };
        let (code, small6) = Self::split_apci(apci10);
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
        let outputs = self.tl.process(TlEvent::RequestData { dest }, now_ms);
        for output in outputs {
            if let TlOutput::SendData { dest, seq } = output {
                let mut frame: FrameBuf<FRAME_CAP> = frame::data_frame(
                    priority_bits,
                    own,
                    dest.0,
                    false,
                    Tpci::DataConnected(seq),
                    apci,
                    small6,
                    payload,
                );
                // The TL sequence number is part of the inner TPCI and is
                // therefore added before the secure module protects it.
                // `NoSecurity` receives `()` and this call inlines to nothing.
                if !SEC::protect_reply(&mut self.sec, reply_context, &mut frame) {
                    return;
                }
                self.tl.store_pending(frame.clone());
                out.push(frame);
            }
        }
    }

    // ── Broadcast services (programming mode) ───────────────────────

    fn handle_plain_broadcast(&mut self, view: FrameView<'_>, out: &mut PollOutput<FRAME_CAP>) {
        if view.tpci() != Some(Tpci::DataBroadcast) {
            return;
        }
        let Some(apci10) = view.apci() else { return };
        match ApciCode::from_wire10(apci10) {
            ApciCode::IndividualAddressWrite => {
                let payload = view.payload();
                if self.is_programming_mode() && payload.len() == 2 {
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
        let Some(request) = self.admit_incoming(frame, now_ms, None, plain_access, out) else { return };
        let Some(view) = FrameView::parse(frame) else { return };
        if view.tpci() != Some(Tpci::DataBroadcast) {
            return;
        }
        let Some(apci10) = view.apci() else { return };
        match ApciCode::from_wire10(apci10) {
            ApciCode::IndividualAddressSerialNumberWrite => {
                let payload = view.payload();
                if zweidraehte_proto::access::AccessPolicy::OPEN_OFF_TOOL_ON
                    .can_write(&request.access, SEC::security_mode_enabled(&self.sec))
                    && payload.len() == 8
                    && payload[..6] == self.identity.serial_number
                {
                    let base = F::ia_eeprom_offset();
                    self.eeprom.as_mut()[base..base + 2].copy_from_slice(&payload[6..]);
                }
            }
            ApciCode::IndividualAddressWrite => {
                if request.access.security != zweidraehte_proto::access::SecurityMode::Plain {
                    return;
                }
                let payload = view.payload();
                if self.is_programming_mode() && payload.len() == 2 {
                    let base = F::ia_eeprom_offset();
                    self.eeprom.as_mut()[base..base + 2].copy_from_slice(payload);
                }
            }
            ApciCode::IndividualAddressRead if self.is_programming_mode() => {
                if request.access.security != zweidraehte_proto::access::SecurityMode::Plain {
                    return;
                }
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

    fn dispatch_group(&mut self, frame: &mut FrameBuf<FRAME_CAP>, now_ms: u32, out: &mut PollOutput<FRAME_CAP>) {
        let Some(outer) = FrameView::parse(frame) else { return };
        let Some(tsap) = self.tables().tsap_of(outer.dest_group()) else { return };
        let plain_access = AccessContext::new(self.mgmt.default_access_level::<F>());
        let Some(request) = self.admit_incoming(frame, now_ms, Some(u16::from(tsap)), plain_access, out) else {
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
