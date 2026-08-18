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
//! Byte-oriented media (TPUART) assemble frames *outside* the core in
//! their link driver and feed the result through [`PollInput::Frame`];
//! frame-oriented media (the conformance IPC socket, RF, KNX/IP) pass
//! their frames straight in. That keeps the core medium-agnostic
//! without a trait between it and the driver.

use core::marker::PhantomData;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::transport::TlEvent;

use crate::co_flags;
use crate::eeprom::Tables;
use crate::family::MicroDeviceFamily;
use crate::frame::{self, FrameBuf, FrameView, Tpci};
use crate::management::{ManagementState, ServiceResult};
use crate::transport::{TlOutput, TlState};

/// Sizing ceilings shared by all families this crate will carry (the
/// EEPROM image itself is family-sized through
/// [`MicroDeviceFamily::EepromStore`]; the second RAM window's address
/// and live size are the family's `RAM2_BASE`/`RAM2_SIZE`).
pub const RAM_SIZE: usize = 0x100;
pub const RAM2_CEILING: usize = 0x100;
pub const MAX_AUTH_LEVELS: usize = 16;
pub const MAX_LSM: usize = 4;

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

/// Frames produced by one poll call, in transmission order.
#[derive(Default)]
pub struct PollOutput {
    pub frames: heapless::Vec<FrameBuf, 8>,
    /// The stack accepted an `A_Restart`: the caller must restart the
    /// device (reset the MCU / exit the DUT process) after
    /// transmitting the frames above.
    pub restart: bool,
}

impl PollOutput {
    pub(crate) fn push(&mut self, frame: FrameBuf) {
        // Dropping a frame beyond the eighth would desynchronize the
        // TL sequence bookkeeping; no legitimate single input produces
        // that many.
        self.frames.push(frame).expect("one poll input never produces more than 8 frames");
    }
}

/// The device stack. Generic over the management-model family only.
pub struct Microdevice<F: MicroDeviceFamily> {
    /// The EEPROM image at `F::EEPROM_BASE`. The tables live in here.
    pub(crate) eeprom: F::EepromStore,
    /// Page-0 RAM at 0000h (system status, user RAM, RAM flags,
    /// group object values).
    pub(crate) ram: [u8; RAM_SIZE],
    /// The second RAM area at `F::RAM2_BASE` (ceiling-sized; the
    /// family's `RAM2_SIZE` bounds what is addressable).
    pub(crate) ram2: [u8; RAM2_CEILING],
    pub(crate) identity: DeviceIdentity,
    pub(crate) tl: TlState,
    /// Public so fixtures (tests, the conformance DUT) can seed load
    /// states and keys the way a factory-programmed device ships.
    pub mgmt: ManagementState,
    pub(crate) _family: PhantomData<F>,
}

impl<F: MicroDeviceFamily> Microdevice<F> {
    /// Bring up the stack over an EEPROM image (a fresh default image
    /// or one restored from persistent storage).
    ///
    /// `time_divisor` compresses the TL timeouts for the conformance
    /// harness's fast mode; firmware passes 1.
    pub fn new(eeprom: F::EepromStore, identity: DeviceIdentity, time_divisor: u32) -> Self {
        const {
            assert!(F::RAM2_SIZE <= RAM2_CEILING, "family RAM2 window exceeds the shared ceiling");
        }
        Self {
            eeprom,
            ram: [0; RAM_SIZE],
            ram2: [0; RAM2_CEILING],
            identity,
            tl: TlState::new(F::TL_STYLE, time_divisor),
            mgmt: ManagementState::new(),
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
        self.ram[0x60] & 0x01 != 0
    }

    pub fn set_programming_mode(&mut self, enabled: bool) {
        let mut value = self.ram[0x60] & 0x7E;
        if enabled {
            value |= 0x01;
        }
        if !(value & 0x7F).count_ones().is_multiple_of(2) {
            value |= 0x80;
        }
        self.ram[0x60] = value;
    }

    /// Whether the application program runs — the family's judgment
    /// (BCU2: RunError byte + load state; System 7: load state alone).
    pub fn is_running(&self) -> bool {
        F::is_app_running(self.eeprom.as_ref(), &self.mgmt)
    }

    // ── The runloop ─────────────────────────────────────────────────

    pub fn poll(&mut self, input: PollInput<'_>, now_ms: u32) -> PollOutput {
        let mut out = PollOutput::default();
        match input {
            PollInput::Frame(raw) => {
                if let Some(view) = FrameView::parse(raw) {
                    self.handle_frame(view, now_ms, &mut out);
                }
            }
            PollInput::Timer => {
                let timer_outputs = self.tl.check_timers(now_ms);
                for output in timer_outputs {
                    self.run_tl_output(output, None, now_ms, &mut out);
                }
                self.scan_transmit_requests(&mut out);
            }
        }
        out
    }

    fn handle_frame(&mut self, view: FrameView<'_>, now_ms: u32, out: &mut PollOutput) {
        if view.is_group {
            if view.dest_raw == [0, 0] {
                self.handle_broadcast(view, out);
            } else {
                self.handle_group(view, out);
            }
            return;
        }
        if view.dest_individual() != self.individual_address() {
            return;
        }

        let source = view.source;
        let event = match view.tpci() {
            Tpci::Control { disconnect: false } => TlEvent::ReceivedConnect { source },
            Tpci::Control { disconnect: true } => TlEvent::ReceivedDisconnect { source },
            Tpci::Numbered { seq } => TlEvent::ReceivedData { source, seq_no: seq },
            Tpci::ControlAck { nak: false, seq } => TlEvent::ReceivedAck { source, seq_no: seq },
            Tpci::ControlAck { nak: true, seq } => TlEvent::ReceivedNack { source, seq_no: seq },
            // Connectionless data to our individual address: a BCU2
            // serves its management exclusively connection-oriented.
            Tpci::Unnumbered | Tpci::Unknown => return,
        };

        let outputs = self.tl.process(event, now_ms);
        for output in outputs {
            self.run_tl_output(output, Some(&view), now_ms, out);
        }
    }

    /// Execute one TL obligation. `frame` is the frame that triggered
    /// it, for outputs that consume the received APDU.
    fn run_tl_output(&mut self, output: TlOutput, frame: Option<&FrameView<'_>>, now_ms: u32, out: &mut PollOutput) {
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
                let Some(view) = frame else { return };
                self.dispatch_management(view, source, now_ms, out);
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

    /// Handle a management APDU and send whatever it answers.
    fn dispatch_management(
        &mut self,
        view: &FrameView<'_>,
        source: IndividualAddress,
        now_ms: u32,
        out: &mut PollOutput,
    ) {
        let Some(apci10) = view.apci() else { return };
        // Escaped services (top nibble Fh) use the whole low octet as
        // the code; short services carry up to 6 data bits there.
        let (base, small6) = if apci10 >> 6 == 0x0F { (apci10, 0) } else { (apci10 & 0x3C0, (apci10 & 0x3F) as u8) };

        match self.handle_service(base, small6, view.payload(), source) {
            ServiceResult::None => {}
            ServiceResult::Reply(reply) => {
                self.send_reply(source, view.priority_bits(), reply.apci10, reply.small6, &reply.payload, now_ms, out);
            }
            ServiceResult::Restart => {
                out.restart = true;
            }
        }
    }

    /// Send one connection-oriented reply APDU through the TL.
    // A reply is exactly these eight facts; bundling them into a
    // struct would just move the argument list one type away.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn send_reply(
        &mut self,
        dest: IndividualAddress,
        priority_bits: u8,
        apci10: u16,
        small6: u8,
        payload: &[u8],
        now_ms: u32,
        out: &mut PollOutput,
    ) {
        let own = self.individual_address();
        let outputs = self.tl.process(TlEvent::RequestData { dest }, now_ms);
        for output in outputs {
            if let TlOutput::SendData { dest, seq } = output {
                let frame = frame::data_frame(
                    priority_bits,
                    own,
                    dest.0,
                    false,
                    frame::tpci_numbered(seq),
                    apci10,
                    small6,
                    payload,
                );
                self.tl.store_pending(frame.clone());
                out.push(frame);
            }
        }
    }

    // ── Broadcast services (programming mode) ───────────────────────

    fn handle_broadcast(&mut self, view: FrameView<'_>, out: &mut PollOutput) {
        if view.tpci() != Tpci::Unnumbered {
            return;
        }
        let Some(apci10) = view.apci() else { return };
        match apci10 & 0x3C0 {
            frame::apci::INDIVIDUAL_ADDRESS_WRITE => {
                let payload = view.payload();
                if self.is_programming_mode() && payload.len() == 2 {
                    let base = F::ia_eeprom_offset();
                    self.eeprom.as_mut()[base..base + 2].copy_from_slice(payload);
                }
            }
            frame::apci::INDIVIDUAL_ADDRESS_READ if self.is_programming_mode() => {
                let own = self.individual_address();
                out.push(frame::data_frame(
                    view.priority_bits(),
                    own,
                    [0, 0],
                    true,
                    frame::TPCI_UNNUMBERED,
                    frame::apci::INDIVIDUAL_ADDRESS_RESPONSE,
                    0,
                    &[],
                ));
            }
            _ => {}
        }
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
