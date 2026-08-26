//! Group communication: destination GA → TSAP → associations → group
//! objects, all resolved through the EEPROM tables in place.
//!
//! The receive path mirrors what mask firmware does between a group
//! telegram and the application's RAM: look the destination up in the
//! address table, fan out over the association table, and for each
//! associated object check its config flags, move the value, and raise
//! the RAM flags. The transmit path is the inverse: a flag scan finds
//! transmit requests, the object's sending association — the table
//! slot whose number equals the ASAP (RT2, 03/05/01 §4.17.4.3.1) —
//! names the sending TSAP, and the address table turns that back into
//! a GA.
//!
//! Group communication only happens while the application runs — a
//! halted or unloaded device neither updates objects nor answers
//! reads, which is exactly the state ETS relies on during a download.

use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::security::go_flags_accept;

use crate::co_flags;
use crate::device::{Microdevice, PollOutput, RAM_SIZE};
use crate::family::MicroDeviceFamily;
use crate::frame::{self, ApciCode, FrameView, Tpci};
use crate::sal::RequestContext;
use crate::security::SecurityModule;

impl<F: MicroDeviceFamily, const FRAME_CAP: usize, SEC: SecurityModule> Microdevice<F, FRAME_CAP, SEC> {
    /// Value location and size of an object, if its table entry maps
    /// into RAM. The data pointer is a page-0 RAM address on this
    /// family; the value size comes from the type octet.
    pub(crate) fn value_slot(&self, asap: u8) -> Option<(usize, usize)> {
        let entry = self.tables().co_entry(asap)?;
        let (size, _) = ComObjectType::from(entry.value_type & 0x3F).size_in_bytes();
        let addr = usize::from(entry.data_ptr);
        (addr + size <= RAM_SIZE).then_some((addr, size))
    }

    /// Plain group dispatch retains the base stack's direct table walk.
    /// Carrying access metadata through this path merely so the absent
    /// security module can discard it measurably grows the smallest image.
    pub(crate) fn handle_plain_group(&mut self, view: FrameView<'_>, out: &mut PollOutput<FRAME_CAP>) {
        if view.tpci() != Some(Tpci::DataGroup) || !self.is_running() {
            return;
        }
        let Some(apci10) = view.apci() else { return };
        let code = ApciCode::from_wire10(apci10);
        let small6 = (apci10 & 0x3F) as u8;
        let Some(tsap) = self.tables().tsap_of(view.dest_group()) else { return };

        let association_count = self.tables().assoc_count();
        for number in 0..association_count {
            let Some((association_tsap, asap)) = self.tables().association(number) else { continue };
            if association_tsap != tsap {
                continue;
            }
            let Some(entry) = self.tables().co_entry(asap) else { continue };
            let flags = ComObjectFlags::from_byte(entry.config);
            if !flags.communication_enable() {
                continue;
            }
            match code {
                ApciCode::GroupValueWrite if flags.write_enable() => {
                    self.store_received_value(asap, small6, view.payload());
                }
                ApciCode::GroupValueResponse if flags.update_enable() => {
                    self.store_received_value(asap, small6, view.payload());
                }
                ApciCode::GroupValueRead if flags.read_enable() => {
                    // A read arriving through any receive association is
                    // answered through the object's configured sending
                    // association. RT2 makes that distinction observable:
                    // the sending TSAP is the row at slot ASAP, and it can be
                    // a different GA from the request (03/05/01 §4.17.4.3.1).
                    if let Some(sending_tsap) = self.tables().sending_tsap(asap) {
                        self.send_group_value(asap, sending_tsap, ApciCode::GroupValueResponse, out);
                    }
                    return;
                }
                _ => {}
            }
        }
    }

    pub(crate) fn handle_group(
        &mut self,
        view: FrameView<'_>,
        request: RequestContext<SEC::ReplyContext>,
        out: &mut PollOutput<FRAME_CAP>,
    ) {
        if view.tpci() != Some(Tpci::DataGroup) || !self.is_running() {
            return;
        }
        let Some(apci10) = view.apci() else { return };
        let code = ApciCode::from_wire10(apci10);
        let small6 = (apci10 & 0x3F) as u8;
        let Some(tsap) = self.tables().tsap_of(view.dest_group()) else { return };

        // Admission is atomic across the fan-out: if one associated object
        // requires a different protection level, none of them is mutated or
        // allowed to answer. Walk the table once to validate and again to
        // apply; buffering matches would impose an artificial fan-out limit.
        // The security table is positional from `FIRST_ASAP`, while this
        // stack's associations carry wire ASAPs.
        let received_security = match request.access.security {
            zweidraehte_proto::access::SecurityMode::Plain => 0,
            zweidraehte_proto::access::SecurityMode::AuthOnly => 1,
            zweidraehte_proto::access::SecurityMode::AuthConf => 3,
        };
        let association_count = self.tables().assoc_count();
        for number in 0..association_count {
            let Some((association_tsap, asap)) = self.tables().association(number) else { continue };
            if association_tsap != tsap {
                continue;
            }
            let Some(go_index) = u16::from(asap).checked_sub(F::FIRST_ASAP) else {
                return;
            };
            if let Some(required) = SEC::group_security_flags(&self.sec, go_index)
                && !go_flags_accept([Some(required)], received_security)
            {
                if request.access.security != zweidraehte_proto::access::SecurityMode::Plain {
                    SEC::log_access_failure(&self.sec, request.access.source_addr, view.frame);
                }
                return;
            }
        }

        for number in 0..association_count {
            let Some((association_tsap, asap)) = self.tables().association(number) else { continue };
            if association_tsap != tsap {
                continue;
            }
            let Some(entry) = self.tables().co_entry(asap) else { continue };
            let flags = ComObjectFlags::from_byte(entry.config);
            if !flags.communication_enable() {
                continue;
            }
            match code {
                ApciCode::GroupValueWrite if flags.write_enable() => {
                    self.store_received_value(asap, small6, view.payload());
                }
                ApciCode::GroupValueResponse if flags.update_enable() => {
                    self.store_received_value(asap, small6, view.payload());
                }
                ApciCode::GroupValueRead if flags.read_enable() => {
                    if let Some(sending_tsap) = self.tables().sending_tsap(asap) {
                        self.send_group_value(asap, sending_tsap, ApciCode::GroupValueResponse, out);
                    }
                    // One read, one response — even when several
                    // objects share the TSAP.
                    return;
                }
                _ => {}
            }
        }
    }

    /// Move a received value into the object's RAM slot and raise the
    /// communication flags.
    fn store_received_value(&mut self, asap: u8, small6: u8, payload: &[u8]) {
        let Some((addr, size)) = self.value_slot(asap) else { return };
        let mut changed = false;
        if payload.is_empty() {
            // Small value, transmitted inside the APCI low octet.
            changed |= self.ram[addr] != small6;
            self.ram[addr] = small6;
        } else {
            for (i, &byte) in payload.iter().take(size).enumerate() {
                changed |= self.ram[addr + i] != byte;
                self.ram[addr + i] = byte;
            }
        }
        self.update_flags(asap, |f| {
            let mut f = f | co_flags::UPDATE | co_flags::VALUE_VALID;
            if changed {
                f |= co_flags::VALUE_CHANGED;
            }
            f
        });
    }

    /// Build and queue one outgoing group telegram carrying the
    /// object's value.
    fn send_group_value(&mut self, asap: u8, tsap: u8, apci: ApciCode, out: &mut PollOutput<FRAME_CAP>) -> bool {
        let Some(ga) = self.tables().ga_of_tsap(tsap) else { return false };
        let Some(entry) = self.tables().co_entry(asap) else { return false };
        let Some((addr, size)) = self.value_slot(asap) else { return false };
        let (_, short) = ComObjectType::from(entry.value_type & 0x3F).size_in_bytes();

        let own = self.individual_address();

        // The config octet's low two bits are the transmission
        // priority in the TP1 control-octet encoding.
        let priority_bits = (entry.config & 0x03) << 2;

        let frame = if short {
            frame::data_frame::<FRAME_CAP>(
                priority_bits,
                own,
                ga.0,
                true,
                Tpci::DataGroup,
                apci,
                self.ram[addr] & 0x3F,
                &[],
            )
        } else {
            frame::data_frame::<FRAME_CAP>(
                priority_bits,
                own,
                ga.0,
                true,
                Tpci::DataGroup,
                apci,
                0,
                &self.ram[addr..addr + size],
            )
        };

        let Some(mut frame) = out.capture_frame(frame) else {
            return false;
        };

        let Some(go_index) = u16::from(asap).checked_sub(F::FIRST_ASAP) else {
            return false;
        };

        if let Some(required) = SEC::group_security_flags(&self.sec, go_index)
            && required & zweidraehte_proto::security::GO_FLAG_SECURITY_MASK != 0
        {
            let plain_len = frame.len();

            if frame.resize_default(FRAME_CAP).is_err() {
                return false;
            }

            let mut len = plain_len;

            if !SEC::wrap_group(&mut self.sec, u16::from(tsap), required, &mut frame, &mut len, FRAME_CAP) {
                return false;
            }

            frame.truncate(len);
        }

        out.push(frame);
        self.update_flags(asap, |f| f | co_flags::VALUE_VALID);

        true
    }

    /// The transmit-request scan: the application (or a received
    /// trigger) set an object's transmission state to "request"; turn
    /// each into a telegram through the object's sending association.
    pub(crate) fn scan_transmit_requests(&mut self, out: &mut PollOutput<FRAME_CAP>) {
        if !self.is_running() || self.tables().muted() {
            return;
        }

        let count = self.tables().co_count();

        for asap in 0..count {
            let flags = self.object_flags(asap);

            if co_flags::tx_state(flags) != co_flags::TX_REQUEST {
                continue;
            }

            let Some(entry) = self.tables().co_entry(asap) else { continue };
            let cfg = ComObjectFlags::from_byte(entry.config);

            let Some(tsap) = self.tables().sending_tsap(asap) else {
                // No association to send through: idle with error, the
                // state real firmware reports for an unlinked object.
                self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_IDLE_ERROR));
                continue;
            };

            if flags & co_flags::READ_REQUEST != 0 {
                if let Some(ga) = self.tables().ga_of_tsap(tsap) {
                    let own = self.individual_address();
                    let priority_bits = (entry.config & 0x03) << 2;

                    let Some(mut frame) = out.capture_frame(frame::data_frame::<FRAME_CAP>(
                        priority_bits,
                        own,
                        ga.0,
                        true,
                        Tpci::DataGroup,
                        ApciCode::GroupValueRead,
                        0,
                        &[],
                    )) else {
                        self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_IDLE_ERROR));
                        continue;
                    };

                    let Some(go_index) = u16::from(asap).checked_sub(F::FIRST_ASAP) else {
                        self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_IDLE_ERROR));
                        continue;
                    };

                    if let Some(required) = SEC::group_security_flags(&self.sec, go_index)
                        && required & zweidraehte_proto::security::GO_FLAG_SECURITY_MASK != 0
                    {
                        let plain_len = frame.len();

                        if frame.resize_default(FRAME_CAP).is_err() {
                            self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_IDLE_ERROR));
                            continue;
                        }

                        let mut len = plain_len;

                        if !SEC::wrap_group(&mut self.sec, u16::from(tsap), required, &mut frame, &mut len, FRAME_CAP) {
                            self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_IDLE_ERROR));
                            continue;
                        }

                        frame.truncate(len);
                    }

                    out.push(frame);
                }

                self.update_flags(asap, |f| co_flags::set_tx_state(f & !co_flags::READ_REQUEST, co_flags::TX_IDLE_OK));
            } else if cfg.transmission_enable() {
                let sent = self.send_group_value(asap, tsap, ApciCode::GroupValueWrite, out);
                let state = if sent { co_flags::TX_IDLE_OK } else { co_flags::TX_IDLE_ERROR };

                self.update_flags(asap, |f| co_flags::set_tx_state(f, state));
            } else {
                self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_IDLE_ERROR));
            }
        }
    }
}
