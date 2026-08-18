//! Group communication: destination GA → TSAP → associations → group
//! objects, all resolved through the EEPROM tables in place.
//!
//! The receive path mirrors what mask firmware does between a group
//! telegram and the application's RAM: look the destination up in the
//! address table, fan out over the association table, and for each
//! associated object check its config flags, move the value, and raise
//! the RAM flags. The transmit path is the inverse: a flag scan finds
//! transmit requests, the object's *first* association names the
//! sending TSAP, and the address table turns that back into a GA.
//!
//! Group communication only happens while the application runs — a
//! halted or unloaded device neither updates objects nor answers
//! reads, which is exactly the state ETS relies on during a download.

use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};

use crate::co_flags;
use crate::device::{Microdevice, PollOutput, RAM_SIZE};
use crate::family::MicroDeviceFamily;
use crate::frame::{self, FrameView, Tpci, apci};

impl<F: MicroDeviceFamily> Microdevice<F> {
    /// Value location and size of an object, if its table entry maps
    /// into RAM. The data pointer is a page-0 RAM address on this
    /// family; the value size comes from the type octet.
    pub(crate) fn value_slot(&self, asap: u8) -> Option<(usize, usize)> {
        let entry = self.tables().co_entry(asap)?;
        let (size, _) = ComObjectType::from(entry.value_type & 0x3F).size_in_bytes();
        let addr = usize::from(entry.data_ptr);
        (addr + size <= RAM_SIZE).then_some((addr, size))
    }

    pub(crate) fn handle_group(&mut self, view: FrameView<'_>, out: &mut PollOutput) {
        if view.tpci() != Tpci::Unnumbered || !self.is_running() {
            return;
        }
        let Some(apci10) = view.apci() else { return };
        let base = apci10 & 0x3C0;
        let small6 = (apci10 & 0x3F) as u8;
        let Some(tsap) = self.tables().tsap_of(view.dest_group()) else { return };

        // Fan out over every association of this TSAP. Collect the
        // matches first: the update path needs `&mut self`.
        let mut asaps: heapless::Vec<u8, 16> = heapless::Vec::new();
        for (t, asap) in self.tables().associations() {
            if t == tsap {
                let _ = asaps.push(asap);
            }
        }

        for asap in asaps {
            let Some(entry) = self.tables().co_entry(asap) else { continue };
            let flags = ComObjectFlags::from_byte(entry.config);
            if !flags.communication_enable() {
                continue;
            }
            match base {
                apci::GROUP_VALUE_WRITE if flags.write_enable() => {
                    self.store_received_value(asap, small6, view.payload());
                }
                apci::GROUP_VALUE_RESPONSE if flags.update_enable() => {
                    self.store_received_value(asap, small6, view.payload());
                }
                apci::GROUP_VALUE_READ if flags.read_enable() => {
                    self.send_group_value(asap, tsap, apci::GROUP_VALUE_RESPONSE, out);
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
    fn send_group_value(&mut self, asap: u8, tsap: u8, apci10: u16, out: &mut PollOutput) {
        let Some(ga) = self.tables().ga_of_tsap(tsap) else { return };
        let Some(entry) = self.tables().co_entry(asap) else { return };
        let Some((addr, size)) = self.value_slot(asap) else { return };
        let (_, short) = ComObjectType::from(entry.value_type & 0x3F).size_in_bytes();

        let own = self.individual_address();
        // The config octet's low two bits are the transmission
        // priority in the TP1 control-octet encoding.
        let priority_bits = (entry.config & 0x03) << 2;
        let frame = if short {
            frame::data_frame(priority_bits, own, ga.0, true, frame::TPCI_UNNUMBERED, apci10, self.ram[addr] & 0x3F, &[
            ])
        } else {
            frame::data_frame(
                priority_bits,
                own,
                ga.0,
                true,
                frame::TPCI_UNNUMBERED,
                apci10,
                0,
                &self.ram[addr..addr + size],
            )
        };
        out.push(frame);
        self.update_flags(asap, |f| f | co_flags::VALUE_VALID);
    }

    /// The transmit-request scan: the application (or a received
    /// trigger) set an object's transmission state to "request"; turn
    /// each into a telegram through the object's sending association.
    pub(crate) fn scan_transmit_requests(&mut self, out: &mut PollOutput) {
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
                    out.push(frame::data_frame(
                        priority_bits,
                        own,
                        ga.0,
                        true,
                        frame::TPCI_UNNUMBERED,
                        apci::GROUP_VALUE_READ,
                        0,
                        &[],
                    ));
                }
                self.update_flags(asap, |f| co_flags::set_tx_state(f & !co_flags::READ_REQUEST, co_flags::TX_IDLE_OK));
            } else if cfg.transmission_enable() {
                self.send_group_value(asap, tsap, apci::GROUP_VALUE_WRITE, out);
                self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_IDLE_OK));
            } else {
                self.update_flags(asap, |f| co_flags::set_tx_state(f, co_flags::TX_IDLE_ERROR));
            }
        }
    }
}
