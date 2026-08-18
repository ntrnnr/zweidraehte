//! Baking a device definition into the default EEPROM image.
//!
//! One [`Bcu2DeviceDefinition`] describes a product — identity, table
//! capacities, group objects, factory links — and [`build_eeprom`]
//! lays it down as the byte image the device boots from. The same
//! definition drives the conformance DUT's product-file generator, so
//! the firmware image and what ETS believes about the device cannot
//! drift apart.
//!
//! The RT2 pointer bytes are single octets relative to 0100h, which
//! confines all three tables to 0100h–01FFh — the same 256-byte
//! neighborhood a real BCU2 keeps them in. [`build_eeprom`] panics at
//! boot when a definition cannot fit, which is a compile-time error in
//! practice since definitions are `const`.

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::device::EEPROM_SIZE;
use crate::family::bcu2_offsets;

/// One group object as the RT2 table stores it.
#[derive(Debug, Clone, Copy)]
pub struct Bcu2CoDescriptor {
    /// Page-0 RAM address of the value.
    pub data_ptr: u8,
    /// Config octet (`ComObjectFlags` coding).
    pub config: u8,
    /// Type octet (`ComObjectType` coding).
    pub value_type: u8,
}

/// A BCU2 product definition.
#[derive(Debug, Clone, Copy)]
pub struct Bcu2DeviceDefinition {
    /// Product manufacturer (ManData at 0101h, PID_MANUFACTURER_ID).
    pub manufacturer_id: u16,
    /// Application manufacturer + DevType + version (ApplicationID).
    pub app_manufacturer_id: u16,
    pub device_type: u16,
    pub version: u8,
    pub pei_type: u8,
    /// Factory individual address (15.15.255 until commissioned).
    pub individual_address: IndividualAddress,
    /// Address table capacity in group addresses.
    pub max_group_addresses: u8,
    /// Association table capacity in entries.
    pub max_associations: u8,
    /// Page-0 RAM address of the first RAM-flags byte.
    pub ram_flags_ptr: u8,
    pub comm_objects: &'static [Bcu2CoDescriptor],
    /// Factory-loaded group addresses (TSAPs 1.. in order).
    pub group_addresses: &'static [GroupAddress],
    /// Factory-loaded associations `(tsap, asap)`.
    pub associations: &'static [(u8, u8)],
}

impl Bcu2DeviceDefinition {
    /// EEPROM offset of the address table (fixed by the mask).
    pub const fn addr_table_offset(&self) -> usize {
        0x16
    }

    /// EEPROM offset of the association table (behind the address
    /// table's declared capacity).
    pub const fn assoc_table_offset(&self) -> usize {
        self.addr_table_offset() + 3 + self.max_group_addresses as usize * 2
    }

    /// EEPROM offset of the group object table.
    pub const fn cot_offset(&self) -> usize {
        self.assoc_table_offset() + 1 + self.max_associations as usize * 2
    }

    /// Build the boot EEPROM image.
    pub fn build_eeprom(&self) -> [u8; EEPROM_SIZE] {
        let mut e = [0u8; EEPROM_SIZE];

        // ── Fixed header ────────────────────────────────────────────
        // OptionReg stays 00h raw: the inverted read presents FFh,
        // matching a factory-erased register with no protection bits.
        e[bcu2_offsets::MAN_DATA..bcu2_offsets::MAN_DATA + 2].copy_from_slice(&self.manufacturer_id.to_be_bytes());
        let app = bcu2_offsets::APPLICATION_ID;
        e[app..app + 2].copy_from_slice(&self.app_manufacturer_id.to_be_bytes());
        e[app + 2..app + 4].copy_from_slice(&self.device_type.to_be_bytes());
        e[app + 4] = self.version;
        e[bcu2_offsets::PEI_TYPE] = self.pei_type;
        // RunError all-clear (error bits are active-low).
        e[0x0D] = 0xFF;
        // Routing count constant 6 in bits 6..4, the universal default.
        e[0x0E] = 0x60;
        // Three BUSY and three NAK retransmissions.
        e[0x0F] = 0x33;
        // ManagementStyle 48h: native BCU2 management, the value ETS
        // reads from 0115h to rule out BCU1-compat mode.
        e[bcu2_offsets::MANAGEMENT_STYLE] = 0x48;

        // ── Table placement ─────────────────────────────────────────
        // Address table is fixed at 0116h; the other two follow their
        // declared capacities. Pointer bytes are offsets from 0100h.
        let addr_table = self.addr_table_offset();
        let assoc_table = self.assoc_table_offset();
        let cot = self.cot_offset();
        let cot_end = cot + 2 + self.comm_objects.len() * 3;
        assert!(cot_end <= 0x100, "RT2 tables must fit below 0200h (one-byte pointers)");
        e[0x11] = assoc_table as u8;
        e[0x12] = cot as u8;

        // ── Address table ───────────────────────────────────────────
        // RT2 length counts the IA slot.
        assert!(self.group_addresses.len() <= usize::from(self.max_group_addresses));
        e[addr_table] = 1 + self.group_addresses.len() as u8;
        e[addr_table + 1..addr_table + 3].copy_from_slice(self.individual_address.as_bytes());
        for (i, ga) in self.group_addresses.iter().enumerate() {
            let off = addr_table + 3 + i * 2;
            e[off..off + 2].copy_from_slice(ga.as_bytes());
        }

        // ── Association table ───────────────────────────────────────
        assert!(self.associations.len() <= usize::from(self.max_associations));
        e[assoc_table] = self.associations.len() as u8;
        for (i, &(tsap, asap)) in self.associations.iter().enumerate() {
            let off = assoc_table + 1 + i * 2;
            e[off] = tsap;
            e[off + 1] = asap;
        }

        // ── Group object table ──────────────────────────────────────
        e[cot] = self.comm_objects.len() as u8;
        e[cot + 1] = self.ram_flags_ptr;
        for (i, co) in self.comm_objects.iter().enumerate() {
            let off = cot + 2 + i * 3;
            e[off] = co.data_ptr;
            e[off + 1] = co.config;
            e[off + 2] = co.value_type;
        }

        e
    }
}
