//! Baking a System 7 device definition into the default EEPROM image.
//!
//! One [`System7DeviceDefinition`] describes a product — identity,
//! table capacities, group objects, factory links, and the placement
//! of the movable segments — and [`System7Family::build_eeprom`] lays
//! it down as the byte image the device boots from. The image starts
//! at 4000h; only the RT8 address table's place in it is fixed by the
//! mask. The association table and application segment go where the
//! product says (a real download may later re-allocate them anywhere
//! in the window), and the group object table goes at the family's
//! `COT_ADDR` — the same address the product database publishes, which
//! is why the builder lives on the family type rather than on the
//! definition.

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use super::family::System7Family;
use crate::device::MAX_LSM;

/// One group object as the System 7 table stores it.
#[derive(Debug, Clone, Copy)]
pub struct System7CoDescriptor {
    /// RAM address of the value (2 bytes on System 7; this stack maps
    /// page-0, so practical values are 0000h–00FFh).
    pub data_ptr: u16,
    /// Config octet (`ComObjectFlags` coding).
    pub config: u8,
    /// Type octet (`ComObjectType` coding).
    pub value_type: u8,
}

/// A System 7 product definition.
#[derive(Debug, Clone, Copy)]
pub struct System7DeviceDefinition {
    /// Application manufacturer, surfaced through the product data.
    pub manufacturer_id: u16,
    pub device_type: u16,
    pub version: u8,
    /// Factory individual address (15.15.255 until commissioned).
    pub individual_address: IndividualAddress,
    /// Address table capacity in group addresses.
    pub max_group_addresses: u8,
    /// Association table capacity in entries.
    pub max_associations: u8,
    /// RAM address of the first RAM-flags byte (System 7 carries it as a
    /// 2-byte pointer; this stack maps page-0).
    pub ram_flags_ptr: u16,
    pub comm_objects: &'static [System7CoDescriptor],
    /// Factory-loaded group addresses (TSAPs 1.. in order). RT8
    /// mandates ascending order — the builder asserts it.
    pub group_addresses: &'static [GroupAddress],
    /// Factory-loaded associations `(tsap, asap)`.
    pub associations: &'static [(u8, u8)],
    /// Image offset (from 4000h) of the factory association table.
    pub ast_offset: usize,
    /// Image offset (from 4000h) of the factory application segment.
    pub app_offset: usize,
    /// Factory-default application parameter bytes, laid down at
    /// `app_offset` — the same bytes the product database ships as the
    /// parameter segment's default data, so an undownloaded device
    /// behaves like a factory-configured one. Empty for products
    /// without ETS-configurable parameters.
    pub app_params: &'static [u8],
}

impl<const EEPROM_LEN: usize, const COT_ADDR: u16, P> System7Family<EEPROM_LEN, COT_ADDR, P> {
    /// Build the boot EEPROM image. Panics when the definition cannot
    /// fit, which is a compile-time error in practice since
    /// definitions are `const`.
    pub fn build_eeprom(def: &System7DeviceDefinition) -> [u8; EEPROM_LEN] {
        let mut e = [0u8; EEPROM_LEN];

        // ── RT8 address table at 4000h ──────────────────────────────
        // [length][IA:2BE][GA:2BE × (length - 1)].
        assert!(def.max_group_addresses < u8::MAX, "RT8 length leaves room for at most 254 group addresses");
        assert!(def.group_addresses.len() <= usize::from(def.max_group_addresses));
        assert!(3 + usize::from(def.max_group_addresses) * 2 <= def.ast_offset, "ADT capacity overlaps the AST");
        e[0] = 1 + def.group_addresses.len() as u8;
        e[1..3].copy_from_slice(def.individual_address.as_bytes());
        let mut prev: Option<GroupAddress> = None;
        for (i, ga) in def.group_addresses.iter().enumerate() {
            // Big-endian byte order makes the derived ordering the
            // numeric one.
            assert!(prev.is_none_or(|p| p < *ga), "group addresses must ascend");
            prev = Some(*ga);
            let off = 3 + i * 2;
            e[off..off + 2].copy_from_slice(ga.as_bytes());
        }

        // ── RT8 association table at the product's placement ────────
        // [count][(tsap, asap) × count]
        assert!(def.associations.len() <= usize::from(def.max_associations));
        let ast = def.ast_offset;
        assert!(ast + 1 + usize::from(def.max_associations) * 2 <= EEPROM_LEN, "AST does not fit the image");
        e[ast] = def.associations.len() as u8;
        for (i, &(tsap, asap)) in def.associations.iter().enumerate() {
            let off = ast + 1 + i * 2;
            e[off] = tsap;
            e[off + 1] = asap;
        }

        // ── System 7 group object table at the product's COT address ─
        // [count][ram_flags_ptr:2BE][(data_ptr:2BE, config, type) × count]
        let cot = usize::from(COT_ADDR - Self::EEPROM_BASE_CONST);
        let cot_end = cot + 3 + def.comm_objects.len() * 4;
        assert!(cot_end <= EEPROM_LEN, "COT does not fit the image");
        e[cot] = def.comm_objects.len() as u8;
        e[cot + 1..cot + 3].copy_from_slice(&def.ram_flags_ptr.to_be_bytes());
        for (i, co) in def.comm_objects.iter().enumerate() {
            let off = cot + 3 + i * 4;
            e[off..off + 2].copy_from_slice(&co.data_ptr.to_be_bytes());
            e[off + 2] = co.config;
            e[off + 3] = co.value_type;
        }

        // ── Application parameters at the application segment ───────
        if !def.app_params.is_empty() {
            let end = def.app_offset + def.app_params.len();
            assert!(end <= EEPROM_LEN, "application parameters do not fit the image");
            e[def.app_offset..end].copy_from_slice(def.app_params);
        }

        e
    }

    /// The `table_ref` values a factory-loaded device reports: the
    /// fixed ADT, the product's AST and application placements, and no
    /// second application program. Fixtures seed
    /// `ManagementState::lsm[..].table_ref` from this next to setting
    /// the load states.
    pub fn factory_table_refs(def: &System7DeviceDefinition) -> [u16; MAX_LSM] {
        [
            Self::EEPROM_BASE_CONST,
            Self::EEPROM_BASE_CONST + def.ast_offset as u16,
            Self::EEPROM_BASE_CONST + def.app_offset as u16,
            0,
        ]
    }

    // `Self::EEPROM_BASE` through the trait needs the trait in scope at
    // every call site; a plain inherent alias keeps the arithmetic here
    // readable.
    const EEPROM_BASE_CONST: u16 = super::offsets::ADT_ADDR;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eeprom::Tables;
    use crate::management::ManagementState;

    type Fam = System7Family<0x400, 0x4200>;

    static COS: &[System7CoDescriptor] =
        &[System7CoDescriptor { data_ptr: 0x00C6, config: 0x9F, value_type: 0x00 }, System7CoDescriptor {
            data_ptr: 0x00C7,
            config: 0x4C,
            value_type: 0x06,
        }];
    static GAS: &[GroupAddress] = &[GroupAddress::from_three_level(1, 0, 1), GroupAddress::from_three_level(2, 0, 2)];
    static ASSOCS: &[(u8, u8)] = &[(1, 0), (2, 1)];

    fn definition() -> System7DeviceDefinition {
        System7DeviceDefinition {
            manufacturer_id: 0x00FA,
            device_type: 0x0705,
            version: 1,
            individual_address: IndividualAddress::new(1, 1, 10),
            max_group_addresses: 8,
            max_associations: 8,
            ram_flags_ptr: 0x00D0,
            comm_objects: COS,
            group_addresses: GAS,
            associations: ASSOCS,
            ast_offset: 0x100,
            app_offset: 0x300,
            app_params: &[0xA5, 0x01, 0x02],
        }
    }

    #[test]
    fn built_image_walks_back_through_tables() {
        let def = definition();
        let image = Fam::build_eeprom(&def);
        let mut mgmt = ManagementState::new();
        let refs = Fam::factory_table_refs(&def);
        assert_eq!(refs, [0x4000, 0x4100, 0x4300, 0]);
        for (lsm, table_ref) in mgmt.lsm.iter_mut().zip(refs) {
            lsm.table_ref = table_ref;
        }

        let t = Tables::<Fam>::new(&image, &mgmt);
        assert_eq!(t.individual_address(), IndividualAddress::new(1, 1, 10));
        assert_eq!(t.ga_count(), 2);
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(2, 0, 2)), Some(2));
        assert_eq!(t.sending_tsap(1), Some(2));
        assert_eq!(t.ram_flags_ptr(), 0x00D0);
        let entry = t.co_entry(1).expect("ASAP 1 exists");
        assert_eq!(entry.data_ptr, 0x00C7);
        assert_eq!(entry.value_type, 0x06);

        // The factory parameters sit at the application segment.
        assert_eq!(&image[0x300..0x303], &[0xA5, 0x01, 0x02]);
    }
}
