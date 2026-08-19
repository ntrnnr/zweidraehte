//! Const builders turning ETS comm-object metadata into micro
//! group-object-table rows.
//!
//! A device definition declares its objects once, through the
//! `#[ets_com_objects]` macro; the resulting `ETS_COMM_OBJECTS` /
//! `ETS_COMM_OBJECT_REFS` constants carry everything a BCU-era table
//! row needs except the RAM placement. These builders add that — so a
//! product's boot image, its product-database defaults and its micro
//! firmware all come from the same declaration and cannot drift.
//!
//! Two deliberately different sizing policies live here:
//!
//! - The **value slot width** (how many RAM bytes an object's value
//!   occupies, and thus where the next object's `data_ptr` lands) is
//!   the widest DPT any `#[ets_ref]` can configure the object to —
//!   a reconfiguration must never make neighbouring slots overlap.
//! - The **`value_type` octet** is the *declared* (factory-default)
//!   DPT's coding. A download re-types the objects per configured DPT
//!   anyway (the client's table overlay writes the config/type octets),
//!   so the factory image simply describes the factory configuration.

use zweidraehte_ets_model::{EtsCommObjectDef, EtsCommObjectRefDef};

use super::CoDescriptor;
use super::system7::System7CoDescriptor;

/// The `ComObjectType` code (03/05/01 Table 87) for a value of
/// `size_bits` bits: the sub-byte `Uint1..Uint7` codes, then the
/// byte-multiple `Byte*` codes. Panics — at compile time, since every
/// caller is `const` — on a width this coding does not define.
const fn size_bits_to_com_object_type(size_bits: u8) -> u8 {
    match size_bits {
        1..=7 => size_bits - 1, // Uint1..Uint7
        8 => 7,                 // Byte1
        16 => 8,                // Byte2
        24 => 9,                // Byte3
        32 => 10,               // Byte4
        48 => 11,               // Byte6
        64 => 12,               // Byte8
        _ => panic!("no ComObjectType coding for this size_bits value"),
    }
}

/// The widest width (in bits) this object can be configured to: the
/// maximum over its `#[ets_ref]` DPTs, falling back to the declared
/// DPT for objects without refs.
const fn max_ref_size_bits(object_index: u16, base_size_bits: u8, refs: &[EtsCommObjectRefDef]) -> u8 {
    let mut max = base_size_bits;
    let mut i = 0;
    while i < refs.len() {
        if refs[i].object_index == object_index && refs[i].size_bits > max {
            max = refs[i].size_bits;
        }
        i += 1;
    }
    max
}

/// RAM byte offset of object `target` from the base: the sum of the
/// preceding objects' slot widths.
const fn cumulative_byte_offset(target: usize, objects: &[EtsCommObjectDef], refs: &[EtsCommObjectRefDef]) -> usize {
    let mut offset = 0;
    let mut j = 0;
    while j < target {
        let bits = max_ref_size_bits(objects[j].index, objects[j].size_bits, refs) as usize;
        offset += bits.div_ceil(8);
        j += 1;
    }
    offset
}

/// Build the RT1/RT2 (BCU1/BCU2) group-object-table rows for a device
/// declaration. `data_base` is the page-0 RAM address of the first
/// object's value; objects are laid out contiguously by slot width.
///
/// `config` is `EtsCommObjectDef::default_flags` verbatim — the macro
/// stores the complete Table 87 octet including the priority bits, so
/// declarations spell the priority (`... | LOW`).
pub const fn build_bcu2_descriptors<const N: usize>(
    objects: &[EtsCommObjectDef],
    refs: &[EtsCommObjectRefDef],
    data_base: u8,
) -> [CoDescriptor; N] {
    assert!(objects.len() == N, "N must equal the declaration's object count");
    let mut rows = [CoDescriptor { data_ptr: 0, config: 0, value_type: 0 }; N];
    let mut i = 0;
    while i < N {
        rows[i] = CoDescriptor {
            data_ptr: data_base + cumulative_byte_offset(i, objects, refs) as u8,
            config: objects[i].default_flags,
            value_type: size_bits_to_com_object_type(objects[i].size_bits),
        };
        i += 1;
    }
    rows
}

/// The System 7 rows — [`build_bcu2_descriptors`] with the
/// family's two-byte data pointers.
pub const fn build_system7_descriptors<const N: usize>(
    objects: &[EtsCommObjectDef],
    refs: &[EtsCommObjectRefDef],
    data_base: u16,
) -> [System7CoDescriptor; N] {
    assert!(objects.len() == N, "N must equal the declaration's object count");
    let mut rows = [System7CoDescriptor { data_ptr: 0, config: 0, value_type: 0 }; N];
    let mut i = 0;
    while i < N {
        rows[i] = System7CoDescriptor {
            data_ptr: data_base + cumulative_byte_offset(i, objects, refs) as u16,
            config: objects[i].default_flags,
            value_type: size_bits_to_com_object_type(objects[i].size_bits),
        };
        i += 1;
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECTS: &[EtsCommObjectDef] = &[
        EtsCommObjectDef {
            index: 0,
            name: "switch",
            display_name: "Switch",
            function_text: "",
            dpt_main: 1,
            dpt_sub: 1,
            size_bits: 1,
            default_flags: 0x47,
            object_size_override: None,
            text_template: None,
        },
        EtsCommObjectDef {
            index: 1,
            name: "scene",
            display_name: "Scene",
            function_text: "",
            dpt_main: 18,
            dpt_sub: 1,
            size_bits: 8,
            default_flags: 0xF7,
            object_size_override: None,
            text_template: None,
        },
    ];

    #[test]
    fn rows_follow_slot_widths_and_declared_types() {
        // Object 0 is declared 1-bit but a ref can widen it to a byte:
        // the slot is a byte wide, the factory type stays Uint1.
        const REFS: &[EtsCommObjectRefDef] = &[EtsCommObjectRefDef {
            object_index: 0,
            ref_name: "wide",
            text: None,
            function_text: "",
            dpt_main: 5,
            dpt_sub: 1,
            size_bits: 8,
            flag_overrides: None,
            selector_value: None,
            selector_value_name: None,
            selector_param: None,
        }];
        let rows: [CoDescriptor; 2] = build_bcu2_descriptors(OBJECTS, REFS, 0xC6);
        assert_eq!(rows[0].data_ptr, 0xC6);
        assert_eq!(rows[0].config, 0x47);
        assert_eq!(rows[0].value_type, 0x00); // declared DPT: Uint1
        assert_eq!(rows[1].data_ptr, 0xC7); // one byte-wide slot before it
        assert_eq!(rows[1].value_type, 0x07); // Byte1
    }
}
