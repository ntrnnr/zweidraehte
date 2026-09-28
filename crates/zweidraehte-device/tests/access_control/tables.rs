//! The expected property surface of each preset, from the specification.
//!
//! Policies come from AN193 v04 §2.2.4.6 unless a later document that
//! specifies the property says otherwise; levels from 06 Profiles Annex A
//! (07B0h, 27B0h and 0705h columns; the Data Security module §9.1.2.6) and
//! 03/05/01. Annex A levels are recommended defaults (06 Profiles A.1.2.1
//! Table 3); where we choose another permitted value, the `source` says so.

use super::spec::Audience::{
    Configuration as Cfg, Controller as Ctl, Free, ProductManufacturer as Pm, SystemManufacturer as Sm,
};
use super::spec::Expected;
use super::spec::Kind::{Function, ReadOnly as Ro, ReadWrite as Rw, WriteOnly as Wo};

// Interface object types.
const DEVICE: u16 = 0;
const ADDRESS_TABLE: u16 = 1;
const ASSOCIATION_TABLE: u16 = 2;
const APPLICATION: u16 = 3;
const INTERFACE_PROGRAM: u16 = 4;
const KNXNET_IP_PARAMETER: u16 = 11;
const GROUP_OBJECT_TABLE: u16 = 9;
const SECURITY: u16 = 17;
const RF_MEDIUM: u16 = 19;

const OPEN_TOOL: &str = "3FF/0CC";

/// What changes a table: AN193's `3FF/0CC` reads with 03/05/01's Tool-only
/// writes (§4.16.2, §4.17.2, §4.18.2), a spec conflict resolved in
/// `AccessPolicy::OPEN_OFF_TOOL_WRITES_ON`.
const TABLE_WRITE: &str = "3FF/04C";

const fn e(
    object_type: u16,
    pid: u16,
    kind: super::spec::Kind,
    read: super::spec::Audience,
    write: super::spec::Audience,
    policy: &'static str,
    source: &'static str,
) -> Expected {
    Expected { object_type, pid, kind, read, write, policy, source }
}

// ============================================================================
// Device Object
// ============================================================================

/// The Device Object of System B (07B0h/27B0h, Annex A.2.3), 4 levels.
pub const SYSTEM_B_DEVICE: &[Expected] = &[
    e(DEVICE, 1, Ro, Free, Sm, OPEN_TOOL, "A.2.3 3/x"),
    e(DEVICE, 11, Ro, Free, Sm, OPEN_TOOL, "A.2.3 3/x"),
    e(DEVICE, 12, Ro, Free, Sm, OPEN_TOOL, "A.2.3 3/x"),
    e(DEVICE, 14, Rw, Free, Free, OPEN_TOOL, "A.2.3 3/3"),
    e(DEVICE, 15, Ro, Free, Sm, OPEN_TOOL, "A.2.3 3/x"),
    e(DEVICE, 25, Ro, Free, Sm, OPEN_TOOL, "A.2.3 3/x"),
    e(DEVICE, 51, Rw, Free, Free, OPEN_TOOL, "A.2.3 3/3"),
    e(DEVICE, 54, Rw, Free, Free, OPEN_TOOL, "A.2.3 3/3"),
    e(DEVICE, 56, Ro, Free, Sm, "3FF/1FF", "A.2.3 3/x; AN193 3FF/1FF"),
    e(DEVICE, 57, Ro, Free, Sm, "3FF/00C", "A.2.3 3/0; served on TP1 despite fn. 59 (TSS J 3.8.18)"),
    e(DEVICE, 58, Ro, Free, Sm, "3FF/00C", "A.2.3 3/0; served on TP1 despite fn. 59 (TSS J 3.8.18)"),
    e(DEVICE, 71, Ro, Free, Sm, OPEN_TOOL, "A.2.3 57B0h 3/0, §9.1.2.6.2 3/X"),
    e(DEVICE, 78, Rw, Free, Pm, OPEN_TOOL, "A.2.3 (3/1)"),
    e(DEVICE, 83, Ro, Free, Sm, OPEN_TOOL, "A.2.3 57B0h 3/x"),
];

/// The Device Object of System 7 (0705h, Annex A.2.3). The 0705h column
/// states literal levels of the 16-level model: controller access (3)
/// where it reads 3, the free level (15) for the container's PID_IO_LIST.
pub const SYSTEM_7_DEVICE: &[Expected] = &[
    e(DEVICE, 1, Ro, Ctl, Sm, OPEN_TOOL, "A.2.3 0705h 3/x"),
    e(DEVICE, 11, Ro, Ctl, Sm, OPEN_TOOL, "A.2.3 0705h 3/x"),
    e(DEVICE, 12, Ro, Ctl, Sm, OPEN_TOOL, "A.2.3 0705h 3/(1), read-only allowed"),
    e(DEVICE, 14, Rw, Ctl, Ctl, OPEN_TOOL, "A.2.3 0705h 3/3"),
    e(DEVICE, 15, Ro, Ctl, Sm, OPEN_TOOL, "A.2.3 0705h (3/3), optional"),
    e(DEVICE, 25, Ro, Ctl, Sm, OPEN_TOOL, "A.2.3 0705h (3/3), optional"),
    e(DEVICE, 51, Rw, Ctl, Ctl, OPEN_TOOL, "A.2.3 0705h (3/3)"),
    e(DEVICE, 54, Rw, Ctl, Ctl, OPEN_TOOL, "A.2.3 0705h (3/3)"),
    e(DEVICE, 56, Ro, Ctl, Sm, "3FF/1FF", "A.2.3 3/x; AN193 3FF/1FF"),
    e(DEVICE, 57, Ro, Ctl, Sm, "3FF/00C", "A.2.3 0705h (3/x); AN193 3FF/00C"),
    e(DEVICE, 58, Ro, Ctl, Sm, "3FF/00C", "A.2.3 0705h (3/x); AN193 3FF/00C"),
    e(DEVICE, 71, Ro, Free, Sm, OPEN_TOOL, "container-served, readable by everyone"),
    e(DEVICE, 78, Rw, Ctl, Pm, OPEN_TOOL, "A.2.3 0705h 3/1"),
    e(DEVICE, 83, Ro, Ctl, Sm, OPEN_TOOL, "A.2.3 3/x"),
];

/// PID_MAX_RETRY_COUNT, added to the Device Object by the TP1 medium.
pub const TP1_DEVICE: &[Expected] = &[e(DEVICE, 52, Rw, Ctl, Ctl, OPEN_TOOL, "A.2.3 07B0h 3/3, 0705h (3/3)")];

/// The Data Security module's Device Object overrides (§9.1.2.6.2): the
/// Programming Mode becomes 3/2.
pub fn secure_device(base: &[Expected]) -> Vec<Expected> {
    base.iter()
        .map(|entry| match entry.pid {
            54 => Expected { write: Cfg, source: "06 Profiles §9.1.2.6.2 3/2", ..*entry },
            _ => *entry,
        })
        .collect()
}

// ============================================================================
// Table objects
// ============================================================================

const fn system_b_table(object_type: u16) -> [Expected; 6] {
    [
        e(object_type, 1, Ro, Free, Sm, OPEN_TOOL, "A.2.4 3/x"),
        e(
            object_type,
            5,
            Rw,
            Free,
            Pm,
            TABLE_WRITE,
            "A.2.4 3/(3); write level 1 is allowed (Table 3) and LSM 2.6 needs it; AN193 0CC vs 03/05/01 §4.16.2",
        ),
        e(object_type, 7, Ro, Free, Sm, OPEN_TOOL, "A.2.4 3/x"),
        e(object_type, 23, Rw, Free, Free, TABLE_WRITE, "A.2.4 3/(3); AN193 0CC vs 03/05/01 §4.16.2"),
        // TODO: Annex A lists PID_MCB_TABLE (3/3), which the legend makes
        // writable when implemented, and 03/05/03 §3.9.3.1 merge points 2
        // and 3 write it. We serve it read-only; see SESSION.md.
        e(object_type, 27, Ro, Free, Sm, OPEN_TOOL, "A.2.4 (3/3); read-only is a known gap"),
        e(object_type, 28, Ro, Free, Sm, OPEN_TOOL, "A.2.4 (3/x)"),
    ]
}

pub const SYSTEM_B_ADDRESS_TABLE: [Expected; 6] = system_b_table(ADDRESS_TABLE);
pub const SYSTEM_B_ASSOCIATION_TABLE: [Expected; 6] = system_b_table(ASSOCIATION_TABLE);
pub const SYSTEM_B_GROUP_OBJECT_TABLE: [Expected; 6] = system_b_table(GROUP_OBJECT_TABLE);

const fn system_7_table(object_type: u16) -> [Expected; 5] {
    [
        e(object_type, 1, Ro, Ctl, Sm, OPEN_TOOL, "A.2.4 0705h 3/x"),
        e(object_type, 5, Rw, Ctl, Ctl, TABLE_WRITE, "A.2.4 0705h 3/3; AN193 0CC vs 03/05/01 §4.16.2"),
        e(object_type, 7, Rw, Ctl, Ctl, TABLE_WRITE, "A.2.4 0705h 3/3; AN193 0CC vs 03/05/01 §4.16.2"),
        e(object_type, 27, Ro, Ctl, Sm, OPEN_TOOL, "A.2.4 0705h (3/x)"),
        e(object_type, 28, Ro, Ctl, Sm, OPEN_TOOL, "A.2.4 0705h (3/x)"),
    ]
}

pub const SYSTEM_7_ADDRESS_TABLE: [Expected; 5] = system_7_table(ADDRESS_TABLE);
pub const SYSTEM_7_ASSOCIATION_TABLE: [Expected; 5] = system_7_table(ASSOCIATION_TABLE);

// ============================================================================
// Application Program objects
// ============================================================================

pub const SYSTEM_B_APPLICATION: &[Expected] = &[
    e(APPLICATION, 1, Ro, Free, Sm, OPEN_TOOL, "A.2.6 3/x"),
    e(APPLICATION, 5, Rw, Free, Free, OPEN_TOOL, "A.2.6 3/3"),
    e(APPLICATION, 6, Rw, Free, Free, OPEN_TOOL, "A.2.6 (3/3)"),
    e(APPLICATION, 7, Ro, Free, Sm, OPEN_TOOL, "A.2.6 3/x"),
    e(APPLICATION, 13, Rw, Free, Free, OPEN_TOOL, "A.2.6 3/3"),
    e(APPLICATION, 16, Rw, Free, Free, OPEN_TOOL, "A.2.6 3/3"),
    e(APPLICATION, 27, Ro, Free, Free, OPEN_TOOL, "A.2.6 (3/3); read-only is a known gap"),
    e(APPLICATION, 28, Ro, Free, Sm, OPEN_TOOL, "A.2.6 (3/x)"),
];

pub const SYSTEM_B_INTERFACE_PROGRAM: &[Expected] = &[
    e(INTERFACE_PROGRAM, 1, Ro, Free, Sm, OPEN_TOOL, "A.2.7 3/x"),
    e(INTERFACE_PROGRAM, 5, Rw, Free, Free, OPEN_TOOL, "A.2.7 3/(3)"),
    e(INTERFACE_PROGRAM, 6, Rw, Free, Free, OPEN_TOOL, "A.2.7 3/(3)"),
    e(INTERFACE_PROGRAM, 7, Ro, Free, Sm, OPEN_TOOL, "A.2.7 3/x"),
    e(INTERFACE_PROGRAM, 13, Rw, Free, Free, OPEN_TOOL, "A.2.7 3/3"),
    e(INTERFACE_PROGRAM, 16, Ro, Free, Sm, OPEN_TOOL, "A.2.7 3/(3), read-only allowed"),
];

const fn system_7_program(object_type: u16, pei_type: super::spec::Kind) -> [Expected; 8] {
    [
        e(object_type, 1, Ro, Ctl, Sm, OPEN_TOOL, "A.2.6/A.2.7 0705h 3/x"),
        e(object_type, 5, Rw, Ctl, Ctl, OPEN_TOOL, "A.2.6/A.2.7 0705h 3/3"),
        e(object_type, 6, Rw, Ctl, Ctl, OPEN_TOOL, "A.2.6/A.2.7 0705h 3/3"),
        e(object_type, 7, Ro, Ctl, Sm, OPEN_TOOL, "A.2.6/A.2.7 0705h (3/x)"),
        e(object_type, 13, Rw, Ctl, Ctl, OPEN_TOOL, "A.2.6/A.2.7 0705h 3/(3)"),
        e(
            object_type,
            16,
            pei_type,
            Ctl,
            if matches!(pei_type, Ro) { Sm } else { Ctl },
            OPEN_TOOL,
            "A.2.6/A.2.7 0705h 3/(3)",
        ),
        e(object_type, 27, Ro, Ctl, Sm, OPEN_TOOL, "A.2.6/A.2.7 0705h (3/3); read-only is a known gap"),
        e(object_type, 28, Ro, Ctl, Sm, OPEN_TOOL, "A.2.6/A.2.7 0705h (3/x)"),
    ]
}

pub const SYSTEM_7_APPLICATION: [Expected; 8] = system_7_program(APPLICATION, Rw);
pub const SYSTEM_7_INTERFACE_PROGRAM: [Expected; 8] = system_7_program(INTERFACE_PROGRAM, Ro);

// ============================================================================
// Data Security module
// ============================================================================

/// The Security Interface Object (06 Profiles §9.1.2.6.4, AN193 Object
/// Type 17). Its free audience resolves per profile (3 or 15).
pub const SECURITY_OBJECT: &[Expected] = &[
    e(SECURITY, 1, Ro, Free, Sm, OPEN_TOOL, "§9.1.2.6.4 3/X"),
    e(SECURITY, 2, Ro, Free, Sm, OPEN_TOOL, "§9.1.2.6.4 3/X"),
    e(SECURITY, 5, Rw, Cfg, Cfg, "15F/04C", "§9.1.2.6.4 2/2"),
    e(SECURITY, 51, Function, Cfg, Cfg, "15F/04C", "§9.1.2.6.4 2/2"),
    e(SECURITY, 52, Rw, Cfg, Cfg, "00C/00C", "§9.1.2.6.4 2/2"),
    e(SECURITY, 53, Rw, Cfg, Cfg, "00C/00C", "§9.1.2.6.4 2/2"),
    e(SECURITY, 54, Rw, Cfg, Cfg, "00C/00C", "§9.1.2.6.4 2/2"),
    e(SECURITY, 55, Function, Free, Cfg, "1FF/0CC", "§9.1.2.6.4 3/2"),
    e(SECURITY, 56, Wo, Sm, Cfg, "008/008", "§9.1.2.6.4 X/2"),
    e(SECURITY, 57, Rw, Free, Cfg, "1FF/0CC", "§9.1.2.6.4 3/2"),
    e(SECURITY, 58, Rw, Cfg, Cfg, "00C/00C", "§9.1.2.6.4 2/2"),
    e(SECURITY, 59, Rw, Cfg, Cfg, "00C/00C", "§9.1.2.6.4 2/2"),
    e(SECURITY, 61, Rw, Cfg, Cfg, "00C/00C", "§9.1.2.6.4 2/2"),
];

/// GO Diagnostics (AN170, 03/05/01 §4.4.1 and §4.8.1), which the secure
/// presets compose: PID_OPERATION_MODE on the Application Program and
/// PID_GO_DIAGNOSTICS on the Group Object Table.
pub const DIAGNOSTICS: &[Expected] = &[
    e(
        APPLICATION,
        52,
        Function,
        Ctl,
        Ctl,
        "3FF/00C",
        "AN193 3FF/00C, as TSS J 6.1.6 requires; 03/05/01 §4.4.1 says 15F/00C; 3/3",
    ),
    e(GROUP_OBJECT_TABLE, 66, Function, Ctl, Ctl, OPEN_TOOL, "03/05/01 §4.8.1 3/3; AN193 3FF/0CC"),
];

/// The Group Object Table Object a secure System 7 device adds (§9.1.2.6.3).
pub const SYSTEM_7_GROUP_OBJECT_TABLE: &[Expected] = &[
    e(GROUP_OBJECT_TABLE, 1, Ro, Free, Sm, OPEN_TOOL, "§9.1.2.6.3 3/X"),
    e(GROUP_OBJECT_TABLE, 2, Ro, Free, Sm, OPEN_TOOL, "§9.1.2.6.3 3/X"),
];

// ============================================================================
// KNX RF
// ============================================================================

/// The RF Medium Object (27B0h mask document §6.8, AN193 Object Type 19).
pub const RF_MEDIUM_OBJECT: &[Expected] = &[
    e(
        RF_MEDIUM,
        1,
        Ro,
        Free,
        Sm,
        OPEN_TOOL,
        "27B0h §6.8 lists 3/1; object types are read-only in every Annex A table; AN193 3FF/0CC",
    ),
    e(RF_MEDIUM, 56, Rw, Free, Cfg, "3FF/1FF", "27B0h §6.8 3/2; AN193 3FF/1FF"),
];

/// What the RF retransmitter adds (AN193 3FF/0CC for both).
pub const RF_RETRANSMITTER: &[Expected] = &[
    e(RF_MEDIUM, 57, Rw, Free, Free, OPEN_TOOL, "AN193 3FF/0CC"),
    e(DEVICE, 74, Rw, Free, Free, OPEN_TOOL, "AN193 3FF/0CC"),
];

// ============================================================================
// KNXnet/IP
// ============================================================================

/// The KNXnet/IP Parameter Object of every KNXnet/IP device (06 Profiles
/// Annex A.5.4, column "All KNXnet/IP devices"; AN193 Object Type 11).
///
/// TODO: A.5.4 also makes PID_KNXNETIP_DEVICE_STATE (69, `3/x`) and
/// PID_ROUTING_BUSY_WAIT_TIME (78, `3/1`, footnote 112) mandatory for every
/// KNXnet/IP device, and for routing devices PID_ADDITIONAL_INDIVIDUAL_-
/// ADDRESSES (53, footnote 110), PID_KNXNETIP_ROUTING_CAPABILITIES (70) and
/// the statistics 72-75. None is served; see SESSION.md.
pub const KNXNET_IP: &[Expected] = &[
    e(KNXNET_IP_PARAMETER, 1, Ro, Free, Sm, OPEN_TOOL, "A.5.4 3/x"),
    e(KNXNET_IP_PARAMETER, 51, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
    e(KNXNET_IP_PARAMETER, 52, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
    e(KNXNET_IP_PARAMETER, 54, Ro, Free, Sm, OPEN_TOOL, "A.5.4 (3/x)"),
    e(KNXNET_IP_PARAMETER, 55, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
    e(KNXNET_IP_PARAMETER, 56, Ro, Free, Sm, OPEN_TOOL, "A.5.4 (3/x)"),
    e(KNXNET_IP_PARAMETER, 57, Ro, Free, Sm, OPEN_TOOL, "A.5.4 3/x"),
    e(KNXNET_IP_PARAMETER, 58, Ro, Free, Sm, OPEN_TOOL, "A.5.4 3/x"),
    e(KNXNET_IP_PARAMETER, 59, Ro, Free, Sm, OPEN_TOOL, "A.5.4 3/x"),
    e(KNXNET_IP_PARAMETER, 60, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
    e(KNXNET_IP_PARAMETER, 61, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
    e(KNXNET_IP_PARAMETER, 62, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
    e(KNXNET_IP_PARAMETER, 64, Ro, Free, Sm, OPEN_TOOL, "A.5.4 3/x"),
    e(KNXNET_IP_PARAMETER, 65, Ro, Free, Sm, OPEN_TOOL, "A.5.4 3/x"),
    e(KNXNET_IP_PARAMETER, 66, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
    e(KNXNET_IP_PARAMETER, 67, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
    e(KNXNET_IP_PARAMETER, 68, Ro, Free, Sm, OPEN_TOOL, "A.5.4 3/x"),
    e(KNXNET_IP_PARAMETER, 76, Rw, Free, Free, OPEN_TOOL, "A.5.4 3/3"),
];

/// What KNXnet/IP Tunnelling adds (03/08/04; 03/08/03 §2.5.29).
pub const TUNNELLING: &[Expected] = &[
    e(KNXNET_IP_PARAMETER, 53, Rw, Free, Free, OPEN_TOOL, "A.5.4 (3/3), mandatory with tunnelling (fn. 110)"),
    e(KNXNET_IP_PARAMETER, 79, Ro, Free, Sm, "15F/04C", "03/08/03 §2.5.29 3/X 15F/04C; AN193 15F/04C"),
];

/// The KNX IP Secure properties (03/08/09 §2.3.1.2-2.3.1.8).
pub const IP_SECURE: &[Expected] = &[
    e(KNXNET_IP_PARAMETER, 91, Wo, Sm, Cfg, "008/008", "03/08/09 §2.3.1.2 X/2"),
    e(KNXNET_IP_PARAMETER, 92, Wo, Sm, Cfg, "008/008", "03/08/09 §2.3.1.3 X/2"),
    e(KNXNET_IP_PARAMETER, 93, Wo, Sm, Cfg, "008/008", "03/08/09 §2.3.1.4 X/2"),
    e(KNXNET_IP_PARAMETER, 94, Function, Free, Cfg, "15D/15D", "03/08/09 §2.3.1.5 3/2 15D/15D; AN193 15F/04C"),
    e(KNXNET_IP_PARAMETER, 95, Rw, Free, Cfg, "15D/15D", "03/08/09 §2.3.1.6 3/2 15D/15D; AN193 15F/04C"),
    e(KNXNET_IP_PARAMETER, 96, Rw, Free, Cfg, "15D/15D", "03/08/09 §2.3.1.7 3/2 15D/15D; AN193 15F/04C"),
    e(KNXNET_IP_PARAMETER, 97, Rw, Cfg, Cfg, "00C/00C", "03/08/09 §2.3.1.8 2/2 00C/00C; AN193 15F/04C"),
];
