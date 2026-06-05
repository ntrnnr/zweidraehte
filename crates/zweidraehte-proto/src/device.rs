//! KNX device identification types.
//!
//! Protocol-level types for identifying KNX devices: mask versions,
//! mask families, and device descriptors. Used by both device stacks
//! and client implementations.

// ============================================================================
// Mask Version / Mask Family
// ============================================================================

/// KNX mask family — groups mask versions by BCU architecture.
///
/// Different families have different memory models, load procedures,
/// and feature sets. This is relevant for both the runtime stack and
/// for MTXML/knxprod generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskFamily {
    /// System 7 masks (0701, 0705, 2705, 5705)
    /// - Absolute memory segments
    /// - ProductProcedure load style
    /// - ComObject indices start at 0
    System7,
    /// System B masks (07B0, 27B0, 57B0)
    /// - Relative memory segments with load state machines
    /// - MergedProcedure load style
    /// - ComObject indices start at 1
    /// - Generates address/association tables
    SystemB,
    /// BIM masks (0912, 091A)
    /// - Absolute memory segments
    /// - DefaultProcedure load style
    /// - No ComObject table
    Bim,
    /// BIM M masks (0920, 2920)
    /// - Absolute memory segments
    /// - MergedProcedure load style
    /// - No ComObject table
    BimM,
}

impl MaskFamily {
    /// Determine mask family from a raw mask version value.
    pub fn from_mask_version(mask: u16) -> Self {
        match mask {
            0x0701 | 0x0705 | 0x2705 | 0x5705 | 0x0700 => MaskFamily::System7,
            0x07B0 | 0x17B0 | 0x27B0 | 0x57B0 => MaskFamily::SystemB,
            0x0912 | 0x091A => MaskFamily::Bim,
            0x0920 | 0x2920 => MaskFamily::BimM,
            // Default to SystemB for unknown masks with 'B0' suffix
            m if (m & 0x00FF) == 0x00B0 => MaskFamily::SystemB,
            // Default to System7 for other unknown masks
            _ => MaskFamily::System7,
        }
    }
}

create_protocol_enum!(
    /// KNX Device Descriptor Type 0 / Mask Version.
    ///
    /// Identifies the BCU type and communication medium of a device.
    /// The high nibble encodes the medium (0 = TP1, 1 = PL110, 2 = RF,
    /// 5 = KNX/IP), and the lower 12 bits encode the BCU model.
    ///
    /// # Variants
    ///
    /// - `System7Tp1` (0x0705) — System 7 TP1
    /// - `SystemBTp1` (0x07B0) — System B TP1
    /// - `SystemBRf` (0x27B0) — System B KNX-RF
    /// - `SystemBKnxIp` (0x57B0) — System B KNX/IP
    /// - `Other(u16)` — Unknown / unsupported mask version
    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    pub enum MaskVersion: u16 {
        System7Tp1,         0x0705, "System 7 TP1 (0705)";
        SystemBTp1,         0x07B0, "System B TP1 (07B0)";
        SystemBRf,          0x27B0, "System B RF (27B0)";
        SystemBKnxIp,       0x57B0, "System B KNX/IP (57B0)";
        _, "Unknown mask version (0x{:04X})";
    }
);

impl MaskVersion {
    /// Check if this is a KNX/IP device (mask version 57B0).
    pub fn is_knxip(&self) -> bool {
        matches!(self, MaskVersion::SystemBKnxIp)
    }

    /// Check if this is a TP1 device (0705 or 07B0).
    pub fn is_tp1(&self) -> bool {
        matches!(self, MaskVersion::System7Tp1 | MaskVersion::SystemBTp1)
    }

    /// Check if this is a KNX-RF device (mask version 27B0).
    pub fn is_rf(&self) -> bool {
        matches!(self, MaskVersion::SystemBRf)
    }

    /// Get the raw u16 value.
    pub const fn as_u16(&self) -> u16 {
        match self {
            MaskVersion::System7Tp1 => 0x0705,
            MaskVersion::SystemBTp1 => 0x07B0,
            MaskVersion::SystemBRf => 0x27B0,
            MaskVersion::SystemBKnxIp => 0x57B0,
            MaskVersion::Other(v) => *v,
        }
    }

    /// Get the mask version as bytes (big-endian).
    pub const fn to_bytes(&self) -> [u8; 2] {
        let v = self.as_u16();
        [(v >> 8) as u8, v as u8]
    }

    /// Derive the mask family from this mask version.
    pub fn family(&self) -> MaskFamily {
        MaskFamily::from_mask_version(self.as_u16())
    }
}

// ============================================================================
// Device Descriptor
// ============================================================================

/// Device descriptor containing firmware/application-level metadata.
///
/// This struct consolidates the **compile-time** information that identifies
/// the firmware/application, NOT individual device instances. This is what
/// gets exported to ETS product definitions.
///
/// # What Goes Here vs. Runtime State
///
/// **DeviceDescriptor (compile-time, per-firmware):**
/// - Mask version, manufacturer ID, hardware type
/// - Application program ID and version
/// - Table capacities (max sizes)
///
/// **Runtime State (per-device instance):**
/// - Serial number (factory-programmed, unique per device)
/// - Individual address (ETS-configured)
/// - Device name/description (ETS-configured)
///
/// # Fields
///
/// ## Hardware/Firmware Identification
/// - `mask_version`: Device Descriptor Type 0 (see [`MaskVersion`])
/// - `manufacturer_id`: KNX manufacturer ID (assigned by KNX Association)
/// - `hardware_type`: 6-byte hardware type identifier
///
/// ## Application Program
/// - `application_id`: Application program identifier (2 bytes)
/// - `application_version`: Application program version (1 byte)
///
/// ## Table Capacities
/// - `max_address_table_entries`: Maximum group addresses
/// - `max_association_table_entries`: Maximum associations
/// - `max_com_objects`: Maximum communication objects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceDescriptor {
    // ========================================================================
    // Hardware/Firmware Identification
    // ========================================================================
    /// Device Descriptor Type 0 / Mask Version.
    ///
    /// See [`MaskVersion`] for known variants.
    pub mask_version: MaskVersion,

    /// KNX Manufacturer ID.
    ///
    /// Assigned by the KNX Association. This identifies who made the firmware.
    /// Note: This is also used as the first 2 bytes of any device's serial number.
    pub manufacturer_id: u16,

    /// Hardware type identifier (6 bytes).
    ///
    /// Identifies the hardware platform/revision.
    pub hardware_type: [u8; 6],

    // ========================================================================
    // Application Program Identification
    // ========================================================================
    /// Application program identifier (2 bytes).
    ///
    /// Together with manufacturer_id and application_version, this uniquely
    /// identifies the application program in ETS.
    pub application_id: u16,

    /// Application program version (1 byte).
    ///
    /// Incremented when the application program changes.
    pub application_version: u8,

    // ========================================================================
    // Table Capacities
    // ========================================================================
    /// Maximum number of entries in the address table.
    ///
    /// This determines how many group addresses the device can handle.
    pub max_address_table_entries: u16,

    /// Maximum number of entries in the association table.
    ///
    /// This determines how many group address to communication object
    /// mappings the device supports.
    pub max_association_table_entries: u16,

    /// Maximum number of communication objects.
    ///
    /// This should match the number of objects defined in the application.
    pub max_com_objects: u16,

    /// PEI type (Physical External Interface).
    ///
    /// System B hardware concept. Most modern devices don't have a PEI,
    /// so this is typically 0.
    pub pei_type: u8,
}

impl DeviceDescriptor {
    /// Create a new device descriptor with the given values.
    pub const fn new(
        mask_version: MaskVersion,
        manufacturer_id: u16,
        hardware_type: [u8; 6],
        application_id: u16,
        application_version: u8,
        max_address_table_entries: u16,
        max_association_table_entries: u16,
        max_com_objects: u16,
        pei_type: u8,
    ) -> Self {
        Self {
            mask_version,
            manufacturer_id,
            hardware_type,
            application_id,
            application_version,
            max_address_table_entries,
            max_association_table_entries,
            max_com_objects,
            pei_type,
        }
    }

    /// Get the program version bytes (5 bytes).
    ///
    /// Format: 2 bytes manufacturer + 2 bytes app ID + 1 byte version.
    /// This matches the PID_PROGRAM_VERSION property format.
    pub const fn program_version(&self) -> [u8; 5] {
        [
            (self.manufacturer_id >> 8) as u8,
            self.manufacturer_id as u8,
            (self.application_id >> 8) as u8,
            self.application_id as u8,
            self.application_version,
        ]
    }

    /// Get the PEI program version bytes (5 bytes).
    ///
    /// For devices without a separate PEI application, this returns a default
    /// version [0x00, 0x00, 0x00, 0x00, 0x00].
    /// The PEI Program Object (Interface Object 5) reports this as PID_PROGRAM_VERSION.
    pub const fn pei_program_version(&self) -> [u8; 5] {
        [0x00, 0x00, 0x00, 0x00, 0x00]
    }

    /// Get the mask version as bytes (big-endian).
    pub const fn mask_version_bytes(&self) -> [u8; 2] {
        self.mask_version.to_bytes()
    }

    /// Check if this is a KNX/IP device (mask version 57B0).
    pub fn is_knxip(&self) -> bool {
        self.mask_version.is_knxip()
    }

    /// Check if this is a TP1 device (mask version 07B0 or 27B0).
    pub fn is_tp1(&self) -> bool {
        self.mask_version.is_tp1()
    }

    /// Get the address table size in bytes.
    ///
    /// Format: 2-byte count + 2 bytes per entry.
    pub const fn address_table_size(&self) -> usize {
        2 + (self.max_address_table_entries as usize) * 2
    }

    /// Get the association table size in bytes.
    ///
    /// Format: 2-byte count + 4 bytes per entry (for System B).
    pub const fn association_table_size(&self) -> usize {
        2 + (self.max_association_table_entries as usize) * 4
    }

    /// Get the communication object table size in bytes.
    ///
    /// Format: 2-byte count + 2 bytes per entry.
    pub const fn comm_object_table_size(&self) -> usize {
        2 + (self.max_com_objects as usize) * 2
    }
}
