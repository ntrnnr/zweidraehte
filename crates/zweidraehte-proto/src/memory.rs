//! Pure access policy for KNX memory regions.
//!
//! A memory map still owns storage and address dispatch. This module only
//! answers the question that is common to every implementation: whether one
//! complete read or write fits a declared region and has sufficient legacy
//! authorization.

use crate::access::{AccessContext, AccessLevel};

/// Memory access error reported by a device memory map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MemoryError {
    /// The address is not mapped or accessible.
    NotAccessible,
    /// The direction is not supported by the addressed region.
    ///
    /// The application service renders this as read-only for a write and
    /// write-only for a read.
    WriteProtected,
    /// The caller lacks the required authorization level, or the request
    /// crosses a region boundary.
    AccessDenied,
}

/// Direction of a memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MemoryOperation {
    Read,
    Write,
}

/// Permission for one direction of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MemoryPermission {
    /// This direction is unavailable.
    Denied,
    /// No legacy authorization check is required.
    Open,
    /// The caller needs at least this profile-independent access audience.
    Level(AccessLevel),
}

impl MemoryPermission {
    fn check(self, ctx: AccessContext, max_access_levels: u8) -> Result<(), MemoryError> {
        match self {
            Self::Denied => Err(MemoryError::WriteProtected),
            Self::Open => Ok(()),
            Self::Level(level) if max_access_levels > 0 && ctx.has_level(level.for_levels(max_access_levels)) => Ok(()),
            Self::Level(_) => Err(MemoryError::AccessDenied),
        }
    }

    const fn allows(self, access_level: u8, max_access_levels: u8) -> bool {
        match self {
            Self::Denied => false,
            Self::Open => true,
            Self::Level(level) => max_access_levels > 0 && access_level <= level.for_levels(max_access_levels),
        }
    }
}

/// One non-overlapping absolute memory region.
///
/// A request must fit entirely inside one region. Even when two adjacent
/// regions both permit the operation, crossing the boundary is rejected: a
/// map may route them to different storage or apply different side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use]
pub struct MemoryRegion {
    start: u32,
    length: u32,
    read: MemoryPermission,
    write: MemoryPermission,
}

impl MemoryRegion {
    /// Define a region with independent read and write permissions.
    pub const fn new(start: u32, length: u32, read: MemoryPermission, write: MemoryPermission) -> Self {
        Self { start, length, read, write }
    }

    /// A region readable and writable without authorization.
    pub const fn open(start: u32, length: u32) -> Self {
        Self::new(start, length, MemoryPermission::Open, MemoryPermission::Open)
    }

    /// A region readable with `permission` and never writable.
    pub const fn read_only(start: u32, length: u32, permission: MemoryPermission) -> Self {
        Self::new(start, length, permission, MemoryPermission::Denied)
    }

    /// A region writable with `permission` and never readable.
    pub const fn write_only(start: u32, length: u32, permission: MemoryPermission) -> Self {
        Self::new(start, length, MemoryPermission::Denied, permission)
    }

    /// First absolute address in the region.
    pub const fn start(&self) -> u32 {
        self.start
    }

    /// Region size in octets.
    pub const fn length(&self) -> u32 {
        self.length
    }

    /// Permission applied to reads.
    pub const fn read_permission(&self) -> MemoryPermission {
        self.read
    }

    /// Permission applied to writes.
    pub const fn write_permission(&self) -> MemoryPermission {
        self.write
    }

    const fn end(self) -> u32 {
        self.start.saturating_add(self.length)
    }

    const fn contains(self, address: u32) -> bool {
        address >= self.start && address < self.end()
    }

    const fn permission(self, operation: MemoryOperation) -> MemoryPermission {
        match operation {
            MemoryOperation::Read => self.read,
            MemoryOperation::Write => self.write,
        }
    }
}

/// Validate that regions are non-empty, fit the KNX 24-bit address space, and do
/// not overlap.
#[must_use]
pub const fn memory_regions_valid(regions: &[MemoryRegion]) -> bool {
    let mut i = 0;
    while i < regions.len() {
        let region = regions[i];
        let start = u64::from(region.start);
        let end = start + region.length as u64;
        if region.length == 0 || end > 0x01_00_00_00 {
            return false;
        }

        let mut j = i + 1;
        while j < regions.len() {
            let other = regions[j];
            let other_start = u64::from(other.start);
            let other_end = other_start + other.length as u64;
            if start < other_end && other_start < end {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Check an access against a set of non-overlapping regions.
///
/// `None` means that the request does not start in a declared region, allowing
/// a composed memory map to fall through to another map. `Some(Ok(index))`
/// names the region that accepts the whole request. Once an access starts in a
/// region, crossing its boundary is an error.
#[must_use]
pub fn check_memory_access(
    regions: &[MemoryRegion],
    address: u32,
    length: usize,
    operation: MemoryOperation,
    ctx: AccessContext,
    max_access_levels: u8,
) -> Option<Result<usize, MemoryError>> {
    let start = address;
    let requested_length = u32::try_from(length).unwrap_or(u32::MAX);
    let end = start.saturating_add(requested_length);

    let (index, region) = regions.iter().copied().enumerate().find(|(_, region)| region.contains(start))?;

    if let Err(error) = region.permission(operation).check(ctx, max_access_levels) {
        return Some(Err(error));
    }

    if end > region.end() {
        // A direction-protected region at the far end supplies the more
        // specific read-only/write-only error. Otherwise crossing storage or
        // policy boundaries is an access denial.
        if length > 0 {
            let tail = end - 1;
            if let Some(tail_region) = regions.iter().copied().find(|candidate| candidate.contains(tail))
                && let Err(MemoryError::WriteProtected) =
                    tail_region.permission(operation).check(ctx, max_access_levels)
            {
                return Some(Err(MemoryError::WriteProtected));
            }
        }
        return Some(Err(MemoryError::AccessDenied));
    }

    Some(Ok(index))
}

/// Check whether one complete access is allowed by a region set.
///
/// This compact predicate is for callers, such as BCU-era devices, whose
/// wire protocol only distinguishes acceptance from rejection. Richer
/// management services should use [`check_memory_access`] to retain the
/// rejection reason and composed-map fallthrough.
#[must_use]
pub fn memory_access_allowed(
    regions: &[MemoryRegion],
    address: u32,
    length: usize,
    operation: MemoryOperation,
    access_level: u8,
    max_access_levels: u8,
) -> bool {
    let start = address;
    let requested_length = u32::try_from(length).unwrap_or(u32::MAX);
    let end = start.saturating_add(requested_length);

    for region in regions.iter().copied() {
        if region.contains(start) {
            return end <= region.end() && region.permission(operation).allows(access_level, max_access_levels);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGIONS: &[MemoryRegion] = &[
        MemoryRegion::open(0x0200, 0x100),
        MemoryRegion::read_only(0x0300, 0x10, MemoryPermission::Open),
        MemoryRegion::write_only(0x0310, 0x10, MemoryPermission::Open),
        MemoryRegion::new(
            0x0320,
            0xE0,
            MemoryPermission::Level(AccessLevel::Configuration),
            MemoryPermission::Level(AccessLevel::Configuration),
        ),
        MemoryRegion::new(
            0x0400,
            0x100,
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
        ),
    ];

    fn check(
        address: u32,
        length: usize,
        operation: MemoryOperation,
        level: u8,
        max_levels: u8,
    ) -> Option<Result<usize, MemoryError>> {
        check_memory_access(REGIONS, address, length, operation, AccessContext::new(level), max_levels)
    }

    #[test]
    fn distinguishes_unmapped_and_mapped_ranges() {
        assert_eq!(check(0x1000, 1, MemoryOperation::Read, 3, 4), None);
        assert_eq!(check(0x0200, 12, MemoryOperation::Read, 3, 4), Some(Ok(0)));
        assert_eq!(check(0x01FF, 2, MemoryOperation::Read, 3, 4), None);
    }

    #[test]
    fn accepts_regions_above_the_classic_address_space() {
        const EXTENDED: &[MemoryRegion] = &[MemoryRegion::open(0x01_0200, 0x100)];

        assert!(memory_regions_valid(EXTENDED));
        assert_eq!(
            check_memory_access(EXTENDED, 0x01_0200, 1, MemoryOperation::Read, AccessContext::new(0), 4),
            Some(Ok(0))
        );
        assert_eq!(check_memory_access(EXTENDED, 0x00_0200, 1, MemoryOperation::Read, AccessContext::new(0), 4), None);
    }

    #[test]
    fn compact_check_preserves_acceptance_semantics() {
        let allowed = |address, length, operation, level, max_levels| {
            memory_access_allowed(REGIONS, address, length, operation, level, max_levels)
        };

        assert!(allowed(0x0200, 12, MemoryOperation::Read, 3, 4));
        assert!(!allowed(0x01FF, 2, MemoryOperation::Read, 0, 4));
        assert!(!allowed(0x02FF, 2, MemoryOperation::Read, 0, 4));
        assert!(!allowed(0x0300, 1, MemoryOperation::Write, 0, 4));
        assert!(allowed(0x0320, 1, MemoryOperation::Read, 2, 4));
        assert!(!allowed(0x0320, 1, MemoryOperation::Read, 3, 4));
    }

    #[test]
    fn enforces_direction_and_boundaries() {
        assert_eq!(check(0x0300, 1, MemoryOperation::Write, 0, 4), Some(Err(MemoryError::WriteProtected)));
        assert_eq!(check(0x0310, 1, MemoryOperation::Read, 0, 4), Some(Err(MemoryError::WriteProtected)));
        assert_eq!(check(0x02FF, 2, MemoryOperation::Read, 0, 4), Some(Err(MemoryError::AccessDenied)));
        assert_eq!(check(0x02FF, 2, MemoryOperation::Write, 0, 4), Some(Err(MemoryError::WriteProtected)));
    }

    #[test]
    fn resolves_access_audiences_for_each_profile() {
        assert_eq!(check(0x0320, 1, MemoryOperation::Read, 2, 4), Some(Ok(3)));
        assert_eq!(check(0x0320, 1, MemoryOperation::Read, 3, 4), Some(Err(MemoryError::AccessDenied)));
        assert_eq!(check(0x0400, 1, MemoryOperation::Read, 1, 16), Some(Ok(4)));
        assert_eq!(check(0x0400, 1, MemoryOperation::Read, 2, 16), Some(Err(MemoryError::AccessDenied)));
    }

    #[test]
    fn validates_region_sets() {
        assert!(memory_regions_valid(REGIONS));
        assert!(!memory_regions_valid(&[MemoryRegion::open(0x1000, 0)]));
        assert!(!memory_regions_valid(&[MemoryRegion::open(0xFF_FFF0, 0x20)]));
        assert!(!memory_regions_valid(&[MemoryRegion::open(0x1000, 0x20), MemoryRegion::open(0x1010, 0x20)]));
    }
}
