//! A span of a storage medium.

/// `len` bytes of a medium starting at `offset`.
///
/// The unit a storage layout is made of: a platform places each store's area
/// on its chip and checks the areas against each other and against the
/// chip's geometry, all in `const` code, so a bad layout is a compile error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Area {
    /// Offset of the first byte on the medium.
    pub offset: u32,
    /// Length in bytes.
    pub len: u32,
}

impl Area {
    pub const fn new(offset: u32, len: u32) -> Self {
        Self { offset, len }
    }

    /// The offset just past the area.
    pub const fn end(&self) -> u32 {
        self.offset + self.len
    }

    /// `len` bytes directly after this area.
    pub const fn after(&self, len: u32) -> Self {
        Self::new(self.end(), len)
    }

    /// Whether the two areas share a byte.
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.offset < other.end() && other.offset < self.end()
    }

    /// Whether the area starts and ends on `granule` boundaries.
    pub const fn is_aligned(&self, granule: u32) -> bool {
        self.offset % granule == 0 && self.len % granule == 0
    }

    /// Whether `offset` lies inside the area.
    pub const fn contains(&self, offset: u32) -> bool {
        self.offset <= offset && offset < self.end()
    }
}

#[cfg(test)]
mod tests {
    use super::Area;

    #[test]
    fn neighbours_touch_without_overlapping() {
        let config = Area::new(0x1F_2000, 0x4000);
        let siat = config.after(0x6000);

        assert_eq!(siat, Area::new(0x1F_6000, 0x6000));
        assert!(!config.overlaps(&siat) && !siat.overlaps(&config));
        assert!(config.overlaps(&Area::new(0x1F_5FFF, 1)));
        assert!(config.contains(0x1F_2000) && !config.contains(config.end()));
    }

    #[test]
    fn alignment_covers_both_ends() {
        assert!(Area::new(0x1000, 0x2000).is_aligned(0x1000));
        assert!(!Area::new(0x1000, 0x1800).is_aligned(0x1000));
        assert!(!Area::new(0x0800, 0x1000).is_aligned(0x1000));
    }
}
