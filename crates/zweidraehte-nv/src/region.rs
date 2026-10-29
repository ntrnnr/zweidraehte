//! One store's share of a medium.
//!
//! A board hands every store a handle to the whole chip, and several stores
//! may share one chip. [`Region`] narrows such a handle to the store's
//! [`Area`]: the store addresses its bytes from 0 and cannot name a
//! neighbouring store's bytes by accident.
//!
//! The bounds are checked in debug builds only. The layout is checked at
//! compile time, and every store bounds its own accesses to the size it was
//! opened with, so an access past the area's end is a bug inside a store
//! implementation, which the host tests catch. Release firmware does not
//! pay for the check.

use crate::{Area, ByteIo, SectorIo};

/// The `area` of the medium behind `io`, addressed from 0.
///
/// `Copy` when the handle is, so one chip handle can open several regions.
#[derive(Clone, Copy, Debug)]
pub struct Region<Io> {
    io: Io,
    area: Area,
}

impl<Io> Region<Io> {
    /// The `area` of the medium `io` opens. The area is checked against the
    /// medium where the layout is declared, not here.
    pub const fn new(io: Io, area: Area) -> Self {
        Self { io, area }
    }

    /// The area this region covers, in the medium's own offsets.
    pub const fn area(&self) -> Area {
        self.area
    }

    /// The medium offset of `len` bytes at region offset `offset`.
    ///
    /// # Panics
    ///
    /// In debug builds, if the range does not lie inside the region.
    fn absolute(&self, offset: u32, len: usize) -> u32 {
        debug_assert!(u64::from(offset) + len as u64 <= u64::from(self.area.len), "access outside the store's region");

        self.area.offset + offset
    }
}

impl<Io: SectorIo> SectorIo for Region<Io> {
    type Error = Io::Error;

    const WRITE_ALIGN: usize = Io::WRITE_ALIGN;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        let at = self.absolute(offset, buf.len());
        self.io.read(at, buf)
    }

    fn erase(&mut self, start: u32, end: u32) -> Result<(), Self::Error> {
        debug_assert!(start <= end, "erase range runs backwards");
        let at = self.absolute(start, (end - start) as usize);

        self.io.erase(at, at + (end - start))
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
        let at = self.absolute(offset, data.len());
        self.io.write(at, data)
    }
}

impl<Io: ByteIo> ByteIo for Region<Io> {
    type Error = Io::Error;

    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        let at = self.absolute(off, buf.len());
        self.io.read_at(at, buf)
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        let at = self.absolute(off, data.len());
        self.io.write_at(at, data)
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        self.io.sync()
    }
}

#[cfg(test)]
mod tests {
    use super::Region;
    use crate::mock::Backing;
    use crate::{Area, ByteIo, SectorIo};

    /// Region offsets map onto the medium past the area's start.
    #[test]
    fn offsets_are_relative_to_the_area() {
        let medium = Backing::new(64, 1);
        let mut region = Region::new(medium.open_bytes(), Area::new(16, 16));

        region.write_at(0, &[1, 2]).expect("write");
        region.write_at(14, &[3, 4]).expect("write");

        assert_eq!(&medium.bytes()[16..18], &[1, 2]);
        assert_eq!(&medium.bytes()[30..32], &[3, 4]);

        let mut buf = [0u8; 2];
        region.read_at(14, &mut buf).expect("read");
        assert_eq!(buf, [3, 4]);
    }

    /// A store cannot reach past its area into a neighbour's.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "outside the store's region")]
    fn an_access_past_the_area_panics() {
        let medium = Backing::new(64, 1);
        let mut region = Region::new(medium.open_bytes(), Area::new(16, 16));

        let _ = region.write_at(15, &[1, 2]);
    }

    /// Erases are translated and bounded like reads and writes.
    #[test]
    fn erases_stay_inside_the_area() {
        let medium = Backing::new(4 * 1024, 1024);
        let mut region = Region::new(medium.open(), Area::new(1024, 2048));

        region.write(0, &[0]).expect("program a byte");
        region.erase(0, 1024).expect("erase the region's first sector");

        assert_eq!(medium.bytes()[1024], 0xFF);
        assert_eq!(medium.erases(), 1);
    }
}
