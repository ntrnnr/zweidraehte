//! Write-through configuration storage for the Linux device shells.
//!
//! The device state's persistent sections live in a [`ByteNv`] image in a
//! plain file, the host twin of a FRAM-backed device: every section at a
//! fixed offset, written in place and synced before the response that
//! caused the change leaves the device (the router flushes through the
//! [`NvConfig`] in the device's stores struct).
//!
//! The image is binary. [`dump_config`] prints what a file holds, section by
//! section, for the shells' `--dump-config` flag.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use zweidraehte_device::sections::{PersistentSections, Section, SectionKind};
use zweidraehte_device::storage::{ByteIo, NvConfig};
use zweidraehte_nv::{ByteNv, Loaded, NvStore};

use super::FileByteIo;

/// Size of the config file. It bounds the section layout, which is far
/// smaller for the light switches; a layout that does not fit is reported
/// at boot as `LayoutTooLarge`. The file is created sparse, so the unused
/// tail costs nothing on disk.
pub const CONFIG_FILE_LEN: u32 = 64 * 1024;

/// The write-through config backend of a Linux shell.
pub type LinuxConfigNv = NvConfig<ByteNv<FileByteIo>>;

/// Open (creating if absent) the config file at `path`. The sections are
/// applied at boot with [`NvConfig::load`].
pub fn open_config_nv(path: impl AsRef<Path>) -> io::Result<LinuxConfigNv> {
    let io = FileByteIo::open(path, u64::from(CONFIG_FILE_LEN))?;
    Ok(NvConfig::new(ByteNv::new(io, 0, CONFIG_FILE_LEN)))
}

// ============================================================================
// Dump
// ============================================================================

/// A [`ByteIo`] over a copy of the file in memory, so that loading it for a
/// dump never formats or otherwise touches the file itself.
struct MemoryImage(Vec<u8>);

/// A read or write past the end of the in-memory image.
#[derive(Debug)]
struct OutOfRange;

impl MemoryImage {
    fn range(&self, off: u32, len: usize) -> Result<std::ops::Range<usize>, OutOfRange> {
        let start = off as usize;
        let end = start.checked_add(len).filter(|&end| end <= self.0.len()).ok_or(OutOfRange)?;
        Ok(start..end)
    }
}

impl ByteIo for MemoryImage {
    type Error = OutOfRange;

    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), OutOfRange> {
        buf.copy_from_slice(&self.0[self.range(off, buf.len())?]);
        Ok(())
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), OutOfRange> {
        let range = self.range(off, data.len())?;
        self.0[range].copy_from_slice(data);
        Ok(())
    }
}

/// Print the configuration the file at `path` holds, as `state`'s layout
/// reads it: the load outcome, then every section's bytes in hex.
///
/// `state` must be factory-fresh; the file's sections are applied to it,
/// so the caller can print decoded fields from it afterwards. A missing,
/// blank or foreign file shows the factory defaults. The file is only read.
///
/// The dump includes whatever the sections hold, key material included, in
/// the clear: the same exposure as the file itself on the same host.
// TODO: name the sections. That needs a per-family id → name table next to
// each state's section list; the ids are stable, so hex is enough for now.
pub fn dump_config<S: PersistentSections>(path: &Path, state: &S, out: &mut impl Write) -> io::Result<()> {
    // A missing file reads as blank, like the zero-filled file a first boot
    // creates.
    let mut image = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    image.resize(CONFIG_FILE_LEN as usize, 0);

    let loaded = ByteNv::new(MemoryImage(image), 0, CONFIG_FILE_LEN)
        .load(state)
        .map_err(|error| io::Error::other(format!("cannot read the config image: {error:?}")))?;

    writeln!(out, "Config file:        {}", path.display())?;
    writeln!(out, "Layout fingerprint: {:08X}", state.layout_fingerprint())?;
    let contents = match loaded {
        Loaded::Restored => "restored",
        Loaded::Fresh => "blank or written by another layout (factory defaults shown)",
    };
    writeln!(out, "Contents:           {contents}")?;

    let mut sections: Vec<Section> = Vec::new();
    state.for_each_section(&mut |section| sections.push(section));
    for section in sections {
        let kind = match section.kind {
            SectionKind::Record => "record",
            SectionKind::Image => "image",
        };
        writeln!(out, "\nSection {:02X}  {kind}, {} bytes", section.id, section.len)?;

        let mut bytes = vec![0; usize::from(section.len)];
        state.read_section(section.id, 0, &mut bytes);
        for (line, chunk) in bytes.chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02X}")).collect();
            writeln!(out, "  {:04X}: {}", line * 16, hex.join(" "))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    use zweidraehte_device::sections::{SectionError, SectionId, apply_image, read_image, whole_record};
    use zweidraehte_device::storage::DeviceStorage;

    use super::*;

    /// A unique temp path per test, avoiding a `tempfile` dependency. The
    /// process id keeps concurrent test binaries from colliding.
    fn temp_path(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("zw-support-config-nv-{}-{}", std::process::id(), tag));
        path
    }

    /// A two-section state: an address Record and a table Image.
    struct TestState {
        address: Cell<[u8; 2]>,
        table: RefCell<[u8; 8]>,
        dirty: Cell<bool>,
    }

    const ADDRESS: SectionId = 0x01;
    const TABLE: SectionId = 0x08;

    impl TestState {
        fn new() -> Self {
            Self { address: Cell::new([0xFF, 0xFF]), table: RefCell::new([0; 8]), dirty: Cell::new(false) }
        }
    }

    impl PersistentSections for TestState {
        fn for_each_section(&self, f: &mut impl FnMut(Section)) {
            f(Section { id: ADDRESS, len: 2, kind: SectionKind::Record });
            f(Section { id: TABLE, len: 8, kind: SectionKind::Image });
        }

        fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
            match id {
                ADDRESS => read_image(&self.address.get(), offset, buf),
                TABLE => read_image(&*self.table.borrow(), offset, buf),
                _ => panic!("unknown section"),
            }
        }

        fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
            match id {
                ADDRESS => {
                    self.address.set(*whole_record::<2>(offset, bytes)?);
                    Ok(())
                }
                TABLE => apply_image(&mut *self.table.borrow_mut(), offset, bytes),
                _ => Err(SectionError::UnknownSection),
            }
        }

        fn reset_section(&self, id: SectionId) {
            match id {
                ADDRESS => self.address.set([0xFF, 0xFF]),
                _ => *self.table.borrow_mut() = [0; 8],
            }
        }

        fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
            if self.dirty.replace(false) {
                f(TABLE, 0, 8);
            }
        }
    }

    fn dump(path: &Path) -> String {
        let mut out = Vec::new();
        dump_config(path, &TestState::new(), &mut out).expect("dump");
        String::from_utf8(out).expect("utf-8")
    }

    #[test]
    fn a_missing_file_dumps_as_blank_and_is_not_created() {
        let path = temp_path("missing");
        let _ = fs::remove_file(&path);

        let text = dump(&path);

        assert!(text.contains("blank"), "{text}");
        assert!(text.contains("Section 01  record, 2 bytes\n  0000: FF FF"), "{text}");
        assert!(!path.exists(), "a dump must not create the file");
    }

    #[test]
    fn a_foreign_file_dumps_as_blank_and_is_left_untouched() {
        let path = temp_path("foreign");
        fs::write(&path, b"not a config image").expect("write");

        let text = dump(&path);

        assert!(text.contains("blank"), "{text}");
        assert_eq!(fs::read(&path).expect("read"), b"not a config image");
        fs::remove_file(&path).ok();
    }

    #[test]
    fn a_flushed_change_dumps_as_restored() {
        let path = temp_path("flushed");
        let _ = fs::remove_file(&path);

        let state = TestState::new();
        let config: LinuxConfigNv = open_config_nv(&path).expect("open");
        assert_eq!(config.load(&state).expect("format"), Loaded::Fresh);
        state.address.set([0x11, 0x05]);
        *state.table.borrow_mut() = [1, 2, 3, 4, 5, 6, 7, 8];
        state.dirty.set(true);
        config.flush(&state).expect("flush");
        drop(config);

        let text = dump(&path);

        assert!(text.contains("Contents:           restored"), "{text}");
        assert!(text.contains("Section 01  record, 2 bytes\n  0000: 11 05"), "{text}");
        assert!(text.contains("Section 08  image, 8 bytes\n  0000: 01 02 03 04 05 06 07 08"), "{text}");
        fs::remove_file(&path).ok();
    }
}
