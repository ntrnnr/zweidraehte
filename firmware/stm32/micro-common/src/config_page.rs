//! The low-write configuration record in the flash page below `KNXP`.
//!
//! The polling micro targets persist their configuration as one snapshot,
//! taken when it matters rather than on every change: after the response to
//! an `A_Restart` has left the UART (ETS ends every download with one), and
//! after a standalone individual-address write, which has no restart. What
//! the record holds is the firmware's business — the management state from
//! `zweidraehte_microdevice::persist`, plus a secure target's Security IO
//! tables. This module only frames it:
//!
//! ```text
//! [magic:4][version:1][reserved:1][total:2 LE][payload][crc32:4 LE]
//! ```
//!
//! `total` counts the header, payload and CRC; the CRC covers everything
//! before it. A wrong magic, version, length or CRC reads as no record, and
//! the target boots factory-fresh. Bump the version whenever the payload
//! layout changes: there is no migration.
//!
//! TODO: a power cut between the page erase and the end of programming
//! loses the configuration, and a torn doubleword can raise a flash ECC NMI
//! that no micro target handles yet, which would hang the next boot. Both
//! wait for a second page (writing the other one first) and an NMI handler
//! like the full stack's `stm32_common::ecc`.

use zweidraehte_nv::{Area, SectorIo};
use zweidraehte_proto::util::crc::crc32;

use crate::flash::{PAGE_SIZE, PROVISIONING_PAGE, RawFlash};

/// The configuration record's page, directly below the `KNXP` page.
pub const CONFIG_PAGE: Area = Area::new(PROVISIONING_PAGE.offset - PAGE_SIZE, PAGE_SIZE);

/// The page's length, the upper bound of a record.
const PAGE_LEN: usize = PAGE_SIZE as usize;

/// Magic, version, a reserved octet, and the total length.
const HEADER_LEN: usize = 8;

/// The trailing CRC32.
const CRC_LEN: usize = 4;

/// The flash controller programs whole doublewords.
const DOUBLEWORD: usize = 8;

/// The staging capacity [`save`] needs for a payload of at most
/// `payload_len` octets: header, payload and CRC in whole doublewords.
pub const fn capacity(payload_len: usize) -> usize {
    (HEADER_LEN + payload_len + CRC_LEN).next_multiple_of(DOUBLEWORD)
}

/// Why a record could not be saved.
#[derive(Debug)]
pub enum ConfigError {
    /// The payload did not fit the staging buffer.
    TooLarge,
    /// The flash erase or program failed.
    Flash,
}

/// The payload of the record tagged `magic` and `version`, read straight
/// from the memory-mapped page, or `None` if the page holds no valid one.
pub fn load(magic: [u8; 4], version: u8) -> Option<&'static [u8]> {
    let page = RawFlash::slice(CONFIG_PAGE.offset, PAGE_LEN);

    if page[..4] != magic || page[4] != version {
        return None;
    }

    let total = usize::from(u16::from_le_bytes([page[6], page[7]]));
    if !(HEADER_LEN + CRC_LEN..=PAGE_LEN).contains(&total) {
        return None;
    }

    let crc_at = total - CRC_LEN;
    let stored_crc = u32::from_le_bytes(page[crc_at..total].try_into().expect("four CRC octets"));
    if crc32(&page[..crc_at]) != stored_crc {
        return None;
    }

    Some(&page[HEADER_LEN..crc_at])
}

/// Save a record tagged `magic` and `version` whose payload `fill` writes
/// into the slice it is given, returning the payload length (`None` when
/// the payload does not fit).
///
/// `CAP` sizes the staging buffer, header and CRC included. It stays per
/// target so the plain targets do not put a whole page on their stack; the
/// erase still covers the whole page.
///
/// A page that already holds exactly this record is left alone, so a
/// restart without configuration changes costs no erase cycle.
pub fn save<const CAP: usize>(
    magic: [u8; 4],
    version: u8,
    fill: impl FnOnce(&mut [u8]) -> Option<usize>,
) -> Result<(), ConfigError> {
    const {
        assert!(CAP.is_multiple_of(DOUBLEWORD), "the staging buffer is whole doublewords");
        assert!(CAP >= HEADER_LEN + CRC_LEN && CAP <= PAGE_LEN, "the staging buffer fits a header, a CRC and the page");
    }

    let mut record = [0xFFu8; CAP];

    // Stage the payload first: the header's length depends on it.
    let payload_len = fill(&mut record[HEADER_LEN..CAP - CRC_LEN]).ok_or(ConfigError::TooLarge)?;
    let crc_at = HEADER_LEN + payload_len;
    let total = crc_at + CRC_LEN;

    record[..4].copy_from_slice(&magic);
    record[4] = version;
    record[6..8].copy_from_slice(&(total as u16).to_le_bytes());

    let crc = crc32(&record[..crc_at]);
    record[crc_at..total].copy_from_slice(&crc.to_le_bytes());

    // `CAP` is whole doublewords, so the padded record still fits it.
    let programmed = &record[..total.next_multiple_of(DOUBLEWORD)];
    if RawFlash::slice(CONFIG_PAGE.offset, programmed.len()) == programmed {
        return Ok(());
    }

    RawFlash.erase(CONFIG_PAGE.offset, CONFIG_PAGE.end()).map_err(|_| ConfigError::Flash)?;
    RawFlash.write(CONFIG_PAGE.offset, programmed).map_err(|_| ConfigError::Flash)
}
