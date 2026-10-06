//! Surviving flash ECC errors in the flash stores.
//!
//! The STM32G0 flash stores every doubleword with ECC. A power cut while a
//! doubleword is being programmed can leave it half-written, and reading it
//! back then fails with a double (uncorrectable) ECC error, which the flash
//! interface reports as a **non-maskable interrupt**. The default NMI
//! handler loops forever, so the first boot after such a cut would hang.
//!
//! The logs read a torn tail by design: replay walks the records until one
//! fails its framing or CRC. The bytes of a torn doubleword are garbage
//! either way, and the log already rejects garbage, so the handler below only
//! has to acknowledge the error and let the read return. It does so for
//! addresses inside the device's stores on the internal flash alone, which
//! are all logs (the byte-image stores need a byte-writable medium); an ECC
//! error anywhere else (code, constants, the provisioning page) or any other
//! NMI source stays fatal.
//!
//! Every firmware installs it with
//! [`storage_platform!`](crate::storage_platform); boot logs how many errors
//! replay passed ([`recovered_ecc_errors`]).
//!
//! # Register facts
//!
//! The G0B0's own manual is RM0454 (G0x0); its flash is the G0B1's, which
//! RM0444 (G0x1) documents. The two agree except on ADDR_ECC.
//!
//! - `FLASH_ECCR` (offset 0x018) reports bank 1, or the whole flash when it
//!   runs single-bank; `FLASH_ECCR2` (0x01C) reports bank 2 (RM0454 §3.7.6,
//!   §3.7.7). Both: SYSF_ECC bit 20, ECCCIE bit 24, ECCC bit 30, ECCD
//!   bit 31; ECCC and ECCD are write-1-to-clear. The metapac maps the G0B0
//!   onto `flash_g0x0`, which lacks `FLASH_ECCR2`, so both are accessed raw.
//! - ADDR_ECC is the failing "double-word offset (multiple of 64 bits) to
//!   main flash memory" in both registers. RM0454 gives it as bits 13:0
//!   (§3.7.6) and as bits 16:0 with bits 2:0 cleared (§3.3.3), both carried
//!   over from its 128 KiB parts: neither reaches the G0B0's upper flash,
//!   where the stores live. RM0444 §3.7.6 gives bits 15:0 in
//!   doublewords, which spans exactly 512 KiB from the flash base, so that
//!   is what the handler reads. If ADDR_ECC\[2:0\] do read as zero, the
//!   page-aligned store areas keep every address inside a store in range.
//! - A double error sets ECCD and raises the NMI; unlike an SRAM parity
//!   error it raises no bus error, so the read itself completes.
//! - "While ECCC or ECCD is set, FLASH_ECCR is not updated if a new ECC
//!   error occurs." A single-bit correction elsewhere would freeze a stale
//!   address that a later double error then reports. Every store read
//!   therefore clears the correction flags before and after it
//!   ([`clear_corrections`], called by [`StmFlashIo`](crate::StmFlashIo)),
//!   so a double error during the read reports its own address.

use core::sync::atomic::{AtomicU32, Ordering};

use zweidraehte_device::storage::{LayoutEntry, Medium};

use crate::storage::InternalFlash;

const FLASH_BASE: u32 = embassy_stm32::flash::FLASH_BASE as u32;
const FLASH_ECCR: *mut u32 = 0x4002_2018 as *mut u32;
const FLASH_ECCR2: *mut u32 = 0x4002_201C as *mut u32;
const ADDR_ECC: u32 = 0xFFFF;
const ECCCIE: u32 = 1 << 24;
const ECCC: u32 = 1 << 30;
const ECCD: u32 = 1 << 31;

/// ECC errors inside the flash stores acknowledged since reset. Only the NMI
/// writes it, and nothing preempts an NMI, so a plain load/store suffices
/// on the M0+ (which has no atomic read-modify-write).
static RECOVERED: AtomicU32 = AtomicU32::new(0);

/// How many double ECC errors inside the flash stores the NMI handler has
/// acknowledged since reset: torn doublewords the log replay walked over.
pub fn recovered_ecc_errors() -> u32 {
    RECOVERED.load(Ordering::Relaxed)
}

/// Clear the single-error correction flags (ECCC) of both ECC registers, so
/// that the next ECC error is recorded with its own address. Corrections
/// need no handling: the corrected data was returned, and ECCCIE is off.
///
/// Writing ECCC as 1 clears it; ECCD is written as 0, which leaves it to the
/// NMI handler even if a double error lands between the read and the write.
pub fn clear_corrections() {
    for register in [FLASH_ECCR, FLASH_ECCR2] {
        // SAFETY: both are FLASH peripheral registers, always mapped.
        let value = unsafe { register.read_volatile() };
        if value & ECCC != 0 {
            // SAFETY: as above; the write clears ECCC and keeps ECCCIE.
            unsafe { register.write_volatile((value & ECCCIE) | ECCC) };
        }
    }
}

/// Whether the absolute flash `address` lies inside one of `layout`'s stores
/// on the internal flash.
fn in_flash_store(layout: &[LayoutEntry], address: u32) -> bool {
    layout.iter().any(|entry| {
        entry.medium == InternalFlash::ID
            && (FLASH_BASE + entry.area.offset..FLASH_BASE + entry.area.end()).contains(&address)
    })
}

/// The NMI body: acknowledge double ECC errors inside the stores `layout`
/// places on the internal flash. Returns false if the NMI had any other
/// cause, which the caller treats as fatal.
///
/// # Safety
///
/// Only to be called from the NMI handler: it clears flash error flags.
#[doc(hidden)]
pub unsafe fn recover_flash_ecc_error(layout: &[LayoutEntry]) -> bool {
    let mut recovered = false;
    for register in [FLASH_ECCR, FLASH_ECCR2] {
        // SAFETY: both are FLASH peripheral registers, always mapped.
        let value = unsafe { register.read_volatile() };
        if value & ECCD == 0 {
            continue;
        }
        let address = FLASH_BASE + (value & ADDR_ECC) * 8;
        if !in_flash_store(layout, address) {
            return false;
        }
        // Clear ECCD, and ECCC with it so the register records the next
        // error; keep ECCCIE.
        // SAFETY: as above; the write only clears the flags.
        unsafe { register.write_volatile((value & ECCCIE) | ECCD | ECCC) };
        recovered = true;
    }

    if recovered {
        RECOVERED.store(RECOVERED.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
    }
    recovered
}
