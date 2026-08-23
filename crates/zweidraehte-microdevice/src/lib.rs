//! Ultra-lightweight, **no-async** KNX device stack for fixed-map TP1
//! BCU-era management models, starting with BCU2 (mask 0020h).
//!
//! # Why a second device stack
//!
//! `zweidraehte-device` is built around System B's flexibility: interface
//! objects everywhere, relative memory allocation, composable extensions,
//! and an embassy-async runtime with channels and a shared buffer pool.
//! BCU-era devices are the opposite trade: a fixed memory map, tables
//! linked by one-byte pointers, four interface objects, and a 15-octet
//! APDU. A stack that embraces those constraints fits small
//! microcontrollers that the full stack does not.
//!
//! # The cooperative runloop
//!
//! There is no executor. The application owns a [`Microdevice`] and calls
//! [`Microdevice::poll`] from its main loop, feeding one input per call:
//! a complete TP1 standard frame or a timer tick. A byte-oriented link
//! driver drains the UART ISR ring and assembles the frame first. Every
//! call returns the frames the stack wants on the bus — the stack itself
//! is single-threaded `&mut self` code with no interior mutability and no
//! locks.
//!
//! # The EEPROM bytes ARE the tables
//!
//! The stack owns one flat EEPROM image at the family's base address.
//! The address, association, and group object tables are parsed in place
//! through the pointer bytes inside that image on every lookup, exactly
//! like the mask firmware on real silicon walks its EEPROM. An ETS
//! `A_Memory_Write` is live the moment it lands; there is no shadow
//! state to sync back.
//!
//! The family seam ([`family::MicroDeviceFamily`]) keeps the core generic
//! over the management model: BCU2 (masks 0020h/0021h),
//! micro-System-7, and BCU1 (mask 0012h).

#![cfg_attr(not(any(test, feature = "std")), no_std)]

pub mod co_flags;
pub mod device;
pub mod eeprom;
pub mod extended_services;
pub mod families;
pub mod family;
pub mod frame;
pub mod group_comm;
pub mod link;
pub mod management;
pub mod sal;
pub mod security;
pub mod transport;

#[cfg(feature = "std")]
pub mod snapshot;

pub use device::{Microdevice, PollInput, PollOutput};
pub use families::bcu1::{Bcu1DeviceDefinition, Bcu1Family};
pub use families::bcu2::{Bcu2DeviceDefinition, Bcu2Family};
pub use families::system7::{System7DeviceDefinition, System7Family};
pub use family::{MemoryAccessPolicy, MicroDeviceFamily};
pub use security::{DataSecure, MicroSecurityResources, NoSecurity, SecurityModule};

/// Plain mask-0012 micro profile.
pub type PlainBcu1 = Microdevice<Bcu1Family>;
/// Plain BCU2 profile. The const parameter is restricted by `Bcu2Family` to
/// the supported BCU2 masks 0020h and 0021h.
pub type PlainBcu2<const MASK: u16 = 0x0020> = Microdevice<Bcu2Family<MASK>>;
/// Data Secure BCU2 composition used by the reference product. It is fixed
/// to mask 0021h because that pairing is backed by hardware evidence; Data
/// Secure itself is a profile module and is not encoded by this mask value.
pub type SecureBcu2<S, const GROUP_KEYS: usize, const GROUP_OBJECTS: usize> =
    Microdevice<Bcu2Family<0x0021>, { frame::SECURE_EXTENDED_FRAME }, DataSecure<S, GROUP_KEYS, GROUP_OBJECTS>>;
/// Plain micro System 7 profile.
pub type PlainSystem7<
    const EEPROM_LEN: usize,
    const COT_ADDR: u16,
    P = families::system7::StandardSystem7MemoryPolicy<EEPROM_LEN>,
> = Microdevice<System7Family<EEPROM_LEN, COT_ADDR, P>>;

/// Crate-internal logging shim: `log` on the host, `defmt` on embedded,
/// nothing when neither feature is enabled. Only `debug!` exists — this
/// stack has no error path that a log line would fix, and every byte of
/// format-string flash matters on the targets it is for.
#[macro_export]
macro_rules! micro_debug {
    ($($arg:tt)*) => {
        #[cfg(feature = "log")]
        ::log::debug!($($arg)*);
        #[cfg(all(feature = "defmt", not(feature = "log")))]
        ::defmt::debug!($($arg)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        { let _ = format_args!($($arg)*); }
    };
}
