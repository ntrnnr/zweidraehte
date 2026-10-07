#![no_std]

//! Small raw-register helpers for the polling STM32G0 micro targets.
//!
//! This deliberately does not depend on embassy. Every micro target gets the
//! internal-flash driver its configuration page is written through; secure
//! targets also get their identity from the `KNXP` page, one shared ADC
//! entropy source, and the FM25L16B medium under the shared
//! `zweidraehte_nv::PackedSeqStore` sequence layout. A plain target links
//! only the flash driver.

mod entropy;
mod flash;
mod fram_store;
mod identity;

pub use entropy::seed_csprng;
pub use flash::{FLASH_SIZE, FlashError, PAGE_SIZE, PROVISIONING_PAGE, RawFlash};
pub use fram_store::FramStore;
pub use identity::{IdentityError, SecureIdentity, load_secure_identity};
