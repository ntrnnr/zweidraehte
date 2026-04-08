//! Application layer service extensions.
//!
//! Each extension handles a group of optional APCI codes that can be
//! composed into a device's [`AlExtension`](crate::StackDefinition::AlExtension)
//! type via tuples. The core AL dispatches unrecognized APCIs to the
//! extension chain.
//!
//! # Available Extensions
//!
//! | Extension | Services | When to use |
//! |-----------|----------|-------------|
//! | [`DomainAddressExtension`] | `A_DomainAddressSerialNumber_*` | KNX/IP and RF devices |
//! | [`PropertyExtValueExtension`] | `A_PropertyExtValue_*`, `A_MemoryExtended_*`, `A_FunctionPropertyExt_*` | Devices supporting AN163 extended services |

pub mod traits;
pub mod domain_addr;
pub mod property_ext;

pub use traits::{AlExtensionContext, AlServiceExtension};
pub use domain_addr::DomainAddressExtension;
pub use property_ext::PropertyExtValueExtension;
