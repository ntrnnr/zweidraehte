//! Supplied or discovered device facts shared by the compilation stages.

use zweidraehte_proto::address::IndividualAddress;

use super::security::ObservedDataSecurity;
use crate::bus::access::ManagementCredential;

/// Identity reached using the selected management credential.
///
/// The credential identifies an access choice, never its secret bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedTarget {
    pub previous_address: IndividualAddress,
    pub serial_number: Option<[u8; 6]>,
    pub credential: ManagementCredential,
}

/// Evidence available to pure compilation. Unknown facts remain explicit so
/// image previews can precede discovery. Lowering requires a selected target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgrammingFacts {
    pub target: Option<ObservedTarget>,
    pub data_security: ObservedDataSecurity,
}

impl ProgrammingFacts {
    pub fn new(target: ObservedTarget) -> Self {
        Self { target: Some(target), ..Self::default() }
    }

    pub fn with_data_security(mut self, mode: ObservedDataSecurity) -> Self {
        self.data_security = mode;
        self
    }
}
