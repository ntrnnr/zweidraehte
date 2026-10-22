//! Supplied or discovered device facts shared by the compilation stages.

use zweidraehte_proto::address::IndividualAddress;

use super::security::ObservedDataSecurity;
use crate::bus::access::ManagementCredential;
use crate::configuration::MaterializedDevice;

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

    /// Facts for an offline compile of `device` without observing a target.
    ///
    /// The target is assumed at the device's own address with its own serial
    /// number, reached through [`ResolvedKeyMaterial::offline_credential`].
    /// The application security mode stays unknown.
    ///
    /// [`ResolvedKeyMaterial::offline_credential`]: crate::configuration::ResolvedKeyMaterial::offline_credential
    pub fn offline_from(device: &MaterializedDevice) -> Self {
        let keys = device.key_material();
        Self::new(ObservedTarget {
            previous_address: device.individual_address(),
            serial_number: keys.serial_number(),
            credential: keys.offline_credential(),
        })
    }
}
