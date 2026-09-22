//! Unambiguous discovery-response selection.

use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::device::OpenMediumDomainAddress;

pub(in crate::commissioning) fn unique_target(
    addresses: Vec<IndividualAddress>,
    method: &str,
) -> Result<IndividualAddress> {
    match addresses.as_slice() {
        [address] => Ok(*address),
        [] => Err(Diagnostic::preparation(format!("no device answered through {method}"))),
        addresses => Err(Diagnostic::preparation(format!("{} devices answered through {method}", addresses.len()))),
    }
}

pub(in crate::commissioning) fn unique_domain_target(
    devices: Vec<(IndividualAddress, OpenMediumDomainAddress)>,
    method: &str,
) -> Result<(IndividualAddress, OpenMediumDomainAddress)> {
    match devices.as_slice() {
        [device] => Ok(*device),
        [] => Err(Diagnostic::preparation(format!("no RF domain response answered through {method}"))),
        devices => {
            Err(Diagnostic::preparation(format!("{} RF domain responses answered through {method}", devices.len())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::runtime::policy::{unique_target, verify_programming_mode_address_responses};

    #[test]
    fn duplicate_target_responses_fail_closed() {
        let address = IndividualAddress::new(1, 0, 10);
        assert!(unique_target(vec![address, address], "test").is_err());
    }

    #[test]
    fn programming_mode_assignment_is_verified_by_the_response_source_address() {
        let previous = IndividualAddress::new(1, 0, 1);
        let desired = IndividualAddress::new(1, 0, 55);

        assert!(verify_programming_mode_address_responses(&[desired], desired).is_ok());
        assert!(verify_programming_mode_address_responses(&[previous], desired).is_err());
        assert!(verify_programming_mode_address_responses(&[desired, desired], desired).is_err());
        assert!(verify_programming_mode_address_responses(&[], desired).is_err());
    }
}
