//! Bind output stamp identities once; runtime observations retain only values.
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::evidence::{DeviceStamp, DifferentialDecision, DiscoveredDevice};
use crate::commissioning::runtime::prepared::PreparedEvidence;
use std::collections::BTreeSet;

impl PreparedEvidence {
    pub(crate) fn discovery(&self, program: &CompiledProgram) -> DiscoveredDevice {
        let target = program.observed_target();
        let management_style = self.management_style.as_ref().map(|(_, style)| *style);
        DiscoveredDevice {
            address: Some(target.previous_address),
            serial_number: target.serial_number,
            mask: program.profile().mask().clone(),
            interface_max_apdu: self.interface_max_apdu,
            target_max_apdu: self.target_max_apdu,
            secure_management: program.management_secure(),
            observed_management_style: management_style,
        }
    }

    pub(crate) fn validate_captured_stamps(
        &self,
        program: &CompiledProgram,
        captured: &[DeviceStamp],
    ) -> Result<(), Diagnostic> {
        let mut seen = BTreeSet::new();
        for stamp in captured {
            if !seen.insert(stamp.resource.clone())
                || program
                    .download_stamps()
                    .iter()
                    .find(|candidate| candidate.id == stamp.resource)
                    .is_none_or(|candidate| !whole_records(&stamp.value, candidate.read.extent.byte_length))
            {
                return Err(Diagnostic::new("the load procedure returned an invalid download-stamp binding"));
            }
        }
        let expected = match &self.differential {
            DifferentialDecision::VerifiedDifference { device_stamps, .. }
            | DifferentialDecision::VerifiedUndifferenced { device_stamps, .. } => Some(device_stamps),
            _ => None,
        };
        if expected.is_some_and(|expected| seen != expected.iter().map(|stamp| stamp.resource.clone()).collect()) {
            return Err(Diagnostic::new("the load procedure did not capture the prepared download-stamp set"));
        }
        Ok(())
    }
}

/// Whether a stamp holds a whole, nonzero number of `record`-byte records:
/// an object's PID 27 holds one record per load segment.
pub(crate) fn whole_records(value: &[u8], record: u32) -> bool {
    record != 0 && !value.is_empty() && value.len().is_multiple_of(record as usize)
}
