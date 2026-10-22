//! Bounded diagnostic reads over the existing single-request services.

use super::{BusError, BusResult, DeviceConnection, MemorySpace, PropertyAddress};
use zweidraehte_proto::{config::MAX_APDU_LENGTH_TP1_STANDARD as STANDARD_APDU_LENGTH, messages::apdu::secure, pid};

/// Commissioning and diagnostics must reserve the same space for the service
/// header and authenticated envelope, using the smaller negotiated APDU.
pub(crate) fn payload_budget(interface: u16, target: u16, secure: bool, header: u16) -> BusResult<usize> {
    let envelope = if secure { secure::OVERHEAD as u16 } else { 0 };
    interface
        .min(target)
        .checked_sub(envelope + header)
        .map(usize::from)
        .ok_or(BusError::Parse("negotiated APDU cannot carry the service header"))
}

impl DeviceConnection {
    /// Probe PID_MAX_APDU_LENGTH, retaining standard-frame capacity when the
    /// property is absent or invalid. A failed probe does not imply support for
    /// the interface's larger frames.
    pub async fn read_max_apdu(&mut self, interface_max: u16) -> u16 {
        if interface_max <= STANDARD_APDU_LENGTH
            || !payload_budget(interface_max, interface_max, self.is_secure_management(), 5)
                .is_ok_and(|bytes| bytes >= 2)
        {
            return STANDARD_APDU_LENGTH;
        }
        let max_apdu = PropertyAddress::indexed(0, pid::device::MAX_APDU_LENGTH).expect("PID fits one octet");
        match self.property_read(max_apdu, 1, 1).await {
            Ok(bytes) if bytes.len() == 2 => {
                let length = u16::from_be_bytes([bytes[0], bytes[1]]);
                if (STANDARD_APDU_LENGTH..=254).contains(&length) { length } else { STANDARD_APDU_LENGTH }
            }
            _ => STANDARD_APDU_LENGTH,
        }
    }

    /// Read an entire classic memory range, splitting it according to both
    /// peers' APDU limits and this connection's actual management protection.
    /// The full range is validated before the first request is sent.
    pub async fn read_memory_range(
        &mut self,
        address: u16,
        length: usize,
        interface_max: u16,
        target_max: u16,
    ) -> BusResult<Vec<u8>> {
        if usize::from(address).checked_add(length).is_none_or(|end| end > 0x1_0000) {
            return Err(BusError::Parse("classic memory range exceeds 16 bits"));
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let chunk = payload_budget(interface_max, target_max, self.is_secure_management(), 3)?.min(63);
        if chunk == 0 {
            return Err(BusError::Parse("negotiated APDU cannot carry memory data"));
        }
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let at = (usize::from(address) + bytes.len()) as u16;
            let count = chunk.min(length - bytes.len()) as u8;
            bytes.extend(self.memory_read(MemorySpace::Standard, u32::from(at), count).await?);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
