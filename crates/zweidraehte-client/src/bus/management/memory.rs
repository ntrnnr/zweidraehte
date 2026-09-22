//! One checked range and response contract per memory service family.

use super::{Error, Result};
use zweidraehte_proto::messages::apdu::coupler::{FilterTableResponse, MAX_COUPLER_MEMORY_COUNT, RouterMemoryResponse};
use zweidraehte_proto::messages::apdu::memory::{MemoryExtendedResponse, MemoryResponse, UserMemoryResponse};
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;

#[derive(Clone, Copy)]
pub(in crate::bus) enum MemoryFamily {
    Classic,
    User,
    Filter,
    Router,
    Extended,
}

pub(in crate::bus) struct MemoryTransfer {
    family: MemoryFamily,
    address: u32,
    count: usize,
}

struct MemoryReply<'a> {
    address: u32,
    count: usize,
    data: &'a [u8],
    complete: bool,
}

impl MemoryTransfer {
    pub(in crate::bus) fn new(family: MemoryFamily, address: u32, count: usize) -> Result<Self> {
        let (maximum_address, maximum_count, allow_empty) = match family {
            MemoryFamily::Classic => (0xffff, 63, true),
            MemoryFamily::User => (0xfffff, 15, false),
            MemoryFamily::Filter | MemoryFamily::Router => (0xffff, MAX_COUPLER_MEMORY_COUNT, false),
            MemoryFamily::Extended => (0xffffff, 255, true),
        };
        // Zero is representable for classic/extended memory; a zero-length
        // response to a zero-length read is distinct from a refused real read.
        if count > maximum_count
            || (!allow_empty && count == 0)
            || address > maximum_address
            || address.checked_add(count.saturating_sub(1) as u32).is_none_or(|end| end > maximum_address)
        {
            return Err(Error::Parse("memory range exceeds its wire fields"));
        }
        Ok(Self { family, address, count })
    }

    fn parse<'a>(&self, buf: &'a [u8]) -> Result<MemoryReply<'a>> {
        Ok(match self.family {
            MemoryFamily::Classic => {
                let reply = MemoryResponse::parse(buf).ok_or(Error::Parse("MemoryResponse too short"))?;
                MemoryReply {
                    address: u32::from(reply.address),
                    count: usize::from(reply.count),
                    data: reply.data,
                    complete: reply.is_length_consistent(buf.len()),
                }
            }
            MemoryFamily::User => {
                let reply = UserMemoryResponse::parse(buf).ok_or(Error::Parse("UserMemoryResponse too short"))?;
                MemoryReply {
                    address: reply.full_address(),
                    count: usize::from(reply.count),
                    data: reply.data,
                    complete: reply.is_length_consistent(buf.len()),
                }
            }
            MemoryFamily::Filter | MemoryFamily::Router => {
                let reply = match self.family {
                    MemoryFamily::Filter => FilterTableResponse::parse(buf),
                    _ => RouterMemoryResponse::parse(buf),
                }
                .ok_or(Error::Parse("coupler memory response too short"))?;
                MemoryReply {
                    address: u32::from(reply.address),
                    count: usize::from(reply.count),
                    data: reply.data,
                    complete: reply.is_length_consistent(buf.len()),
                }
            }
            MemoryFamily::Extended => {
                let reply =
                    MemoryExtendedResponse::parse(buf).ok_or(Error::Parse("extended memory response too short"))?;
                if reply.address != self.address {
                    return Err(Error::UnexpectedResponse);
                }
                if reply.return_code != PropertyReturnCode::Success {
                    return Err(Error::DeviceError(reply.return_code.into()));
                }
                MemoryReply { address: reply.address, count: reply.data.len(), data: reply.data, complete: true }
            }
        })
    }

    pub(in crate::bus) fn read_response<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8]> {
        let reply = self.parse(buf)?;
        if reply.address != self.address {
            return Err(Error::UnexpectedResponse);
        }
        if reply.count == 0 && self.count != 0 && !matches!(self.family, MemoryFamily::Extended) {
            return Err(Error::DeviceError(0));
        }
        if reply.count != self.count || !reply.complete {
            return Err(Error::UnexpectedResponse);
        }
        Ok(reply.data)
    }

    pub(in crate::bus) fn verify_response(&self, buf: &[u8], expected: &[u8]) -> Result<()> {
        let reply = self.parse(buf)?;
        // Keep classic auto-verify's mismatch result for refused writes; the
        // other legacy families have always exposed their zero-count refusal.
        if reply.count == 0 && !matches!(self.family, MemoryFamily::Classic) {
            return Err(Error::DeviceError(0));
        }
        if reply.address != self.address || reply.count != self.count || !reply.complete || reply.data != expected {
            return Err(Error::VerifyMismatch { address: self.address });
        }
        Ok(())
    }

    pub(in crate::bus) fn extended_write_response(&self, buf: &[u8]) -> Result<()> {
        let reply = self.parse(buf)?;
        if !reply.data.is_empty() {
            return Err(Error::UnexpectedResponse);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(family: MemoryFamily, address: u32, count: u8, data: &[u8]) -> Vec<u8> {
        let length = match family {
            MemoryFamily::Classic => MemoryResponse::msg_len(data.len()),
            MemoryFamily::Filter => FilterTableResponse::msg_len(data.len()),
            MemoryFamily::Router => RouterMemoryResponse::msg_len(data.len()),
            MemoryFamily::User => UserMemoryResponse::msg_len(data.len()),
            MemoryFamily::Extended => MemoryExtendedResponse::msg_len(data.len()),
        };
        let mut buf = vec![0; length];
        match family {
            MemoryFamily::Classic => MemoryResponse::write(&mut buf, count, address as u16, data),
            MemoryFamily::User => {
                UserMemoryResponse::write(&mut buf, (address >> 16) as u8, count, address as u16, data)
            }
            MemoryFamily::Filter => FilterTableResponse::write(&mut buf, address as u16, data),
            MemoryFamily::Router => RouterMemoryResponse::write(&mut buf, address as u16, data),
            MemoryFamily::Extended => {
                MemoryExtendedResponse::write(&mut buf, PropertyReturnCode::Success, address, data)
            }
        }
        buf
    }

    #[test]
    fn memory_families_check_boundaries_identity_and_lengths() {
        for (family, limit, count) in [
            (MemoryFamily::Classic, 0xffff, 63),
            (MemoryFamily::User, 0xfffff, 15),
            (MemoryFamily::Filter, 0xffff, 254),
            (MemoryFamily::Router, 0xffff, 254),
            (MemoryFamily::Extended, 0xffffff, 255),
        ] {
            assert!(MemoryTransfer::new(family, limit + 1, 1).is_err());
            assert!(MemoryTransfer::new(family, limit, 2).is_err());
            assert!(MemoryTransfer::new(family, 0, count + 1).is_err());
            let address = limit - count as u32 + 1;
            let transfer = MemoryTransfer::new(family, address, count).expect("complete boundary range");
            let data = vec![0x51; count];
            let valid = response(family, address, count as u8, &data);
            assert_eq!(transfer.read_response(&valid).expect("complete reply"), data);
            let wrong_address = response(family, address - 1, count as u8, &data);
            assert!(transfer.read_response(&wrong_address).is_err());
            assert!(transfer.read_response(&valid[..valid.len() - 1]).is_err());
            let mut trailing = valid.clone();
            trailing.push(0);
            assert!(transfer.read_response(&trailing).is_err());
            if !matches!(family, MemoryFamily::Extended) {
                assert!(transfer.verify_response(&wrong_address, &data).is_err());
                transfer.verify_response(&valid, &data).expect("auto-verify matches");
            }
        }
    }

    #[test]
    fn memory_zero_count_semantics_remain_family_specific() {
        for family in [MemoryFamily::Classic, MemoryFamily::Extended] {
            let empty = MemoryTransfer::new(family, 0xffff, 0).expect("zero-length service request");
            assert!(empty.read_response(&response(family, 0xffff, 0, &[])).expect("empty success").is_empty());
        }
        for family in [MemoryFamily::User, MemoryFamily::Filter, MemoryFamily::Router] {
            assert!(MemoryTransfer::new(family, 0, 0).is_err());
        }
        for family in [MemoryFamily::Classic, MemoryFamily::User, MemoryFamily::Filter, MemoryFamily::Router] {
            let read = MemoryTransfer::new(family, 0, 1).expect("one-byte request");
            assert!(matches!(read.read_response(&response(family, 0, 0, &[])), Err(Error::DeviceError(0))));
        }
    }
}
