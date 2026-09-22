//! Checked property identities and ranges shared by concrete service handles.

use super::{Error, Result};
use zweidraehte_proto::messages::apdu::property::PropertyValueHeader;
use zweidraehte_proto::messages::apdu::property_ext::{PropertyExtValueHeader, PropertyReturnCode};

pub(in crate::bus) struct ClassicProperty {
    object: u8,
    property: u16,
    start: u16,
    count: u16,
}

impl ClassicProperty {
    pub(in crate::bus) fn new(object: u8, property: u16, start: u16, count: u16) -> Result<Self> {
        validate_property_id(property)?;
        validate_property_range(start, count, 0xfff, 15)?;
        Ok(Self { object, property, start, count })
    }

    pub(in crate::bus) fn validate_write(&self, data: &[u8]) -> Result<()> {
        validate_property_data(self.count, data)
    }

    pub(in crate::bus) fn response<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8]> {
        let header = PropertyValueHeader::parse(buf).ok_or(Error::Parse("PropertyValueResponse too short"))?;
        if (header.object_idx, header.prop_id, header.start_idx) != (u16::from(self.object), self.property, self.start)
        {
            return Err(Error::UnexpectedResponse);
        }
        if header.count == 0 {
            return Err(Error::PropertyValueUnavailable { object_index: self.object, property_id: self.property });
        }
        property_elements(header.count, self.count, header.data(buf))
    }
}

pub(in crate::bus) struct ExtendedProperty {
    object_type: u16,
    instance: u16,
    property: u16,
    start: u16,
    count: u8,
}

impl ExtendedProperty {
    pub(in crate::bus) fn new(object_type: u16, instance: u16, property: u16, start: u16, count: u16) -> Result<Self> {
        validate_extended_target(instance, property)?;
        validate_property_range(start, count, u16::MAX, 255)?;
        Ok(Self { object_type, instance, property, start, count: count as u8 })
    }

    pub(in crate::bus) fn count(&self) -> u8 {
        self.count
    }

    pub(in crate::bus) fn validate_write(&self, data: &[u8]) -> Result<()> {
        validate_property_data(u16::from(self.count), data)
    }

    fn header(&self, buf: &[u8]) -> Result<PropertyExtValueHeader> {
        let header = PropertyExtValueHeader::parse(buf).ok_or(Error::Parse("extended property response too short"))?;
        if (header.object_type, header.object_instance, header.prop_id, header.start_idx)
            != (self.object_type, self.instance, self.property, self.start)
        {
            return Err(Error::UnexpectedResponse);
        }
        Ok(header)
    }

    pub(in crate::bus) fn read_response<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8]> {
        let header = self.header(buf)?;
        if header.count == 0 {
            let code = header.data(buf).first().copied().unwrap_or(u8::from(PropertyReturnCode::Error));
            return Err(Error::DeviceError(code));
        }
        property_elements(u16::from(header.count), u16::from(self.count), header.data(buf))
    }

    pub(in crate::bus) fn write_response(&self, buf: &[u8]) -> Result<()> {
        let header = self.header(buf)?;
        let code =
            header.data(buf).first().copied().ok_or(Error::Parse("extended property confirmation has no code"))?;
        if code != u8::from(PropertyReturnCode::Success) {
            return Err(Error::DeviceError(code));
        }
        if header.count != self.count || header.data(buf).len() != 1 {
            return Err(Error::UnexpectedResponse);
        }
        Ok(())
    }
}

fn property_elements(actual: u16, expected: u16, data: &[u8]) -> Result<&[u8]> {
    if actual != expected || data.is_empty() || data.len() % usize::from(actual) != 0 {
        return Err(Error::UnexpectedResponse);
    }
    Ok(data)
}

pub(in crate::bus) fn validate_property_id(property: u16) -> Result<()> {
    if property > u16::from(u8::MAX) {
        return Err(Error::Parse("classic property identifier exceeds one octet"));
    }
    Ok(())
}

pub(in crate::bus) fn validate_extended_target(instance: u16, property: u16) -> Result<()> {
    if !(1..=0xfff).contains(&instance) || property > 0xfff {
        return Err(Error::Parse("extended property instance or identifier exceeds its wire range"));
    }
    Ok(())
}

fn validate_property_range(start: u16, count: u16, max_start: u16, max_count: u16) -> Result<()> {
    if count > max_count
        || start > max_start
        || u32::from(start) + u32::from(count.saturating_sub(1)) > u32::from(max_start)
    {
        return Err(Error::Parse("property range exceeds its wire fields"));
    }
    Ok(())
}

fn validate_property_data(count: u16, data: &[u8]) -> Result<()> {
    if count == 0 || data.is_empty() || data.len() % usize::from(count) != 0 {
        return Err(Error::Parse("property write must contain complete nonempty elements"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_proto::messages::apdu::property_ext::{PropertyExtValueResponse, PropertyExtValueWriteConRes};

    #[test]
    fn extended_values_and_confirmations_require_exact_identity_and_shape() {
        let property = ExtendedProperty::new(11, 4095, 4095, 65534, 2).expect("boundary range");
        let mut valid = vec![0; PropertyExtValueResponse::msg_len(4)];
        PropertyExtValueResponse::write(&mut valid, 11, 4095, 4095, 2, 65534, &[1, 2, 3, 4]);
        assert_eq!(property.read_response(&valid).expect("two complete elements"), [1, 2, 3, 4]);
        assert!(property.read_response(&valid[..valid.len() - 1]).is_err());
        for (object, instance, pid, start, count) in [
            (12, 4095, 4095, 65534, 2),
            (11, 4094, 4095, 65534, 2),
            (11, 4095, 4094, 65534, 2),
            (11, 4095, 4095, 65533, 2),
            (11, 4095, 4095, 65534, 1),
        ] {
            let mut reply = valid.clone();
            PropertyExtValueResponse::write(&mut reply, object, instance, pid, count, start, &[1, 2, 3, 4]);
            assert!(matches!(property.read_response(&reply), Err(Error::UnexpectedResponse)));
            reply.resize(PropertyExtValueWriteConRes::MSG_LEN, 0);
            PropertyExtValueWriteConRes::write_success(
                &mut reply,
                object,
                instance,
                pid,
                count,
                start,
                PropertyReturnCode::Success,
            );
            assert!(matches!(property.write_response(&reply), Err(Error::UnexpectedResponse)));
        }
        let mut reply = vec![0; PropertyExtValueWriteConRes::MSG_LEN];
        PropertyExtValueWriteConRes::write_success(&mut reply, 11, 4095, 4095, 2, 65534, PropertyReturnCode::Success);
        property.write_response(&reply).expect("complete confirmation");
        reply.push(0);
        assert!(property.write_response(&reply).is_err());
        reply.truncate(PropertyExtValueWriteConRes::MSG_LEN - 1);
        assert!(property.write_response(&reply).is_err());
    }
}
