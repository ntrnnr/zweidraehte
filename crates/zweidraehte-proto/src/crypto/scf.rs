//! Security Control Field (SCF) parsing and construction.
//!
//! The SCF is a single byte in the Secure ASDU that encodes the security
//! algorithm, tool access flag, system broadcast flag, and service type.
//!
//! ```text
//! Bit 7: Tool Access (T flag)
//! Bit 6: reserved (must be 0)
//! Bit 5: Confidentiality (1 = Auth+Conf, 0 = Auth only)
//! Bit 4: SAI algorithm (0 = CCM, 1 = reserved)
//!        Combined with bit 5: SAI field = bits 5:4
//! Bit 3: System Broadcast (SBC flag)
//! Bit 2: reserved (must be 0)
//! Bits 1:0: Service type (00 = Data, 10 = SyncReq, 11 = SyncRes)
//! ```

/// Parsed Security Control Field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecurityControlField {
    /// Service type (Data, SyncRequest, SyncResponse).
    pub service: SecureServiceType,
    /// System broadcast flag (SBC).
    pub system_broadcast: bool,
    /// Confidentiality flag: true = Authentication + Confidentiality,
    /// false = Authentication only.
    pub confidentiality: bool,
    /// Tool access flag (T): true = message uses the Tool Key.
    pub tool_access: bool,
}

/// Secure Application Layer service type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecureServiceType {
    /// S-A_Data: normal secure data transfer.
    Data,
    /// S-A_Sync_Req: sequence number synchronization request.
    SyncRequest,
    /// S-A_Sync_Res: sequence number synchronization response.
    SyncResponse,
}

/// Error when parsing an invalid SCF byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InvalidScf;

impl SecurityControlField {
    /// Parse an SCF byte. Returns `Err` if reserved bits are set or
    /// the SAI/service type combination is invalid.
    pub fn parse(byte: u8) -> Result<Self, InvalidScf> {
        // Reserved bits: bit 6 and bit 2 must be 0.
        if byte & 0x44 != 0 {
            return Err(InvalidScf);
        }

        // SAI field (bits 5:4):
        //   00 = CCM, authentication only
        //   01 = CCM, authentication + confidentiality
        //   10, 11 = reserved
        let sai = (byte >> 4) & 0x03;
        let confidentiality = match sai {
            0b00 => false,               // Auth only
            0b01 => true,                // Auth + Conf
            _ => return Err(InvalidScf), // Reserved SAI
        };

        let service = match byte & 0x03 {
            0b00 => SecureServiceType::Data,
            0b10 => SecureServiceType::SyncRequest,
            0b11 => SecureServiceType::SyncResponse,
            _ => return Err(InvalidScf), // 0b01 is reserved
        };

        Ok(Self { service, system_broadcast: byte & 0x08 != 0, confidentiality, tool_access: byte & 0x80 != 0 })
    }

    /// Encode to a single SCF byte.
    pub fn encode(&self) -> u8 {
        let mut byte = 0u8;
        if self.tool_access {
            byte |= 0x80;
        }
        // SAI field: 01 for auth+conf, 00 for auth-only
        if self.confidentiality {
            byte |= 0x10; // SAI = 01 (bit 4 set)
        }
        if self.system_broadcast {
            byte |= 0x08;
        }
        byte |= match self.service {
            SecureServiceType::Data => 0b00,
            SecureServiceType::SyncRequest => 0b10,
            SecureServiceType::SyncResponse => 0b11,
        };
        byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_data_auth_only() {
        // SCF = 0x00: Data, no tool, no SBC, auth only
        let scf = SecurityControlField::parse(0x00).unwrap();
        assert_eq!(scf.service, SecureServiceType::Data);
        assert!(!scf.tool_access);
        assert!(!scf.system_broadcast);
        assert!(!scf.confidentiality);
    }

    #[test]
    fn parse_tool_auth_conf() {
        // SCF = 0x90: tool access + auth+conf + data
        let scf = SecurityControlField::parse(0x90).unwrap();
        assert_eq!(scf.service, SecureServiceType::Data);
        assert!(scf.tool_access);
        assert!(scf.confidentiality);
        assert!(!scf.system_broadcast);
    }

    #[test]
    fn parse_sync_req_with_sbc() {
        // SCF = 0x9A: tool(1) + SAI=01(A+C) + SBC(1) + sync_req(10)
        // = 1_0_01_1_0_10 = 0x9A
        let scf = SecurityControlField::parse(0x9A).unwrap();
        assert_eq!(scf.service, SecureServiceType::SyncRequest);
        assert!(scf.tool_access);
        assert!(scf.confidentiality);
        assert!(scf.system_broadcast);
    }

    #[test]
    fn parse_spec_example_0x90() {
        // From Annex C.1.1: SCF = 90h
        let scf = SecurityControlField::parse(0x90).unwrap();
        assert!(scf.tool_access);
        assert!(scf.confidentiality);
        assert_eq!(scf.service, SecureServiceType::Data);
    }

    #[test]
    fn parse_spec_example_0x92() {
        // From Annex C.1.3: SCF = 92h (sync req)
        let scf = SecurityControlField::parse(0x92).unwrap();
        assert!(scf.tool_access);
        assert!(scf.confidentiality);
        assert_eq!(scf.service, SecureServiceType::SyncRequest);
    }

    #[test]
    fn reserved_bit_rejected() {
        // Bit 6 set — reserved
        assert!(SecurityControlField::parse(0x40).is_err());
        // Bit 2 set — reserved
        assert!(SecurityControlField::parse(0x04).is_err());
    }

    #[test]
    fn round_trip() {
        // Valid SCF values: SAI=00 (auth only) or SAI=01 (A+C).
        // service: 00=Data, 10=SyncReq, 11=SyncRes
        for byte in [0x00u8, 0x08, 0x10, 0x80, 0x90, 0x92, 0x93, 0x13, 0x18, 0x98, 0x9B] {
            if let Ok(scf) = SecurityControlField::parse(byte) {
                assert_eq!(scf.encode(), byte, "round-trip failed for 0x{:02X}", byte);
            }
        }
    }
}
