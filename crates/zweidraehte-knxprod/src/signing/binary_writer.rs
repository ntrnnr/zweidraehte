//! .NET BinaryWriter compatible serialization.
//!
//! This module provides functions to serialize data in the same format as
//! .NET's BinaryWriter class, which is used by ETS for computing hashes.

use std::io::{self, Write};

/// Write an integer as a 7-bit encoded variable length integer.
///
/// This matches .NET BinaryWriter.Write7BitEncodedInt().
/// Values are written in 7-bit chunks with the high bit indicating continuation.
pub fn write_7bit_encoded_int<W: Write>(writer: &mut W, mut value: u32) -> io::Result<()> {
    while value >= 0x80 {
        writer.write_all(&[(value as u8 & 0x7F) | 0x80])?;
        value >>= 7;
    }
    writer.write_all(&[value as u8])?;
    Ok(())
}

/// Write a string exactly as .NET BinaryWriter.Write(string) does.
///
/// The format is:
/// - Length as 7-bit encoded int (byte count, not char count)
/// - UTF-8 encoded string bytes
///
/// If the string is None, writes the special marker "$<null>$".
pub fn write_dotnet_string<W: Write>(writer: &mut W, s: Option<&str>) -> io::Result<()> {
    let s = s.unwrap_or("$<null>$");
    let bytes = s.as_bytes();
    write_7bit_encoded_int(writer, bytes.len() as u32)?;
    writer.write_all(bytes)?;
    Ok(())
}

/// Write a bool as .NET BinaryWriter.Write(bool) - single byte.
pub fn write_dotnet_bool<W: Write>(writer: &mut W, value: bool) -> io::Result<()> {
    writer.write_all(&[if value { 0x01 } else { 0x00 }])
}

/// Parse a string as a bool value.
///
/// Accepts "true", "1" (case insensitive) as true, everything else as false.
pub fn parse_bool(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "true" | "1")
}

/// Write uint32 as .NET BinaryWriter.Write(uint) - 4 bytes little-endian.
pub fn write_dotnet_uint32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

/// Write uint32 from string value.
pub fn write_dotnet_uint32_str<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    let v: u32 = value.parse().unwrap_or(0);
    write_dotnet_uint32(writer, v)
}

/// Write int32 as .NET BinaryWriter.Write(int) - 4 bytes little-endian, signed.
pub fn write_dotnet_int32<W: Write>(writer: &mut W, value: i32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

/// Write int32 from string value.
pub fn write_dotnet_int32_str<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    let v: i32 = value.parse().unwrap_or(0);
    write_dotnet_int32(writer, v)
}

/// Write uint16 as .NET BinaryWriter.Write(ushort) - 2 bytes little-endian.
pub fn write_dotnet_uint16<W: Write>(writer: &mut W, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

/// Write uint16 from string value.
pub fn write_dotnet_uint16_str<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    let v: u16 = value.parse().unwrap_or(0);
    write_dotnet_uint16(writer, v)
}

/// Write byte as .NET BinaryWriter.Write(byte) - 1 byte.
pub fn write_dotnet_byte<W: Write>(writer: &mut W, value: u8) -> io::Result<()> {
    writer.write_all(&[value])
}

/// Write byte from string value.
pub fn write_dotnet_byte_str<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    let v: u8 = value.parse().unwrap_or(0);
    write_dotnet_byte(writer, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_7bit_encoded_int_small() {
        let mut buf = Vec::new();
        write_7bit_encoded_int(&mut buf, 0).unwrap();
        assert_eq!(buf, vec![0x00]);

        let mut buf = Vec::new();
        write_7bit_encoded_int(&mut buf, 127).unwrap();
        assert_eq!(buf, vec![0x7F]);
    }

    #[test]
    fn test_7bit_encoded_int_medium() {
        let mut buf = Vec::new();
        write_7bit_encoded_int(&mut buf, 128).unwrap();
        assert_eq!(buf, vec![0x80, 0x01]);

        let mut buf = Vec::new();
        write_7bit_encoded_int(&mut buf, 255).unwrap();
        assert_eq!(buf, vec![0xFF, 0x01]);
    }

    #[test]
    fn test_7bit_encoded_int_large() {
        let mut buf = Vec::new();
        write_7bit_encoded_int(&mut buf, 16384).unwrap();
        assert_eq!(buf, vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn test_dotnet_string() {
        let mut buf = Vec::new();
        write_dotnet_string(&mut buf, Some("test")).unwrap();
        assert_eq!(buf, vec![0x04, b't', b'e', b's', b't']);
    }

    #[test]
    fn test_dotnet_string_null() {
        let mut buf = Vec::new();
        write_dotnet_string(&mut buf, None).unwrap();
        // "$<null>$" has 8 bytes
        assert_eq!(buf[0], 8);
        assert_eq!(&buf[1..], b"$<null>$");
    }

    #[test]
    fn test_dotnet_bool() {
        let mut buf = Vec::new();
        write_dotnet_bool(&mut buf, true).unwrap();
        assert_eq!(buf, vec![0x01]);

        let mut buf = Vec::new();
        write_dotnet_bool(&mut buf, false).unwrap();
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn test_dotnet_uint32() {
        let mut buf = Vec::new();
        write_dotnet_uint32(&mut buf, 0x12345678).unwrap();
        assert_eq!(buf, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_dotnet_int32() {
        let mut buf = Vec::new();
        write_dotnet_int32(&mut buf, -1).unwrap();
        assert_eq!(buf, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_dotnet_uint16() {
        let mut buf = Vec::new();
        write_dotnet_uint16(&mut buf, 0x1234).unwrap();
        assert_eq!(buf, vec![0x34, 0x12]);
    }

    #[test]
    fn test_dotnet_byte() {
        let mut buf = Vec::new();
        write_dotnet_byte(&mut buf, 0x42).unwrap();
        assert_eq!(buf, vec![0x42]);
    }

    #[test]
    fn test_parse_bool() {
        assert!(parse_bool("true"));
        assert!(parse_bool("True"));
        assert!(parse_bool("TRUE"));
        assert!(parse_bool("1"));
        assert!(!parse_bool("false"));
        assert!(!parse_bool("0"));
        assert!(!parse_bool(""));
        assert!(!parse_bool("anything"));
    }
}
