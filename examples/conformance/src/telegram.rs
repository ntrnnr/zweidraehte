//! Telegram representation and matching for conformance tests

use std::collections::BTreeMap;

use crate::{GroupAddress, IndividualAddress, TestVariable};

// ============================================================================
// Variable Expression Parsing
// ============================================================================

/// Parse a variable expression and return the resulting bytes
///
/// Supported formats:
/// - `#VAR` - simple variable reference
/// - `#VAR.N` - array index (byte at position N)
/// - `#VAR+N` - arithmetic addition (for 16-bit values, adds N to the value)
///
/// Examples:
/// - `#MEMPOS` -> [0x02, 0x00] (for MEMPOS=0x0200)
/// - `#MEMPOS+12` -> [0x02, 0x0C] (0x0200 + 12 = 0x020C)
/// - `#MEM.0` -> [0x01] (first byte of MEM array)
/// - `#MEM.12` -> [0x0D] (13th byte of MEM array)
fn parse_variable_expr(expr: &str, variables: &BTreeMap<String, TestVariable>) -> Result<Vec<u8>, String> {
    // Check for array indexing: #VAR.N
    if let Some(dot_pos) = expr.find('.') {
        let var_name = &expr[..dot_pos];
        let index_str = &expr[dot_pos + 1..];
        let index: usize = index_str.parse().map_err(|_| format!("Invalid array index: {}", index_str))?;

        match variables.get(var_name) {
            Some(var) => {
                let bytes = var.as_bytes();
                if index >= bytes.len() {
                    return Err(format!("Array index {} out of bounds for {} (len={})", index, var_name, bytes.len()));
                }
                Ok(vec![bytes[index]])
            }
            None => Err(format!("Unknown variable: {}", var_name)),
        }
    }
    // Check for arithmetic: #VAR+N or #VAR-N
    else if let Some(plus_pos) = expr.find('+') {
        let var_name = &expr[..plus_pos];
        let offset_str = &expr[plus_pos + 1..];
        let offset: i32 = offset_str.parse().map_err(|_| format!("Invalid offset: {}", offset_str))?;

        match variables.get(var_name) {
            Some(var) => {
                let bytes = var.as_bytes();
                if bytes.len() == 2 {
                    // 16-bit value (big-endian)
                    let value = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
                    let new_value = (value as i32 + offset) as u16;
                    Ok(vec![(new_value >> 8) as u8, (new_value & 0xFF) as u8])
                } else if bytes.len() == 1 {
                    // 8-bit value
                    let value = bytes[0] as i32;
                    let new_value = (value + offset) as u8;
                    Ok(vec![new_value])
                } else {
                    Err(format!("Arithmetic only supported for 1 or 2 byte values, {} has {} bytes", var_name, bytes.len()))
                }
            }
            None => Err(format!("Unknown variable: {}", var_name)),
        }
    } else if let Some(minus_pos) = expr.find('-') {
        let var_name = &expr[..minus_pos];
        let offset_str = &expr[minus_pos + 1..];
        let offset: i32 = offset_str.parse().map_err(|_| format!("Invalid offset: {}", offset_str))?;

        match variables.get(var_name) {
            Some(var) => {
                let bytes = var.as_bytes();
                if bytes.len() == 2 {
                    let value = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
                    let new_value = (value as i32 - offset) as u16;
                    Ok(vec![(new_value >> 8) as u8, (new_value & 0xFF) as u8])
                } else if bytes.len() == 1 {
                    let value = bytes[0] as i32;
                    let new_value = (value - offset) as u8;
                    Ok(vec![new_value])
                } else {
                    Err(format!("Arithmetic only supported for 1 or 2 byte values, {} has {} bytes", var_name, bytes.len()))
                }
            }
            None => Err(format!("Unknown variable: {}", var_name)),
        }
    }
    // Simple variable reference
    else {
        match variables.get(expr) {
            Some(var) => Ok(var.as_bytes()),
            None => Err(format!("Unknown variable: {}", expr)),
        }
    }
}

// ============================================================================
// Telegram
// ============================================================================

/// A KNX telegram for testing
///
/// Can contain both literal bytes and variable references that will be
/// resolved at test runtime.
#[derive(Debug, Clone)]
pub struct Telegram {
    /// Raw bytes with placeholders resolved
    pub data: Vec<u8>,
}

impl Telegram {
    /// Create a new telegram from raw bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        Self { data: data.to_vec() }
    }

    /// Parse a telegram from a hex string with variable references
    ///
    /// Format: "BC #EDI #BDUT 61 43 00"
    /// - Hex bytes are space-separated
    /// - Variables start with #
    /// - Variable expressions: #VAR, #VAR.N (array index), #VAR+N (arithmetic)
    /// - Wildcards are ?? (for matching only)
    pub fn parse(input: &str, variables: &BTreeMap<String, TestVariable>) -> Result<Self, String> {
        let mut data = Vec::new();

        for token in input.split_whitespace() {
            if let Some(expr) = token.strip_prefix('#') {
                // Variable expression
                let bytes = parse_variable_expr(expr, variables)?;
                data.extend(bytes);
            } else if token == "??" {
                // Wildcard - use 0x00 as placeholder (matching handles this)
                data.push(0x00);
            } else {
                // Hex byte
                let byte = u8::from_str_radix(token, 16).map_err(|_| format!("Invalid hex byte: {}", token))?;
                data.push(byte);
            }
        }

        Ok(Self { data })
    }
}

// ============================================================================
// Telegram Matcher
// ============================================================================

/// Matches telegrams with support for wildcards
#[derive(Debug, Clone)]
pub struct TelegramMatcher {
    /// Expected bytes (0x00 with wildcard flag means "any")
    pub expected: Vec<u8>,
    /// Which positions are wildcards (true = any byte accepted)
    pub wildcards: Vec<bool>,
}

impl TelegramMatcher {
    /// Create a matcher from raw bytes (no wildcards)
    pub fn exact(data: &[u8]) -> Self {
        Self { expected: data.to_vec(), wildcards: vec![false; data.len()] }
    }

    /// Parse a matcher from a hex string with variable references and wildcards
    ///
    /// Format: "BC #BDUT #EDI 63 43 40 ?? ??"
    /// - ?? means any byte at that position
    /// - Variable expressions: #VAR, #VAR.N (array index), #VAR+N (arithmetic)
    pub fn parse(input: &str, variables: &BTreeMap<String, TestVariable>) -> Result<Self, String> {
        let mut expected = Vec::new();
        let mut wildcards = Vec::new();

        for token in input.split_whitespace() {
            if let Some(expr) = token.strip_prefix('#') {
                // Variable expression
                let bytes = parse_variable_expr(expr, variables)?;
                expected.extend(&bytes);
                wildcards.extend(vec![false; bytes.len()]);
            } else if token == "??" {
                // Wildcard
                expected.push(0x00);
                wildcards.push(true);
            } else {
                // Hex byte
                let byte = u8::from_str_radix(token, 16).map_err(|_| format!("Invalid hex byte: {}", token))?;
                expected.push(byte);
                wildcards.push(false);
            }
        }

        Ok(Self { expected, wildcards })
    }

    /// Check if an actual telegram matches this pattern
    pub fn matches(&self, actual: &[u8]) -> bool {
        if actual.len() != self.expected.len() {
            return false;
        }

        for (i, (exp, act)) in self.expected.iter().zip(actual.iter()).enumerate() {
            if !self.wildcards[i] && exp != act {
                return false;
            }
        }

        true
    }

    /// Get a diff description between expected and actual
    pub fn diff(&self, actual: &[u8]) -> String {
        use core::fmt::Write;
        let mut result = String::new();

        if actual.len() != self.expected.len() {
            let _ = writeln!(result, "Length mismatch: expected {} bytes, got {}", self.expected.len(), actual.len());
        }

        let _ = write!(result, "Expected: ");
        for (i, b) in self.expected.iter().enumerate() {
            if self.wildcards[i] {
                let _ = write!(result, "?? ");
            } else {
                let _ = write!(result, "{:02X} ", b);
            }
        }
        let _ = writeln!(result);

        let _ = write!(result, "Actual:   ");
        for (i, b) in actual.iter().enumerate() {
            if i < self.wildcards.len() && !self.wildcards[i] && *b != self.expected[i] {
                let _ = write!(result, "[{:02X}] ", b); // Highlight mismatch
            } else {
                let _ = write!(result, "{:02X} ", b);
            }
        }
        let _ = writeln!(result);

        result
    }
}

// ============================================================================
// Telegram Builder (for fluent API)
// ============================================================================

/// Builder for constructing telegrams programmatically
pub struct TelegramBuilder {
    data: Vec<u8>,
}

impl TelegramBuilder {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Add a control byte
    pub fn ctrl(mut self, byte: u8) -> Self {
        self.data.push(byte);
        self
    }

    /// Add source address
    pub fn source(mut self, addr: IndividualAddress) -> Self {
        self.data.extend(addr.as_bytes());
        self
    }

    /// Add destination individual address
    pub fn dest_individual(mut self, addr: IndividualAddress) -> Self {
        self.data.extend(addr.as_bytes());
        self
    }

    /// Add destination group address
    pub fn dest_group(mut self, addr: GroupAddress) -> Self {
        self.data.extend(addr.as_bytes());
        self
    }

    /// Add NPDU byte (address type + hop count + length)
    pub fn npdu(mut self, byte: u8) -> Self {
        self.data.push(byte);
        self
    }

    /// Add raw bytes
    pub fn bytes(mut self, data: &[u8]) -> Self {
        self.data.extend(data);
        self
    }

    /// Build the telegram
    pub fn build(self) -> Telegram {
        Telegram { data: self.data }
    }
}

impl Default for TelegramBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_telegram_parse() {
        let mut vars = BTreeMap::new();
        vars.insert("EDI".into(), TestVariable::IndividualAddr(IndividualAddress::new(10, 15, 254)));
        vars.insert("BDUT".into(), TestVariable::IndividualAddr(IndividualAddress::new(1, 0, 1)));

        let telegram = Telegram::parse("BC #EDI #BDUT 61 43 00", &vars).unwrap();

        assert_eq!(telegram.data, vec![0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x43, 0x00]);
    }

    #[test]
    fn test_matcher_exact() {
        let matcher = TelegramMatcher::exact(&[0xBC, 0x10, 0x01]);

        assert!(matcher.matches(&[0xBC, 0x10, 0x01]));
        assert!(!matcher.matches(&[0xBC, 0x10, 0x02]));
        assert!(!matcher.matches(&[0xBC, 0x10]));
    }

    #[test]
    fn test_matcher_wildcards() {
        let mut vars = BTreeMap::new();
        vars.insert("BDUT".into(), TestVariable::IndividualAddr(IndividualAddress::new(1, 0, 1)));

        let matcher = TelegramMatcher::parse("BC #BDUT 63 43 40 ?? ??", &vars).unwrap();

        assert!(matcher.matches(&[0xBC, 0x10, 0x01, 0x63, 0x43, 0x40, 0x12, 0x34]));
        assert!(matcher.matches(&[0xBC, 0x10, 0x01, 0x63, 0x43, 0x40, 0xFF, 0xFF]));
        assert!(!matcher.matches(&[0xBC, 0x10, 0x01, 0x63, 0x43, 0x41, 0x12, 0x34]));
        // 0x40 vs 0x41
    }

    #[test]
    fn test_array_indexing() {
        let mut vars = BTreeMap::new();
        // MEM = 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D
        vars.insert(
            "MEM".into(),
            TestVariable::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D]),
        );

        let telegram = Telegram::parse("BC #MEM.0 #MEM.1 #MEM.12", &vars).unwrap();
        assert_eq!(telegram.data, vec![0xBC, 0x01, 0x02, 0x0D]);
    }

    #[test]
    fn test_arithmetic_16bit() {
        let mut vars = BTreeMap::new();
        // MEMPOS = 0x0200 (512 in decimal)
        vars.insert("MEMPOS".into(), TestVariable::Bytes(vec![0x02, 0x00]));

        // MEMPOS + 12 = 0x020C
        let telegram = Telegram::parse("BC #MEMPOS #MEMPOS+12", &vars).unwrap();
        assert_eq!(telegram.data, vec![0xBC, 0x02, 0x00, 0x02, 0x0C]);

        // MEMPOS + 24 = 0x0218
        let telegram2 = Telegram::parse("#MEMPOS+24", &vars).unwrap();
        assert_eq!(telegram2.data, vec![0x02, 0x18]);

        // MEMPOS + 255 = 0x02FF
        let telegram3 = Telegram::parse("#MEMPOS+255", &vars).unwrap();
        assert_eq!(telegram3.data, vec![0x02, 0xFF]);
    }

    #[test]
    fn test_arithmetic_subtraction() {
        let mut vars = BTreeMap::new();
        vars.insert("MEMPOS".into(), TestVariable::Bytes(vec![0x02, 0x00]));

        // MEMPOS - 1 = 0x01FF
        let telegram = Telegram::parse("#MEMPOS-1", &vars).unwrap();
        assert_eq!(telegram.data, vec![0x01, 0xFF]);
    }

    #[test]
    fn test_combined_expressions() {
        let mut vars = BTreeMap::new();
        vars.insert("EDI".into(), TestVariable::Bytes(vec![0xAF, 0xFE]));
        vars.insert("BDUT".into(), TestVariable::Bytes(vec![0x10, 0x01]));
        vars.insert("MEMPOS".into(), TestVariable::Bytes(vec![0x02, 0x00]));
        vars.insert(
            "MEM".into(),
            TestVariable::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]),
        );

        // Example from test 2.6.1: "BC #EDI #BDUT 6F 42 8C #MEMPOS #MEM.0 #MEM.1 #MEM.2"
        let telegram = Telegram::parse("BC #EDI #BDUT 6F 42 8C #MEMPOS #MEM.0 #MEM.1 #MEM.2", &vars).unwrap();
        assert_eq!(
            telegram.data,
            vec![0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x6F, 0x42, 0x8C, 0x02, 0x00, 0x01, 0x02, 0x03]
        );

        // Example with offset: "#MEMPOS+12"
        let telegram2 = Telegram::parse("BC #EDI #BDUT 6F 46 8C #MEMPOS+12 #MEM.0", &vars).unwrap();
        assert_eq!(telegram2.data, vec![0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x6F, 0x46, 0x8C, 0x02, 0x0C, 0x01]);
    }
}
