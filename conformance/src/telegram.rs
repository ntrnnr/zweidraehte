//! Telegram representation and matching for conformance tests

use std::collections::BTreeMap;

use crate::{GroupAddress, IndividualAddress, TestVariable};

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
    /// - Wildcards are ?? (for matching only)
    pub fn parse(input: &str, variables: &BTreeMap<String, TestVariable>) -> Result<Self, String> {
        let mut data = Vec::new();

        for token in input.split_whitespace() {
            if token.starts_with('#') {
                // Variable reference
                let var_name = &token[1..];
                match variables.get(var_name) {
                    Some(var) => data.extend(var.as_bytes()),
                    None => return Err(format!("Unknown variable: {}", var_name)),
                }
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
    pub fn parse(input: &str, variables: &BTreeMap<String, TestVariable>) -> Result<Self, String> {
        let mut expected = Vec::new();
        let mut wildcards = Vec::new();

        for token in input.split_whitespace() {
            if token.starts_with('#') {
                // Variable reference
                let var_name = &token[1..];
                match variables.get(var_name) {
                    Some(var) => {
                        let bytes = var.as_bytes();
                        expected.extend(&bytes);
                        wildcards.extend(vec![false; bytes.len()]);
                    }
                    None => return Err(format!("Unknown variable: {}", var_name)),
                }
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
            let _ = write!(result, "Length mismatch: expected {} bytes, got {}\n", self.expected.len(), actual.len());
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
}
