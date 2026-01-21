//! Memory layout comparison.
//!
//! This module compares memory layouts between two programs to verify that
//! the same parameter configuration produces identical bytes.

use std::collections::HashMap;
use std::fmt;

use super::canonical::{CanonicalProgram, ParameterKey};

// ============================================================================
// Test Configuration
// ============================================================================

/// A test configuration specifying parameter values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestConfig {
    /// Parameter values by key.
    pub values: HashMap<ParameterKey, i64>,
}

impl TestConfig {
    /// Create a new empty test configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a parameter value.
    pub fn with_value(mut self, key: ParameterKey, value: i64) -> Self {
        self.values.insert(key, value);
        self
    }

    /// Get a parameter value.
    pub fn get(&self, key: &ParameterKey) -> Option<i64> {
        self.values.get(key).copied()
    }
}

// ============================================================================
// Memory Image
// ============================================================================

/// A memory image representing parameter values in device memory.
#[derive(Debug, Clone)]
pub struct MemoryImage {
    /// Raw bytes, indexed by offset.
    pub bytes: Vec<u8>,
    /// Base offset (for relative segments).
    pub base_offset: u32,
}

impl MemoryImage {
    /// Create a new memory image with the given size.
    pub fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            base_offset: 0,
        }
    }

    /// Create a new memory image with the given size and base offset.
    pub fn with_base(size: usize, base_offset: u32) -> Self {
        Self {
            bytes: vec![0; size],
            base_offset,
        }
    }

    /// Write a value at the given offset and bit position.
    pub fn write_bits(&mut self, offset: u32, bit_offset: u8, size_bits: u32, value: u64) {
        let local_offset = (offset - self.base_offset) as usize;

        if size_bits <= 8 && bit_offset + size_bits as u8 <= 8 {
            // Single byte, possibly with bit offset
            let byte_idx = local_offset;
            if byte_idx < self.bytes.len() {
                let mask = ((1u64 << size_bits) - 1) as u8;
                let shifted_mask = mask << bit_offset;
                let shifted_value = ((value as u8) & mask) << bit_offset;
                self.bytes[byte_idx] = (self.bytes[byte_idx] & !shifted_mask) | shifted_value;
            }
        } else {
            // Multi-byte value (assume bit_offset is 0 for simplicity)
            let num_bytes = ((size_bits + 7) / 8) as usize;
            for i in 0..num_bytes {
                let byte_idx = local_offset + i;
                if byte_idx < self.bytes.len() {
                    self.bytes[byte_idx] = ((value >> (i * 8)) & 0xFF) as u8;
                }
            }
        }
    }

    /// Read a value from the given offset and bit position.
    pub fn read_bits(&self, offset: u32, bit_offset: u8, size_bits: u32) -> u64 {
        let local_offset = (offset - self.base_offset) as usize;

        if size_bits <= 8 && bit_offset + size_bits as u8 <= 8 {
            // Single byte, possibly with bit offset
            let byte_idx = local_offset;
            if byte_idx < self.bytes.len() {
                let mask = ((1u64 << size_bits) - 1) as u8;
                ((self.bytes[byte_idx] >> bit_offset) & mask) as u64
            } else {
                0
            }
        } else {
            // Multi-byte value
            let num_bytes = ((size_bits + 7) / 8) as usize;
            let mut value: u64 = 0;
            for i in 0..num_bytes {
                let byte_idx = local_offset + i;
                if byte_idx < self.bytes.len() {
                    value |= (self.bytes[byte_idx] as u64) << (i * 8);
                }
            }
            value
        }
    }
}

// ============================================================================
// Memory Difference
// ============================================================================

/// A difference in memory layout.
#[derive(Debug, Clone)]
pub struct MemoryDiff {
    /// The test configuration that produced the difference.
    pub config: TestConfig,
    /// Byte-level differences.
    pub byte_diffs: Vec<ByteDiff>,
}

/// A single byte difference.
#[derive(Debug, Clone)]
pub struct ByteDiff {
    /// Offset where the difference occurs.
    pub offset: u32,
    /// Expected byte value (from reference).
    pub expected: u8,
    /// Actual byte value (from generated).
    pub actual: u8,
}

impl fmt::Display for MemoryDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Memory differs for config {:?}: ", self.config.values)?;
        write!(f, "{} byte(s) differ", self.byte_diffs.len())?;
        if !self.byte_diffs.is_empty() {
            write!(f, " [")?;
            for (i, diff) in self.byte_diffs.iter().take(5).enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(
                    f,
                    "@0x{:X}: 0x{:02X}!=0x{:02X}",
                    diff.offset, diff.expected, diff.actual
                )?;
            }
            if self.byte_diffs.len() > 5 {
                write!(f, ", ...")?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

// ============================================================================
// Memory Comparator
// ============================================================================

/// Compares memory layouts between two programs.
pub struct MemoryComparator<'a> {
    reference: &'a CanonicalProgram,
    generated: &'a CanonicalProgram,
}

impl<'a> MemoryComparator<'a> {
    /// Create a new memory comparator.
    pub fn new(reference: &'a CanonicalProgram, generated: &'a CanonicalProgram) -> Self {
        Self {
            reference,
            generated,
        }
    }

    /// Generate a memory image for the given configuration using a program's parameters.
    pub fn generate_memory(
        program: &CanonicalProgram,
        config: &TestConfig,
        memory_size: usize,
    ) -> MemoryImage {
        let mut image = MemoryImage::new(memory_size);

        // Write default values first
        for (key, param) in &program.parameters {
            if let Ok(default_val) = param.default_value.parse::<i64>() {
                image.write_bits(key.memory_offset, key.bit_offset, key.size_bits, default_val as u64);
            }
        }

        // Overwrite with test config values
        for (key, value) in &config.values {
            image.write_bits(key.memory_offset, key.bit_offset, key.size_bits, *value as u64);
        }

        image
    }

    /// Compare memory layouts for a single configuration.
    pub fn compare_config(&self, config: &TestConfig, memory_size: usize) -> Option<MemoryDiff> {
        let ref_image = Self::generate_memory(self.reference, config, memory_size);
        let gen_image = Self::generate_memory(self.generated, config, memory_size);

        let mut byte_diffs = Vec::new();
        for (i, (expected, actual)) in ref_image.bytes.iter().zip(gen_image.bytes.iter()).enumerate()
        {
            if expected != actual {
                byte_diffs.push(ByteDiff {
                    offset: i as u32,
                    expected: *expected,
                    actual: *actual,
                });
            }
        }

        if byte_diffs.is_empty() {
            None
        } else {
            Some(MemoryDiff {
                config: config.clone(),
                byte_diffs,
            })
        }
    }

    /// Compare memory layouts for multiple configurations.
    pub fn compare(&self, configs: &[TestConfig], memory_size: usize) -> Vec<MemoryDiff> {
        configs
            .iter()
            .filter_map(|config| self.compare_config(config, memory_size))
            .collect()
    }

    /// Generate test configurations covering all parameter default values.
    pub fn generate_default_configs(&self) -> Vec<TestConfig> {
        // For now, just test the default configuration
        vec![TestConfig::new()]
    }
}

// ============================================================================
// Memory Comparison Report
// ============================================================================

/// Report of memory comparison results.
#[derive(Debug, Clone, Default)]
pub struct MemoryComparisonReport {
    /// Configurations tested.
    pub configs_tested: usize,
    /// Configurations that matched.
    pub configs_matched: usize,
    /// Differences found.
    pub diffs: Vec<MemoryDiff>,
}

impl MemoryComparisonReport {
    /// Check if there are any differences.
    pub fn has_differences(&self) -> bool {
        !self.diffs.is_empty()
    }
}

impl fmt::Display for MemoryComparisonReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "--- Memory Layout Comparison ---")?;
        writeln!(
            f,
            "Configs tested: {}, matched: {}",
            self.configs_tested, self.configs_matched
        )?;
        if self.diffs.is_empty() {
            writeln!(f, "✓ All memory layouts matched")?;
        } else {
            writeln!(f, "✗ {} configurations differ:", self.diffs.len())?;
            for diff in &self.diffs {
                writeln!(f, "  - {}", diff)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_image_write_read_byte() {
        let mut image = MemoryImage::new(16);
        image.write_bits(0, 0, 8, 0x42);
        assert_eq!(image.read_bits(0, 0, 8), 0x42);
    }

    #[test]
    fn test_memory_image_write_read_bits() {
        let mut image = MemoryImage::new(16);
        // Write 3 bits at bit offset 2
        image.write_bits(0, 2, 3, 0b101);
        assert_eq!(image.bytes[0], 0b00010100);
        assert_eq!(image.read_bits(0, 2, 3), 0b101);
    }

    #[test]
    fn test_memory_image_write_read_multibyte() {
        let mut image = MemoryImage::new(16);
        image.write_bits(0, 0, 16, 0x1234);
        assert_eq!(image.read_bits(0, 0, 16), 0x1234);
    }

    #[test]
    fn test_test_config() {
        let key = ParameterKey::new(0x100, 0, 8);
        let config = TestConfig::new().with_value(key, 42);
        assert_eq!(config.get(&key), Some(42));
    }
}
