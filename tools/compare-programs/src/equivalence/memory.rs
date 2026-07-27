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
    ///
    /// Unused outside tests until `generate_default_configs` learns to sweep
    /// parameters; kept as the way callers will build those configurations.
    #[allow(dead_code)]
    pub fn with_value(mut self, key: ParameterKey, value: i64) -> Self {
        self.values.insert(key, value);
        self
    }

    /// Get a parameter value. See [`TestConfig::with_value`] on why this is
    /// currently only exercised by tests.
    #[allow(dead_code)]
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
        Self { bytes: vec![0; size], base_offset: 0 }
    }

    /// Create a new memory image with the given size and base offset.
    ///
    /// Every comparison currently builds offset-zero images, because parameter
    /// offsets are already segment-relative. A non-zero base becomes necessary
    /// once several segments are imaged side by side.
    #[allow(dead_code)]
    pub fn with_base(size: usize, base_offset: u32) -> Self {
        Self { bytes: vec![0; size], base_offset }
    }

    /// Write a value at the given offset and bit position.
    ///
    /// Writes that fall outside the image (below its base or past its end) are
    /// dropped rather than panicking: a malformed program should surface as a
    /// parameter difference, not as a crash in the comparator.
    pub fn write_bits(&mut self, offset: u32, bit_offset: u8, size_bits: u32, value: u64) {
        let Some(local_offset) = offset.checked_sub(self.base_offset).map(|o| o as usize) else {
            return;
        };

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
            // Multi-byte value (assume bit_offset is 0 for simplicity). KNX
            // parameter memory is big-endian, so the most significant byte goes
            // to the lowest offset.
            let num_bytes = size_bits.div_ceil(8) as usize;
            for i in 0..num_bytes {
                let byte_idx = local_offset + i;
                if byte_idx < self.bytes.len() {
                    let shift = (num_bytes - 1 - i) * 8;
                    self.bytes[byte_idx] = ((value >> shift) & 0xFF) as u8;
                }
            }
        }
    }

    /// Read a value from the given offset and bit position.
    ///
    /// Reads outside the image yield 0, mirroring [`MemoryImage::write_bits`].
    /// Comparison works on raw bytes, so this exists to pin down the encoding
    /// `write_bits` produces rather than to serve the comparison itself.
    #[allow(dead_code)]
    pub fn read_bits(&self, offset: u32, bit_offset: u8, size_bits: u32) -> u64 {
        let Some(local_offset) = offset.checked_sub(self.base_offset).map(|o| o as usize) else {
            return 0;
        };

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
            // Multi-byte value, big-endian; mirrors `write_bits`.
            let num_bytes = size_bits.div_ceil(8) as usize;
            let mut value: u64 = 0;
            for i in 0..num_bytes {
                let byte_idx = local_offset + i;
                if byte_idx < self.bytes.len() {
                    let shift = (num_bytes - 1 - i) * 8;
                    value |= (self.bytes[byte_idx] as u64) << shift;
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
                write!(f, "@0x{:X}: 0x{:02X}!=0x{:02X}", diff.offset, diff.expected, diff.actual)?;
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
        Self { reference, generated }
    }

    /// Generate a memory image for the given configuration using a program's parameters.
    pub fn generate_memory(program: &CanonicalProgram, config: &TestConfig, memory_size: usize) -> MemoryImage {
        let mut image = MemoryImage::new(memory_size);

        // Write default values first. Tool-only parameters have no location
        // and contribute no bytes — the device never receives them.
        for (key, param) in &program.parameters {
            if let (Some((offset, bit_offset, size_bits)), Ok(default_val)) =
                (key.memory_location(), param.default_value.parse::<i64>())
            {
                image.write_bits(offset, bit_offset, size_bits, default_val as u64);
            }
        }

        // Overwrite with test config values
        for (key, value) in &config.values {
            if let Some((offset, bit_offset, size_bits)) = key.memory_location() {
                image.write_bits(offset, bit_offset, size_bits, *value as u64);
            }
        }

        image
    }

    /// Compare memory layouts for a single configuration.
    pub fn compare_config(&self, config: &TestConfig, memory_size: usize) -> Option<MemoryDiff> {
        let ref_image = Self::generate_memory(self.reference, config, memory_size);
        let gen_image = Self::generate_memory(self.generated, config, memory_size);

        let mut byte_diffs = Vec::new();
        for (i, (expected, actual)) in ref_image.bytes.iter().zip(gen_image.bytes.iter()).enumerate() {
            if expected != actual {
                byte_diffs.push(ByteDiff { offset: i as u32, expected: *expected, actual: *actual });
            }
        }

        if byte_diffs.is_empty() { None } else { Some(MemoryDiff { config: config.clone(), byte_diffs }) }
    }

    /// Compare memory layouts for multiple configurations.
    pub fn compare(&self, configs: &[TestConfig], memory_size: usize) -> Vec<MemoryDiff> {
        configs.iter().filter_map(|config| self.compare_config(config, memory_size)).collect()
    }

    /// Generate the test configurations to compare the two programs under.
    ///
    /// Currently only the empty configuration, which leaves every parameter at
    /// its declared default and so compares the images ETS would download from
    /// a freshly-added device.
    ///
    /// TODO: sweep each enum parameter through its variants, so layouts that
    /// only diverge for non-default values are caught too. That needs a shared
    /// notion of "the same parameter" across programs beyond the memory key.
    pub fn generate_default_configs(&self) -> Vec<TestConfig> {
        vec![TestConfig::new()]
    }

    /// Compare both programs across the given configurations and summarise.
    pub fn compare_report(&self, configs: &[TestConfig], memory_size: usize) -> MemoryComparisonReport {
        let diffs = self.compare(configs, memory_size);

        MemoryComparisonReport {
            configs_tested: configs.len(),
            configs_matched: configs.len() - diffs.len(),
            memory_size,
            diffs,
            skipped: None,
        }
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
    /// Size of the memory image the comparison was run over.
    pub memory_size: usize,
    /// Differences found.
    pub diffs: Vec<MemoryDiff>,
    /// Why the comparison did not run, when it did not.
    pub skipped: Option<String>,
}

impl MemoryComparisonReport {
    /// A report standing in for a comparison that could not be run.
    ///
    /// A skipped comparison is not a difference: it reports nothing either way,
    /// so it must not fail the run.
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self { skipped: Some(reason.into()), ..Self::default() }
    }

    /// Check if there are any differences.
    pub fn has_differences(&self) -> bool {
        !self.diffs.is_empty()
    }
}

impl fmt::Display for MemoryComparisonReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "--- Memory Layout Comparison ---")?;

        if let Some(ref reason) = self.skipped {
            writeln!(f, "- Skipped: {}", reason)?;
            return Ok(());
        }

        writeln!(
            f,
            "Image size: {} bytes, configs tested: {}, matched: {}",
            self.memory_size, self.configs_tested, self.configs_matched
        )?;
        if !self.has_differences() {
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

    /// KNX parameter memory is big-endian; the round-trip test above would pass
    /// either way, so pin the actual byte placement.
    #[test]
    fn test_memory_image_multibyte_is_big_endian() {
        let mut image = MemoryImage::new(16);
        image.write_bits(0, 0, 16, 0x1234);
        assert_eq!(&image.bytes[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn test_memory_image_ignores_out_of_range_writes() {
        let mut image = MemoryImage::with_base(4, 0x100);
        image.write_bits(0x0F, 0, 8, 0xFF);
        image.write_bits(0x200, 0, 8, 0xFF);
        assert_eq!(image.bytes, vec![0; 4]);
    }

    #[test]
    fn test_test_config() {
        let key = ParameterKey::new(0x100, 0, 8);
        let config = TestConfig::new().with_value(key.clone(), 42);
        assert_eq!(config.get(&key), Some(42));
    }
}
