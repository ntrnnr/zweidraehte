//! Comparison management services.

use super::ProcedureRunner;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::procedure::{
    Comparison, ComparisonPadding, MemoryByteOrder, NumericEncoding, NumericRange, NumericSignExtension, OperationData,
};

impl ProcedureRunner<'_, '_> {
    pub(super) fn compare_value(&self, actual: &[u8], comparison: &Comparison) -> Result<(), Diagnostic> {
        let matches = match comparison {
            Comparison::Exact { data: OperationData::Inline(expected), mask, padding } => {
                if let Some(mask) = mask
                    && mask.len() != expected.len()
                {
                    return Err(Diagnostic::new(format!(
                        "comparison mask has {} bytes, expected {}",
                        mask.len(),
                        expected.len()
                    )));
                }

                let compared_length = match padding {
                    ComparisonPadding::None => {
                        if expected.len() != actual.len() {
                            return Err(self.session.compare_error(format!(
                                "comparison expects {} bytes, device returned {}",
                                expected.len(),
                                actual.len()
                            )));
                        }

                        actual.len()
                    }
                    ComparisonPadding::ExpectedTrailingZeros => {
                        if actual.len() > expected.len() {
                            return Err(self.session.compare_error(format!(
                                "zero-padded comparison expects at most {} bytes, device returned {}",
                                expected.len(),
                                actual.len()
                            )));
                        }
                        if expected[actual.len()..].iter().any(|byte| *byte != 0) {
                            return Err(self
                                .session
                                .compare_error("zero-padded comparison has nonzero bytes after the device value"));
                        }

                        actual.len()
                    }
                };

                match mask {
                    Some(mask) => actual
                        .iter()
                        .zip(&expected[..compared_length])
                        .zip(&mask[..compared_length])
                        .all(|((actual, expected), mask)| actual & mask == expected & mask),
                    None => actual == &expected[..compared_length],
                }
            }
            Comparison::Exact { .. } | Comparison::ImageExact { .. } => {
                return Err(Diagnostic::new("comparison data was not materialized before device execution"));
            }
            Comparison::NumericRange { range, encoding } => {
                let value = numeric_value(actual, *encoding, self.tool_state.memory_byte_order)?;
                match range {
                    NumericRange::Unsigned { lower, upper } => value >= *lower && value <= *upper,
                    NumericRange::Signed { lower, upper } => (value as i64) >= *lower && (value as i64) <= *upper,
                }
            }
        };

        if matches {
            Ok(())
        } else {
            Err(self.session.compare_error("device value does not satisfy the compiled comparison"))
        }
    }
}

fn numeric_value(bytes: &[u8], encoding: NumericEncoding, memory_order: MemoryByteOrder) -> Result<u64, Diagnostic> {
    if bytes.is_empty() && matches!(encoding, NumericEncoding::Property { sign_extension: NumericSignExtension::Sign })
    {
        return Err(Diagnostic::new("signed property numeric conversion has no leading octet"));
    }

    let order = match encoding {
        NumericEncoding::Memory => memory_order,
        NumericEncoding::Property { .. } => MemoryByteOrder::BigEndian,
    };
    let mut value = match order {
        MemoryByteOrder::BigEndian => bytes.iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
        MemoryByteOrder::LittleEndian => bytes.iter().rev().fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
    };
    // Signedness of the interval does not choose byte extension. Native
    // memory and generic property types zero-extend short values; only
    // signed property PDTs extend their high bit before interval evaluation.
    if matches!(encoding, NumericEncoding::Property { sign_extension: NumericSignExtension::Sign })
        && bytes.len() < 8
        && bytes[0] & 0x80 != 0
    {
        value |= u64::MAX << (bytes.len() * 8);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_conversion_matches_property_pdt_and_memory_native_probes() {
        for memory_order in [MemoryByteOrder::BigEndian, MemoryByteOrder::LittleEndian] {
            for (pdt, bytes, expected) in [
                (1, vec![0x81], -127i64),
                (2, vec![0x81], 129),
                (3, vec![0x80, 1], -32767),
                (4, vec![0x80, 1], 32769),
                (8, vec![0x80, 0, 0, 1], -2147483647),
                (20, vec![0x80, 0, 0, 1], 2147483649),
                (22, vec![2, 4, 0, 0, 0, 0], 2216203124736),
                (24, vec![0xff; 8], -1),
            ] {
                let encoding =
                    NumericEncoding::Property { sign_extension: NumericSignExtension::for_property_data_type(pdt) };
                let actual = numeric_value(&bytes, encoding, memory_order).expect("probed numeric input");
                assert_eq!(actual as i64, expected, "PDT {pdt}, memory order {memory_order:?}");
            }
        }
        assert_eq!(
            numeric_value(&[0x80, 1], NumericEncoding::Memory, MemoryByteOrder::BigEndian).expect("two memory octets"),
            32769
        );
        assert_eq!(
            numeric_value(&[0x80, 1], NumericEncoding::Memory, MemoryByteOrder::LittleEndian)
                .expect("two memory octets"),
            384
        );
        assert_eq!(
            numeric_value(&[0xff; 8], NumericEncoding::Memory, MemoryByteOrder::BigEndian).expect("eight memory octets")
                as i64,
            -1
        );
        let oversized: Vec<u8> = (1..=16).collect();
        assert_eq!(
            numeric_value(&oversized, NumericEncoding::Memory, MemoryByteOrder::BigEndian)
                .expect("native retains the last eight big-endian octets"),
            0x090A0B0C0D0E0F10
        );
        assert_eq!(
            numeric_value(&oversized, NumericEncoding::Memory, MemoryByteOrder::LittleEndian)
                .expect("native retains the first eight little-endian octets"),
            0x0807060504030201
        );
        assert_eq!(
            numeric_value(&[], NumericEncoding::Memory, MemoryByteOrder::BigEndian)
                .expect("empty memory has numeric value zero"),
            0
        );
        assert_eq!(
            numeric_value(
                &[],
                NumericEncoding::Property { sign_extension: NumericSignExtension::Zero },
                MemoryByteOrder::BigEndian
            )
            .expect("empty unsigned property has numeric value zero"),
            0
        );
        assert!(
            numeric_value(
                &[],
                NumericEncoding::Property { sign_extension: NumericSignExtension::Sign },
                MemoryByteOrder::BigEndian
            )
            .is_err()
        );
    }
}
