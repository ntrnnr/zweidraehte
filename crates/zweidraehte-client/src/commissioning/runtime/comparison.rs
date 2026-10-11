//! Comparison management services.

use super::ProcedureRunner;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::procedure::{Comparison, ComparisonPadding, MemoryByteOrder, OperationData, RangeBound};

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
            Comparison::UnsignedRange { lower, upper } => {
                let value = self.decode_unsigned_comparison(actual)?;
                range_contains(value, lower, upper)
            }
            Comparison::SignedRange { lower, upper } => {
                let value = self.decode_signed_comparison(actual)?;
                range_contains(value, lower, upper)
            }
        };

        if matches {
            Ok(())
        } else {
            Err(self.session.compare_error("device value does not satisfy the compiled comparison"))
        }
    }

    pub(super) fn decode_unsigned_comparison(&self, bytes: &[u8]) -> Result<u64, Diagnostic> {
        if bytes.is_empty() || bytes.len() > 8 {
            return Err(Diagnostic::new(format!(
                "numeric comparison requires one through eight bytes, got {}",
                bytes.len()
            )));
        }

        Ok(match self.tool_state.memory_byte_order {
            MemoryByteOrder::BigEndian => bytes.iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
            MemoryByteOrder::LittleEndian => {
                bytes.iter().rev().fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
            }
        })
    }

    pub(super) fn decode_signed_comparison(&self, bytes: &[u8]) -> Result<i64, Diagnostic> {
        let unsigned = self.decode_unsigned_comparison(bytes)?;
        let bits = bytes.len() * 8;
        let sign_bit = 1u128 << (bits - 1);
        let unsigned = u128::from(unsigned);
        let signed = if unsigned & sign_bit == 0 { unsigned as i128 } else { unsigned as i128 - (1i128 << bits) };

        i64::try_from(signed).map_err(|_| Diagnostic::new("signed comparison value exceeds 64 bits"))
    }
}

pub(super) fn range_contains<T: PartialOrd + Copy>(value: T, lower: &RangeBound<T>, upper: &RangeBound<T>) -> bool {
    let above_lower = match lower {
        RangeBound::Unbounded => true,
        RangeBound::Inclusive(lower) => value >= *lower,
        RangeBound::Exclusive(lower) => value > *lower,
    };
    let below_upper = match upper {
        RangeBound::Unbounded => true,
        RangeBound::Inclusive(upper) => value <= *upper,
        RangeBound::Exclusive(upper) => value < *upper,
    };

    above_lower && below_upper
}
