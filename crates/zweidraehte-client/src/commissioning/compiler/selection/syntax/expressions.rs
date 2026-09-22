//! Evaluate parameter tests used in authored choices.

use super::decode_hex;
use crate::configuration::ProcedureParameterValue;

pub(in crate::commissioning) fn parameter_test_matches(
    value: &ProcedureParameterValue,
    test: &str,
) -> Result<bool, String> {
    let test = test.trim();
    if test.is_empty() {
        return Err("choose test is empty".to_owned());
    }

    if let Some((operator, operand)) = comparison_expression(test) {
        if operand.is_empty() {
            return Err(format!("choose test {test:?} has no operand"));
        }

        return compare_parameter(value, operator, operand);
    }

    // The load-control language uses a whitespace-separated value list as an
    // OR expression. This is distinct from comma-separated `AppliesTo`.
    let operands: Vec<&str> = test.split_ascii_whitespace().collect();
    if operands.is_empty() {
        return Err("choose test contains no values".to_owned());
    }

    for operand in operands {
        if compare_parameter(value, TestOperator::Equal, operand)? {
            return Ok(true);
        }
    }

    Ok(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commissioning) enum TestOperator {
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

pub(in crate::commissioning) fn comparison_expression(test: &str) -> Option<(TestOperator, &str)> {
    let candidates = [
        (">=", TestOperator::GreaterOrEqual),
        ("<=", TestOperator::LessOrEqual),
        ("!=", TestOperator::NotEqual),
        ("=", TestOperator::Equal),
        (">", TestOperator::Greater),
        ("<", TestOperator::Less),
    ];

    candidates
        .into_iter()
        .find_map(|(prefix, operator)| test.strip_prefix(prefix).map(|operand| (operator, operand.trim())))
}

pub(in crate::commissioning) fn compare_parameter(
    value: &ProcedureParameterValue,
    operator: TestOperator,
    operand: &str,
) -> Result<bool, String> {
    use std::cmp::Ordering;

    let ordering = match value {
        ProcedureParameterValue::Signed(value) => {
            let operand = parse_signed_integer(operand)
                .map_err(|_| format!("choose operand {operand:?} is not a signed integer"))?;
            value.cmp(&operand)
        }
        ProcedureParameterValue::Unsigned(value) => {
            let operand = parse_unsigned_integer(operand)
                .map_err(|_| format!("choose operand {operand:?} is not an unsigned integer"))?;
            value.cmp(&operand)
        }
        ProcedureParameterValue::Boolean(value) => {
            let operand = match operand.to_ascii_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => return Err(format!("choose operand {operand:?} is not a boolean")),
            };
            value.cmp(&operand)
        }
        ProcedureParameterValue::Text(value) => value.as_str().cmp(strip_quotes(operand)),
        ProcedureParameterValue::Bytes(value) => {
            let operand = operand.strip_prefix("0x").or_else(|| operand.strip_prefix("0X")).unwrap_or(operand);
            let operand = decode_hex(operand).map_err(|message| format!("invalid byte choose operand: {message}"))?;
            value.cmp(&operand)
        }
    };

    Ok(match operator {
        TestOperator::Equal => ordering == Ordering::Equal,
        TestOperator::NotEqual => ordering != Ordering::Equal,
        TestOperator::Greater => ordering == Ordering::Greater,
        TestOperator::GreaterOrEqual => ordering != Ordering::Less,
        TestOperator::Less => ordering == Ordering::Less,
        TestOperator::LessOrEqual => ordering != Ordering::Greater,
    })
}

pub(in crate::commissioning) fn parse_signed_integer(value: &str) -> Result<i64, std::num::ParseIntError> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("-0x").or_else(|| value.strip_prefix("-0X")) {
        i64::from_str_radix(hex, 16).map(|value| -value)
    } else if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
}

pub(in crate::commissioning) fn parse_unsigned_integer(value: &str) -> Result<u64, std::num::ParseIntError> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
}

pub(in crate::commissioning) fn strip_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!((bytes[0], bytes[value.len() - 1]), (b'\'', b'\'') | (b'"', b'"')) {
            return &value[1..value.len() - 1];
        }
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::compiler::selection::syntax::{TestOperator, compare_parameter, parameter_test_matches};

    #[test]
    fn choose_supports_lists_and_ordered_numeric_comparisons() {
        let value = ProcedureParameterValue::Unsigned(9);

        assert!(parameter_test_matches(&value, "1 9 12").expect("value list parses"));
        assert!(parameter_test_matches(&value, ">=9").expect("comparison parses"));
        assert!(!parameter_test_matches(&value, "<9").expect("comparison parses"));
        assert!(compare_parameter(&value, TestOperator::NotEqual, "10").expect("operand parses"));
    }
}
