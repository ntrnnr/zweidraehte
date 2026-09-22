//! Parse typed comparison ranges.

use super::expressions::{parse_signed_integer, parse_unsigned_integer};
use crate::commissioning::procedure::{Comparison, RangeBound};

pub(in crate::commissioning) fn parse_range(value: &str) -> Result<Comparison, String> {
    let value = value.trim();
    let (body, signed) = match value.as_bytes().last().copied() {
        Some(b's') | Some(b'S') => (&value[..value.len() - 1], true),
        Some(b'u') | Some(b'U') => (&value[..value.len() - 1], false),
        _ => (value, false),
    };

    if body.len() < 3 {
        return Err(format!("comparison range {value:?} is too short"));
    }

    let opening = body.as_bytes()[0];
    let closing = *body.as_bytes().last().expect("range has at least three bytes");
    if !matches!(opening, b'[' | b'(') || !matches!(closing, b']' | b')') {
        return Err(format!("comparison range {value:?} has invalid endpoints"));
    }

    let contents = &body[1..body.len() - 1];
    let (lower, upper) =
        contents.split_once(',').ok_or_else(|| format!("comparison range {value:?} has no comma separator"))?;
    if upper.contains(',') {
        return Err(format!("comparison range {value:?} has more than two endpoints"));
    }

    if signed {
        let lower = parse_signed_bound(lower.trim(), opening == b'[', "lower")?;
        let upper = parse_signed_bound(upper.trim(), closing == b']', "upper")?;
        validate_signed_range(&lower, &upper)?;

        Ok(Comparison::SignedRange { lower, upper })
    } else {
        let lower = parse_unsigned_bound(lower.trim(), opening == b'[', "lower")?;
        let upper = parse_unsigned_bound(upper.trim(), closing == b']', "upper")?;
        validate_unsigned_range(&lower, &upper)?;

        Ok(Comparison::UnsignedRange { lower, upper })
    }
}

pub(in crate::commissioning) fn parse_signed_bound(
    value: &str,
    inclusive: bool,
    name: &str,
) -> Result<RangeBound<i64>, String> {
    if value.is_empty() {
        return Ok(RangeBound::Unbounded);
    }

    let value =
        parse_signed_integer(value).map_err(|_| format!("signed {name} range endpoint {value:?} is invalid"))?;

    Ok(if inclusive { RangeBound::Inclusive(value) } else { RangeBound::Exclusive(value) })
}

pub(in crate::commissioning) fn parse_unsigned_bound(
    value: &str,
    inclusive: bool,
    name: &str,
) -> Result<RangeBound<u64>, String> {
    if value.is_empty() {
        return Ok(RangeBound::Unbounded);
    }

    let value =
        parse_unsigned_integer(value).map_err(|_| format!("unsigned {name} range endpoint {value:?} is invalid"))?;

    Ok(if inclusive { RangeBound::Inclusive(value) } else { RangeBound::Exclusive(value) })
}

pub(in crate::commissioning) fn validate_signed_range(
    lower: &RangeBound<i64>,
    upper: &RangeBound<i64>,
) -> Result<(), String> {
    let lower = bound_value(lower);
    let upper = bound_value(upper);
    if lower.zip(upper).is_some_and(|(lower, upper)| lower > upper) {
        return Err("signed comparison range has its lower endpoint above its upper endpoint".to_owned());
    }

    Ok(())
}

pub(in crate::commissioning) fn validate_unsigned_range(
    lower: &RangeBound<u64>,
    upper: &RangeBound<u64>,
) -> Result<(), String> {
    let lower = bound_value(lower);
    let upper = bound_value(upper);
    if lower.zip(upper).is_some_and(|(lower, upper)| lower > upper) {
        return Err("unsigned comparison range has its lower endpoint above its upper endpoint".to_owned());
    }

    Ok(())
}

pub(in crate::commissioning) fn bound_value<T: Copy>(bound: &RangeBound<T>) -> Option<T> {
    match bound {
        RangeBound::Unbounded => None,
        RangeBound::Inclusive(value) | RangeBound::Exclusive(value) => Some(*value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::compiler::selection::syntax::parse_range;

    #[test]
    fn range_preserves_open_closed_and_unbounded_endpoints() {
        assert_eq!(parse_range("(-12,42]s").expect("signed range parses"), Comparison::SignedRange {
            lower: RangeBound::Exclusive(-12),
            upper: RangeBound::Inclusive(42),
        });
        assert_eq!(parse_range("[,65535)u").expect("unsigned range parses"), Comparison::UnsignedRange {
            lower: RangeBound::Unbounded,
            upper: RangeBound::Exclusive(65_535),
        });
    }
}
