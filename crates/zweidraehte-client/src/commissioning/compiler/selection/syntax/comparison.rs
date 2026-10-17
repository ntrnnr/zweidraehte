//! Parse native numeric intervals into inclusive 64-bit endpoints.

use crate::commissioning::procedure::NumericRange;

pub(in crate::commissioning) fn parse_range(value: &str) -> Result<NumericRange, String> {
    let (body, signed) = match value.as_bytes().last().copied() {
        Some(b's') => (&value[..value.len() - 1], true),
        Some(b'u') => (&value[..value.len() - 1], false),
        _ => (value, true),
    };
    if body.len() < 3 {
        return Err(format!("comparison range {value:?} is too short"));
    }
    let opening = body.as_bytes()[0];
    let closing = *body.as_bytes().last().expect("range has at least three bytes");
    if !matches!(opening, b'[' | b'(') || !matches!(closing, b']' | b')') {
        return Err(format!("comparison range {value:?} has invalid endpoints"));
    }
    let (lower, upper) = body[1..body.len() - 1]
        .split_once(',')
        .ok_or_else(|| format!("comparison range {value:?} has no comma separator"))?;
    for endpoint in [lower, upper] {
        let digits = endpoint.strip_prefix('-').unwrap_or(endpoint);
        if !endpoint.is_empty() && (digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())) {
            return Err(format!("comparison range {value:?} has an invalid decimal endpoint"));
        }
    }
    // Native arithmetic is unchecked: exclusive extrema wrap to the opposite
    // endpoint. Missing endpoints use the whole domain; reversed intervals
    // remain valid and match nothing, rather than failing compilation.
    if signed {
        let lower = if lower.is_empty() {
            i64::MIN
        } else {
            let parsed: i64 = lower.parse().map_err(|_| format!("signed lower range endpoint {lower:?} is invalid"))?;
            if opening == b'(' { parsed.wrapping_add(1) } else { parsed }
        };
        let upper = if upper.is_empty() {
            i64::MAX
        } else {
            let parsed: i64 = upper.parse().map_err(|_| format!("signed upper range endpoint {upper:?} is invalid"))?;
            if closing == b')' { parsed.wrapping_sub(1) } else { parsed }
        };
        Ok(NumericRange::Signed { lower, upper })
    } else {
        // .NET accepts a minus sign on unsigned zero, but rejects every
        // negative nonzero magnitude. Keep that distinction before parsing.
        let unsigned = |endpoint: &str| {
            if endpoint.strip_prefix('-').is_some_and(|digits| digits.bytes().all(|byte| byte == b'0')) {
                Ok(0_u64)
            } else {
                endpoint.parse::<u64>()
            }
        };
        let lower = if lower.is_empty() {
            0
        } else {
            let parsed = unsigned(lower).map_err(|_| format!("unsigned lower range endpoint {lower:?} is invalid"))?;
            if opening == b'(' { parsed.wrapping_add(1) } else { parsed }
        };
        let upper = if upper.is_empty() {
            u64::MAX
        } else {
            let parsed = unsigned(upper).map_err(|_| format!("unsigned upper range endpoint {upper:?} is invalid"))?;
            if closing == b')' { parsed.wrapping_sub(1) } else { parsed }
        };
        Ok(NumericRange::Unsigned { lower, upper })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_normalizes_native_defaults_exclusive_bounds_and_empty_intervals() {
        assert_eq!(parse_range("(-12,42]s").expect("signed range"), NumericRange::Signed { lower: -11, upper: 42 });
        assert_eq!(parse_range("[,65535)u").expect("unsigned range"), NumericRange::Unsigned {
            lower: 0,
            upper: 65534
        });
        assert_eq!(parse_range("[2216203124736,]").expect("default signed range"), NumericRange::Signed {
            lower: 2216203124736,
            upper: i64::MAX
        });
        assert_eq!(
            parse_range("(9223372036854775807,]").expect("native wraps exclusive maximum"),
            NumericRange::Signed { lower: i64::MIN, upper: i64::MAX }
        );
        assert_eq!(parse_range("[,0)u").expect("native wraps exclusive unsigned minimum"), NumericRange::Unsigned {
            lower: 0,
            upper: u64::MAX
        });
        assert_eq!(parse_range("[5,3]").expect("native empty interval"), NumericRange::Signed { lower: 5, upper: 3 });
        assert!(parse_range("[0,18446744073709551616]u").is_err());
        assert_eq!(parse_range("[-0,-0]u").expect("native unsigned minus zero"), NumericRange::Unsigned {
            lower: 0,
            upper: 0
        });
        assert_eq!(parse_range("(-000,1]u").expect("exclusive unsigned minus zero"), NumericRange::Unsigned {
            lower: 1,
            upper: 1
        });
        assert_eq!(parse_range("[,-0)u").expect("exclusive unsigned zero wraps"), NumericRange::Unsigned {
            lower: 0,
            upper: u64::MAX
        });
        assert!(parse_range("[-1,3]u").is_err());
        for invalid in ["[+1,3]", "[0x1,3]", " [1,3]", "[1, 3]", "[1,3]U"] {
            assert!(parse_range(invalid).is_err(), "native grammar rejects {invalid}");
        }
    }
}
