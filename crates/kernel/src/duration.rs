//! Go `time.ParseDuration` syntax, so existing policy files keep working:
//! `"90s"`, `"10m"`, `"1h30m"`, `"1.5h"`, `"300ms"`, `"-2m"`, `"0"`.

use jiff::SignedDuration;

/// A duration string Go's `time.ParseDuration` would also reject.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid duration {0:?} (want e.g. \"20m\", \"1h30m\")")]
pub struct DurationError(pub String);

const NANOS_PER_UNIT: [(&str, u128); 8] = [
    ("ns", 1),
    ("us", 1_000),
    ("\u{b5}s", 1_000),  // micro sign
    ("\u{3bc}s", 1_000), // Greek mu
    ("ms", 1_000_000),
    ("s", 1_000_000_000),
    ("m", 60_000_000_000),
    ("h", 3_600_000_000_000),
];

/// Fraction digits kept; finer digits cannot change a nanosecond count.
const MAX_FRACTION_DIGITS: u32 = 18;

/// Parses a Go-syntax duration: optional sign, then one or more
/// `<decimal><unit>` terms.
///
/// # Errors
///
/// Returns [`DurationError`] for empty input, a missing or unknown unit, a
/// term without digits, or a total beyond ±2⁶³ ns.
pub fn parse_go_duration(input: &str) -> Result<SignedDuration, DurationError> {
    let err = || DurationError(input.to_owned());
    let (neg, mut rest) = match input.as_bytes().first() {
        Some(b'-') => (true, &input[1..]),
        Some(b'+') => (false, &input[1..]),
        _ => (false, input),
    };
    if rest == "0" {
        return Ok(SignedDuration::ZERO);
    }
    if rest.is_empty() {
        return Err(err());
    }
    let limit: u128 = if neg { 1 << 63 } else { (1 << 63) - 1 };
    let mut total: u128 = 0;
    while !rest.is_empty() {
        let (nanos, tail) = term(rest, limit).ok_or_else(err)?;
        total = total
            .checked_add(nanos)
            .filter(|t| *t <= limit)
            .ok_or_else(err)?;
        rest = tail;
    }
    let signed = if neg {
        -i128::try_from(total).map_err(|_| err())?
    } else {
        i128::try_from(total).map_err(|_| err())?
    };
    i64::try_from(signed)
        .map(SignedDuration::from_nanos)
        .map_err(|_| err())
}

/// One `<decimal><unit>` term: its value in nanoseconds and the remaining input.
fn term(s: &str, limit: u128) -> Option<(u128, &str)> {
    let int_len = s.bytes().take_while(u8::is_ascii_digit).count();
    let mut whole: u128 = 0;
    for b in s[..int_len].bytes() {
        whole = whole.checked_mul(10)?.checked_add(u128::from(b - b'0'))?;
        if whole > limit {
            return None;
        }
    }
    let mut rest = &s[int_len..];
    let (mut frac, mut scale, mut frac_len) = (0u128, 1u128, 0usize);
    if let Some(after_dot) = rest.strip_prefix('.') {
        frac_len = after_dot.bytes().take_while(u8::is_ascii_digit).count();
        for b in after_dot[..frac_len]
            .bytes()
            .take(MAX_FRACTION_DIGITS as usize)
        {
            frac = frac * 10 + u128::from(b - b'0');
            scale *= 10;
        }
        rest = &after_dot[frac_len..];
    }
    if int_len == 0 && frac_len == 0 {
        return None;
    }
    let unit_len = rest
        .find(|c: char| c == '.' || c.is_ascii_digit())
        .unwrap_or(rest.len());
    let unit = &rest[..unit_len];
    let (_, per) = NANOS_PER_UNIT.iter().find(|(name, _)| *name == unit)?;
    let nanos = whole.checked_mul(*per)?.checked_add(frac * per / scale)?;
    Some((nanos, &rest[unit_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go_duration_accepts_go_syntax() {
        let cases = [
            ("1h", SignedDuration::from_hours(1)),
            ("10m", SignedDuration::from_mins(10)),
            ("90s", SignedDuration::from_secs(90)),
            ("1h30m", SignedDuration::from_mins(90)),
            ("1.5h", SignedDuration::from_mins(90)),
            ("300ms", SignedDuration::from_millis(300)),
            ("1h0m0s", SignedDuration::from_hours(1)),
            ("2\u{b5}s", SignedDuration::from_micros(2)),
            (".5s", SignedDuration::from_millis(500)),
            ("-2m", SignedDuration::from_mins(-2)),
            ("+5s", SignedDuration::from_secs(5)),
            ("0", SignedDuration::ZERO),
            (
                "-9223372036854775808ns",
                SignedDuration::from_nanos(i64::MIN),
            ),
        ];
        for (s, want) in cases {
            assert_eq!(parse_go_duration(s), Ok(want), "{s}");
        }
    }

    #[test]
    fn test_parse_go_duration_rejects_what_go_rejects() {
        for s in [
            "",
            "-",
            "h",
            "10",
            "1x",
            ".s",
            "1.h2",
            "9223372036854775808ns",
            "99999999999h",
            "1 h",
            "1H",
        ] {
            assert!(parse_go_duration(s).is_err(), "{s:?} must be rejected");
        }
    }
}
