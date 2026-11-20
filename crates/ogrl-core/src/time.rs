//! Timestamps and calendar dates, RFC 0001 sections 6.1 and 8.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TimeError {
    #[error("invalid RFC 3339 timestamp {0:?}")]
    InvalidTimestamp(String),
    #[error("invalid calendar date {0:?} (expected YYYY-MM-DD)")]
    InvalidDate(String),
}

/// Parse an RFC 3339 UTC timestamp. Also handles NIST's 5-fractional-digit timestamps
/// (e.g. `2026-10-22T11:30:00.00000-00:00`) and naive timestamps treated as UTC.
pub fn parse_timestamp(raw: &str) -> Result<DateTime<Utc>, TimeError> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(dt.with_timezone(&Utc));
    }
    // Trim non-standard fractional precision if present before timezone offset.
    if let Some(dot_idx) = raw.find('.') {
        if let Some(rel_end) = raw[dot_idx..].find(['Z', 'z', '+', '-']) {
            let trimmed = format!("{}{}", &raw[..dot_idx], &raw[dot_idx + rel_end..]);
            if let Ok(dt) = DateTime::parse_from_rfc3339(&trimmed) {
                return Ok(dt.with_timezone(&Utc));
            }
        }
    }
    // Accept naive ISO-8601 timestamps as UTC (matching Python kernel `utc()`).
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Ok(naive.and_utc());
        }
    }
    Err(TimeError::InvalidTimestamp(raw.to_string()))
}

/// Format a UTC timestamp in canonical RFC 3339 form:
/// `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.uuuuuuZ` when microseconds are non-zero.
pub fn format_timestamp(value: &DateTime<Utc>) -> String {
    let micros = value.timestamp_subsec_micros();
    if micros != 0 {
        format!("{}.{:06}Z", value.format("%Y-%m-%dT%H:%M:%S"), micros)
    } else {
        format!("{}Z", value.format("%Y-%m-%dT%H:%M:%S"))
    }
}

/// Parse a `YYYY-MM-DD` calendar date.
pub fn parse_date(raw: &str) -> Result<NaiveDate, TimeError> {
    NaiveDate::parse_from_str(raw, "%Y-%m-%d").map_err(|_| TimeError::InvalidDate(raw.to_string()))
}

/// Format a calendar date as `YYYY-MM-DD`.
pub fn format_date(value: NaiveDate) -> String {
    value.format("%Y-%m-%d").to_string()
}

/// A calendar date includes the whole of that UTC day. `None` means no end.
pub fn on_or_after(day: Option<NaiveDate>, evaluation_date: NaiveDate) -> bool {
    day.is_none_or(|d| d >= evaluation_date)
}

/// RFC 0001 section 8 freshness window in days. `event-driven` uses `result.valid_until`.
pub fn freshness_days(interval: &str) -> Option<i64> {
    match interval {
        "continuous" | "daily" => Some(1),
        "weekly" => Some(7),
        "monthly" => Some(30),
        "quarterly" => Some(90),
        "annual" => Some(365),
        _ => None,
    }
}

/// Serde module for OGRL timestamps: accepts RFC 3339 / NIST formats and serializes canonically.
pub mod serde_timestamp {
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    use super::{format_timestamp, parse_timestamp};

    pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format_timestamp(dt))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_timestamp(&s).map_err(serde::de::Error::custom)
    }
}

pub mod serde_opt_timestamp {
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    use super::{format_timestamp, parse_timestamp};

    pub fn serialize<S>(dt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dt {
            Some(v) => serializer.serialize_str(&format_timestamp(v)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => parse_timestamp(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_and_nist_timestamps() {
        let a = parse_timestamp("2026-10-22T11:30:00Z").unwrap();
        let b = parse_timestamp("2026-10-22T11:30:00.00000-00:00").unwrap();
        assert_eq!(a, b);
        assert_eq!(format_timestamp(&a), "2026-10-22T11:30:00Z");
    }
}
