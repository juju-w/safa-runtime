use std::time::{SystemTime, UNIX_EPOCH};

/// Clock boundary used to make the public envelope deterministic in conformance tests.
pub trait Clock {
    /// Return the current UTC time as an RFC 3339 timestamp with second precision.
    fn now_rfc3339(&self) -> String;
}

/// Standard-library UTC clock used by the executable.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        let seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
        };
        format_unix_seconds(seconds)
    }
}

fn format_unix_seconds(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    // Howard Hinnant's civil-from-days algorithm, with day zero at the Unix epoch.
    let shifted_days = days + 719_468;
    let era = shifted_days.div_euclid(146_097);
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::format_unix_seconds;

    #[test]
    fn timestamp_formatter_handles_epoch_and_pre_epoch_values() {
        assert_eq!(format_unix_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_seconds(-1), "1969-12-31T23:59:59Z");
        assert_eq!(format_unix_seconds(951_782_400), "2000-02-29T00:00:00Z");
    }
}
