use crate::rcl_bindings::*;
use std::ops::{Add, Sub};
use std::sync::{Mutex, Weak};
use std::time::Duration;

/// Struct that represents time.
#[derive(Clone, Debug)]
pub struct Time {
    /// Timestamp in nanoseconds.
    pub nsec: i64,
    /// Weak reference to the clock that generated this time
    pub clock: Weak<Mutex<rcl_clock_t>>,
}

impl Time {
    /// Compares self to rhs, if they can be compared (originated from the same clock) calls f with
    /// the values of the timestamps.
    pub fn compare_with<U, F>(&self, rhs: &Time, f: F) -> Option<U>
    where
        F: FnOnce(i64, i64) -> U,
    {
        self.clock
            .ptr_eq(&rhs.clock)
            .then(|| f(self.nsec, rhs.nsec))
    }
}

impl Add<Duration> for Time {
    type Output = Self;

    fn add(self, other: Duration) -> Self {
        let dur_ns = i64::try_from(other.as_nanos()).unwrap();
        Time {
            nsec: self.nsec.checked_add(dur_ns).unwrap(),
            clock: self.clock.clone(),
        }
    }
}

impl Sub<Duration> for Time {
    type Output = Self;

    fn sub(self, other: Duration) -> Self {
        let dur_ns = i64::try_from(other.as_nanos()).unwrap();
        Time {
            nsec: self.nsec.checked_sub(dur_ns).unwrap(),
            clock: self.clock.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Clock;

    #[test]
    fn compare_times_from_same_clock() {
        let clock = Clock::system().unwrap();
        let t1 = clock.now();
        std::thread::sleep(std::time::Duration::from_micros(1));
        let t2 = clock.now();
        assert_eq!(t1.compare_with(&t2, |t1, t2| t1 > t2), Some(false));
        assert_eq!(t1.compare_with(&t2, |t1, t2| t2 > t1), Some(true));
    }

    #[test]
    fn compare_times_from_different_clocks() {
        // Times from different clocks, even if of the same type, can't be compared
        let c1 = Clock::system().unwrap();
        let c2 = Clock::system().unwrap();
        let t1 = c1.now();
        let t2 = c2.now();
        assert!(t2.compare_with(&t1, |_, _| ()).is_none());
        assert!(t1.compare_with(&t2, |_, _| ()).is_none());
    }

    #[test]
    fn add_duration_to_time() {
        let (clock, _) = Clock::with_source().unwrap();
        let t = clock.now();
        let t2 = t.clone() + Duration::from_secs(1);
        assert_eq!(t2.nsec - t.nsec, 1_000_000_000i64);
        let t3 = t2 - Duration::from_secs(1);
        assert_eq!(t3.nsec, t.nsec);
    }
}
