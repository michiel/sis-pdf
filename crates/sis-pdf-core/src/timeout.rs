use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TimeoutError {
    pub budget: Duration,
    pub elapsed: Duration,
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "timeout exceeded: budget {:?}, elapsed {:?}", self.budget, self.elapsed)
    }
}

impl Error for TimeoutError {}

#[derive(Debug, Clone)]
pub struct TimeoutChecker {
    start: Instant,
    budget: Duration,
}

impl TimeoutChecker {
    pub fn new(budget: Duration) -> Self {
        Self { start: Instant::now(), budget }
    }

    pub fn check(&self) -> Result<(), TimeoutError> {
        let elapsed = self.start.elapsed();
        if elapsed > self.budget {
            return Err(TimeoutError { budget: self.budget, elapsed });
        }
        Ok(())
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn remaining(&self) -> Option<Duration> {
        let elapsed = self.start.elapsed();
        self.budget.checked_sub(elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::TimeoutChecker;
    use std::time::Duration;

    #[test]
    fn timeout_expires_immediately() {
        let checker = TimeoutChecker::new(Duration::from_millis(0));
        assert!(checker.check().is_err());
    }
}
