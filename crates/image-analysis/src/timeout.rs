use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

#[derive(Debug)]
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

#[derive(Debug)]
pub struct TimeoutChecker {
    start: Instant,
    budget: Duration,
    checkpoint_interval: usize,
    ops: AtomicUsize,
}

impl TimeoutChecker {
    pub fn new(budget: Duration, checkpoint_interval: usize) -> Self {
        Self {
            start: Instant::now(),
            budget,
            checkpoint_interval: checkpoint_interval.max(1),
            ops: AtomicUsize::new(0),
        }
    }

    pub fn check(&self) -> Result<(), TimeoutError> {
        let ops = self.ops.fetch_add(1, Ordering::Relaxed);
        if ops.is_multiple_of(self.checkpoint_interval) {
            let elapsed = self.start.elapsed();
            if elapsed > self.budget {
                return Err(TimeoutError { budget: self.budget, elapsed });
            }
        }
        Ok(())
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}
