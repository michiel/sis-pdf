use std::collections::VecDeque;

/// Maximum number of events retained in the telemetry log.
const MAX_EVENTS: usize = 1000;

/// Rolling window size for frame-time percentile calculation.
const FRAME_TIME_WINDOW: usize = 300;

/// A lightweight, append-only telemetry log for UI performance and analyst actions.
pub struct TelemetryLog {
    events: VecDeque<TelemetryEvent>,
    /// Rolling window of recent frame times in seconds.
    frame_times: VecDeque<f64>,
    /// Timestamp (seconds since app start) of the first event.
    session_start: Option<f64>,
    /// Most recent timestamp seen.
    last_timestamp: f64,
}

/// A single telemetry event with a timestamp and kind.
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    /// Seconds since application start.
    pub timestamp: f64,
    pub kind: TelemetryEventKind,
}

/// The kind of telemetry event recorded.
#[derive(Debug, Clone)]
pub enum TelemetryEventKind {
    /// A file was opened for analysis.
    FileOpened { file_name: String, file_size: usize },
    /// A panel was opened.
    PanelOpened { panel: String },
    /// A panel was closed.
    PanelClosed { panel: String },
    /// A tab was switched.
    TabSwitched { from: usize, to: usize },
    /// A command bar query was executed.
    QueryExecuted { query: String, duration_ms: f64 },
    /// The graph layout completed.
    GraphLayoutCompleted { node_count: usize, duration_ms: f64 },
    /// A cross-panel navigation occurred.
    Navigation { from_panel: String, to_panel: String, target: String },
    /// A finding was selected.
    FindingSelected { index: usize },
    /// A filter was applied.
    FilterApplied { filter_type: String, value: String },
}

/// Frame-time percentiles (p50, p95, p99) in milliseconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameTimePercentiles {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

impl TelemetryLog {
    /// Create a new empty telemetry log.
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS),
            frame_times: VecDeque::with_capacity(FRAME_TIME_WINDOW),
            session_start: None,
            last_timestamp: 0.0,
        }
    }

    /// Record a telemetry event. If the log is at capacity, the oldest event is dropped.
    pub fn record(&mut self, timestamp: f64, kind: TelemetryEventKind) {
        if self.session_start.is_none() {
            self.session_start = Some(timestamp);
        }
        self.last_timestamp = timestamp;

        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(TelemetryEvent { timestamp, kind });
    }

    /// Record a frame time in seconds. Maintains a rolling window.
    pub fn record_frame_time(&mut self, dt_seconds: f64) {
        if self.frame_times.len() >= FRAME_TIME_WINDOW {
            self.frame_times.pop_front();
        }
        self.frame_times.push_back(dt_seconds);
    }

    /// Compute frame-time percentiles over the rolling window.
    pub fn frame_time_percentiles(&self) -> FrameTimePercentiles {
        if self.frame_times.is_empty() {
            return FrameTimePercentiles::default();
        }

        let mut sorted: Vec<f64> = self.frame_times.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let len = sorted.len();
        FrameTimePercentiles {
            p50_ms: percentile_at(&sorted, len, 0.50) * 1000.0,
            p95_ms: percentile_at(&sorted, len, 0.95) * 1000.0,
            p99_ms: percentile_at(&sorted, len, 0.99) * 1000.0,
        }
    }

    /// Duration of the current session in seconds, or 0 if no events recorded.
    pub fn session_duration(&self) -> f64 {
        match self.session_start {
            Some(start) => self.last_timestamp - start,
            None => 0.0,
        }
    }

    /// Number of events in the log.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Number of frame-time samples in the rolling window.
    pub fn frame_sample_count(&self) -> usize {
        self.frame_times.len()
    }

    /// Iterator over all events (oldest first).
    pub fn events(&self) -> impl Iterator<Item = &TelemetryEvent> {
        self.events.iter()
    }

    /// The most recent N events (newest first).
    pub fn recent_events(&self, n: usize) -> Vec<&TelemetryEvent> {
        self.events.iter().rev().take(n).collect()
    }
}

impl Default for TelemetryLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the value at a given percentile (0.0..1.0) from a sorted slice.
fn percentile_at(sorted: &[f64], len: usize, p: f64) -> f64 {
    if len == 0 {
        return 0.0;
    }
    if len == 1 {
        return sorted[0];
    }
    let rank = p * (len as f64 - 1.0);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        let frac = rank - lower as f64;
        sorted[lower] * (1.0 - frac) + sorted[upper] * frac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_at_1000_events() {
        let mut log = TelemetryLog::new();
        for i in 0..1200 {
            log.record(
                i as f64,
                TelemetryEventKind::PanelOpened { panel: format!("p{}", i) },
            );
        }
        assert_eq!(log.event_count(), MAX_EVENTS);
        // Oldest events should have been dropped; first remaining should be event 200
        let first = log.events().next().expect("should have events");
        assert_eq!(first.timestamp, 200.0);
    }

    #[test]
    fn percentile_math_basic() {
        let mut log = TelemetryLog::new();
        // Insert 100 frame times: 1ms, 2ms, ..., 100ms (as seconds)
        for i in 1..=100 {
            log.record_frame_time(i as f64 / 1000.0);
        }
        let p = log.frame_time_percentiles();
        // p50 should be around 50ms
        assert!((p.p50_ms - 50.5).abs() < 1.0, "p50 = {}", p.p50_ms);
        // p95 should be around 95ms
        assert!((p.p95_ms - 95.05).abs() < 1.0, "p95 = {}", p.p95_ms);
        // p99 should be around 99ms
        assert!((p.p99_ms - 99.01).abs() < 1.0, "p99 = {}", p.p99_ms);
    }

    #[test]
    fn percentile_single_value() {
        let mut log = TelemetryLog::new();
        log.record_frame_time(0.016);
        let p = log.frame_time_percentiles();
        assert!((p.p50_ms - 16.0).abs() < 0.01);
        assert!((p.p95_ms - 16.0).abs() < 0.01);
        assert!((p.p99_ms - 16.0).abs() < 0.01);
    }

    #[test]
    fn percentile_empty() {
        let log = TelemetryLog::new();
        let p = log.frame_time_percentiles();
        assert_eq!(p.p50_ms, 0.0);
        assert_eq!(p.p95_ms, 0.0);
        assert_eq!(p.p99_ms, 0.0);
    }

    #[test]
    fn frame_time_window_rolls() {
        let mut log = TelemetryLog::new();
        for i in 0..400 {
            log.record_frame_time(i as f64 / 1000.0);
        }
        // Window should be capped at 300
        assert_eq!(log.frame_sample_count(), 300);
    }

    #[test]
    fn session_duration_tracks_first_and_last() {
        let mut log = TelemetryLog::new();
        assert_eq!(log.session_duration(), 0.0);

        log.record(10.0, TelemetryEventKind::PanelOpened { panel: "findings".to_string() });
        assert_eq!(log.session_duration(), 0.0); // only one event

        log.record(25.0, TelemetryEventKind::PanelClosed { panel: "findings".to_string() });
        assert!((log.session_duration() - 15.0).abs() < f64::EPSILON);

        log.record(100.0, TelemetryEventKind::PanelOpened { panel: "chains".to_string() });
        assert!((log.session_duration() - 90.0).abs() < f64::EPSILON);
    }

    #[test]
    fn recent_events_returns_newest_first() {
        let mut log = TelemetryLog::new();
        log.record(1.0, TelemetryEventKind::PanelOpened { panel: "a".to_string() });
        log.record(2.0, TelemetryEventKind::PanelOpened { panel: "b".to_string() });
        log.record(3.0, TelemetryEventKind::PanelOpened { panel: "c".to_string() });

        let recent = log.recent_events(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].timestamp, 3.0);
        assert_eq!(recent[1].timestamp, 2.0);
    }
}
