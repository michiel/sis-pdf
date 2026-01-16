use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Zero-cost profiler that tracks scan performance metrics
///
/// When disabled (default), all operations are inlined and optimized away.
/// When enabled via CLI flags, collects detailed timing and statistics.
#[derive(Clone)]
pub struct Profiler {
    enabled: Arc<AtomicBool>,
    data: Arc<Mutex<ProfileData>>,
}

#[derive(Default)]
struct ProfileData {
    start: Option<Instant>,
    phases: Vec<PhaseRecord>,
    detectors: Vec<DetectorRecord>,
    current_phase: Option<PhaseRecord>,
    current_detector: Option<DetectorRecord>,
}

#[derive(Clone)]
struct PhaseRecord {
    name: String,
    start: Instant,
    duration: Option<Duration>,
}

#[derive(Clone)]
struct DetectorRecord {
    id: String,
    cost: String,
    start: Instant,
    duration: Option<Duration>,
    findings_count: usize,
}

/// Complete profile report with all collected metrics
#[derive(Debug, Clone)]
pub struct ProfileReport {
    pub total_duration_ms: u64,
    pub phases: Vec<PhaseInfo>,
    pub detectors: Vec<DetectorInfo>,
    pub document: DocumentInfo,
}

#[derive(Debug, Clone)]
pub struct PhaseInfo {
    pub name: String,
    pub duration_ms: u64,
    pub percentage: f64,
}

#[derive(Debug, Clone)]
pub struct DetectorInfo {
    pub id: String,
    pub cost: String,
    pub duration_ms: u64,
    pub findings_count: usize,
    pub percentage: f64,
}

#[derive(Debug, Clone, Default)]
pub struct DocumentInfo {
    pub file_size_bytes: u64,
    pub object_count: usize,
    pub stream_count: usize,
    pub page_count: usize,
}

impl Profiler {
    /// Create a new profiler (disabled by default)
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            data: Arc::new(Mutex::new(ProfileData::default())),
        }
    }

    /// Enable profiling
    #[inline]
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
        if let Ok(mut data) = self.data.lock() {
            data.start = Some(Instant::now());
        }
    }

    /// Check if profiling is enabled
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Begin a named phase (parse, detection, reporting, etc.)
    #[inline(always)]
    pub fn begin_phase(&self, name: &str) {
        if !self.is_enabled() {
            return;
        }

        if let Ok(mut data) = self.data.lock() {
            // End previous phase if any
            if let Some(mut phase) = data.current_phase.take() {
                phase.duration = Some(phase.start.elapsed());
                data.phases.push(phase);
            }

            data.current_phase = Some(PhaseRecord {
                name: name.to_string(),
                start: Instant::now(),
                duration: None,
            });
        }
    }

    /// End the current phase
    #[inline(always)]
    pub fn end_phase(&self) {
        if !self.is_enabled() {
            return;
        }

        if let Ok(mut data) = self.data.lock() {
            if let Some(mut phase) = data.current_phase.take() {
                phase.duration = Some(phase.start.elapsed());
                data.phases.push(phase);
            }
        }
    }

    /// Begin detector execution
    #[inline(always)]
    pub fn begin_detector(&self, id: &str, cost: &str) {
        if !self.is_enabled() {
            return;
        }

        if let Ok(mut data) = self.data.lock() {
            data.current_detector = Some(DetectorRecord {
                id: id.to_string(),
                cost: cost.to_string(),
                start: Instant::now(),
                duration: None,
                findings_count: 0,
            });
        }
    }

    /// End detector execution
    #[inline(always)]
    pub fn end_detector(&self, findings_count: usize) {
        if !self.is_enabled() {
            return;
        }

        if let Ok(mut data) = self.data.lock() {
            if let Some(mut detector) = data.current_detector.take() {
                detector.duration = Some(detector.start.elapsed());
                detector.findings_count = findings_count;
                data.detectors.push(detector);
            }
        }
    }

    /// Record a completed detector execution with explicit duration
    /// This is useful for parallel execution where timing is captured separately
    #[inline(always)]
    pub fn record_detector(&self, id: &str, cost: &str, duration: Duration, findings_count: usize) {
        if !self.is_enabled() {
            return;
        }

        if let Ok(mut data) = self.data.lock() {
            data.detectors.push(DetectorRecord {
                id: id.to_string(),
                cost: cost.to_string(),
                start: Instant::now(), // Not used when duration is explicitly set
                duration: Some(duration),
                findings_count,
            });
        }
    }

    /// Finalize and generate the profile report
    pub fn finalize(&self, doc_info: DocumentInfo) -> Option<ProfileReport> {
        if !self.is_enabled() {
            return None;
        }

        let data = self.data.lock().ok()?;
        let start = data.start?;
        let total_duration = start.elapsed();
        let total_ms = total_duration.as_millis() as u64;

        // Build phase info
        let phases: Vec<PhaseInfo> = data
            .phases
            .iter()
            .filter_map(|p| {
                let duration_ms = p.duration?.as_millis() as u64;
                Some(PhaseInfo {
                    name: p.name.clone(),
                    duration_ms,
                    percentage: (duration_ms as f64 / total_ms as f64) * 100.0,
                })
            })
            .collect();

        // Build detector info
        let mut detectors: Vec<DetectorInfo> = data
            .detectors
            .iter()
            .filter_map(|d| {
                let duration_ms = d.duration?.as_millis() as u64;
                Some(DetectorInfo {
                    id: d.id.clone(),
                    cost: d.cost.clone(),
                    duration_ms,
                    findings_count: d.findings_count,
                    percentage: (duration_ms as f64 / total_ms as f64) * 100.0,
                })
            })
            .collect();

        // Sort detectors by duration (descending)
        detectors.sort_by(|a, b| b.duration_ms.cmp(&a.duration_ms));

        Some(ProfileReport {
            total_duration_ms: total_ms,
            phases,
            detectors,
            document: doc_info,
        })
    }
}

impl Default for Profiler {
    fn default() -> Self {
        Self::new()
    }
}

/// Format profile report as human-readable text
pub fn format_text(report: &ProfileReport) -> String {
    let mut output = String::new();

    output.push_str("Scan Profile Report\n");
    output.push_str("===================\n");
    output.push_str(&format!("Total Time: {:.3}s\n\n", report.total_duration_ms as f64 / 1000.0));

    // Phase breakdown
    if !report.phases.is_empty() {
        output.push_str("Phase Breakdown:\n");
        for phase in &report.phases {
            output.push_str(&format!(
                "  {:.<20} {:>8.3}s  ({:>5.1}%)\n",
                phase.name,
                phase.duration_ms as f64 / 1000.0,
                phase.percentage
            ));
        }
        output.push('\n');
    }

    // Detector performance (top 10)
    if !report.detectors.is_empty() {
        output.push_str("Detector Performance:\n");
        let top_detectors = report.detectors.iter().take(10);
        for (i, detector) in top_detectors.enumerate() {
            let bar_width = 20;
            let filled = ((detector.percentage / 100.0) * bar_width as f64) as usize;
            let filled = filled.min(bar_width);
            let bar = format!(
                "[{}{}]",
                "█".repeat(filled),
                " ".repeat(bar_width - filled)
            );

            output.push_str(&format!(
                "  {:2}. {:.<30} {:>7}ms  {:>3} findings  {} {:>5.1}%\n",
                i + 1,
                detector.id,
                detector.duration_ms,
                detector.findings_count,
                bar,
                detector.percentage
            ));
        }

        if report.detectors.len() > 10 {
            output.push_str(&format!("  ... and {} more\n", report.detectors.len() - 10));
        }
        output.push('\n');
    }

    // Document stats
    output.push_str("Document Stats:\n");
    output.push_str(&format!(
        "  Size:     {:.1} MB\n",
        report.document.file_size_bytes as f64 / 1_000_000.0
    ));
    output.push_str(&format!("  Objects:  {}\n", report.document.object_count));
    output.push_str(&format!("  Streams:  {}\n", report.document.stream_count));
    output.push_str(&format!("  Pages:    {}\n", report.document.page_count));
    output.push('\n');

    // Recommendations
    let recommendations = analyze_profile(report);
    if !recommendations.is_empty() {
        output.push_str("Recommendations:\n");
        for rec in recommendations {
            let icon = match rec.level.as_str() {
                "warning" => "⚠",
                "info" => "ℹ",
                _ => "•",
            };
            output.push_str(&format!("  {} {}\n", icon, rec.message));
        }
        output.push('\n');
    }

    output
}

/// Format profile report as JSON
pub fn format_json(report: &ProfileReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

struct Recommendation {
    level: String,
    message: String,
}

/// Analyze profile and generate recommendations
fn analyze_profile(report: &ProfileReport) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();

    // Check for slow detectors that might need reclassification
    for detector in &report.detectors {
        if detector.duration_ms > 1000 && detector.cost != "Expensive" {
            recommendations.push(Recommendation {
                level: "warning".to_string(),
                message: format!(
                    "Detector '{}' took {}ms but is marked as {}. Consider using --fast for routine scans.",
                    detector.id,
                    detector.duration_ms,
                    detector.cost
                ),
            });
        }

        // Check if a detector took majority of time
        if detector.percentage > 50.0 {
            recommendations.push(Recommendation {
                level: "info".to_string(),
                message: format!(
                    "Detector '{}' took {:.1}% of scan time. Use --fast to skip expensive detectors.",
                    detector.id, detector.percentage
                ),
            });
        }
    }

    // Check overall scan speed
    if report.total_duration_ms > 5000 {
        recommendations.push(Recommendation {
            level: "warning".to_string(),
            message: format!(
                "Scan took {:.1}s. Consider using --fast for routine analysis or --deep only when needed.",
                report.total_duration_ms as f64 / 1000.0
            ),
        });
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    fn build_sample_report() -> ProfileReport {
        ProfileReport {
            total_duration_ms: 120,
            phases: vec![
                PhaseInfo {
                    name: "parse".to_string(),
                    duration_ms: 40,
                    percentage: 33.3,
                },
                PhaseInfo {
                    name: "detect".to_string(),
                    duration_ms: 80,
                    percentage: 66.7,
                },
            ],
            detectors: vec![DetectorInfo {
                id: "js_detector".to_string(),
                cost: "Moderate".to_string(),
                duration_ms: 80,
                findings_count: 2,
                percentage: 66.7,
            }],
            document: DocumentInfo {
                file_size_bytes: 1024,
                object_count: 12,
                stream_count: 4,
                page_count: 2,
            },
        }
    }

    #[test]
    fn profiler_records_phases_and_detectors() {
        let profiler = Profiler::new();
        profiler.enable();
        profiler.begin_phase("parse");
        thread::sleep(Duration::from_millis(3));
        profiler.end_phase();
        profiler.begin_phase("detection");
        thread::sleep(Duration::from_millis(3));
        profiler.end_phase();

        profiler.begin_detector("d1", "Cheap");
        thread::sleep(Duration::from_millis(1));
        profiler.end_detector(1);
        profiler.begin_detector("d2", "Expensive");
        thread::sleep(Duration::from_millis(1));
        profiler.end_detector(0);

        let report = profiler.finalize(DocumentInfo {
            file_size_bytes: 2048,
            object_count: 8,
            stream_count: 2,
            page_count: 1,
        });
        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.document.file_size_bytes, 2048);
        assert!(report.total_duration_ms >= 6);
        assert!(report.phases.len() >= 2);
        assert!(report.detectors.len() >= 2);
    }

    #[test]
    fn format_text_includes_sections() {
        let report = build_sample_report();
        let text = format_text(&report);
        assert!(text.contains("Scan Profile Report"));
        assert!(text.contains("Phase Breakdown"));
        assert!(text.contains("Detector Performance"));
        assert!(text.contains("Document Stats"));
    }

    #[test]
    fn format_json_outputs_valid_data() {
        let report = build_sample_report();
        let json = format_json(&report).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["total_duration_ms"], 120);
        assert!(parsed["phases"].is_array());
    }
}

// Implement Serialize/Deserialize for ProfileReport
impl serde::Serialize for ProfileReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ProfileReport", 4)?;
        state.serialize_field("total_duration_ms", &self.total_duration_ms)?;
        state.serialize_field("phases", &self.phases)?;
        state.serialize_field("detectors", &self.detectors)?;
        state.serialize_field("document", &self.document)?;
        state.end()
    }
}

impl serde::Serialize for PhaseInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PhaseInfo", 3)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("duration_ms", &self.duration_ms)?;
        state.serialize_field("percentage", &self.percentage)?;
        state.end()
    }
}

impl serde::Serialize for DetectorInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DetectorInfo", 5)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("cost", &self.cost)?;
        state.serialize_field("duration_ms", &self.duration_ms)?;
        state.serialize_field("findings_count", &self.findings_count)?;
        state.serialize_field("percentage", &self.percentage)?;
        state.end()
    }
}

impl serde::Serialize for DocumentInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DocumentInfo", 4)?;
        state.serialize_field("file_size_bytes", &self.file_size_bytes)?;
        state.serialize_field("object_count", &self.object_count)?;
        state.serialize_field("stream_count", &self.stream_count)?;
        state.serialize_field("page_count", &self.page_count)?;
        state.end()
    }
}
