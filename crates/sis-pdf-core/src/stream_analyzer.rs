#[derive(Debug, Clone)]
pub struct StreamAnalysisState {
    pub bytes_seen: usize,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ThreatDetected {
    pub kind: String,
    pub reason: String,
}

pub struct StreamAnalyzer {
    buffer: Vec<u8>,
    max_buffer: usize,
    indicators: Vec<String>,
}

impl StreamAnalyzer {
    pub fn new(max_buffer: usize) -> Self {
        Self { buffer: Vec::new(), max_buffer, indicators: Vec::new() }
    }

    pub fn analyze_chunk(&mut self, chunk: &[u8]) -> StreamAnalysisState {
        if chunk.len() >= self.max_buffer {
            self.buffer = chunk[chunk.len() - self.max_buffer..].to_vec();
        } else {
            let total = self.buffer.len() + chunk.len();
            if total > self.max_buffer {
                let drop_len = total - self.max_buffer;
                self.buffer.drain(0..drop_len);
            }
            self.buffer.extend_from_slice(chunk);
        }
        let markers = [
            b"/JavaScript".as_slice(),
            b"/OpenAction".as_slice(),
            b"/Launch".as_slice(),
            b"/URI".as_slice(),
        ];
        for m in markers {
            if self.buffer.windows(m.len()).any(|w| w == m) {
                let s = String::from_utf8_lossy(m).to_string();
                if !self.indicators.contains(&s) {
                    self.indicators.push(s);
                }
            }
        }
        StreamAnalysisState { bytes_seen: self.buffer.len(), indicators: self.indicators.clone() }
    }

    pub fn early_terminate(&self, state: &StreamAnalysisState) -> Option<ThreatDetected> {
        for indicator in &state.indicators {
            if indicator == "/JavaScript" || indicator == "/Launch" || indicator == "/OpenAction" {
                return Some(ThreatDetected {
                    kind: "stream_indicator".into(),
                    reason: format!("Found indicator {}", indicator),
                });
            }
        }
        None
    }
}
