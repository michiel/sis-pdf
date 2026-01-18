/// Type 1 charstring analysis for detecting dangerous operators and exploit patterns

use tracing::{debug, instrument, warn};

/// Analysis results from charstring parsing
#[derive(Debug, Clone)]
pub struct CharstringAnalysis {
    pub max_stack_depth: usize,
    pub total_operators: usize,
    pub dangerous_ops: Vec<DangerousOperator>,
    pub has_blend_pattern: bool,
}

#[derive(Debug, Clone)]
pub struct DangerousOperator {
    pub position: usize,
    pub operator: String,
    pub context: String,
}

const MAX_SAFE_STACK_DEPTH: usize = 100;
const MAX_SAFE_OPERATORS: usize = 10_000;

/// Dangerous Type 1 operators that can be exploited
const DANGEROUS_OPERATORS: &[&str] = &[
    "callothersubr",
    "pop",
    "return",
    "put",
    "store",
    "blend",
];

/// Analyze Type 1 charstrings for dangerous patterns
#[instrument(skip(data), fields(data_len = data.len()))]
pub fn analyze_charstring(data: &[u8]) -> CharstringAnalysis {
    let mut analysis = CharstringAnalysis {
        max_stack_depth: 0,
        total_operators: 0,
        dangerous_ops: Vec::new(),
        has_blend_pattern: false,
    };

    // Try to parse charstrings from the data
    let charstrings = extract_charstrings(data);
    debug!(charstring_count = charstrings.len(), "Extracted charstrings");

    for (name, cs_data) in charstrings {
        analyze_single_charstring(&mut analysis, &name, cs_data);
    }

    // Detect BLEND exploit pattern: multiple callothersubr/return sequences
    analysis.has_blend_pattern = detect_blend_pattern(&analysis.dangerous_ops);

    if analysis.has_blend_pattern {
        warn!("BLEND exploit pattern detected in charstrings");
    }

    analysis
}

/// Extract charstring data from Type 1 font
fn extract_charstrings(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut charstrings = Vec::new();

    // Convert to string for parsing (Type 1 fonts are mostly ASCII)
    let text = String::from_utf8_lossy(data);

    // Look for charstring definitions
    // Pattern: /glyphname { charstring } ND or /glyphname { charstring } |-
    let mut i = 0;
    while i < text.len() {
        if let Some(start) = text[i..].find('/') {
            i += start;

            // Extract glyph name
            if let Some(space_pos) = text[i..].find(|c: char| c.is_whitespace() || c == '{') {
                let name = text[i + 1..i + space_pos].to_string();

                // Find charstring body between { }
                if let Some(body_start) = text[i..].find('{') {
                    if let Some(body_end) = text[i + body_start..].find('}') {
                        let body = &text[i + body_start + 1..i + body_start + body_end];
                        charstrings.push((name, body.as_bytes().to_vec()));
                        i += body_start + body_end + 1;
                        continue;
                    }
                }
            }

            i += 1;
        } else {
            break;
        }
    }

    charstrings
}

/// Analyze a single charstring
#[instrument(skip(analysis, data), fields(glyph = name, data_len = data.len()))]
fn analyze_single_charstring(
    analysis: &mut CharstringAnalysis,
    name: &str,
    data: Vec<u8>,
) {
    let text = String::from_utf8_lossy(&data);
    let tokens: Vec<&str> = text.split_whitespace().collect();

    let mut stack_depth: usize = 0;
    let mut max_depth: usize = 0;

    for (pos, token) in tokens.iter().enumerate() {
        analysis.total_operators += 1;

        // Check if it's a dangerous operator
        if DANGEROUS_OPERATORS.contains(token) {
            debug!(operator = token, position = pos, "Dangerous operator found");
            analysis.dangerous_ops.push(DangerousOperator {
                position: pos,
                operator: token.to_string(),
                context: format!("{}:{}", name, pos),
            });
        }

        // Simulate stack operations for depth tracking
        match *token {
            // Stack manipulation
            "pop" => stack_depth = stack_depth.saturating_sub(1),
            "exch" => {} // no net change
            "dup" => stack_depth += 1,
            "copy" | "index" => stack_depth += 1,
            "roll" => {} // no net change

            // Arithmetic operations (pop operands, push result)
            "add" | "sub" | "mul" | "div" | "neg" | "abs" => {
                stack_depth = stack_depth.saturating_sub(1);
            }

            // Comparison operations
            "eq" | "ne" | "gt" | "ge" | "lt" | "le" => {
                stack_depth = stack_depth.saturating_sub(1);
            }

            // Control flow
            "if" | "ifelse" => stack_depth = stack_depth.saturating_sub(1),

            // Type 1 charstring operators
            "rmoveto" | "rlineto" => stack_depth = stack_depth.saturating_sub(2),
            "rrcurveto" => stack_depth = stack_depth.saturating_sub(6),
            "closepath" | "endchar" => {}

            // Subroutine calls
            "callsubr" | "callothersubr" => stack_depth = stack_depth.saturating_sub(1),
            "return" => {} // may push values

            // Numbers push to stack
            token if token.parse::<f64>().is_ok() || token.parse::<i32>().is_ok() => {
                stack_depth += 1;
            }

            _ => {}
        }

        max_depth = max_depth.max(stack_depth);
    }

    analysis.max_stack_depth = analysis.max_stack_depth.max(max_depth);
}

/// Detect BLEND exploit pattern
///
/// The BLEND exploit uses multiple callothersubr/return sequences to corrupt memory.
/// We look for this specific pattern.
fn detect_blend_pattern(dangerous_ops: &[DangerousOperator]) -> bool {
    let mut callothersubr_count = 0;
    let mut return_count = 0;
    let mut blend_count = 0;

    for op in dangerous_ops {
        match op.operator.as_str() {
            "callothersubr" => callothersubr_count += 1,
            "return" => return_count += 1,
            "blend" => blend_count += 1,
            _ => {}
        }
    }

    // BLEND exploit pattern: multiple callothersubr + return sequences, or use of blend operator
    (callothersubr_count >= 3 && return_count >= 3) || blend_count > 0
}

/// Check if analysis indicates potential security issues
pub fn is_suspicious(analysis: &CharstringAnalysis) -> bool {
    analysis.max_stack_depth > MAX_SAFE_STACK_DEPTH
        || analysis.total_operators > MAX_SAFE_OPERATORS
        || !analysis.dangerous_ops.is_empty()
        || analysis.has_blend_pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_blend_pattern() {
        let mut ops = Vec::new();

        // Add multiple callothersubr and return
        for i in 0..4 {
            ops.push(DangerousOperator {
                position: i,
                operator: "callothersubr".to_string(),
                context: format!("test:{}", i),
            });
        }
        for i in 0..4 {
            ops.push(DangerousOperator {
                position: i + 4,
                operator: "return".to_string(),
                context: format!("test:{}", i + 4),
            });
        }

        assert!(detect_blend_pattern(&ops));
    }

    #[test]
    fn test_no_blend_pattern() {
        let ops = vec![DangerousOperator {
            position: 0,
            operator: "callothersubr".to_string(),
            context: "test:0".to_string(),
        }];

        assert!(!detect_blend_pattern(&ops));
    }

    #[test]
    fn test_blend_operator() {
        let ops = vec![DangerousOperator {
            position: 0,
            operator: "blend".to_string(),
            context: "test:0".to_string(),
        }];

        assert!(detect_blend_pattern(&ops));
    }

    #[test]
    fn test_analyze_simple_charstring() {
        let data = b"/.notdef { 0 0 rmoveto 100 100 rlineto closepath endchar } ND";
        let analysis = analyze_charstring(data);

        assert!(analysis.total_operators > 0);
        assert!(analysis.max_stack_depth > 0);
    }

    #[test]
    fn test_is_suspicious_excessive_stack() {
        let analysis = CharstringAnalysis {
            max_stack_depth: 150,
            total_operators: 100,
            dangerous_ops: Vec::new(),
            has_blend_pattern: false,
        };

        assert!(is_suspicious(&analysis));
    }

    #[test]
    fn test_is_suspicious_dangerous_ops() {
        let analysis = CharstringAnalysis {
            max_stack_depth: 10,
            total_operators: 100,
            dangerous_ops: vec![DangerousOperator {
                position: 0,
                operator: "callothersubr".to_string(),
                context: "test:0".to_string(),
            }],
            has_blend_pattern: false,
        };

        assert!(is_suspicious(&analysis));
    }
}
