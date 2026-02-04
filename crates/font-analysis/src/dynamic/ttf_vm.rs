/// TrueType Virtual Machine interpreter for hinting program analysis
///
/// This module implements a minimal TrueType VM to analyze hinting programs
/// for security issues. It tracks instruction counts, stack depth, and
/// detects suspicious patterns.
use std::collections::HashMap;
use std::fmt;
use tracing::{debug, instrument, warn};

use crate::model::{Confidence, FontAnalysisConfig, FontFinding, Severity};

/// TrueType VM execution limits (for security analysis)
const DEFAULT_MAX_INSTRUCTIONS_PER_GLYPH: usize = 50_000;
const DEFAULT_MAX_STACK_DEPTH: usize = 256;
const DEFAULT_MAX_LOOP_DEPTH: usize = 10;

#[derive(Debug, Clone, Copy)]
pub struct VmLimits {
    max_instructions_per_glyph: usize,
    max_stack_depth: usize,
    max_loop_depth: usize,
}

impl VmLimits {
    pub fn from_config(config: &FontAnalysisConfig) -> Self {
        let max_instructions = usize::try_from(config.max_charstring_ops)
            .unwrap_or(DEFAULT_MAX_INSTRUCTIONS_PER_GLYPH);
        let max_stack_depth = config.max_stack_depth.max(1);
        Self {
            max_instructions_per_glyph: max_instructions,
            max_stack_depth,
            max_loop_depth: DEFAULT_MAX_LOOP_DEPTH,
        }
    }
}

impl Default for VmLimits {
    fn default() -> Self {
        Self {
            max_instructions_per_glyph: DEFAULT_MAX_INSTRUCTIONS_PER_GLYPH,
            max_stack_depth: DEFAULT_MAX_STACK_DEPTH,
            max_loop_depth: DEFAULT_MAX_LOOP_DEPTH,
        }
    }
}

/// Errors observed while running the TrueType VM
#[derive(Debug)]
enum VmError {
    StackUnderflow,
    StackOverflow,
    InstructionBudgetExceeded(usize),
    UnexpectedEnd,
    DivisionByZero,
    UnmatchedIf,
    UnmatchedFdef,
}

impl VmError {
    fn kind(&self) -> &'static str {
        match self {
            VmError::StackUnderflow => "stack_underflow",
            VmError::StackOverflow => "stack_overflow",
            VmError::InstructionBudgetExceeded(_) => "instruction_budget_exceeded",
            VmError::UnexpectedEnd => "unexpected_end",
            VmError::DivisionByZero => "division_by_zero",
            VmError::UnmatchedIf => "unmatched_if",
            VmError::UnmatchedFdef => "unmatched_fdef",
        }
    }

    fn severity(&self) -> Severity {
        match self {
            VmError::StackUnderflow | VmError::StackOverflow => Severity::Low,
            _ => Severity::Medium,
        }
    }

    fn confidence(&self) -> Confidence {
        match self {
            VmError::StackUnderflow | VmError::StackOverflow => Confidence::Heuristic,
            _ => Confidence::Probable,
        }
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmError::StackUnderflow => write!(f, "Stack underflow"),
            VmError::StackOverflow => write!(f, "Stack overflow"),
            VmError::InstructionBudgetExceeded(count) => {
                write!(f, "Instruction budget exceeded: {} instructions", count)
            }
            VmError::UnexpectedEnd => write!(f, "Unexpected end of program"),
            VmError::DivisionByZero => write!(f, "Division by zero"),
            VmError::UnmatchedIf => write!(f, "Unmatched IF/ELSE block"),
            VmError::UnmatchedFdef => write!(f, "Unmatched FDEF/ENDF block"),
        }
    }
}

/// VM execution state (for future full VM execution)
#[allow(dead_code)]
#[derive(Debug)]
struct VMState {
    stack: Vec<i32>,
    instruction_count: usize,
    max_stack_depth: usize,
    loop_depth: usize,
    suspicious_patterns: Vec<String>,
    limits: VmLimits,
}

impl VMState {
    fn new(limits: VmLimits) -> Self {
        Self {
            stack: Vec::with_capacity(limits.max_stack_depth),
            instruction_count: 0,
            max_stack_depth: 0,
            loop_depth: 0,
            suspicious_patterns: Vec::new(),
            limits,
        }
    }

    fn push(&mut self, value: i32) -> Result<(), VmError> {
        if self.stack.len() >= self.limits.max_stack_depth {
            return Err(VmError::StackOverflow);
        }
        self.stack.push(value);
        self.max_stack_depth = self.max_stack_depth.max(self.stack.len());
        Ok(())
    }

    fn pop(&mut self) -> Result<i32, VmError> {
        self.stack.pop().ok_or(VmError::StackUnderflow)
    }

    fn check_budget(&mut self) -> Result<(), VmError> {
        self.instruction_count += 1;
        if self.instruction_count > self.limits.max_instructions_per_glyph {
            return Err(VmError::InstructionBudgetExceeded(self.instruction_count));
        }
        Ok(())
    }
}

/// Analyze TrueType hinting program
#[cfg(feature = "dynamic")]
#[instrument(skip(program), fields(program_len = program.len()))]
pub fn analyze_hinting_program(program: &[u8], limits: &VmLimits) -> Vec<FontFinding> {
    let mut findings = Vec::new();

    if program.is_empty() {
        debug!("Empty hinting program, skipping analysis");
        return findings;
    }

    // Parse and execute the program
    let mut state = VMState::new(*limits);
    if let Err(err) = execute_program(&mut state, program) {
        warn!(
            error = %err,
            instruction_count = state.instruction_count,
            max_stack_depth = state.max_stack_depth,
            "Hinting program execution failed"
        );
        let mut meta = HashMap::new();
        meta.insert("error_kind".to_string(), err.kind().to_string());
        meta.insert("error_message".to_string(), err.to_string());
        meta.insert("instruction_count".to_string(), state.instruction_count.to_string());
        meta.insert("max_stack_depth".to_string(), state.max_stack_depth.to_string());

        findings.push(FontFinding {
            kind: "font.ttf_hinting_suspicious".to_string(),
            severity: err.severity(),
            confidence: err.confidence(),
            title: "Suspicious TrueType hinting program".to_string(),
            description: format!("Hinting program triggered security check: {}", err),
            meta,
        });
    }

    // Check for suspicious patterns even if execution succeeded
    if !state.suspicious_patterns.is_empty() {
        let mut meta = HashMap::new();
        meta.insert("patterns".to_string(), state.suspicious_patterns.join(", "));
        meta.insert("instruction_count".to_string(), state.instruction_count.to_string());

        findings.push(FontFinding {
            kind: "font.ttf_hinting_suspicious".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            title: "Suspicious patterns in hinting program".to_string(),
            description: "Hinting program contains unusual patterns".to_string(),
            meta,
        });
    }

    findings
}

#[cfg(not(feature = "dynamic"))]
pub fn analyze_hinting_program(_program: &[u8], _limits: &VmLimits) -> Vec<FontFinding> {
    Vec::new()
}

/// Execute TrueType bytecode program
#[instrument(skip_all, fields(program_len = program.len()))]
fn execute_program(state: &mut VMState, program: &[u8]) -> Result<(), VmError> {
    let mut pc = 0; // Program counter

    debug!("Starting TrueType VM execution");

    while pc < program.len() {
        state.check_budget()?;

        let opcode = program[pc];
        pc += 1;

        // Simplified instruction set - focusing on security-relevant operations
        match opcode {
            // Push instructions
            0xB0..=0xB7 => {
                // PUSHB[abc]: Push bytes
                let count = ((opcode - 0xB0) + 1) as usize;
                for _ in 0..count {
                    if pc >= program.len() {
                        return Err(VmError::UnexpectedEnd);
                    }
                    state.push(program[pc] as i32)?;
                    pc += 1;
                }
            }
            0xB8..=0xBF => {
                // PUSHW[abc]: Push words
                let count = ((opcode - 0xB8) + 1) as usize;
                for _ in 0..count {
                    if pc + 1 >= program.len() {
                        return Err(VmError::UnexpectedEnd);
                    }
                    let word = i16::from_be_bytes([program[pc], program[pc + 1]]);
                    state.push(word as i32)?;
                    pc += 2;
                }
            }

            // Stack manipulation
            0x20 => {
                // DUP: Duplicate top stack element
                let top = state.pop()?;
                state.push(top)?;
                state.push(top)?;
            }
            0x21 => {
                // POP: Pop top stack element
                state.pop()?;
            }
            0x22 => {
                // CLEAR: Clear the stack
                state.stack.clear();
            }
            0x23 => {
                // SWAP: Swap top two elements
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(a)?;
                state.push(b)?;
            }
            0x24 => {
                // DEPTH: Push current stack depth
                state.push(state.stack.len() as i32)?;
            }

            // Arithmetic operations
            0x60 => {
                // ADD
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(a.wrapping_add(b))?;
            }
            0x61 => {
                // SUB
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(a.wrapping_sub(b))?;
            }
            0x62 => {
                // DIV
                let b = state.pop()?;
                let a = state.pop()?;
                if b == 0 {
                    return Err(VmError::DivisionByZero);
                }
                state.push(a / b)?;
            }
            0x63 => {
                // MUL
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(a.wrapping_mul(b))?;
            }
            0x64 => {
                // ABS
                let a = state.pop()?;
                state.push(a.abs())?;
            }
            0x65 => {
                // NEG
                let a = state.pop()?;
                state.push(-a)?;
            }

            // Comparison operations
            0x50 => {
                // LT: Less than
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(if a < b { 1 } else { 0 })?;
            }
            0x51 => {
                // LTEQ: Less than or equal
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(if a <= b { 1 } else { 0 })?;
            }
            0x52 => {
                // GT: Greater than
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(if a > b { 1 } else { 0 })?;
            }
            0x53 => {
                // GTEQ: Greater than or equal
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(if a >= b { 1 } else { 0 })?;
            }
            0x54 => {
                // EQ: Equal
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(if a == b { 1 } else { 0 })?;
            }
            0x55 => {
                // NEQ: Not equal
                let b = state.pop()?;
                let a = state.pop()?;
                state.push(if a != b { 1 } else { 0 })?;
            }

            // Control flow
            0x58 => {
                // IF: Conditional
                let condition = state.pop()?;
                if condition == 0 {
                    // Skip to ELSE or EIF
                    pc = skip_to_else_or_eif(program, pc)?;
                }
            }
            0x1B => {
                // ELSE: Else clause
                // Skip to EIF
                pc = skip_to_eif(program, pc)?;
            }
            0x59 => {
                // EIF: End if
                // No operation needed
            }

            // Loop detection
            0x2A => {
                // LOOPCALL: Loop and call function
                state.loop_depth += 1;
                if state.loop_depth > state.limits.max_loop_depth {
                    state.suspicious_patterns.push("Deep loop nesting".to_string());
                }
                let _iterations = state.pop()?;
                let _function = state.pop()?;
                // Note: We don't actually execute the loop to avoid complexity
                state.loop_depth = state.loop_depth.saturating_sub(1);
            }

            // Function calls (potential security risk)
            0x2B => {
                // CALL: Call function
                let _function = state.pop()?;
                state.suspicious_patterns.push("Function call".to_string());
                // Don't actually execute to avoid infinite recursion
            }
            0x2C => {
                // FDEF: Function definition
                // Skip function body
                pc = skip_to_endf(program, pc)?;
            }
            0x2D => {
                // ENDF: End function definition
                // No operation needed
            }

            // No-ops and ignored instructions
            0x7F => {
                // AA: Adjust angle (no-op for security analysis)
            }
            0x7E => {
                // SANGW: Set angle weight (no-op)
            }

            _ => {
                // Unknown instruction - potentially suspicious
                state.suspicious_patterns.push(format!(
                    "Unknown opcode 0x{:02X} at offset {}",
                    opcode,
                    pc - 1
                ));
            }
        }
    }

    Ok(())
}

/// Skip to ELSE or EIF instruction
fn skip_to_else_or_eif(program: &[u8], mut pc: usize) -> Result<usize, VmError> {
    let mut depth = 1;
    while pc < program.len() && depth > 0 {
        match program[pc] {
            0x58 => depth += 1, // IF
            0x1B => {
                // ELSE
                if depth == 1 {
                    return Ok(pc + 1);
                }
            }
            0x59 => {
                // EIF
                depth -= 1;
                if depth == 0 {
                    return Ok(pc + 1);
                }
            }
            _ => {}
        }
        pc += 1;
    }
    Err(VmError::UnmatchedIf)
}

/// Skip to EIF instruction
fn skip_to_eif(program: &[u8], mut pc: usize) -> Result<usize, VmError> {
    let mut depth = 1;
    while pc < program.len() && depth > 0 {
        match program[pc] {
            0x58 => depth += 1, // IF
            0x59 => {
                // EIF
                depth -= 1;
                if depth == 0 {
                    return Ok(pc + 1);
                }
            }
            _ => {}
        }
        pc += 1;
    }
    Err(VmError::UnmatchedIf)
}

/// Skip to ENDF instruction
fn skip_to_endf(program: &[u8], mut pc: usize) -> Result<usize, VmError> {
    let mut depth = 1;
    while pc < program.len() && depth > 0 {
        match program[pc] {
            0x2C => depth += 1, // FDEF
            0x2D => {
                // ENDF
                depth -= 1;
                if depth == 0 {
                    return Ok(pc + 1);
                }
            }
            _ => {}
        }
        pc += 1;
    }
    Err(VmError::UnmatchedFdef)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_push_pop() -> Result<(), VmError> {
        let mut state = VMState::new(VmLimits::default());
        state.push(42)?;
        state.push(100)?;
        assert_eq!(state.pop()?, 100);
        assert_eq!(state.pop()?, 42);
        Ok(())
    }

    #[test]
    fn test_vm_stack_overflow() -> Result<(), VmError> {
        let limits = VmLimits::default();
        let mut state = VMState::new(limits);
        for i in 0..limits.max_stack_depth {
            state.push(i as i32)?;
        }
        assert!(state.push(1000).is_err());
        Ok(())
    }

    #[test]
    fn test_vm_stack_underflow() {
        let mut state = VMState::new(VmLimits::default());
        assert!(state.pop().is_err());
    }

    #[test]
    fn test_vm_budget() {
        let mut state = VMState::new(VmLimits::default());
        state.instruction_count = state.limits.max_instructions_per_glyph;
        assert!(state.check_budget().is_err());
    }

    #[test]
    #[cfg(feature = "dynamic")]
    fn test_simple_program() -> Result<(), VmError> {
        // PUSHB[0] 42, PUSHB[0] 100, ADD
        let program = vec![0xB0, 42, 0xB0, 100, 0x60];
        let mut state = VMState::new(VmLimits::default());
        execute_program(&mut state, &program)?;
        assert_eq!(state.pop()?, 142);
        Ok(())
    }

    #[test]
    #[cfg(feature = "dynamic")]
    fn test_division_by_zero() {
        // PUSHB[0] 100, PUSHB[0] 0, DIV
        let program = vec![0xB0, 100, 0xB0, 0, 0x62];
        let mut state = VMState::new(VmLimits::default());
        assert!(execute_program(&mut state, &program).is_err());
    }

    #[test]
    #[cfg(feature = "dynamic")]
    fn test_excessive_instructions() {
        // Create a program that would exceed instruction budget
        let mut program = Vec::new();
        for _ in 0..60_000 {
            program.push(0xB0); // PUSHB[0]
            program.push(1);
        }
        let findings = analyze_hinting_program(&program, &VmLimits::default());
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.kind == "font.ttf_hinting_suspicious"));
    }
}
