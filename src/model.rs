//! Data model: findings and severity, shared by rules/report.

use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Severity {
    Info,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    /// The field's name (e.g. `password`) — kept as its own column for
    /// grep-ability, the way sibling packages surface their own
    /// "the interesting name" field.
    pub field: String,
    pub message: String,
}
