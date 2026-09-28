//! Output formatting for findings: human-readable text (default) and JSON.

use crate::model::Finding;

pub fn print_text(findings: &[Finding]) {
    if findings.is_empty() {
        println!("debugslip: no derived-Debug secret leaks found");
        return;
    }
    for f in findings {
        println!(
            "[{}] {} {}:{} ({}): {}",
            f.severity, f.rule, f.file, f.line, f.field, f.message
        );
    }
    println!();
    println!("debugslip: {} finding(s)", findings.len());
}

pub fn print_json(findings: &[Finding]) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    println!("{json}");
    Ok(())
}
