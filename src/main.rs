use clap::Parser;
use debugslip::model::Finding;
use debugslip::model::Severity;
use debugslip::report;
use std::path::PathBuf;
use std::process::ExitCode;

/// Flags a #[derive(Debug)] struct/enum with a sensitive-named field
/// (password, secret, token, api_key, ssn, credit_card, ...) typed as a
/// plain String/&str/Vec<u8> — not already wrapped in a known-safe
/// redacting type (SecretString, Secret<T>, Redacted<T>, ...).
#[derive(Parser, Debug)]
#[command(name = "debugslip", version, about)]
struct Cli {
    /// One or more .rs files or directories to scan (directories are
    /// walked recursively for .rs files). Multiple paths may be given.
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Emit findings as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Exit non-zero only if a finding at or above this severity exists.
    #[arg(long, value_enum, default_value = "medium")]
    fail_on: FailOn,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum FailOn {
    Medium,
    High,
    Never,
}

fn severity_at_least(f: &Finding, sev: Severity) -> bool {
    f.severity >= sev
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let findings = match debugslip::scan(&cli.paths) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("debugslip: error: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    if cli.json {
        if let Err(e) = report::print_json(&findings) {
            eprintln!("debugslip: error writing JSON: {e:#}");
            return ExitCode::FAILURE;
        }
    } else {
        report::print_text(&findings);
    }

    let should_fail = match cli.fail_on {
        FailOn::Never => false,
        FailOn::Medium => findings
            .iter()
            .any(|f| severity_at_least(f, Severity::Medium)),
        FailOn::High => findings
            .iter()
            .any(|f| severity_at_least(f, Severity::High)),
    };

    if should_fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
