use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sel-deploy")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Cryptographically chained deployment timeline — built on SEL Core")]
#[command(
    after_help = "Data directory: $SEL_DEPLOY_HOME or the platform user data dir.\n\
Exit codes: 0 ok · 1 failure / broken chain / failed command · 2 usage error"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate an Ed25519 signing keypair
    Keygen(KeygenArgs),
    /// Wrap and attest a deployment command
    Run(RunArgs),
    /// Show recent deployment history
    History(HistoryArgs),
    /// Query deployments around a specific time
    Timeline(TimelineArgs),
    /// Verify chain integrity (exits 1 if anything is wrong)
    Verify(VerifyArgs),
    /// Export attestations as JSON
    Export(ExportArgs),
    /// Rebuild the SQLite index from JSON attestations
    Rebuild(RebuildArgs),
}

#[derive(clap::Args)]
pub struct KeygenArgs {
    /// Overwrite existing key (previous public key is archived)
    #[arg(short, long)]
    pub force: bool,
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// Environment label (e.g. production, staging)
    #[arg(short, long)]
    pub env: Option<String>,
    /// Explicit compliance claims to record (never inferred).
    /// Repeatable. Allowed: soc2_cc8, change_management
    #[arg(long, value_name = "CLAIM")]
    pub claim: Vec<String>,
    /// Exit 0 even if the wrapped command failed (still records the real exit code)
    #[arg(long)]
    pub ignore_fail: bool,
    /// The deployment command to run
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(clap::Args)]
pub struct HistoryArgs {
    /// Number of recent deployments to show
    #[arg(short, long, default_value = "20")]
    pub limit: usize,
}

#[derive(clap::Args)]
pub struct TimelineArgs {
    /// Center timestamp (ISO8601, e.g. 2026-02-16T15:30:00)
    pub timestamp: String,
    /// Window in minutes (± around the timestamp)
    #[arg(short, long, default_value = "60")]
    pub window: i64,
}

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Path to a specific attestation JSON file
    #[arg(short, long)]
    pub file: Option<String>,
}

#[derive(clap::Args)]
pub struct ExportArgs {
    /// Export format (json only)
    #[arg(short, long, default_value = "json")]
    pub format: String,
    /// Output file (stdout if omitted)
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(clap::Args)]
pub struct RebuildArgs {}
