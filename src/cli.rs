use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sel-deploy")]
#[command(version = "0.1.0")]
#[command(about = "Cryptographically chained deployment timeline — built on SEL Core")]
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
    /// Verify chain integrity
    Verify(VerifyArgs),
    /// Export attestations as JSON
    Export(ExportArgs),
}

#[derive(clap::Args)]
pub struct KeygenArgs {
    /// Overwrite existing key
    #[arg(short, long)]
    pub force: bool,
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// Environment label (e.g. production, staging)
    #[arg(short, long)]
    pub env: Option<String>,
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
    /// Export format (json only in v0.1)
    #[arg(short, long, default_value = "json")]
    pub format: String,
    /// Output file (stdout if omitted)
    #[arg(short, long)]
    pub output: Option<String>,
}
