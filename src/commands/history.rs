use anyhow::Result;
use crate::{cli::HistoryArgs, storage::{paths::SelPaths, sqlite::TimelineDb}};

pub async fn execute(args: HistoryArgs) -> Result<()> {
    let paths = SelPaths::load()?;
    let db    = TimelineDb::open(&paths.db)?;
    let rows  = db.recent(args.limit)?;

    if rows.is_empty() {
        println!("No deployments yet. Run: sel-deploy run -- <command>");
        return Ok(());
    }

    println!("{:<26} {:<10} {:<5} {}", "Timestamp (UTC)", "Git", "Exit", "Hash");
    println!("{}", "─".repeat(72));
    for row in rows.iter().rev() {
        let ts   = &row.timestamp[..19].replace('T', " ");
        let git  = row.git_commit.as_deref().unwrap_or("—");
        let icon = if row.exit_code == 0 { "✔" } else { "✘" };
        let env  = row.environment.as_deref()
                       .map(|e| format!("[{}]", e)).unwrap_or_default();
        let hash_short = &row.attestation_hash[..row.attestation_hash.len().min(28)];
        println!("{:<26} {:<10} {}  {}... {}", ts, git, icon, hash_short, env);
    }
    println!("{}", "─".repeat(72));
    let total  = db.total()?;
    let oldest = db.oldest_timestamp()?;
    if let Some(ts) = oldest {
        println!("  Total: {}  │  First: {}", total, &ts[..10]);
    }
    Ok(())
}
