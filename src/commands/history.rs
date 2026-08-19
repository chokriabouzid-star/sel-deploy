use anyhow::Result;

use crate::cli::HistoryArgs;
use sel_deploy::storage::paths::SelPaths;
use sel_deploy::storage::sqlite::{self, TimelineDb};
use sel_deploy::util::{command_line, ellipsize, prefix};

pub async fn execute(args: HistoryArgs) -> Result<i32> {
    let paths = SelPaths::load()?;
    let db = TimelineDb::open(&paths.db)?;
    let rows = db.recent(args.limit)?;

    if rows.is_empty() {
        println!("No deployments yet. Run: sel-deploy run -- <command>");
        println!("If JSON files exist, restore the index with: sel-deploy rebuild");
        return Ok(0);
    }

    println!(
        "{:<20} {:<28} {:<4} Hash",
        "Timestamp (UTC)", "Command", "Exit"
    );
    println!("{}", "─".repeat(88));
    for row in rows.iter().rev() {
        let ts = prefix(&row.timestamp, 19).replace('T', " ");
        let cmd = ellipsize(&command_line(&sqlite::command_from_row(&row.command)), 26);
        let icon = if row.exit_code == 0 { "✔" } else { "✘" };
        let env = match (row.environment.as_deref(), row.git_commit.as_deref()) {
            (Some(e), Some(g)) => format!("[{e} @{g}]"),
            (Some(e), None) => format!("[{e}]"),
            (None, Some(g)) => format!("[@{g}]"),
            (None, None) => String::new(),
        };
        let hash_short = prefix(&row.attestation_hash, 28);
        println!("{ts:<20} {cmd:<28} {icon}  {hash_short}... {env}");
    }
    println!("{}", "─".repeat(88));
    let total = db.total()?;
    let oldest = db.oldest_timestamp()?;
    if let Some(ts) = oldest {
        println!("  Total: {total}  │  First: {}", prefix(&ts, 10));
    }
    Ok(0)
}
