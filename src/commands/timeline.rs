use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};

use crate::cli::TimelineArgs;
use sel_deploy::storage::paths::SelPaths;
use sel_deploy::storage::sqlite::{self, TimelineDb};
use sel_deploy::util::{command_line, ellipsize, prefix};

pub async fn execute(args: TimelineArgs) -> Result<i32> {
    let centre: DateTime<Utc> = if args.timestamp.contains('+') || args.timestamp.ends_with('Z') {
        DateTime::parse_from_rfc3339(&args.timestamp)
            .context("Invalid RFC3339 timestamp")?
            .with_timezone(&Utc)
    } else {
        chrono::NaiveDateTime::parse_from_str(&args.timestamp, "%Y-%m-%dT%H:%M:%S")
            .or_else(|_| {
                chrono::NaiveDateTime::parse_from_str(&args.timestamp, "%Y-%m-%d %H:%M:%S")
            })
            .context("Invalid timestamp. Use ISO8601, e.g. 2026-02-16T15:30:00")?
            .and_utc()
    };

    let window = Duration::minutes(args.window);
    let paths = SelPaths::load()?;
    let db = TimelineDb::open(&paths.db)?;
    let rows = db.in_range(centre - window, centre + window)?;

    println!(
        "Deployments ±{} min of {} UTC\n",
        args.window,
        centre.format("%Y-%m-%d %H:%M:%S")
    );

    if rows.is_empty() {
        println!("  (none found — try --window <minutes> to widen)");
        return Ok(0);
    }

    println!(
        "{:<20} {:<28} {:<4} Hash",
        "Timestamp (UTC)", "Command", "Exit"
    );
    println!("{}", "─".repeat(88));
    for row in &rows {
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
    println!("  Found: {}", rows.len());
    Ok(0)
}
