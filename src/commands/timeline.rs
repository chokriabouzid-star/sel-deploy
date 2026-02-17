use anyhow::{Result, Context};
use chrono::{DateTime, Utc, Duration};
use crate::{cli::TimelineArgs, storage::{paths::SelPaths, sqlite::TimelineDb}};

pub async fn execute(args: TimelineArgs) -> Result<()> {
    let centre: DateTime<Utc> = if args.timestamp.contains('+')
        || args.timestamp.ends_with('Z')
    {
        DateTime::parse_from_rfc3339(&args.timestamp)
            .context("Invalid RFC3339 timestamp")?
            .with_timezone(&Utc)
    } else {
        chrono::NaiveDateTime::parse_from_str(&args.timestamp, "%Y-%m-%dT%H:%M:%S")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(&args.timestamp, "%Y-%m-%d %H:%M:%S"))
            .context("Invalid timestamp. Use ISO8601, e.g. 2026-02-16T15:30:00")?
            .and_utc()
    };

    let window = Duration::minutes(args.window);
    let paths  = SelPaths::load()?;
    let db     = TimelineDb::open(&paths.db)?;
    let rows   = db.in_range(centre - window, centre + window)?;

    println!(
        "Deployments ±{} min of {} UTC\n",
        args.window,
        centre.format("%Y-%m-%d %H:%M:%S")
    );

    if rows.is_empty() {
        println!("  (none found — try --window <minutes> to widen)");
        return Ok(());
    }

    println!("{:<26} {:<10} {:<5} {}", "Timestamp (UTC)", "Git", "Exit", "Hash");
    println!("{}", "─".repeat(72));
    for row in &rows {
        let ts         = &row.timestamp[..19].replace('T', " ");
        let git        = row.git_commit.as_deref().unwrap_or("—");
        let icon       = if row.exit_code == 0 { "✔" } else { "✘" };
        let env        = row.environment.as_deref()
                            .map(|e| format!("[{}]", e)).unwrap_or_default();
        let hash_short = &row.attestation_hash[..row.attestation_hash.len().min(28)];
        println!("{:<26} {:<10} {}  {}... {}", ts, git, icon, hash_short, env);
    }
    println!("{}", "─".repeat(72));
    println!("  Found: {}", rows.len());
    Ok(())
}
