use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;

use crate::attestation::model::DeploymentAttestation;

pub struct TimelineDb {
    conn: Connection,
}

impl TimelineDb {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("Cannot open timeline.db")?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS attestations (
                id               TEXT PRIMARY KEY,
                timestamp        TEXT NOT NULL,
                command          TEXT,
                command_hash     TEXT NOT NULL,
                git_commit       TEXT,
                environment      TEXT,
                exit_code        INTEGER NOT NULL,
                attestation_hash TEXT UNIQUE NOT NULL,
                previous_hash    TEXT,
                signer_key_id    TEXT NOT NULL,
                cwd              TEXT,
                actor            TEXT,
                hostname         TEXT,
                duration_ms      INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_ts  ON attestations(timestamp);
            CREATE INDEX IF NOT EXISTS idx_git ON attestations(git_commit);
        ",
        )
        .context("Cannot initialize database")?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn insert(&self, a: &DeploymentAttestation) -> Result<()> {
        let command_json = serde_json::to_string(&a.command).unwrap_or_default();
        self.conn
            .execute(
                "INSERT OR IGNORE INTO attestations
             (id,timestamp,command,command_hash,git_commit,environment,
              exit_code,attestation_hash,previous_hash,signer_key_id,
              cwd,actor,hostname,duration_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    a.id,
                    a.timestamp.to_rfc3339(),
                    command_json,
                    a.command_hash,
                    a.git_commit,
                    a.environment,
                    a.exit_code,
                    a.attestation_hash,
                    a.previous_hash,
                    a.signer.key_id,
                    a.cwd,
                    a.actor,
                    a.hostname,
                    a.duration_ms.map(|n| n as i64),
                ],
            )
            .context("Cannot insert attestation")?;
        Ok(())
    }

    /// Wipe the index and reload from JSON (source of truth).
    pub fn rebuild_from(&mut self, atts: &[DeploymentAttestation]) -> Result<usize> {
        let tx = self.conn.transaction().context("begin rebuild")?;
        tx.execute("DELETE FROM attestations", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO attestations
             (id,timestamp,command,command_hash,git_commit,environment,
              exit_code,attestation_hash,previous_hash,signer_key_id,
              cwd,actor,hostname,duration_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            )?;
            for a in atts {
                let command_json = serde_json::to_string(&a.command).unwrap_or_default();
                stmt.execute(params![
                    a.id,
                    a.timestamp.to_rfc3339(),
                    command_json,
                    a.command_hash,
                    a.git_commit,
                    a.environment,
                    a.exit_code,
                    a.attestation_hash,
                    a.previous_hash,
                    a.signer.key_id,
                    a.cwd,
                    a.actor,
                    a.hostname,
                    a.duration_ms.map(|n| n as i64),
                ])?;
            }
        }
        tx.commit().context("commit rebuild")?;
        Ok(atts.len())
    }

    pub fn last_hash(&self) -> Result<Option<String>> {
        let mut st = self.conn.prepare(
            "SELECT attestation_hash FROM attestations
             ORDER BY timestamp ASC, id ASC",
        )?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        let mut last = None;
        for row in rows {
            last = Some(row?);
        }
        Ok(last)
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<Row>> {
        let mut st = self.conn.prepare(
            "SELECT id,timestamp,git_commit,exit_code,attestation_hash,environment,command
             FROM attestations ORDER BY timestamp DESC, id DESC LIMIT ?1",
        )?;
        let rows = st
            .query_map([limit as i64], map_row)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Row>> {
        let mut st = self.conn.prepare(
            "SELECT id,timestamp,git_commit,exit_code,attestation_hash,environment,command
             FROM attestations WHERE timestamp>=?1 AND timestamp<=?2
             ORDER BY timestamp ASC, id ASC",
        )?;
        let rows = st
            .query_map([start.to_rfc3339(), end.to_rfc3339()], map_row)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn total(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM attestations", [], |r| r.get(0))?)
    }

    pub fn oldest_timestamp(&self) -> Result<Option<String>> {
        let mut st = self
            .conn
            .prepare("SELECT timestamp FROM attestations ORDER BY timestamp ASC, id ASC LIMIT 1")?;
        let mut rows = st.query([])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }
}

fn migrate(conn: &Connection) -> Result<()> {
    // Existing 0.1 databases lack the new columns. ALTER is idempotent-enough:
    // we ignore "duplicate column" errors.
    for sql in [
        "ALTER TABLE attestations ADD COLUMN command TEXT",
        "ALTER TABLE attestations ADD COLUMN cwd TEXT",
        "ALTER TABLE attestations ADD COLUMN actor TEXT",
        "ALTER TABLE attestations ADD COLUMN hostname TEXT",
        "ALTER TABLE attestations ADD COLUMN duration_ms INTEGER",
    ] {
        match conn.execute(sql, []) {
            Ok(_) => {}
            Err(e) if e.to_string().to_lowercase().contains("duplicate column") => {}
            Err(e) => {
                // Some SQLite builds say "duplicate column name"
                if !e.to_string().to_lowercase().contains("duplicate") {
                    return Err(e).context(sql.to_string());
                }
            }
        }
    }
    Ok(())
}

pub struct Row {
    pub timestamp: String,
    pub git_commit: Option<String>,
    pub exit_code: i32,
    pub attestation_hash: String,
    pub environment: Option<String>,
    pub command: Option<String>,
}

fn map_row(r: &rusqlite::Row) -> rusqlite::Result<Row> {
    Ok(Row {
        timestamp: r.get(1)?,
        git_commit: r.get(2)?,
        exit_code: r.get(3)?,
        attestation_hash: r.get(4)?,
        environment: r.get(5)?,
        command: r.get(6)?,
    })
}

/// Parse a command stored as a JSON array, falling back to the raw string.
pub fn command_from_row(raw: &Option<String>) -> Vec<String> {
    match raw {
        None => Vec::new(),
        Some(s) if s.is_empty() => Vec::new(),
        Some(s) => serde_json::from_str::<Vec<String>>(s).unwrap_or_else(|_| vec![s.clone()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::model::DeploymentAttestation;
    use tempfile::TempDir;

    #[test]
    fn last_hash_follows_timestamp_then_id() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("t.db");
        let db = TimelineDb::open(&db_path).unwrap();
        assert!(db.last_hash().unwrap().is_none());

        let mut a = DeploymentAttestation::build_simple(
            &["echo".into(), "a".into()],
            0,
            None,
            None,
            None,
            "kid".into(),
        );
        a.attestation_hash = "sel:v1.0:sha256:aaa".into();
        db.insert(&a).unwrap();
        assert_eq!(
            db.last_hash().unwrap().as_deref(),
            Some("sel:v1.0:sha256:aaa")
        );
    }
}
