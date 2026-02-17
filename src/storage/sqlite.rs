use anyhow::{Result, Context};
use rusqlite::{Connection, params};
use std::path::Path;
use chrono::{DateTime, Utc};
use crate::attestation::model::DeploymentAttestation;

pub struct TimelineDb {
    conn: Connection,
}

impl TimelineDb {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("Cannot open timeline.db")?;
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS attestations (
                id               TEXT PRIMARY KEY,
                timestamp        TEXT NOT NULL,
                command_hash     TEXT NOT NULL,
                git_commit       TEXT,
                environment      TEXT,
                exit_code        INTEGER NOT NULL,
                attestation_hash TEXT UNIQUE NOT NULL,
                previous_hash    TEXT,
                signer_key_id    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ts  ON attestations(timestamp);
            CREATE INDEX IF NOT EXISTS idx_git ON attestations(git_commit);
        ").context("Cannot initialize database")?;
        Ok(Self { conn })
    }

    pub fn insert(&self, a: &DeploymentAttestation) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO attestations
             (id,timestamp,command_hash,git_commit,environment,
              exit_code,attestation_hash,previous_hash,signer_key_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                a.id,
                a.timestamp.to_rfc3339(),
                a.command_hash,
                a.git_commit,
                a.environment,
                a.exit_code,
                a.attestation_hash,
                a.previous_hash,
                a.signer.key_id,
            ],
        ).context("Cannot insert attestation")?;
        Ok(())
    }

    pub fn last_hash(&self) -> Result<Option<String>> {
        let mut st = self.conn.prepare(
            "SELECT attestation_hash FROM attestations ORDER BY timestamp DESC LIMIT 1"
        )?;
        let mut rows = st.query([])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<Row>> {
        let mut st = self.conn.prepare(
            "SELECT id,timestamp,git_commit,exit_code,attestation_hash,environment
             FROM attestations ORDER BY timestamp DESC LIMIT ?1"
        )?;
        let rows = st.query_map([limit as i64], map_row)?
                     .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Row>> {
        let mut st = self.conn.prepare(
            "SELECT id,timestamp,git_commit,exit_code,attestation_hash,environment
             FROM attestations WHERE timestamp>=?1 AND timestamp<=?2
             ORDER BY timestamp"
        )?;
        let rows = st.query_map(
            [start.to_rfc3339(), end.to_rfc3339()],
            map_row,
        )?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn total(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM attestations", [], |r| r.get(0),
        )?)
    }

    pub fn oldest_timestamp(&self) -> Result<Option<String>> {
        let mut st = self.conn.prepare(
            "SELECT timestamp FROM attestations ORDER BY timestamp ASC LIMIT 1"
        )?;
        let mut rows = st.query([])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }
}

pub struct Row {
    pub timestamp:        String,
    pub git_commit:       Option<String>,
    pub exit_code:        i32,
    pub attestation_hash: String,
    pub environment:      Option<String>,
}

fn map_row(r: &rusqlite::Row) -> rusqlite::Result<Row> {
    Ok(Row {
        timestamp:        r.get(1)?,
        git_commit:       r.get(2)?,
        exit_code:        r.get(3)?,
        attestation_hash: r.get(4)?,
        environment:      r.get(5)?,
    })
}
