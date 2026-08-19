use anyhow::Result;

use crate::cli::RebuildArgs;
use sel_deploy::storage::filesystem::AttestationStore;
use sel_deploy::storage::paths::SelPaths;
use sel_deploy::storage::sqlite::TimelineDb;

pub async fn execute(_args: RebuildArgs) -> Result<i32> {
    let paths = SelPaths::load()?;
    let store = AttestationStore::new(paths.attestations.clone())?;
    let all = store.load_all_sorted()?;

    // Recreate the DB file so a corrupt index cannot linger.
    if paths.db.exists() {
        std::fs::remove_file(&paths.db)?;
    }
    let mut db = TimelineDb::open(&paths.db)?;
    let n = db.rebuild_from(&all)?;

    println!("✔  Rebuilt index from {n} JSON attestation(s)");
    println!("   Home   : {}", paths.root.display());
    println!("   Source : {}", store.dir().display());
    println!("   Index  : {}", paths.db.display());
    if n == 0 {
        println!("   (no JSON files found — the index is empty)");
    }
    Ok(0)
}
