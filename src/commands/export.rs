use anyhow::Result;
use std::fs;

use crate::cli::ExportArgs;
use sel_deploy::storage::filesystem::AttestationStore;
use sel_deploy::storage::paths::SelPaths;

pub async fn execute(args: ExportArgs) -> Result<i32> {
    if args.format != "json" {
        eprintln!(
            "Unsupported --format '{}'. v0.2 supports JSON only.",
            args.format
        );
        eprintln!("Use: sel-deploy export --format json [--output PATH]");
        return Ok(2);
    }
    let paths = SelPaths::load()?;
    let store = AttestationStore::new(paths.attestations)?;
    let all = store.load_all_sorted()?;
    let json = serde_json::to_string_pretty(&all)?;

    match args.output {
        Some(ref path) => {
            fs::write(path, &json)?;
            println!("✔  Exported {} attestation(s) to {}", all.len(), path);
        }
        None => println!("{json}"),
    }
    Ok(0)
}
