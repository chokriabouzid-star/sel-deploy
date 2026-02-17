use anyhow::Result;
use std::fs;
use crate::{cli::ExportArgs, storage::{paths::SelPaths, filesystem::AttestationStore}};

pub async fn execute(args: ExportArgs) -> Result<()> {
    if args.format != "json" {
        println!("🔒  --format {} requires the Enterprise tier.", args.format);
        println!("    v0.1 supports JSON export only.");
        println!("    SOC2/ISO reports planned for v0.2.");
        return Ok(());
    }
    let paths = SelPaths::load()?;
    let store = AttestationStore::new(paths.attestations)?;
    let all   = store.load_all_sorted()?;
    let json  = serde_json::to_string_pretty(&all)?;

    match args.output {
        Some(ref path) => {
            fs::write(path, &json)?;
            println!("✔  Exported {} attestation(s) to {}", all.len(), path);
        }
        None => println!("{}", json),
    }
    Ok(())
}
