use anyhow::Result;
use std::path::Path;

use crate::cli::VerifyArgs;
use crate::commands::load_all_public_keys;
use sel_deploy::attestation::chain::audit_chain;
use sel_deploy::attestation::verify::{verify_attestation_with_keys, verify_file_with_keys};
use sel_deploy::storage::filesystem::AttestationStore;
use sel_deploy::storage::paths::SelPaths;
use sel_deploy::util::prefix;

pub async fn execute(args: VerifyArgs) -> Result<i32> {
    let paths = SelPaths::load()?;
    let keys = load_all_public_keys(&paths)?;
    if keys.is_empty() {
        anyhow::bail!("Public key not found. Run 'sel-deploy keygen' first.");
    }

    if let Some(ref file) = args.file {
        let a = verify_file_with_keys(Path::new(file), &keys)?;
        println!("✔  Valid attestation");
        println!("   ID      : {}", prefix(&a.id, 8));
        println!("   Command : {}", a.command.join(" "));
        println!("   Hash    : {}", a.attestation_hash);
        println!(
            "   Time    : {} UTC",
            a.timestamp.format("%Y-%m-%d %H:%M:%S")
        );
        return Ok(0);
    }

    let store = AttestationStore::new(paths.attestations.clone())?;
    let all = store.load_all_sorted()?;

    if all.is_empty() {
        println!("No attestations found. Run 'sel-deploy run -- <cmd>'.");
        return Ok(0);
    }

    println!("Verifying {} attestation(s)...\n", all.len());

    let mut invalid = 0usize;
    for a in &all {
        if let Err(e) = verify_attestation_with_keys(a, &keys) {
            eprintln!("  ✘  {} — {}", prefix(&a.id, 8), e);
            invalid += 1;
        }
    }

    let report = audit_chain(&all);

    if invalid == 0 && report.is_clean() {
        println!("✔  {} attestations verified", all.len());
        println!("✔  Chain intact");
        println!("✔  No gaps detected");
        Ok(0)
    } else {
        if invalid > 0 {
            println!("✘  {invalid} invalid signature(s) or hash mismatch(es)");
        }
        if let Some(ref id) = report.broken_at {
            println!("✘  Chain broken at attestation {}", prefix(id, 8));
        }
        if report.gaps_detected > 0 {
            println!("✘  {} gap(s) detected", report.gaps_detected);
        }
        if report.missing_predecessors > 0 {
            println!(
                "✘  {} missing predecessor(s) — a prior attestation file was lost or overwritten",
                report.missing_predecessors
            );
        }
        Ok(1)
    }
}
