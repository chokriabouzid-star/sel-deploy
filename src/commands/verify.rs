use anyhow::{Result, Context};
use std::{fs, path::Path};
use crate::{
    cli::VerifyArgs,
    attestation::{
        chain::audit_chain,
        verify::{verify_attestation, verify_file},
    },
    storage::{paths::SelPaths, filesystem::AttestationStore},
};

pub async fn execute(args: VerifyArgs) -> Result<()> {
    let paths    = SelPaths::load()?;
    let vk_bytes = fs::read(&paths.public_key)
        .context("Public key not found. Run 'sel-deploy keygen' first.")?;

    // ── فحص ملف واحد ──────────────────────────────────────────────────────
    if let Some(ref file) = args.file {
        let a = verify_file(Path::new(file), &vk_bytes)?;
        println!("✔  Valid attestation");
        println!("   ID   : {}", &a.id[..8]);
        println!("   Hash : {}", a.attestation_hash);
        println!("   Time : {} UTC", a.timestamp.format("%Y-%m-%d %H:%M:%S"));
        return Ok(());
    }

    // ── فحص كامل السلسلة ───────────────────────────────────────────────────
    let store = AttestationStore::new(paths.attestations.clone())?;
    let all   = store.load_all_sorted()?;

    if all.is_empty() {
        println!("No attestations found. Run 'sel-deploy run -- <cmd>'.");
        return Ok(());
    }

    println!("Verifying {} attestation(s)...\n", all.len());

    let mut invalid = 0usize;
    for a in &all {
        if let Err(e) = verify_attestation(a, &vk_bytes) {
            eprintln!("  ✘  {} — {}", &a.id[..8], e);
            invalid += 1;
        }
    }

    let report = audit_chain(&all);

    if invalid == 0 && report.broken_at.is_none() {
        println!("✔  {} attestations verified", all.len());
        println!("✔  Chain intact");
        match report.gaps_detected {
            0 => println!("✔  No gaps detected"),
            n => println!("⚠️   {} gap(s) detected", n),
        }
    } else {
        if invalid > 0 {
            println!("✘  {} invalid signature(s)", invalid);
        }
        if let Some(ref id) = report.broken_at {
            println!("✘  Chain broken at attestation {}", &id[..8]);
        }
    }
    Ok(())
}
