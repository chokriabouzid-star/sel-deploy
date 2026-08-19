use anyhow::{bail, Context, Result};
use std::process::Command;
use std::time::Instant;

use crate::cli::RunArgs;
use sel_deploy::attestation::chain::ChainBuilder;
use sel_deploy::attestation::model::{AttestationMeta, ComplianceHints, DeploymentAttestation};
use sel_deploy::attestation::signer::AttestationSigner;
use sel_deploy::storage::filesystem::AttestationStore;
use sel_deploy::storage::paths::SelPaths;
use sel_deploy::storage::sqlite::TimelineDb;
use sel_deploy::util::{current_actor, current_cwd, current_hostname, prefix};

pub async fn execute(args: RunArgs) -> Result<i32> {
    let paths = SelPaths::load()?;
    let signer = AttestationSigner::load(&paths.private_key)?;
    let claims = parse_claims(&args.claim)?;

    println!("🚀 Executing: {}", args.command.join(" "));

    let started = Instant::now();
    let output = Command::new(&args.command[0])
        .args(&args.command[1..])
        .output()
        .with_context(|| format!("Cannot execute '{}'", args.command[0]))?;
    let duration_ms = started.elapsed().as_millis() as u64;

    let exit_code = output.status.code().unwrap_or(-1);
    if !output.stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    let store = AttestationStore::new(paths.attestations.clone())?;
    // JSON is the source of truth for the chain tip — not SQLite.
    let existing = store.load_all_sorted()?;
    let prev_hash = existing.last().map(|a| a.attestation_hash.clone());
    let mut chain = match prev_hash {
        Some(h) => ChainBuilder::with_tip(h),
        None => ChainBuilder::new(),
    };

    let meta = AttestationMeta {
        cwd: current_cwd(),
        actor: current_actor(),
        hostname: current_hostname(),
        duration_ms: Some(duration_ms),
        claims,
    };

    let mut att = DeploymentAttestation::build(
        &args.command,
        exit_code,
        get_git_commit(),
        args.env,
        chain.previous_hash(),
        signer.key_id(),
        meta,
    )?;

    let payload = att.canonical_payload()?;
    let hash = att.compute_hash()?;
    let signature = signer.sign(&payload);

    att.attestation_hash = hash.clone();
    att.signature = signature;

    store.save(&att)?;
    let db = TimelineDb::open(&paths.db)?;
    db.insert(&att)?;
    chain.advance(&att);

    println!("\n✔  Deployment attested");
    println!("   Command    : {}", att.command.join(" "));
    println!("   Hash       : {}...", prefix(&hash, 32));
    match &att.previous_hash {
        Some(ph) => println!("   Chained to : {}...", prefix(ph, 32)),
        None => println!("   Chained to : (genesis — first attestation)"),
    }
    if let Some(ref gc) = att.git_commit {
        println!("   Git commit : {gc}");
    }
    println!(
        "   Signed     : {} UTC",
        att.timestamp.format("%Y-%m-%d %H:%M:%S")
    );
    if exit_code != 0 {
        println!("\n⚠️   Exit code: {exit_code}");
    }

    if args.ignore_fail {
        Ok(0)
    } else if exit_code < 0 {
        Ok(1)
    } else {
        Ok(exit_code)
    }
}

fn parse_claims(raw: &[String]) -> Result<ComplianceHints> {
    let mut hints = ComplianceHints::default();
    for c in raw {
        match c.to_ascii_lowercase().as_str() {
            "soc2_cc8" | "soc2-cc8" | "soc2" => hints.soc2_cc8 = true,
            "change_management" | "change-management" | "cm" => hints.change_management = true,
            other => bail!("Unknown --claim '{other}'. Allowed: soc2_cc8, change_management"),
        }
    }
    Ok(hints)
}

fn get_git_commit() -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}
