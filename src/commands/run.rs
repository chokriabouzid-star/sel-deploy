use anyhow::{Result, Context};
use std::process::Command;
use crate::{
    cli::RunArgs,
    attestation::{
        model::DeploymentAttestation,
        signer::AttestationSigner,
        chain::ChainBuilder,
    },
    storage::{
        paths::SelPaths,
        sqlite::TimelineDb,
        filesystem::AttestationStore,
    },
};

pub async fn execute(args: RunArgs) -> Result<()> {
    let paths  = SelPaths::load()?;
    let signer = AttestationSigner::load(&paths.private_key)?;

    println!("🚀 Executing: {}", args.command.join(" "));

    let output = Command::new(&args.command[0])
        .args(&args.command[1..])
        .output()
        .with_context(|| format!("Cannot execute '{}'", &args.command[0]))?;

    let exit_code = output.status.code().unwrap_or(-1);
    if !output.stdout.is_empty() { print!("{}", String::from_utf8_lossy(&output.stdout)); }
    if !output.stderr.is_empty() { eprint!("{}", String::from_utf8_lossy(&output.stderr)); }

    let db    = TimelineDb::open(&paths.db)?;
    let store = AttestationStore::new(paths.attestations.clone())?;

    let prev_hash = db.last_hash()?;
    let mut chain = match prev_hash {
        Some(h) => ChainBuilder::with_tip(h),
        None    => ChainBuilder::new(),
    };

    let mut att = DeploymentAttestation::build(
        &args.command,
        exit_code,
        get_git_commit(),
        args.env,
        chain.previous_hash(),
        signer.key_id(),
    );

    let payload   = att.canonical_payload()?;
    let hash      = att.compute_hash()?;
    let signature = signer.sign(&payload);

    att.attestation_hash = hash.clone();
    att.signature        = signature;

    store.save(&att)?;
    db.insert(&att)?;
    chain.advance(&att);

    println!("\n✔  Deployment attested");
    println!("   Hash       : {}...", &hash[..32]);
    match &att.previous_hash {
        Some(ph) => println!("   Chained to : {}...", &ph[..32]),
        None     => println!("   Chained to : (genesis — first attestation)"),
    }
    if let Some(ref gc) = att.git_commit {
        println!("   Git commit : {}", gc);
    }
    println!("   Signed     : {} UTC", att.timestamp.format("%Y-%m-%d %H:%M:%S"));
    if exit_code != 0 {
        println!("\n⚠️   Exit code: {}", exit_code);
    }
    Ok(())
}

fn get_git_commit() -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output().ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}
