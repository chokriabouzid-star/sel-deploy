//! End-to-end CLI tests. Each test gets its own SEL_DEPLOY_HOME.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sel-deploy"))
}

struct Harness {
    _tmp: TempDir,
    home: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("sel-home");
        fs::create_dir_all(&home).unwrap();
        Self { _tmp: tmp, home }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(bin());
        c.env("SEL_DEPLOY_HOME", &self.home);
        c.env_remove("USER"); // keep actor deterministic-ish
        c.env("SEL_DEPLOY_ACTOR", "cli-test");
        c.env("SEL_DEPLOY_HOSTNAME", "test-host");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        let out = self.cmd().args(args).output().expect("spawn sel-deploy");
        Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn att_dir(&self) -> PathBuf {
        self.home.join("attestations")
    }

    fn json_files(&self) -> Vec<PathBuf> {
        let mut v: Vec<_> = fs::read_dir(self.att_dir())
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Output {
    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

#[test]
fn cli_run_without_key_fails() {
    let h = Harness::new();
    let o = h.run(&["run", "--", "echo", "x"]);
    assert_ne!(o.code, 0);
    assert!(o.combined().contains("keygen"));
}

#[test]
fn cli_keygen_and_refuse_overwrite() {
    let h = Harness::new();
    let o = h.run(&["keygen"]);
    assert_eq!(o.code, 0, "{}", o.combined());
    let pem = fs::read_to_string(h.home.join("keys/default.pem")).unwrap();
    assert!(pem.contains("BEGIN ED25519 PRIVATE KEY"));
    let o2 = h.run(&["keygen"]);
    assert_eq!(o2.code, 1, "refusing overwrite must be a hard error");
    assert!(o2.combined().contains("already exists"));
}

#[test]
fn cli_run_records_command_and_propagates_exit() {
    let h = Harness::new();
    assert_eq!(h.run(&["keygen"]).code, 0);
    let ok = h.run(&[
        "run",
        "--env",
        "production",
        "--",
        "echo",
        "Deploying app v1.0.0",
    ]);
    assert_eq!(ok.code, 0, "{}", ok.combined());
    assert!(ok.stdout.contains("Command"));
    assert!(ok.stdout.contains("Deploying app v1.0.0"));

    let files = h.json_files();
    assert_eq!(files.len(), 1);
    let json = fs::read_to_string(&files[0]).unwrap();
    assert!(json.contains("\"Deploying app v1.0.0\""));
    assert!(json.contains("\"cli-test\""));
    assert!(json.contains("\"soc2_cc8\": false"));

    let fail = h.run(&["run", "--env", "staging", "--", "sh", "-c", "exit 7"]);
    assert_eq!(
        fail.code,
        7,
        "wrapped exit code must propagate: {}",
        fail.combined()
    );
    assert!(fail.stdout.contains("Exit code: 7"));

    let ignored = h.run(&["run", "--ignore-fail", "--", "false"]);
    assert_eq!(ignored.code, 0, "{}", ignored.combined());

    let hist = h.run(&["history"]);
    assert_eq!(hist.code, 0);
    assert!(
        hist.stdout.contains("echo"),
        "history must show the command"
    );
    assert!(hist.stdout.contains("exit 7") || hist.stdout.contains("sh"));
}

#[test]
fn cli_same_second_keeps_both_files_and_verify_passes() {
    let h = Harness::new();
    assert_eq!(h.run(&["keygen"]).code, 0);
    let a = h.run(&["run", "--", "echo", "first"]);
    let b = h.run(&["run", "--", "echo", "second"]);
    assert_eq!(a.code, 0, "{}", a.combined());
    assert_eq!(b.code, 0, "{}", b.combined());
    assert_eq!(
        h.json_files().len(),
        2,
        "must not overwrite same-second files"
    );

    let v = h.run(&["verify"]);
    assert_eq!(v.code, 0, "clean chain must exit 0: {}", v.combined());
    assert!(v.stdout.contains("Chain intact"));
}

#[test]
fn cli_verify_tamper_exits_nonzero() {
    let h = Harness::new();
    assert_eq!(h.run(&["keygen"]).code, 0);
    assert_eq!(h.run(&["run", "--", "echo", "ok"]).code, 0);
    let f = &h.json_files()[0];
    let mut val: serde_json::Value = serde_json::from_str(&fs::read_to_string(f).unwrap()).unwrap();
    val["exit_code"] = serde_json::json!(99);
    fs::write(f, serde_json::to_vec_pretty(&val).unwrap()).unwrap();

    let v = h.run(&["verify"]);
    assert_eq!(v.code, 1, "tamper must fail CI: {}", v.combined());
    assert!(v.combined().contains("✘") || v.combined().contains("Hash mismatch"));
}

#[test]
fn cli_rebuild_restores_sqlite() {
    let h = Harness::new();
    assert_eq!(h.run(&["keygen"]).code, 0);
    assert_eq!(h.run(&["run", "--", "echo", "alpha"]).code, 0);
    assert_eq!(h.run(&["run", "--", "echo", "beta"]).code, 0);
    fs::remove_file(h.home.join("timeline.db")).unwrap();
    let empty = h.run(&["history"]);
    assert!(empty.stdout.contains("No deployments") || empty.stdout.contains("rebuild"));
    let rb = h.run(&["rebuild"]);
    assert_eq!(rb.code, 0, "{}", rb.combined());
    let hist = h.run(&["history"]);
    assert!(hist.stdout.contains("alpha"));
    assert!(hist.stdout.contains("beta"));
}

#[test]
fn cli_export_unknown_format_is_usage_error() {
    let h = Harness::new();
    assert_eq!(h.run(&["keygen"]).code, 0);
    let o = h.run(&["export", "--format", "csv"]);
    assert_eq!(o.code, 2, "{}", o.combined());
    assert!(!o.combined().to_lowercase().contains("enterprise"));
}

#[test]
fn cli_keygen_force_archives_old_key_and_old_attestation_still_verifies() {
    let h = Harness::new();
    assert_eq!(h.run(&["keygen"]).code, 0);
    assert_eq!(h.run(&["run", "--", "echo", "signed-with-key-1"]).code, 0);
    let first_pub = fs::read(h.home.join("keys/default.pub")).unwrap();

    let rotated = h.run(&["keygen", "--force"]);
    assert_eq!(rotated.code, 0, "{}", rotated.combined());
    assert!(rotated.stdout.contains("Archived") || rotated.combined().contains("Archived"));

    let new_pub = fs::read(h.home.join("keys/default.pub")).unwrap();
    assert_ne!(first_pub, new_pub);

    let archive = h.home.join("keys/archive");
    let archived: Vec<_> = fs::read_dir(&archive)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(!archived.is_empty(), "old public key must be archived");

    let v = h.run(&["verify"]);
    assert_eq!(
        v.code,
        0,
        "attestations signed with the archived key must still verify: {}",
        v.combined()
    );
}

#[test]
fn cli_claims_are_opt_in() {
    let h = Harness::new();
    assert_eq!(h.run(&["keygen"]).code, 0);
    let o = h.run(&["run", "--claim", "soc2_cc8", "--", "echo", "claimed"]);
    assert_eq!(o.code, 0, "{}", o.combined());
    let json = fs::read_to_string(&h.json_files()[0]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["compliance_hints"]["soc2_cc8"], true);
    assert_eq!(v["compliance_hints"]["change_management"], false);
}

#[test]
fn cli_bad_timestamp_exits_nonzero() {
    let h = Harness::new();
    assert_eq!(h.run(&["keygen"]).code, 0);
    let o = h.run(&["timeline", "not-a-date"]);
    assert_ne!(o.code, 0);
}
