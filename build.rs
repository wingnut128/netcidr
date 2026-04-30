use std::process::Command;

fn main() {
    let short = git_output(&["rev-parse", "--short=8", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let full = git_output(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=GIT_SHA_SHORT={short}");
    println!("cargo:rustc-env=GIT_SHA_FULL={full}");

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-env-changed=GIT_SHA_SHORT");
    println!("cargo:rerun-if-env-changed=GIT_SHA_FULL");
}

fn git_output(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
