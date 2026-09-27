// Records the compiler version in the generated vector file.
use std::process::Command;

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = Command::new(rustc)
        .arg("--version")
        .output()
        .expect("rustc --version");
    let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
    println!("cargo:rustc-env=GEN_RUSTC_VERSION={version}");
}
