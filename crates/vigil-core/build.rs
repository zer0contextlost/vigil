fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let out = std::process::Command::new(&rustc)
        .arg("--version")
        .output()
        .expect("failed to run rustc --version");
    let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
    println!("cargo:rustc-env=VIGIL_RUSTC_VERSION={}", version);
    println!("cargo:rerun-if-env-changed=RUSTC");
}
