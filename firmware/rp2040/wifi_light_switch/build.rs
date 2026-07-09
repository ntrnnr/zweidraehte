use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Copy memory.x to the output directory for the linker to find it.
    let out = &PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    File::create(out.join("memory.x"))
        .expect("create memory.x")
        .write_all(include_bytes!("memory.x"))
        .expect("write memory.x");
    println!("cargo:rustc-link-search={}", out.display());

    println!("cargo:rerun-if-changed=memory.x");

    // WiFi credentials are read via `option_env!` in main.rs. Cargo does not
    // track env vars consumed by `option_env!`, so declare them here to force
    // a rebuild when they change between builds.
    println!("cargo:rerun-if-env-changed=WIFI_SSID");
    println!("cargo:rerun-if-env-changed=WIFI_PASS");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tlink-rp.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");

    if std::env::var("CARGO_FEATURE_PROVISION_ON_BOOT").is_ok() {
        dev_provisioning_build::emit_dev_provisioning();
    }
}
