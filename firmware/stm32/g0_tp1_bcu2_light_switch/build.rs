use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Hand the local memory.x to the linker (no embassy-stm32 here to
    // provide one).
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    fs::copy("memory.x", out.join("memory.x")).expect("copy memory.x");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
}
