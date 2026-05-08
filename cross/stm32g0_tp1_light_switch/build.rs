fn main() {
    // embassy-stm32's "memory-x" feature provides the linker memory layout
    // for the selected chip, so no local memory.x is needed.
    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");

    if std::env::var("CARGO_FEATURE_PROVISION_ON_BOOT").is_ok() {
        dev_provisioning_build::emit_dev_provisioning();
    }
}
