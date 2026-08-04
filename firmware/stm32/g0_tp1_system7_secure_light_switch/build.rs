//! Build-time wiring.
//!
//! Standard embedded linker args, plus — when the `provision-on-boot`
//! feature is enabled — a generated `dev_provisioning.rs` carrying the
//! dev-default serial / FDSK / MAC. See
//! [`dev_provisioning_build`](../../common/dev-provisioning-build/) for the
//! helper that does the actual work.
//!
//! Production builds (no feature) do not need any FDSK env var: the
//! firmware reads its FDSK from the `KNXP` flash record written by
//! `tools/knx-provision` over SWD.

fn main() {
    // Standard embedded linker args — embassy-stm32's "memory-x" feature
    // provides the chip-specific layout.
    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");

    if std::env::var("CARGO_FEATURE_PROVISION_ON_BOOT").is_ok() {
        dev_provisioning_build::emit_dev_provisioning();
    }
}
