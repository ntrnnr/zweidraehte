//! Ships `storage.x`, the linker check that the firmware image ends below
//! the storage a device placed (see `stm32_common::reserve_storage!`).

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(out.join("storage.x"), include_bytes!("storage.x")).expect("write storage.x");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=storage.x");
}
