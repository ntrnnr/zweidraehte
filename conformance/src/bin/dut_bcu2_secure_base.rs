//! Data Secure BCU2 composition with the ordinary base-profile application.

use zweidraehte_conformance::dut::bcu2_secure_runtime::{self, BootImage};

fn main() {
    bcu2_secure_runtime::run(BootImage::BaseProfile)
}
