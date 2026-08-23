//! Data Secure BCU2 DUT with the AN158 sample application.

use zweidraehte_conformance::dut::bcu2_secure_runtime::{self, BootImage};

fn main() {
    bcu2_secure_runtime::run(BootImage::DataSecurity)
}
