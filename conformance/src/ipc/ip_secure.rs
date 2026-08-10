//! The contract with the KNX IP Secure DUT.
//!
//! The IP Secure DUT is the odd one out. It has no socketpair and no
//! shared-memory region: the harness spawns it, then talks to it as an
//! ordinary KNXnet/IP secure client over loopback TCP. So its
//! parent↔child contract is not [`super::protocol`] but this — the key
//! material both sides have to agree on byte for byte, and the
//! environment variables the harness configures the child with.
//!
//! It lives beside the socket protocol for the same reason that does:
//! both halves need it, so neither may own it. The alternative, the
//! harness reading a constant out of the DUT's stack definition, is
//! what the `dut` feature exists to prevent — and the compiler caught
//! exactly that when the feature went in.
//!
//! Key material is fixed to the 03/08/09 Appendix A values, so the
//! runner-side crypto can be cross-checked against the published test
//! vectors rather than against our own implementation.

/// Device Authentication Code — derived from the password `"trustme"`
/// (Appendix A.2.2). Provisioned as the FDSK so the factory-default
/// DAC-seeding path is exercised.
pub const DUT_DEVICE_AUTH_CODE: [u8; 16] =
    [0xe1, 0x58, 0xe4, 0x01, 0x20, 0x47, 0xbd, 0x6c, 0xc4, 0x1a, 0xaf, 0xbc, 0x5c, 0x04, 0xc1, 0xfc];

/// Management user (ID 1) password hash — derived from `"secret"`
/// (Appendix A.3.1).
pub const DUT_USER1_PASSWORD_HASH: [u8; 16] =
    [0x03, 0xfc, 0xed, 0xb6, 0x66, 0x60, 0x25, 0x1e, 0xc8, 0x1a, 0x1a, 0x71, 0x69, 0x01, 0x69, 0x6a];

/// Serial number of the IP Secure DUT.
pub const IP_SECURE_SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

/// Secure Backbone Key for secure-routing tests — the 03/08/09
/// Appendix A.5/A.6 key `00 01 … 0f`.
pub const DUT_BACKBONE_KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Environment variable carrying the DUT's KNXnet/IP port (the harness
/// picks a free port per spawn; default 3671 for manual runs).
pub const PORT_ENV: &str = "KNX_IPS_PORT";

/// Environment variable carrying the routing multicast group. The
/// harness derives a per-spawn group in 239.250.0.0/16 from the control
/// port so concurrent runs never share a group; default 224.0.23.12.
pub const MCAST_ENV: &str = "KNX_IPS_MCAST";

/// Environment variable enabling secure routing in the DUT config
/// (`1` = secured Routing family + provisioned [`DUT_BACKBONE_KEY`]).
pub const SECURE_ROUTING_ENV: &str = "KNX_IPS_SECURE_ROUTING";
