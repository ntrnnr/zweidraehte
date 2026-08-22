# Firmware targets

Device targets for the zweidraehte KNX stack. This is a **separate
Cargo workspace**: build embedded binaries by `cd`-ing into the project
directory (each has its own `.cargo/config.toml` selecting the target);
the `linux/` shells build with a plain `cargo build`.

## Device identity assignments

Full-stack embedded targets and the secure BCU2 micro target read their
identity — KNX serial number, and for secure devices the FDSK, and for
Ethernet devices the MAC — from the
`KNXP` flash record written by [`tools/knx-provision`](../tools/knx-provision)
over SWD. The `linux/` shells read the same identity from a JSON file
(`support::storage::FileIdentity`) instead, self-provisioned with the
defaults below on first run. The two plain micro-stack targets are
experimental demonstrations on `zweidraehte-microdevice`; they bake fixed
test identities into their firmware. The secure BCU2 target uses `KNXP`
because a shared compiled-in FDSK would make Data Secure meaningless.
Each full-stack project's `README.md` carries the exact provisioning
command; this table tracks the assignments so bench devices don't collide.

The serial here is the **device serial** (`PID_SERIAL_NUMBER`, what ETS
sees and RF frames carry). The per-variant knxprod *hardware* serials
(`PID_HARDWARE_TYPE`, `LightSwitchDevice::HARDWARE_TYPE_*`) are a
separate identifier space that happens to occupy `..03`–`..0B` of the
same `00FA 0000 00xx` range — ETS never compares the two, but when a
`00FA000000xx` value turns up in a trace, check which space it belongs
to. The two linux shells deliberately reuse their variant's hardware
serial as device serial, which is why `..03` and `..09` appear as
devices below.

| Project | Package | Serial | FDSK | MAC |
|---|---|---|---|---|
| `rp2040/eth_light_switch` | `pico_eth_light_switch` | `00FA00000001` | — | `0002FA000001` |
| `stm32/g0_tp1_secure_light_switch` | `stm32g0_tp1_secure_light_switch` | `00FA00000002` | dev | — |
| `linux/eth_light_switch` | `linux_eth_light_switch` | `00FA00000003` | — | host NIC |
| `stm32/g0_knxrf_secure_light_switch` | `stm32g0_knxrf_secure_light_switch` | `00FA00000004` | dev | — |
| `stm32/g0_knxrf_secure_retransmitter` | `stm32g0_knxrf_secure_retransmitter` | `00FA00000004` ⚠ | dev | — |
| `stm32/g0_tp1_system7_secure_light_switch` | `stm32g0_tp1_system7_secure_light_switch` | `00FA00000005` | dev | — |
| `stm32/g0_tp1_light_switch` | `stm32g0_tp1_light_switch` | `00FA00000006` | — | — |
| `stm32/g0_tp1_system7_light_switch` | `stm32g0_tp1_system7_light_switch` | `00FA00000007` | — | — |
| `stm32/g0_knxrf_device` | `stm32g0_knxrf_device` | `00FA00000008` | — | — |
| `linux/eth_secure_light_switch` | `linux_eth_secure_light_switch` | `00FA00000009` | dev | host NIC |
| `rp2040/tp1_light_switch` | `pico_tp1_light_switch` | `00FA0000000A` | — | — |
| `rp2040/eth_ip_interface` | `pico_eth_ip_interface` | `00FA0000000B` | — | `0002FA00000B` |
| `rp2040/wifi_light_switch` | `pico_wifi_light_switch` | `00FA0000000C` | — | — |
| `rp2040/eth_secure_light_switch` | `pico_eth_secure_light_switch` | `00FA0000000D` | dev | `0002FA00000D` |
| `stm32/g0_tp1_bcu2_light_switch` | `stm32g0_tp1_bcu2_light_switch` | `00FA00000308` (fixed) | — | — |
| `stm32/g0_tp1_bcu2_secure_light_switch` | `stm32g0_tp1_bcu2_secure_light_switch` | provisioned (`…000E` on the bench) | provisioned | — |
| `stm32/g0_tp1_micro_system7_light_switch` | `stm32g0_tp1_micro_system7_light_switch` | `00FA00000306` (fixed) | — | — |

Conventions and notes:

- **FDSK "dev"** is the shared bench key
  `000102030405060708090a0b0c0d0e0f` — the same obviously-not-production
  default `dev-provisioning-build` bakes into `provision-on-boot`
  builds. Production units get a random FDSK
  (`--fdsk $(openssl rand -hex 16)`) and the printed label instead.
- **MACs** are locally-administered, composed as `0002FA` + the low
  three serial octets — the same rule `knx-provision --oui` applies.
  The Pico W (`wifi_light_switch`) needs no MAC: the CYW43 radio brings
  its own.
- ⚠ The RF secure retransmitter currently shares `..04` with the RF
  secure light switch. Fine while only one of the two boards is powered
  (they are the same hardware, reflashed per role), but the serial is
  the KNX-RF sender address — running both on air at once needs the
  retransmitter re-provisioned with a distinct serial.
- `stm32/g0_blink` and `rp2040/blink` are bring-up shells with no KNX
  identity.
- The fixed identities of the two plain micro targets are development
  defaults in `main.rs`, not `KNXP` records. Change them before placing
  multiple copies on one line.
