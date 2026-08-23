# Secure BCU2 polling light switch

Mask 0021h Data Secure reference firmware for the
`zweidraehte-microdevice` stack. It uses no executor or async HAL. The
release ELF is about 70 KiB of flash and 1 KiB of static RAM on the
STM32G0B0RE; the flash-persistent plain 0020h sibling is about 27 KiB.

Low-write ETS configuration lives in the penultimate internal-flash page.
The secure counters and SIAT live in an external FM25L16B FRAM, because a
counter must be durable before its secure telegram is sent:

| Signal | Pin |
|---|---|
| SPI2 SCK / MISO / MOSI | PB13 / PB14 / PB15 |
| FRAM ~CS / ~WP | PB12 / PB9 |
| ADC entropy input (physically unconnected) | PA0 |

The last flash page is a per-device `KNXP` serial/FDSK record; provision it
before running the production build:

    cargo run -p knx-provision -- \
        --target stm32g0b0re \
        --serial 00FA0000000E \
        --fdsk $(openssl rand -hex 16)

For bench bring-up, `--features provision-on-boot` creates the documented
development identity when the page is blank. Do not ship that feature.

Build from this directory so `.cargo/config.toml` selects Cortex-M0+:

    cargo build --release

Generate the matching MV-0021 MTXML together with the other light-switch
variants from the repository root:

    cargo run --bin gen_light_switch_mtxml

The application file is
`out/LightSwitch2/M-00FA/M-00FA_A-0309-02-0000.mtxml`; the catalogue order
number is `LS-0002-TP-B2-SEC`.
