# Secure micro System 7 polling light switch

Mask 0705h plus the Data Secure profile module on
`zweidraehte-microdevice`. The target has no executor or async HAL. It shares
the secure System 7 application (`0307`) and MTXML with the full-stack target,
including the absolute 4000h/4100h/4200h/4300h segment layout.

The release ELF uses 73,784 bytes of flash and 1,040 bytes of static RAM on
the STM32G0B0RE. The plain micro System 7 sibling uses about 29 KiB of flash;
Data Secure therefore remains an explicit size trade-off rather than a free
part of the base stack.

Low-write configuration is stored in the penultimate internal-flash page.
Sequence counters and the SIAT use the external FM25L16B:

| Signal | Pin |
|---|---|
| SPI2 SCK / MISO / MOSI | PB13 / PB14 / PB15 |
| FRAM ~CS / ~WP | PB12 / PB9 |
| ADC entropy input (physically unconnected) | PA0 |

Provision the last flash page before running a production build:

    cargo run -p knx-provision -- \
        --target stm32g0b0re \
        --serial 00FA0000000F \
        --fdsk $(openssl rand -hex 16)

For bench bring-up, `--features provision-on-boot` writes the documented
development identity when the page is blank. Do not ship that feature.

Build from this directory so `.cargo/config.toml` selects Cortex-M0+:

    cargo build --release

Generate the shared product from the repository root:

    cargo run --bin gen_light_switch_mtxml

The application is `M-00FA_A-0307-02-0000.mtxml`; the catalogue order number
is `LS-0002-TP-S7-SEC`.
