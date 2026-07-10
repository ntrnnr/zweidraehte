# Licensing

License names follow the [SPDX License List](https://spdx.org/licenses/).

The license for this project is [AGPL-3.0-only](LICENSE).

## Dual licensing

zweidraehte is dual-licensed:

1. **AGPL-3.0-only** — the terms in [LICENSE](LICENSE) apply to anyone.
   Note that the AGPL's copyleft extends to software that interacts
   with zweidraehte over a network, and that firmware shipping this
   stack must make the corresponding source available to its users.

2. **Commercial license** — for building proprietary devices or
   products on top of zweidraehte without the obligations of the AGPL,
   a commercial license is available from Netrunner UG. Contact
   <info@netrunner.info>.

This is the same model used by projects such as Grafana: the community
receives a strong copyleft license, while commercial users who cannot
comply with it can obtain different terms.

## Contributions

So that dual licensing remains possible, every contribution must be
covered by the [Netrunner UG Software Grant and Contributor License
Agreement](CLA.md), which grants Netrunner UG the rights needed to
distribute the contribution under both licenses. Contributors keep the
copyright to their work, and the agreement contains a promise in
return: community contributions will always also be available under an
OSI-approved open-source license — they can never become
proprietary-only. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
process.

## Vendored third-party code

These files retain their original upstream license and are **not**
covered by the dual-licensing terms above:

```
crates/zweidraehte-proto/src/util/packets/buffer.rs
crates/zweidraehte-proto/src/util/packets/parsing.rs
crates/zweidraehte-proto/src/util/packets/records.rs
crates/zweidraehte-proto/src/util/packets/util.rs
```

Taken from the Fuchsia `packet` library and modified. Copyright The
Fuchsia Authors; BSD-style license — see
[FUCHSIA_LICENSE](FUCHSIA_LICENSE).

## Trademarks

KNX® is a registered trademark of the KNX Association. This project is
not affiliated with or certified by the KNX Association.
