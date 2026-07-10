# Contributing to zweidraehte

Thank you for wanting to contribute. A few ground rules keep the
project maintainable and the dual-licensing model (see
[LICENSING.md](LICENSING.md)) legally sound.

## Contributor License Agreement

Every contribution requires the [Netrunner UG Software Grant and
Contributor License Agreement](CLA.md) to be on file. It is based on
the Apache Software Foundation CLA and grants Netrunner UG the rights
needed to distribute your contribution under both the AGPL and the
commercial license; you keep the copyright to your work.

Accept it by including the acceptance sentence from
[CLA.md](CLA.md#accepting-this-agreement) in the description of your
first merge request. Contributions cannot be merged without it.

## Before you start

- For anything larger than a small fix, open an issue first and
  describe what you want to change and why — the compile-time
  composition architecture makes some seemingly small changes
  far-reaching, and a short discussion up front avoids wasted work.
- Read [`docs/STACK_ARCHITECTURE.md`](docs/STACK_ARCHITECTURE.md)
  before touching stack internals and
  [`docs/DEVICE_DEFINITION.md`](docs/DEVICE_DEFINITION.md) /
  [`docs/DSL_REFERENCE.md`](docs/DSL_REFERENCE.md) for device
  definitions and the ETS DSL.

## Code expectations

- **Keep the core `no_std` and allocation-free.** Nothing in
  `zweidraehte-proto` / `zweidraehte-device` may assume `std` or
  `alloc`.
- **Compose at compile time.** No `dyn` dispatch on hot paths, no
  runtime registries; optional features must contribute zero code to
  devices that don't enable them.
- **Follow existing patterns** (extensions + augments, context traits,
  the storage vocabulary) rather than inventing parallel ones.
- Use the packet generation/parsing infrastructure in
  `zweidraehte_proto::messages` — no hand-rolled byte fiddling.
- Cite the KNX specification with document and section
  (e.g. "03/03/04 §5.4") in comments that implement spec behaviour.

## Testing

- `cargo build`, then run the conformance suite:
  `cargo run --bin conformance-runner`. It must stay green; rebuild
  the DUT binaries (`cargo build`) before running.
- Add or extend conformance/unit tests for new protocol behaviour.
- Firmware changes: build the affected `firmware/<family>/<project>`
  directories (each is its own workspace with a pinned target — build
  from inside the project directory).

## Merge requests

- Use semantic commit messages (`feat:`, `fix:`, `refactor:`, …) and
  explain non-obvious trade-offs in the commit body.
- Keep `docs/` in sync with structural changes.
- One logical change per merge request.
