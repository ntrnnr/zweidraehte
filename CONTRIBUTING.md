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
- **Preserve compile-time device composition.** Keep fixed device choices
  typed through shared code; a runtime enum or bool can lose specialization
  just as type erasure can. Follow the
  [device composition contract and review checklist](docs/STACK_ARCHITECTURE.md#121-preserve-fixed-device-choices)
  when changing either stack or its shared protocol helpers.
- **Follow existing patterns** (extensions + augments, context traits,
  the storage vocabulary) rather than inventing parallel ones.
- Use the packet generation/parsing infrastructure in
  `zweidraehte_proto::messages` — no hand-rolled byte fiddling.
- Cite the KNX specification with document and section
  (e.g. "03/03/04 §5.4") in comments that implement spec behaviour.

## Testing

- Run the handwritten conformance suite with
  `cargo xtask conformance handwritten`. The wrapper first builds all
  runners and DUT binaries with the same Cargo profile. Append a suite
  or test-name filter for a subset; use
  `cargo xtask conformance --release handwritten` for a release run.
- If the licensed EITT templates are available locally, set
  `EITT_TEMPLATES` to their directory and run
  `cargo xtask conformance eitt --profile full/tp1-systemb`. List other
  device profiles with `cargo xtask conformance profiles`.
- **Do not run other Cargo commands while a conformance suite is running.**
  The runner respawns DUT binaries during tests; rebuilding them can hang
  the run. Preserve complete test output, redirecting it to a log when needed.
- Add or extend conformance/unit tests for new protocol behaviour.
- After changing an API used outside its crate, run
  `cargo test --workspace --no-run` to check its consumers.
- Firmware changes: build the affected `firmware/<family>/<project>`
  projects from inside their directories so Cargo loads their local
  target and linker configuration. They belong to the shared
  `firmware/Cargo.toml` workspace, separate from the host workspace.

## Merge requests

- Use semantic commit messages (`feat:`, `fix:`, `refactor:`, …) and
  explain non-obvious trade-offs in the commit body.
- Keep `docs/` in sync with structural changes.
- One logical change per merge request.
