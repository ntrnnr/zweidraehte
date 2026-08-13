# Programming Real Devices

How to configure a real KNX device from its official vendor product
file, using the tools in this workspace — from finding the device on
the bus to a verified download, interactively through the TUI or
scripted on the command line.

The pipeline is the same one ETS uses, layer for layer:

```
vendor product file (.knxprod / MTXML)      knx_master.xml
        │                                        │
        ▼                                        ▼
   ProductData ──────────────┐            MaskDb (per mask version)
                             │                   │
   mods file (TOML) ──► Device model ──► compile() ──► DeviceImage + procedure
   (params, links, IA)  (defaults +                        │
                         overrides,                        ▼
                         visibility)              Downloader over the bus
                                                  (KNX/IP tunneling or USB)
```

A **mods file** is the only thing you author: one device's diff from
the product defaults — parameter values, group-address links,
com-object flag overrides, and the individual address. Everything
structural comes from the product file and the master data.

> **Tested hardware, so far: exactly one device.** The whole pipeline
> has been validated end-to-end against an **MDT BE-TAL5502.01**
> (Push Button Lite 55/63 2-fold, System 7 / mask 0705) over both USB
> and KNX/IP tunneling — plus our own software DUTs in the
> conformance tier. Every wire-level decision is pinned to the spec,
> the certification templates, or ETS traces of that device, so other
> System 7 products *should* work — but nothing else has met real
> silicon yet, and System B has only ever been driven against our own
> stack. Expect other devices to surface surprises; keep an ETS log
> handy for comparison when they do.

## Prerequisites

- **The product file.** The vendor's official MTXML or `.knxprod`
  matching your device's application *and version* — the download's
  identity check (`LdCtrlCompareProp` on `PID_HARDWARE_TYPE`) refuses
  a mismatched product, exactly as ETS would. Vendor packages often
  contain one program per hardware variant; pick the one whose
  hardware type matches (an ETS log or a failed identity check tells
  you the device's value).
- **Master data** (`knx_master.xml`). Resolved automatically: an
  explicit `--master-data` path, a `.knxprod`'s bundled copy, the
  `KNX_MASTER_DATA` env var, or the on-disk cache/download
  (`~/.cache/knxprod/`). Note that vendor-bundled ETS5-era
  `knx_master.xml` files do not parse — let the resolver find current
  master data instead.
- **Bus access.** Every tool takes the same flags: `--server ip:port`
  (KNX/IP tunneling) or `--usb[=VID:PID]` (KNX USB interface; bare
  `--usb` auto-discovers, the value needs the `=` spelling).

## Finding the device

Sweep a line for present devices (connectionless descriptor probe,
with serial numbers):

```bash
cargo run -p zweidraehte-client --example line_scan -- --usb --line 1.1
#   1.1.2  serial 00C5:0011AABB
```

List devices currently in programming mode:

```bash
cargo run -p zweidraehte-client --example device_scan -- --usb
```

## Assigning an individual address

A factory-fresh device (default `15.15.255`) needs its project address
first. Two ways:

**Programming button** — the loader does it inline during a download:

```bash
cargo run --bin knx-loader -- -p <product> --usb load --mods mods.toml --program-ia
```

`--program-ia` prompts you to press the device's programming button,
writes the mods file's address via `NM_IndividualAddress_Write`,
verifies it with a programming-mode scan, and continues into the
download. Make sure exactly one device is in programming mode — the
write is a broadcast that every listening device accepts.

**By serial number, without touching the device** — switch programming
mode remotely and let the same flow run:

```bash
# serial from line_scan/device_scan
cargo run -p zweidraehte-client --example prog_mode -- --usb --serial 00C50011AABB on
cargo run --bin knx-loader -- -p <product> --usb load --mods mods.toml --program-ia
cargo run -p zweidraehte-client --example prog_mode -- --usb --serial 00C50011AABB off
```

`prog_mode` resolves the serial to the device's current address,
reads its descriptor, and flips programming mode the way that
generation expects: bit 0 of memory `0060h` for System 7 / BCU-era
masks, `PID_PROGMODE` for System B.

The TUI does not assign addresses (its `p` download expects the
device to already answer at the mods file's address); use the loader
for the first-time addressing, then work from the TUI freely.

## The mods file

```toml
[device]
individual_address = "1.1.2"
# max_apdu = 55          # optional; negotiated from the device when absent

[[param]]
id = "M-0083_A-0095-15-B3F0_P-8"   # full MTXML parameter id
value = 1                           # int for enums/numbers, string for text

[[link]]
com_object = 0                      # object number (ASAP)
group_addresses = ["5/1/1", "5/1/3"]  # first sends, the rest listen
# flags = { transmit = true }       # optional per-flag overrides

# Virtual (memoryless) parameters — e.g. button descriptions that only
# shape labels — live in [[param]] like any other; the download simply
# never patches memory for them.
```

Values are validated on load against the product: unknown ids, values
outside the type's range or enum, and parameters not visible under the
configured selections are hard errors. The visibility check is what
protects union members — writing an inactive member would corrupt the
bytes its active sibling owns.

### Producing one

**Dump a skeleton** of everything configurable, as commented TOML with
names, texts, and choices:

```bash
cargo run --bin knx-dump -- --product <product> -o mods.toml
# edit mods.toml, then regenerate the skeleton around your edits —
# a changed selection can reveal new parameters:
cargo run --bin knx-dump -- --product <product> --mods mods.toml
# translated skeletons: --language de-DE
```

**Or export from the TUI** (below) — both emit the same format.

## Programming from the TUI

```bash
cargo run -p knxprod-tui -- <product.xml> --mods mods.toml --usb
```

- **Parameters tab**: ETS-style page tree (group headers are not
  selectable — only the sub-pages carry settings). `Enter` edits the
  selected parameter; visibility, labels, and block renames update
  live, including `{{…}}` text templates fed by description
  parameters.
- **Communication Objects tab**: `Enter` on an object assigns group
  addresses (comma-separated, first one sends).
- `l` opens the language popup (the product's `<Languages>`
  translations); edits survive a switch.
- `e` exports the session as a mods file — back to the `--mods` file
  with its `[device]` section preserved, or to
  `<program id>-mods.toml` with a placeholder address.
- **`p` programs the device**: the session's configuration goes
  through the identical pipeline as the loader (compile, APDU
  negotiation, procedure, load-state verification), with a progress
  popup showing finished and current steps and a byte-accurate gauge.
  Requires the TUI to have been started with a bus target and the
  mods `[device]` section to carry the address.

## Programming from the command line

```bash
# inspect first: parameter patches, regions, the instruction stream
cargo run --bin knx-loader -- -p <product> load --mods mods.toml --dry-run
# optionally write the compiled blobs for inspection
cargo run --bin knx-loader -- -p <product> load --mods mods.toml --dry-run --dump-blobs out/

# the real thing
cargo run --bin knx-loader -- -p <product> --usb load --mods mods.toml [--ia 1.1.2] [--program-ia]
```

`--ia` overrides the mods file's address (one mods file, several
devices). After the procedure's restart the loader reads the load
states back and requires `01` (Loaded) from every machine the
procedure completed — machines the product never loads (e.g. a PEI
program it doesn't have) may rest Unloaded.

The APDU is negotiated like ETS does: the device's
`PID_MAX_APDULENGTH` bounded by the interface's capacity (an MDT
push button: 55 → 52-byte memory-write chunks instead of the standard
frame's 12). Pin it with `max_apdu` in the mods file if a device
misreports.

## Unloading a device (clean slate)

```bash
cargo run --bin knx-loader -- -p <product> --usb unload --ia 1.1.2
# or take the address from a mods file:
cargo run --bin knx-loader -- -p <product> --usb unload --mods mods.toml
```

Runs the mask's `Unload/all` template: every load state machine is
unloaded, which invalidates the address/association/application
tables — the device stops participating in group communication until
the next download. **The individual address survives** (the device
would otherwise lose itself mid-procedure), so a subsequent `load`
needs no re-addressing. The loader prints the load states afterwards;
all `00` (Unloaded) is the clean slate.

## Reading a device's configuration back

```bash
cargo run --bin knx-loader -- -p <product> --usb read --ia 1.1.2 --out dumped/
```

Chunk-reads every absolutely-addressed segment the product declares
into `region_XXXX.bin` files — what the device *actually* holds.
Useful for cross-checking our compiled blobs against an ETS-written
configuration: program with ETS, `read` the device, then compare with
`load --dry-run --dump-blobs` of the equivalent mods (the `read`
files are capacity-sized, the compiled blobs content-sized — compare
the common prefix). System 7 products only; System B devices place
their tables at device-chosen addresses.

## How KNX/IP tunneling carries a configuration session

With `--server ip:port`, the client opens a **KNXnet/IP tunneling**
connection to the interface (default port 3671) and everything below
rides through it unchanged:

1. **Connect**: UDP `CONNECT_REQUEST` with a tunneling CRI; the
   interface answers with a channel id and — critically — an
   **assigned individual address** from its own address pool (visible
   in the log as e.g. `assigned_address=1.0.2`). That address, not
   anything configured on our side, is the source address of every
   management telegram we send; the device answers back to it.
2. **Capabilities**: a `TunnelingFeatureGet` asks the interface for
   its max APDU; interfaces that don't answer are assumed
   extended-frame capable (254). The final chunk size is negotiated
   separately against the *device* (`PID_MAX_APDULENGTH`) — the
   effective value is the minimum of both.
3. **Data**: each telegram is a cEMI `L_Data.req` inside a
   `TUNNELING_REQUEST`; the interface acknowledges with a
   `TUNNELING_ACK` (sequence-numbered, retransmitted on loss) and
   converts to TP1 frames on the line. Incoming traffic — T_ACKs,
   property responses, memory responses — arrives the same way in
   reverse. The transport-layer connection to the device
   (`T_Connect`, sequence numbers, T_ACK timeouts) is entirely
   between us and the *device*; the tunnel is a dumb pipe for it.
4. **Liveness**: `CONNECTIONSTATE_REQUEST` heartbeats keep the
   channel alive; a dead interface surfaces as a tunnel disconnect
   (distinct from the device closing its transport connection).
5. **Teardown**: `DISCONNECT_REQUEST` when the tool finishes.

Practical notes: one tunnel supports one management connection at a
time here (the loader and TUI open and close it per action); a
device's restart at the end of a download kills the *transport*
connection but not the tunnel, which is how the loader can reconnect
for the load-state verification without renegotiating. KNX **IP
Secure** tunneling is not implemented yet — use a plain tunneling
interface or USB.

## What the download actually does

For a System 7 (mask 0705) device, the procedure comes from the
product file and runs over the **property path** — interface objects
1..4 carry `PID_LOAD_STATE_CONTROL`, the machine index is the object
index — because that is what real silicon and ETS speak, even though
the master data still describes the legacy memory window at `0104h`.
The sequence, byte-compatible with an ETS trace of the same device:

1. `T_Connect`, then `A_Authorize` with the free-access key
   (`FF FF FF FF`) — real devices silently discard system-memory
   writes from unauthorized connections.
2. Identity check: `PID_HARDWARE_TYPE` must match the product.
3. Per machine: Unload → StartLoading → allocation records (data
   segments, the task segment announcing the application id) → the
   image writes → LoadCompleted.
4. The group tables are compiled from your links; a vendor product's
   group-object table is *overlaid* (per-object flags/type over the
   firmware's own pointers), never synthesized.
5. Restart. The device kills the connection instead of acknowledging —
   that is the success signal, not an error.
6. After a boot grace, load states are read back.

## Troubleshooting

- **"device identity mismatch on object 0 property 78"** — wrong
  product file for this hardware (or the wrong variant out of a
  multi-program package). The guard is doing its job; find the
  program whose `LdCtrlCompareProp` value matches the device.
- **"parameter … is not visible under the configured values"** — the
  mods file sets something the current selections hide (a different
  mode owns it, or it is the inactive member of a union). Fix the
  selector first; `knx-dump --mods` regenerates the skeleton under
  your current selections so you can see what actually applies.
- **Master data errors** — set `KNX_MASTER_DATA` to a current
  `knx_master.xml`, and don't point at ETS5-era copies from vendor
  directories.
- **A download that stops at the very first Unload/Load event** on
  real hardware usually means the wire format is off, not the device —
  compare against an ETS log of the same device (`RUST_LOG=debug`
  prints every step the loader executes).
