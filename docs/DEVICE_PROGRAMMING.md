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

> **Tested hardware, so far: three devices.** The pipeline has been
> validated end-to-end against an **MDT BE-TAL5502.01** (Push Button
> Lite 55/63 2-fold, System 7 / mask 0705) over both USB and KNX/IP
> tunneling, a **mask-0012h BCU1** device over the direct no-LSM
> path, and a **mask-0020h BCU2** device carrying that same converted
> BCU1 program — the device-mask-aware path, including repeated
> re-downloads onto a running application — plus our own software
> DUTs in the conformance tier. Every wire-level decision is pinned
> to the spec, the certification templates, or ETS traces of those
> devices, so comparable products *should* work — but a native BCU2
> product has not met silicon yet, and System B has only ever been
> driven against our own stack. Expect other devices to surface
> surprises; keep an ETS log handy for comparison when they do.

## Prerequisites

- **The product file.** The vendor's official MTXML or `.knxprod`
  matching your device's application *and version* — the download's
  identity check (`LdCtrlCompareProp` on `PID_HARDWARE_TYPE`) refuses
  a mismatched product, exactly as ETS would. Vendor packages often
  contain one program per hardware variant; pick the one whose
  hardware type matches (an ETS log or a failed identity check tells
  you the device's value). Legacy BCU-era products often exist only
  as `.vd3`/`.vd4` conversions, whose only XML form is a grab from
  ETS's product store — not schema-conformant MTXML: the `Static`
  section uses compact element names (`APS`, `AP`, `PT`, `CO`, …) and
  the root omits `xmlns`. The parser accepts that spelling, so such a
  grab loads directly. An "unknown element" error means the grab uses
  a compact tag we have not seen yet — the alias list follows
  evidence rather than guesswork, so it needs adding.
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

## The mods file

The mods file is one device's configuration, as a diff from the
product's defaults — the role an ETS project plays for a single
device, in a hand-editable TOML. It answers the three questions a
download needs from *you* rather than from the product file: which
parameter values differ from the defaults, which group addresses each
communication object talks on, and which individual address the
device carries. Anything you don't mention stays at the product
default.

Every tool speaks it: `knx-dump` generates one, the TUI loads and
exports one, and `knx-loader` (or the TUI's `p`) applies it to a
fresh device model, compiles the result into the memory image and
tables, and downloads that. Because the file references parameters by
their stable MTXML ids, it survives product-file updates and language
switches, and one file can be replayed onto several devices with
`--ia`.

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
# translated skeletons: --language de-DE
```

Editing a skeleton is usually **iterative**, and the reason is the
product's dynamic pages: a KNX program shows and hides parameters
based on other parameters' values, and the skeleton can only list
what is visible under the *current* configuration. Pick a different
enum value — set a button function to "Dimming" instead of
"Switching", or an LED brightness to "dynamic" — and a whole set of
parameters (dimming times, brightness thresholds) exists that the
first dump never showed, because ETS would not have shown them
either. So after editing, feed the file back to `knx-dump`:

```bash
# apply your edits, then re-dump the skeleton *under that configuration*
cargo run --bin knx-dump -- --product <product> --mods mods.toml -o mods.toml
```

The regenerated skeleton keeps your entries as active (un-commented)
`[[param]]`/`[[link]]` blocks and lists the newly revealed parameters
as fresh commented blocks with their choices — repeat until the
selections stop revealing anything new. (Skipping the loop and
writing entries blind fails safe: an entry for a parameter your
selections keep hidden is rejected on load, not silently ignored.)

**Or export from the TUI** with `e` — see [Programming from the
TUI](#programming-from-the-tui); both emit the same format, and the
TUI shows revealed parameters immediately, which makes it the more
comfortable way to explore deeply nested option trees.

## Assigning an individual address

A factory-fresh device (default `15.15.255`) needs its project address
first. The address comes from the mods file's `[device]` section, and
`--ia` overrides it on the command line — so one mods file can serve
several devices, or a first-time assignment can name the address
without editing the file.

**Programming button** — the loader does it inline during a download:

```bash
cargo run --bin knx-loader -- -p <product> --usb load --mods mods.toml --ia 1.1.2 --program-ia
```

`--program-ia` waits for you to press the device's programming button
— it polls the bus with programming-mode scans until exactly one
device answers (and tells you if several are pressed at once, since
the address write is a broadcast every listening device would
accept). It then writes the target address, verifies it with another
scan, and **switches programming mode back off itself**, mask-aware:
bit 0 of the master data's `ProgrammingMode` memory address on masks
with memory-mapped management (System 7 / BCU lineage), or
`PID_PROGMODE` on the device object elsewhere. A device that refuses
the remote switch-off just gets a note to release the button — the
download continues either way. No keyboard interaction is needed
beyond the physical button press.

**By serial number, without touching the device** — switch programming
mode remotely and let the same flow run:

```bash
# serial from line_scan/device_scan
cargo run -p zweidraehte-client --example prog_mode -- --usb --serial 00C50011AABB on
cargo run --bin knx-loader -- -p <product> --usb load --mods mods.toml --ia 1.1.2 --program-ia
cargo run -p zweidraehte-client --example prog_mode -- --usb --serial 00C50011AABB off
```

`prog_mode` resolves the serial to the device's current address,
reads its descriptor, and flips programming mode the way that
generation expects: bit 0 of memory `0060h` for System 7 / BCU-era
masks, `PID_PROGMODE` for System B. (The trailing `off` is optional —
the loader already switches programming mode off after assigning.)

The TUI does not assign addresses (its `p` download expects the
device to already answer at the mods file's address); use the loader
for the first-time addressing, then work from the TUI freely.

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

### BCU-era masks (BCU1 001xh, BCU2 002xh)

Legacy devices are downloaded by **their own** mask, not the
product's: the loader reads DD0 after connecting and accepts an older
product when the device's `DownwardCompatibleMasks` lists it — the
rule ETS follows, and the reason a BCU2 can run a converted BCU1
program. The procedure, load-control path and authorization then come
from the *device's* mask, while the table codings come from the
*product's* family (an RT1 program stays RT1 whatever silicon runs
it). `--device-mask <hex>` previews that compat compile offline.

Four things differ from the System 7 flow above:

1. **BCU1 has no load state machines at all.** Its download is a
   direct memory-write sequence from the mask's own template — no
   load records, no state polls — and `Connect` skips `A_Authorize`,
   which is a BCU2 addition. BCU2 uses the property path with its
   declared machines and the 03/05/02 §3.31.2 task records.
2. **Writes are diffed.** The image is read back first and only
   changed bytes are written, which is what makes a re-download onto
   a live device cheap; the application is halted before the LSM
   cycle so it cannot run against half-written tables.
3. **Tables are relocated, not placed statically.** For converted
   programs (`DynamicTableManagement="true"`) the association table
   is packed immediately behind the actual-size address table and the
   one-byte AssocTabPtr is repointed, with one placeholder slot per
   unlinked group object — exactly as ETS's table formatter does.
4. **Mask-ROM fixups are applied at compile time.** BCU-era programs
   are native code calling mask-ROM entry points that sit at
   different addresses per mask; each `Fixup` is resolved against the
   mask actually being compiled for. On the product's own mask this
   is an identity patch, on a downward-compatible host it is
   load-bearing.

Vendor products for these devices usually exist only as ETS
product-store XML rather than schema-conformant MTXML; the parser
accepts that spelling (see "Prerequisites").

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
