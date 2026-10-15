# Product fingerprint format

Version 3 is SHA-256 of `zweidraehte-product-v3\0` followed by compact UTF-8
JSON from `ProductData::programming_identity()`. Object keys are sorted
lexicographically at every depth, independently of serde_json map features.
Arrays preserve their declared order. Integers use JSON decimal notation;
bytes are integer arrays, booleans are JSON booleans, absent options are null
unless the retained schema record explicitly omits them through serde.

The product owner lists every contributing field in
`crates/zweidraehte-ets-files/src/product/identity.rs`. Exhaustive destructuring
requires new product fields to be classified. The inventory is:

- Product ID, exact mask ID, namespace, schema version and schema authority.
- Application identity, procedure style, ordered procedures and all nested
  controls, choices, handlers and operands, using their schema serde names.
- Data Secure capability/capacities and ordered bus-interface declarations.
- Ordered memory segments, relative allocation offsets, communication-object
  descriptors/numbers, parameter placements, property placements and fixups.
- Module geometry declarations and argument-name maps, parameter type widths
  and the resolved module parameter roster. Maps and sets use sorted keys.
- Address, association and object table segment IDs/offsets/capacities, and
  dynamic table management.
- The AP2 binding state, complete hardware/catalog relation identity and
  secondary application ID. Unbound and explicitly absent are distinct.
- Programming options: effective schema version, raw application attributes,
  program type, minimum ETS version, replacement versions, application hash,
  dynamic/linkable flags, raw IP mode, address/user/security capacities,
  secure-enabled flag, non-registration version, raw Options and Extension.
  Raw schema records retain explicit/absent distinctions and their serde names.

The fixed array layouts are:

| Field | Array elements in order |
| --- | --- |
| schema | namespace, schema version, authority (`document_namespace` or `explicit_binding`) |
| application_identity | five ID bytes, PEI type |
| application_program_2 | state (`unbound`, `absent`, `present`), relation or null, secondary ID or null |
| secondary_application | present only when a secondary PEI Program is bound: that program's complete version-3 identity object |
| segments | ID, address, size, memory type, user-memory flag, load machine, bytes, mask |
| com_objects | number, protocol type code, DPT reference, protocol flags byte |
| parameters | ID, segment, offset, bit offset, bit width, legacy-always flag, default-seed flag |
| property_parameters | ID, object selector, PID, offset, bit offset, bit width, legacy-always flag |
| property object selector | tag (0=index, 1=type), index/type, occurrence or null |
| module_definitions values | ordered parameter declarations, argument-name map |
| fixups | function, segment, ordered offsets |

Master Data is excluded: the deployment record already carries its exact-document
fingerprint separately. Numeric mask version is derived from the exact mask ID.
Creation-tool and author labels are diagnostic provenance and excluded. Project
parameter values, credentials and counters are not product fields; public image
contents and private credential commitments retain their separate identities.
Some retained declaration fields are conservative inputs: changing an unused
module declaration or an explicit option spelling can invalidate identity.

Changes to this inventory or its encoding require a new domain and deployment
evidence version. Version 3 deployment records use this format; version 2 used
Rust Debug text and is never reinterpreted as version 3. Snapshot/journal loading
discards obsolete image baselines while retaining credential commitments, section
digests and forward-only counters. Section status remains independent of image
baseline eligibility. For a requested application download without a current
baseline, automatic selection uses a full download; explicit partial or required
verified differential requests fail. A successful full download establishes new
version 3 evidence. Raw external baselines still undergo identity, image and stamp
validation at preparation.
