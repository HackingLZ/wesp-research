# WESP driver reverse-engineering dossier

## Scope and bottom line

This report documents the supplied `wesp.sys` using static analysis. The exact Microsoft public PDB was recovered and applied in Ghidra, producing a symbolized project, complete function/call inventories, strings, imports, exports, and approximately 27 MB of decompiler output.

The driver is the **Windows Endpoint Security Platform (WESP) driver**, version `0.1.0.156346177+c3490e8c`. It is a Microsoft development-signed, 64-bit Windows kernel minifilter/security-enforcement driver. It combines file-system, registry, process/thread/image, Object Manager, KTM, boot/ELAM, and WNF telemetry into a common event model. Client-defined BDD-backed rules evaluate those events and can allow, block, or notify. User mode controls it through a Filter Manager communication port, not through a WDM device and IOCTL dispatch table.

This is a broad platform driver, not a single-purpose filter. Its conceptual pipeline is:

```text
FLTMGR / CM / PS / OB / KTM / ELAM callbacks
                    |
                    v
        typed event + related kernel objects
                    |
                    v
    field/property/context-key resolution cache
                    |
                    v
       per-client BDD rule evaluation
          |                    |
          v                    v
 allow/block/modify      notification builder
                               |
                               v
                  bounded async event queues
                               |
                               v
                   FltSendMessage -> client
```

## Confidence and limitations

High-confidence findings come from PE metadata, imports/exports, literal data, Microsoft public symbols, and direct call edges. Architectural descriptions are supported by those symbols and decompiled control flow.

The analysis is static. The driver was not loaded in Windows, so runtime-only configuration, exact service INF settings, and every wire-level numeric discriminator were not observed. Microsoft's public PDB is stripped: it contains excellent function/public names but not the full private source/type database. Rust monomorphization and some deliberately split function bodies exceed Ghidra's decompiler assumptions. The inventory still covers every discovered function, while the failure ledger identifies the 529 functions for which pseudocode was omitted. No claim of vulnerability absence is made.

## Sample identity

| Property | Value |
|---|---|
| Input | `wesp.sys` |
| Size | 4,338,320 bytes |
| SHA-256 | `9ade5cd21e0ecb8245011eaaec047295686051e4b52af1b97552847fc3bca6b2` |
| MD5 | `3678b18f586baecf980f1a803824cc2c` |
| Format | PE32+, AMD64, native subsystem, driver DLL |
| Image base | `0x180000000` |
| Entry point | `0x180001000` (`DriverEntry`, RVA `0x1000`) |
| Link timestamp | 2026-08-31 20:38:14 America/Chicago |
| Linker | Microsoft 14.44 |
| Product | Windows Endpoint Security Platform |
| Description | Windows Endpoint Security Platform Driver |
| Internal/original name | `wesp.sys` |
| File version | `0.1.0.156346177` |
| Product version | `0.1.0.156346177+c3490e8c` |
| Embedded provider name | `Microsoft.Windows.WESP.Driver` |
| Export-table DLL name | `wesp.dll` |
| SDK evidence | Windows SDK `10.0.26100.0` build paths |
| Implementation | Rust plus a C/C++ minifilter support layer |

The link time precedes the Authenticode timestamp and is internally plausible. It is later than many currently public Windows builds, so compatibility assumptions should be tied to the exact sample rather than generalized to older WESP binaries.

## PDB provenance

The PE CodeView record identifies:

| Property | Value |
|---|---|
| PDB name | `wesp.pdb` |
| GUID | `33A0A49D-2312-4C89-9A0E-DA57A6095A25` |
| PE age | 1 |
| Symbol-server key | `33A0A49D23124C899A0EDA57A6095A251` |
| Downloaded size | 1,593,344 bytes |
| PDB SHA-256 | `3fed8f9d6f30f442f436bd3b674f03b7532a4f0223636d025fa7033b5c15c7fa` |
| PDB-reported age | 2 |
| Kind | Stripped Microsoft public PDB |

The GUID matches exactly. The age difference is consistent with a public/stripped PDB transformation; the symbols loaded successfully and map coherently to the image. The retrieval URL was:

`https://msdl.microsoft.com/download/symbols/wesp.pdb/33A0A49D23124C899A0EDA57A6095A251/wesp.pdb`

PDB module records show the Rust WESP objects and the C support modules `espfltinit`, `EspFltUtil`, `contextsup`, `Mount`, `create`, `SectionSync`, `readwrite`, `fileinfo`, `IoControl`, `DirContol`, `lockcontrol`, `cleanup`, `security`, `EspFltTxF`, `espfltutils`, `EspFltObRundown`, `EspFltCsvSup`, `EspFltData`, and generated buffer accessors.

## Authenticode

The embedded Authenticode SHA-256 digest matches the computed image digest.

| Property | Value |
|---|---|
| Subject | Microsoft Windows |
| Organization | Microsoft Corporation |
| Issuer | Microsoft Development PCA 2014 |
| Leaf validity | 2026-06-18 through 2027-10-31 UTC |
| Timestamp | 2026-09-06 04:44:21 UTC |
| Description | Microsoft Windows |
| URL | `http://www.microsoft.com/windows` |

`osslsigncode` validates the embedded digest but cannot complete local trust validation because the Microsoft Development Root Certificate Authority 2014 is not in macOS's configured CA bundle. This is a development certificate chain, not evidence of a production WHQL/Microsoft Windows Hardware Compatibility signature.

## PE layout and mitigations

| Section | Virtual address | Size | Role |
|---|---:|---:|---|
| `.text` | `0x180001000` | 4,002,816 | Primary executable code, mostly Rust |
| `.rdata` | `0x1803d3000` | 227,840 | Constants, RTTI-like data, strings, jump tables, imports |
| `.data` | `0x18040b000` | 512 | Writable globals |
| `.pdata` | `0x18040c000` | 43,008 | x64 unwind/runtime function data |
| `PAGE` | `0x180417000` | 30,720 | Pageable executable support code |
| `.edata` | `0x18041f000` | 2,048 | Export directory |
| `INIT` | `0x180420000` | 13,312 | Initialization-only code |
| `.rsrc` | `0x180424000` | 1,024 | Version resource |
| `.reloc` | `0x180425000` | 5,632 | Base relocations |

Enabled image characteristics include high-entropy ASLR, dynamic base, force integrity, NX compatibility, and Control Flow Guard. The executable has a stack security cookie and guarded indirect-call dispatch.

## External dependency surface

Ghidra resolves 261 imported functions:

| Module | Count | Purpose |
|---|---:|---|
| `FLTMGR.SYS` | 81 | Minifilter registration, contexts, names, volumes, ports, messaging, transactions |
| `NTOSKRNL.EXE` | 179 | Registry, process/thread/image, Object Manager, memory, synchronization, tokens, WNF, ETW, KTM |
| `HAL.DLL` | 1 | Platform timing/entropy support |

Important imports include `FltRegisterFilter`, `FltStartFiltering`, `FltCreateCommunicationPort`, `FltSendMessage`, `CmRegisterCallbackEx`, `ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutineEx2`, `PsSetCreateThreadNotifyRoutineEx`, `PsSetLoadImageNotifyRoutineEx`, WNF subscribe/query/unsubscribe routines, registry-transaction APIs, ETW routines, and system-thread primitives.

There are no `IoCreateDevice` or `IoCreateSymbolicLink` imports and no `DriverObject->MajorFunction` initialization. The `IoControl` C module services file-system control events inside the minifilter; it is not a classic `DeviceIoControl` API.

Several newer kernel services are resolved dynamically by name, including `ExAllocatePool2`, `FsRtlSetKernelEaFile`, `FsRtlKernelFsControlFile`, `SeGetCachedSigningLevel`, `IoGetSiloParameters`, `FltRegisterForDataScan`, `FltCreateSectionForDataScan`, `FltCloseSectionForDataScan`, `FltRequestFileInfoOnCreateCompletion`, and `FltRetrieveFileInfoOnCreateCompletion`. That permits feature probing across kernel revisions.

## Initialization and teardown

`DriverEntry` transfers control to `wesp::impl$0::main`. The recovered initialization sequence is:

1. Query feature/runtime configuration and initialize global rundown state.
2. Register the TraceLogging/ETW provider and activity infrastructure.
3. Open or create the persisted-store registry hierarchy.
4. Read the boot identifier, load persisted clients/rules/collections/queues, and initialize recovery monitoring.
5. Subscribe to and query WNF boot state.
6. Construct the central `EspCore`, client manager, rule stores, event dispatcher, trusted-thread tracking, and event queues.
7. Register the Filter Manager filter and its operation/context tables.
8. Initialize the legacy/C filesystem provider through `EspFltInitialize`.
9. Register Configuration Manager callbacks at altitude `1000001`.
10. Register process, thread, image-load, and Object Manager callbacks.
11. Create the Filter Manager communication port.
12. Start minifilter filtering.

Every stage has reverse-order failure cleanup. Normal teardown waits for rundown and removes image, thread, and process callbacks; unregisters Object Manager and registry callbacks; closes communication/client ports; releases WNF subscriptions; drops client/rule/event state; closes handles; calls `EspFltUninitialize`; unregisters the minifilter; frees pools; and unregisters tracing.

This ordering matters: callback entry wrappers acquire rundown protection, and shutdown first prevents new work, then drains active work, then releases shared objects.

## Core subsystem map

### `wesp` driver shell

Owns `DriverEntry`, port setup/message dispatch, provider registration, global `EspState`, tracing, ELAM synchronization, and coordination of the lower-level libraries.

### `wesp_lib::EspCore`

The shared core holds the client manager, event dispatcher, rule/persistence state, object tables, context keys, notification machinery, process/thread state, and recovery state. Reference-counted kernel-safe `Arc`/`Weak` implementations and rundown guards manage lifetime.

### Filter Manager filesystem provider

The minifilter observes and can act on create/open, cleanup, read/write, metadata, security, directory, EA, lock, FSCTL, section creation, pipe/mailslot, volume, and KTM transaction paths. It uses instance, stream, stream-handle, file-object, and transaction contexts. Pre/post correlation data connects asynchronous or completed operations to the same logical event.

### Registry provider

The Configuration Manager callback translates registry operation classes into typed WESP events. It supports create/open/delete key, set/delete value, rename/replace/restore, security changes, query/enumerate, save, and load. Registry names are normalized between native `\REGISTRY\MACHINE\`/`\REGISTRY\USER\` and `HKLM\`/`HKEY_LOCAL_MACHINE\`/`HKEY_USERS\` forms.

### Process/thread/image provider

The driver registers:

- one process callback using `PsSetCreateProcessNotifyRoutineEx2`;
- two thread callbacks, one subsystem-aware and one non-system path;
- one image-load callback.

These generate process create/terminate/load-image and thread create/start/terminate events. Process chains and related token/file-stream data can be captured for rules and notifications.

### Object Manager provider

`ObRegisterCallbacks` is called at altitude `1234` for process, thread, and desktop object types, with both create-handle and duplicate-handle operations enabled. Pre callbacks can affect desired access according to rule results; post callbacks supply completion data.

### Boot, ELAM, and WNF

Boot state is coordinated using WNF plus an ELAM interoperability path. The latter uses a system thread, shared section/event synchronization, notification ingestion, and event-object-ID remapping (`patch_event_object_ids`). A recovery monitor compares persisted boot IDs and repairs or discards stale persisted state. `ESP_EVENT_TYPE_BOOT_LOAD_DRIVER` is present in the event schema even though it does not arise from the ordinary runtime callbacks.

### Event dispatcher and correlation

Each provider constructs a typed event argument, associates current thread/process and related event objects, and calls the generic `EventDispatcher`. The dispatcher:

- registers/tracks the current thread to suppress trusted or recursive activity;
- obtains pre/post correlation state where applicable;
- determines clients interested in the event type;
- resolves requested fields lazily into a per-event cache;
- runs each client's BDD rule engine;
- merges enforcement outcomes and context-key updates;
- builds selected notifications and queues them;
- releases correlation and rundown state.

### Rules and BDD engine

Rules are converted into binary decision diagrams. Predicates resolve typed event fields and comparands; subrules are finalized before activation. Per-client counters maintain active event-type interest, avoiding expensive callback work for unused event types.

Recovered externally meaningful actions are:

| Action | Meaning |
|---|---|
| `NoAction` | No enforcement result from this rule |
| `Allow` | Permit the operation |
| `Block` | Deny the operation and attach a reason |
| `ForceAllow` | Internal override; deliberately rejected from persisted rules |

Recovered block-reason categories are `ProcessIdLookup`, `ThreadIdLookup`, `FetchRegistryPath`, `GetRegistryKeyObjectId`, `OpenFileObject`, `RegistryKeyObjectNotAvailable`, `RuleEngine`, `EventArgumentNotImplemented`, and `Other`.

Comparisons cover numeric, boolean, string/string-list, binary, SID, EA list, byte range, IP address, memory address, security descriptor, collections, paths/patterns, process-chain modes, and context-key values. Numeric transforms detect division by zero and type mismatches. String matching uses NFA/trie support; collection and BDD implementations are custom Rust crates.

### Event objects and property queries

Stable event-object IDs represent thread, process, token, file object, file stream, file, volume, disk, pipe, mailslot, desktop, registry key, registry key object, and KTM transaction objects. Rules and notifications request properties by type. Resolution is lazy and cached because many properties require handles, name queries, token queries, signing-level queries, or object conversion.

The notification builder can include the triggering event, thread/process/token details, process chains, related object IDs, configured object properties, pre/post status, and context-key updates. It calculates total serialized size before writing and returns explicit buffer/layout errors.

### Context keys

Context keys are client-defined state attached to clients or event objects. Supported payload families include numeric, string, and binary values with lifetimes, transformations, pinning/reference tracking, transactional update groups, and persistence. Updates are applied after rule evaluation; disconnect paths remove or retain pinned state according to ownership.

### Event queues

Each client can create multiple bounded event queues. Queues support synchronous/in-flight tracking and an asynchronous producer state, are addressed by GUID, and send serialized messages using `FltSendMessage`. They expose maximum-capacity bytes, memory reporting, clear/stash/open/close/connect operations, dropped-notification accounting, and state-change thresholds.

Memory and recovery threshold percentages drive a state-change callback. Queue teardown takes the port once, drains or marks in-flight messages disconnected, and releases client/event-object references. Trace strings include `PendingNotificationsDropped` and `ClearEventQueue`.

## User-mode control plane

The server Filter Manager port is the UTF-16 name:

`\EspFilterPort1234`

It is created with a default Filter Manager security descriptor for `FLT_PORT_ALL_ACCESS`, maximum connection count `0x200` (512), and connect/disconnect/message callbacks. The default descriptor is a kernel-generated ACL; the access constant alone does not mean all local users receive access.

The connect context differentiates the primary client port from an event-queue port. Message dispatch explicitly rejects `EventQueueMessageOnClientPort`, `NonEventQueueMessageOnEventQueuePort`, and unsupported messages. Incoming buffers use guarded user-pointer probing/copy helpers, checked offsets/alignment, bit-valid enum validation, version/capability checks, and output-buffer sizing.

Recovered operation families include:

| Family | Operations/evidence |
|---|---|
| Client lifecycle | connect, register, disconnect, unregister; GUID, name, altitude, capability tier |
| Rules | update, remove, enumerate; replace/remove/enable/disable and ensure-subrules modes |
| Collections | create, open, update, close, enumerate IDs; binary/string/integer and pattern collection validation |
| Event queues | create, open, connect, stash, clear, close, enumerate IDs; capacity and threshold controls |
| Context keys | set/update, enumerate info, apply client/event-object updates |
| Object references | add/remove event-object reference and disconnect cleanup |
| Notifications | queue delivery, reply/in-flight tracking, property selection, dropped-message state |
| State callback | queue GUID plus memory and recovery threshold percentages |

`ClientMessage::try_read` parses the discriminated request, and `ClientMessage::verify_capabilities` gates the operation before the server's jump-table dispatch. The exact private C header and all numeric message IDs are not present in the stripped PDB, so this report does not invent them. The Ghidra project retains the raw dispatch table for further ABI reconstruction.

The string `WESP://Permission` is used as a permission/capability identity in the access-control path. Client registration rejects empty client names/altitudes, duplicate IDs, invalid transitions, capability mismatches, and disconnected clients.

## Persistence model

The root is:

`\Registry\Machine\System\Wesp\PersistedStore`

The store persists the boot ID and per-client state. Recovered path builders and loaders show subtrees for clients, rules, collections, and event queues. Values include GUIDs, strings, DWORDs, QWORDs, and binary serialized schemas.

Writes use kernel registry transactions:

1. `ZwCreateRegistryTransaction` creates a transaction.
2. Transacted create/open/delete/value operations stage the update.
3. `ZwCommitRegistryTransaction` commits success.
4. Drop/error paths roll back with `ZwRollbackRegistryTransaction`.

The loader enumerates clients, validates every stored schema, counts errors, and reconstructs rule/collection/queue objects. Recovery uses the stored `boot_id`; malformed, version-mismatched, duplicate, or stale entries have explicit error categories rather than being trusted blindly.

## Complete event schema

The image contains the following event-type names:

### Thread and process

- `ESP_EVENT_TYPE_THREAD_CREATE`
- `ESP_EVENT_TYPE_THREAD_START`
- `ESP_EVENT_TYPE_THREAD_TERMINATE`
- `ESP_EVENT_TYPE_PROCESS_CREATE`
- `ESP_EVENT_TYPE_PROCESS_TERMINATE`
- `ESP_EVENT_TYPE_PROCESS_LOAD_IMAGE`

### File and filesystem

- `ESP_EVENT_TYPE_FO_CREATE`
- `ESP_EVENT_TYPE_FO_OPEN`
- `ESP_EVENT_TYPE_FO_READ`
- `ESP_EVENT_TYPE_FO_WRITE`
- `ESP_EVENT_TYPE_FO_CLEANUP`
- `ESP_EVENT_TYPE_FS_CREATE_FILE_SECTION`
- `ESP_EVENT_TYPE_FS_QUERY_FILE_INFORMATION`
- `ESP_EVENT_TYPE_FS_SET_FILE_INFORMATION`
- `ESP_EVENT_TYPE_FS_SET_FILE_SECURITY`
- `ESP_EVENT_TYPE_FS_QUERY_DIRECTORY_INFORMATION`
- `ESP_EVENT_TYPE_FS_FSCTL_FILE`
- `ESP_EVENT_TYPE_FS_SET_EA`
- `ESP_EVENT_TYPE_FS_QUERY_OPEN_FILE`
- `ESP_EVENT_TYPE_FS_LOCK_FILE`
- `ESP_EVENT_TYPE_FS_UNLOCK_FILE`

### Transactions, volumes, named pipes, and mailslots

- `ESP_EVENT_TYPE_KTM_TRANSACTION_COMMIT`
- `ESP_EVENT_TYPE_KTM_TRANSACTION_ROLLBACK`
- `ESP_EVENT_TYPE_VOLUME_MOUNT`
- `ESP_EVENT_TYPE_VOLUME_DISMOUNT`
- `ESP_EVENT_TYPE_VOLUME_FSCTL`
- `ESP_EVENT_TYPE_PIPE_CREATE`
- `ESP_EVENT_TYPE_MAILSLOT_CREATE`

### Registry

- `ESP_EVENT_TYPE_REG_CREATE_KEY`
- `ESP_EVENT_TYPE_REG_OPEN_KEY`
- `ESP_EVENT_TYPE_REG_DELETE_KEY`
- `ESP_EVENT_TYPE_REG_SET_VALUE_KEY`
- `ESP_EVENT_TYPE_REG_DELETE_VALUE_KEY`
- `ESP_EVENT_TYPE_REG_RENAME_KEY`
- `ESP_EVENT_TYPE_REG_REPLACE_KEY`
- `ESP_EVENT_TYPE_REG_RESTORE_KEY`
- `ESP_EVENT_TYPE_REG_SET_KEY_SECURITY`
- `ESP_EVENT_TYPE_REG_QUERY_KEY`
- `ESP_EVENT_TYPE_REG_QUERY_VALUE_KEY`
- `ESP_EVENT_TYPE_REG_SAVE_KEY`
- `ESP_EVENT_TYPE_REG_LOAD_KEY`
- `ESP_EVENT_TYPE_REG_ENUM_KEY`
- `ESP_EVENT_TYPE_REG_ENUM_VALUE_KEY`

### Object Manager and boot

- `ESP_EVENT_TYPE_OB_CREATE_HANDLE`
- `ESP_EVENT_TYPE_OB_DUPLICATE_HANDLE`
- `ESP_EVENT_TYPE_BOOT_LOAD_DRIVER`

`ESP_EVENT_TYPE_NONE` is also defined as the null/sentinel event.

## Exported minifilter ABI

The image exports 50 ordinals. Several are standard C++ support symbols; the rest expose the C minifilter bridge. Exact addresses are in `analysis/wesp.sys/ghidra/exports.tsv`.

| Group | Exports |
|---|---|
| Entry | `DriverEntry` |
| File pre | cleanup, create, FSCTL, lock control, query directory, query information, query open, read, set EA, set information, set security, write |
| File post | cleanup, create, FSCTL, lock control, open, query directory, query information, query open, read, set EA, set information, set security, write |
| Context/support | delete stream, release completion, loopback EA query, instance teardown complete, KTM context deleted, remove file object |
| Named endpoints | mailslot pre/post create, pipe pre/post create |
| Sections | section pre/post create |
| Volumes | mount pre/post, dismount pre/post |
| KTM | transaction commit pre/post, rollback pre/post |
| Runtime | `__CxxFrameHandler3`, `__CxxFrameHandler4`, `__GSHandlerCheck_EH4`, `_fltused` |

`EspFsMailslotPreCreate`, `EspFsPipePreCreate`, both volume-dismount callbacks, and both KTM post callbacks alias a shared no-op/success stub at `0x1800278d0`. This is intentional export aliasing, not missing code.

## Failure and defensive behavior

The binary has explicit error taxonomies for:

- malformed/unaligned user buffers and insufficient output buffers;
- invalid enums, versions, message kinds, port contexts, and capabilities;
- duplicate/missing client, collection, queue, rule, notification, and context-key IDs;
- quota/capacity/memory threshold violations;
- bad persisted data, object collisions, and recovery failures;
- missing event fields/properties or wrong polymorphic types;
- token, SID, registry-name, file-object, volume, transaction, and path-query failures;
- arithmetic overflow, division by zero, and overlong strings/process chains;
- disconnect/rundown races and state-transition timing.

Kernel callbacks generally fail open when metadata collection alone fails, but an explicit rule `Block` is propagated into the provider-specific denial mechanism. Exact NTSTATUS selection depends on the event/provider path. Rust allocation errors are converted to NTSTATUS/error enums; pool allocations use the visible `rust` tag (`0x74737572`).

## Security-relevant observations

- The driver is privileged enforcement infrastructure with a very large parser and callback surface. Its highest-risk static surfaces are port-message deserialization, persisted-schema loading, rule/BDD construction, property resolution from kernel objects, and asynchronous queue teardown.
- User pointers are not directly trusted: wrapper types probe/copy memory and validate sizes, alignment, enum bits, offsets, and integer arithmetic.
- The communication protocol is capability-gated and distinguishes client and event-queue port contexts.
- Trusted-thread tracking and reentrancy guards prevent the driver's own activity from recursively re-entering policy evaluation.
- Rundown protection is pervasive across callbacks and teardown.
- Registry persistence is transactional, reducing partial-update exposure.
- CFG, NX, ASLR, force-integrity, stack cookies, and x64 unwind metadata are present.
- Development signing is appropriate for test/development distribution but should not be treated as a production trust assertion.

## Analysis inventory

| Artifact | Contents |
|---|---|
| `analysis/wesp.sys/pdb-symbols.txt` | 36,294-line raw public/global symbol dump |
| `analysis/wesp.sys/pdb-types.txt` | PDB type-summary output; sparse because symbols are stripped |
| `analysis/wesp.sys/ghidra/functions.tsv` | All 3,947 discovered local functions: address, size, name, prototype, flags |
| `analysis/wesp.sys/ghidra/callgraph.tsv` | 29,943 direct caller/callee edges |
| `analysis/wesp.sys/ghidra/external-functions.tsv` | All 261 resolved imported functions |
| `analysis/wesp.sys/ghidra/exports.tsv` | Export labels, ordinals, aliases, and addresses |
| `analysis/wesp.sys/ghidra/strings.tsv` | All 732 Ghidra-defined strings and references |
| `analysis/wesp.sys/ghidra/memory-blocks.tsv` | Loaded image memory map |
| `decompiled-all.c` (local only) | First pseudocode volume, 20,093,864 bytes / 518,142 lines |
| `decompiled-rest.c` (local only) | Second pseudocode volume, 7,051,085 bytes / 188,828 lines |
| `analysis/wesp.sys/ghidra/decompiled-rest.c.failures.tsv` | Named/addressed functions skipped or failed in volume two |
| `analysis/wesp.sys/ghidra/decompile-failures.tsv` | One additional failed function from volume one |
| Ghidra project (local only) | Persisted, symbolized instruction-level analysis |
| `ghidra_scripts/ConfigureWespAnalysis.java` | Disables the pathological decompiler switch analyzer |
| `ghidra_scripts/ExportWespInventory.java` | Recreates inventory TSV files |
| `ghidra_scripts/DecompileWespAll.java` | Recreates bounded full-image pseudocode volumes |

The two local pseudocode files were split so editors and indexing tools could handle them. They are reproducible outputs and are not distributed. Function names and addresses are the reliable index; Ghidra-generated C types and parameter names are approximations.

## Reproduction notes

The local Ghidra project contained program `/wesp.sys`. Ghidra 12.0.3 was used with the exact PDB. The default **Decompiler Switch Analysis** analyzer was disabled because it misidentifies very large Rust enum/monomorphization dispatch regions as switch tables and can run indefinitely. All other normal analyzers completed.

To investigate a function, search `analysis/wesp.sys/ghidra/functions.tsv` for its symbol, then use its address in a reproduced Ghidra project or generated pseudocode. Use `callgraph.tsv` for direct static callers and callees. Indirect trait calls, callback tables, guarded indirect calls, and jump-table dispatch cannot all appear as direct edges.

## Source/module provenance recovered from paths

Embedded source paths identify these major internal crates/modules:

- driver shell: `sys/src`, including `server`, provider, and ELAM synchronization;
- core policy library: `lib/src`, including client, dispatcher, event, rule, filter, notification, persistence, recovery, path, property-query, and context-key modules;
- kernel wrappers: `fltmgr`, `cm`, `fs`, `ps`, `nt_types`, `wnf`;
- algorithms/schema: `bdd`, `sorted_map`, `string_match`, `api-types`, `elam-interop`;
- telemetry: `wesp-tracing` and TraceLogging Rust support;
- Rust standard library and `hashbrown 0.16.1` from Microsoft's Azure DevOps cargo registry mirror.

The build paths use `C:\__w\1\...`, consistent with an automated hosted/enterprise build pipeline. This is provenance evidence only; it does not expose the private repository or exact source revision beyond the product suffix `c3490e8c`.
