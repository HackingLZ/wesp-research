# WESP important-function reference

This is the curated function-level companion to [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md). It focuses on routines that define WESP's behavior, trust boundaries, policy decisions, persistence, and lifecycle. Compiler glue, generic Rust destructors, formatting functions, and repeated event-type monomorphizations remain searchable in `analysis/wesp.sys/ghidra/functions.tsv` and the two decompiler volumes.

## Reading conventions

- Addresses are virtual addresses for image base `0x180000000`.
- Names come from the exact Microsoft public PDB where available.
- Ghidra prototypes are approximate because the public PDB is stripped.
- A “family” means Rust emitted a specialized copy for many event types; representative functions are documented instead of repeating identical architecture dozens of times.
- Direct and indirect call evidence is available in `analysis/wesp.sys/ghidra/callgraph.tsv` and the saved Ghidra project.

## 1. Driver lifecycle

### `DriverEntry` — `0x180001000`, 776 bytes

The Windows loader entry point. It establishes the security cookie, enters `wesp::impl$0::main`, and owns top-level unwind/cleanup behavior. If initialization fails partway through, this path removes already-registered process, thread, image, Object Manager, registry, Filter Manager, WNF, and ETW resources in reverse order.

Security significance: partial initialization must not leave callbacks pointing at released state. The observed teardown sequence is deliberately defensive.

### `wesp::impl$0::main` — `0x180001340`, 12,217 bytes

The primary orchestrator. It creates `EspCore`, loads persisted configuration, initializes recovery and boot state, registers event providers, constructs the minifilter communication port, and calls `FltStartFiltering`.

Major responsibilities:

1. Feature/runtime configuration and global rundown setup.
2. TraceLogging/ETW registration.
3. Persisted-store and boot-ID loading.
4. Client, rule, collection, queue, and event-object infrastructure.
5. Filter Manager, registry, process/thread/image, and Object Manager registration.
6. WNF and ELAM boot coordination.
7. Reverse-order error cleanup.

### `wesp::panic` — `0x180001310`, 39 bytes

The terminal Rust panic handler. It calls `KeBugCheckEx(0x52555354, ...)`, where `0x52555354` is ASCII `RUST`.

Security significance: an attacker-reachable panic becomes a system-wide denial of service. Static analysis has not demonstrated such reachability, but all parser and rule invariants should be fuzzed with this behavior in mind.

### `wesp::provider::filesystem::FsProvider::new` — `0x18002b580`, 194 bytes

Constructs the filesystem provider, seeds its random state from kernel timing/random facilities, and enters the C minifilter support layer through `EspFltInitialize`.

### `EspFltInitialize` — `0x1804201d8`, 296 bytes

Initialization entry for the C minifilter bridge. It coordinates Filter Manager registration, globals, contexts, and lookaside lists through `EspFltInitializeFltMgr`, `EspFltInitializeGlobals`, and `EspFltInitializeLookasideLists`.

## 2. User-mode control plane

### `fltmgr::Filter::create_port` — `0x1800430e0`, 541 bytes

Creates `\EspFilterPort1234`. It calls `FltBuildDefaultSecurityDescriptor` with `FLT_PORT_ALL_ACCESS`, installs connect/disconnect/message callbacks, and permits up to 512 simultaneous connections.

The Windows default descriptor restricts the port to administrators and SYSTEM. WESP's connection setup adds capability/security-attribute checks on top.

### `fltmgr::connect_callback` — `0x180043300`, 285 bytes

Filter Manager's connection callback. It validates the caller-supplied connection context and delegates to `wesp::server::impl$0::connect::setup`.

### `wesp::server::impl$0::connect::setup` — `0x180012ef0`, 253-byte primary extent

The real connection-state constructor. The public symbol covers a discontiguous optimized body, which is why Ghidra reports a small nominal size while recovering much more control flow.

Recovered behavior:

- accepts connection-context kinds `0..6` with kind-specific minimum sizes;
- rejects misaligned, truncated, or inconsistent string/pointer layouts;
- references the current process and primary token;
- queries token security attributes for `WESP://Permission`;
- distinguishes primary client, registration, and event-queue connection roles;
- builds a typed connection object or returns an NTSTATUS error.

### `fltmgr::message_notify_callback` — `0x180046cb0`, 197 bytes

The top-level request boundary. It probes the complete input for read access and output for write access, wraps both in bounded user-buffer objects, invokes the WESP server, and converts the result to Filter Manager's output-length/NTSTATUS contract.

### `ClientMessage::try_read` — `0x180041f90`, 208 bytes

Parses the fixed `0x40`-byte outer `ClientRequest`, validates the request discriminant and basic enum fields, then converts it to WESP's internal message enum. The outer request supports discriminants `0x00..0x1c`; `0x1d` represents the parse/error state internally.

### `ClientMessage::verify_capabilities` — `0x180041e90`, 134 bytes

Reads the connected client's capability tier under a shared push lock and uses a per-message dispatch table to decide whether the request is allowed. This is the authorization gate immediately before operation dispatch.

### `wesp::server::impl$0::message` — `0x180004b80`, 509-byte primary extent

Central control-message dispatcher. It creates an ETW activity context, dispatches by parsed message kind through a large jump table, and serializes the selected output. It explicitly distinguishes messages valid on a client port from messages valid on an event-queue port.

Security significance: this is the main privileged parser/dispatcher surface. Nested rules, predicates, property arrays, collections, queues, and context-key data are validated by specialized `probe_and_read_*` helpers before entering persistent state.

## 3. Client and policy management

### `ClientManager::register` — `0x180393050`, 4,268 bytes

Registers a client GUID, name, altitude, capability tier, and persisted/non-persisted state. It rejects duplicate IDs, empty names/altitudes, invalid state transitions, and persistence collisions.

Clients are ordered by altitude, allowing deterministic policy evaluation and resolution among multiple consumers.

### `ClientManager::load_persisted_clients` — `0x1803945d0`, 4,518 bytes

Reconstructs persisted client objects during driver initialization, associates them with the current boot/recovery state, and reports individual load failures without trusting malformed records.

### `ClientManager::update_rules_for` — `0x180392080`, 1,743 bytes

Locates a client and applies a validated batch of rule changes. Updates include replacement, removal, enable/disable, and subrule-resolution modes.

### `ClientManager::remove_rules_for` — `0x180390e60`, 4,578 bytes

Removes selected rules and coordinates counter, BDD, persistence, and event-interest changes.

### `ClientRuleCollection::update_rules` — `0x1802d82e0`, 14,736 bytes

The core rule-update transaction. It validates rule IDs and subrules, constructs candidate rule tables/BDDs, updates active-event counters, commits persistent changes, and rolls back temporary state on error.

This is one of the most security-sensitive functions: malformed graphs must not create cycles, unresolved references, excessive BDD expansion, inconsistent counters, or panic-triggering invariants.

### `ClientObject::new` — `0x18038f7f0`, 3,423 bytes

Constructs one client and its rule set, context-key store, object tables, collections, event queues, persistence binding, altitude, and state machine.

### `ClientObject::create_collection` — `0x1803880b0`, 4,397 bytes

Creates typed binary, string, integer, or pattern collections. It validates key size/alignment, uniqueness, maximum size, pattern syntax, and persistence requirements.

### `ClientObject::update_collection` — `0x180389590`, 12,196 bytes

Applies collection insert/remove/replace operations. This is a large user-controlled mutation path with explicit errors for invalid keys, collisions, fixed-size violations, and maximum capacity.

### `ClientObject::create_event_queue` — `0x18038c5b0`, 4,212 bytes

Creates a bounded queue identified by GUID, configures capacity and delivery state, inserts it into the client's object table, and optionally persists it.

### `ClientManager::connect_event_queue` — `0x180392a70`, 1,492 bytes

Binds a separately connected Filter Manager port to an existing client queue. It validates client/queue identity and prevents duplicate or invalid port state.

### Collection/queue reference family

Important lifecycle helpers include:

| Function | Address | Purpose |
|---|---:|---|
| `ClientObject::open_collection` | `0x180387000` | Open and reference a collection by GUID |
| `ClientObject::open_event_queue` | `0x180387850` | Open and reference a queue by GUID |
| `ClientObject::close_collection_reference` | `0x18038e210` | Release a collection reference safely |
| `ClientObject::close_event_queue_reference` | `0x18038ebf0` | Release a queue reference safely |
| `ClientObject::enumerate_collection_ids` | `0x18038d630` | Return visible collection GUIDs |
| `ClientObject::enumerate_event_queue_ids` | `0x18038da70` | Return visible queue GUIDs |
| `ClientObject::add_event_object_reference` | `0x18038deb0` | Pin a kernel event object for client use |
| `ClientObject::remove_event_object_reference` | `0x18038f5d0` | Remove a pin/reference |

## 4. Event acquisition

### `cm::callback::register_callback` — `0x180032000`, 155 bytes

Registers the Configuration Manager callback at altitude `1000001` and stores its cookie for teardown.

### `cm::callback::registry_callback` — `0x1800320a0`, 139-byte primary extent

Dispatches registry notification classes into typed WESP registry events. Its optimized body covers create/open/delete, value operations, rename/replace/restore, security, query/enumeration, save, and load.

### `ps::register_ps_notify_routines` — `0x18003fe20`, 167 bytes

Registers process, two thread, and image-load callbacks. Each successful stage has reverse cleanup if the next registration fails.

### Process notification family

| Function | Address | Purpose |
|---|---:|---|
| `ps::create_process_notify` | `0x18003e4a0` | Process create/terminate events, process object setup, rule dispatch |
| `ps::create_thread_notify_subsystems` | `0x18003fed0` | Subsystem-aware thread events |
| `ps::create_thread_notify_nonsystem` | `0x180040dc0` | Non-system thread events |
| `ps::load_image_notify` | `0x1800414c0` | Image-load events and related file/process properties |

### `ob::register_callback` — `0x18003c7f0`, 289 bytes

Registers pre/post callbacks at altitude `1234` for process, thread, and desktop object types, covering both handle creation and handle duplication.

### `ob::pre_ob_operation_callback` — `0x18003c920`, 3,398 bytes

Builds an Object Manager handle event, resolves requestor and target information, evaluates policy, and can modify requested access before the handle is created or duplicated.

### `ob::post_ob_operation_callback` — `0x18003d670`, 2,866 bytes

Completes the correlated handle event with final status/granted access and emits post-operation notifications.

### Representative minifilter callbacks

The exported C bridge contains many structurally similar pre/post pairs. These are the most useful representatives:

| Function | Address | Role |
|---|---:|---|
| `EspFsFilePreCreate` | `0x18001e810` | File create/open pre-enforcement |
| `EspFsFilePostCreate` | `0x180017210` | Final create status and object correlation |
| `EspFsFilePreRead` | `0x180022b90` | Read policy evaluation |
| `EspFsFilePostRead` | `0x18001b810` | Completed read notification |
| `EspFsFilePreWrite` | `0x180025040` | Write policy evaluation |
| `EspFsFilePostWrite` | `0x18001d830` | Completed write notification |
| `EspFsSectionPreCreate` | `0x1800290f0` | Executable/data section creation policy |
| `EspFsFilePreSetSecurity` | `0x180024760` | File security descriptor change policy |
| `EspFsFilePreFsctl` | `0x18001f3a0` | FSCTL and volume-control policy |
| `EspKtmTransactionPreCommit` | `0x18002a6f0` | Transaction commit event/enforcement |
| `EspKtmTransactionPreRollback` | `0x18002ad80` | Transaction rollback event/enforcement |

Each wrapper acquires rundown protection, constructs provider-specific arguments, obtains correlation state, invokes the generic dispatcher, translates allow/block results to minifilter behavior, and releases temporary references.

## 5. Dispatch and rule evaluation

### `EventDispatcher::process_rules_with_current_thread_process<FileCreate>` — `0x18034a0b0`, 2,054 bytes

Representative dispatcher specialization. It attaches current thread/process context, registers trusted/reentrant thread state, constructs the event evaluation context, invokes the appropriate `RuleEngine` specialization, applies context-key updates, and queues requested notifications.

Equivalent specializations exist for every supported event family; their architecture is the same while argument/property resolvers differ.

### `EventDispatcher::get_post_correlation` — `0x1803486a0`, 467 bytes

Retrieves and removes pre-operation correlation data for a completed operation. Correct single-consumption behavior prevents stale IDs, leaks, and mismatched post events.

### `RuleEngine::process_event_internal<FileCreate>` — `0x1801fd660`, 7,915 bytes

Representative filesystem rule engine. It evaluates interested clients in altitude order, lazily resolves fields, walks BDD nodes, combines action outcomes, prepares notifications, and applies allow/block semantics.

### `RuleEngine::process_event_internal<RegCreateKey>` — `0x18029caa0`, 18,655 bytes

Representative registry specialization. Its larger size reflects registry path, key-object, security, and pre/post argument handling.

### `RuleEngine::process_event_internal<ProcessCreate>` — `0x1802b65c0`, 16,032 bytes

Representative process specialization. It supports process chains, tokens, image/file properties, and process-creation enforcement.

### `RuleEngine::process_event_internal<ObHandleCreate>` — `0x18026ad30`, 14,216 bytes

Representative Object Manager specialization. It evaluates requestor/target data and can drive access-mask modifications before handle creation.

## 6. Notifications and queues

### `NotificationBuilder<FileCreate>::build` — `0x1800c00f0`, 11,768 bytes

Representative notification constructor. It collects configured event fields, related object IDs, process chain, thread/token/file/volume properties, statuses, and context-key updates. It computes output size before writing and emits typed serialization errors for absent or oversized properties.

### `NotificationBufferBuilder::into_payloads` — `0x18039a310`, 57 bytes

Finalizes the serialized notification into payload buffers suitable for queue delivery.

### `EventQueue::queue_async_notification_internal` — `0x1803021c0`, 424 bytes

Adds a completed notification to the asynchronous delivery path while enforcing queue state and lifetime.

### `AsyncStateInner::enqueue` — `0x180302370`, 2,044 bytes

The central bounded-queue insertion routine. It handles capacity accounting, notification IDs, pending/in-flight state, wakeups, and dropped-notification reporting.

### `EventQueue::clear` — `0x1803030a0`, 289 bytes

Clears queued and eligible in-flight state while preserving disconnect/rundown invariants.

### Event-queue worker entries

| Function | Address | Purpose |
|---|---:|---|
| `thread_entry<with_client_port>` | `0x180302ce0` | Owns a client port while sending/receiving queue traffic |
| `thread_entry<connect>` | `0x1803031d0` | Performs queue connection and worker-state transition |
| `EventQueue::report_memory_usage` | `0x180302ba0` | Reports capacity use and evaluates threshold callbacks |

## 7. Persistence and recovery

### `PersistedStateLoader::read_clients` — `0x18031d120`, 2,543 bytes

Enumerates persisted client keys below `\Registry\Machine\System\Wesp\PersistedStore`, validates their schema, and schedules individual client reconstruction.

### `persistence::loader::load_client` — `0x18030ec70`, 13,713 bytes

Reconstructs one complete client: identity, altitude, capability tier, rules, collections, event queues, context state, and boot metadata. It reports malformed records rather than blindly activating them.

### `PersistedStore::enum_rules` — `0x1803c1520`, 15,351 bytes

Enumerates and decodes persisted rule records. This is a large boot-time parser and a primary fuzz target if an attacker can influence the registry store.

### `StoreTransaction::commit` — `0x18031aea0`, 65 bytes

Commits a staged kernel registry transaction. Related `persist` and `delete` helpers build the operation set; drop/error paths roll back.

### `ClientStoreTransaction::commit` — `0x1802de710`, 131 bytes

Client-level wrapper that commits client/rule/collection/queue persistence only after in-memory validation succeeds.

### `RecoveryMonitor::recover_persisted_store` — `0x1803b25e0`, 1,386 bytes

Compares boot identity and persisted-state health, then repairs, resets, or reloads stale state. It prevents objects from a prior boot from retaining invalid kernel object identities.

## 8. Highest-priority security review targets

1. `connect::setup`: token security-attribute parsing and connection-context variants.
2. `message_notify_callback` → `ClientMessage::try_read` → `server::message`: full user-to-kernel parser chain.
3. `ClientRuleCollection::update_rules`: graph/BDD expansion, cycles, counters, persistence rollback, panic reachability.
4. `ClientObject::update_collection`: nested buffers, collection sizing, pattern parsing, transactional replacement.
5. `ClientObject::create_event_queue` and `AsyncStateInner::enqueue`: quota enforcement and resource exhaustion.
6. `PersistedStore::enum_rules` and `load_client`: boot-time parsing of registry-controlled data.
7. Representative `RuleEngine::process_event_internal` functions: fail-open/fail-closed behavior and property-resolution errors.
8. `wesp::panic`: every path that can turn malformed input or unexpected kernel state into bugcheck `RUST`.
9. Pre/post correlation and queue teardown: races, double-consumption, stale references, and rundown ordering.

## 9. Complete lookup layer

For functions outside this curated set:

- `analysis/wesp.sys/ghidra/functions.tsv` contains all 3,947 discovered functions.
- `analysis/wesp.sys/ghidra/callgraph.tsv` contains 29,943 direct edges.
- `ghidra_scripts/DecompileWespAll.java` regenerates the approximately 27 MB of local pseudocode from the exact sample.
- `analysis/wesp.sys/ghidra/decompiled-rest.c.failures.tsv` and `analysis/wesp.sys/ghidra/decompile-failures.tsv` identify known decompiler gaps.
- The local Ghidra project and generated pseudocode are deliberately not distributed.
