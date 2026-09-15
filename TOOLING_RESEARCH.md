# WESP offsec, defensive, and research tooling roadmap

## Research conclusion

Yes: this sample is sufficient to build a useful WESP research toolkit. The safest and fastest first version should call the 120 exported `Esp*` APIs through `LoadLibraryW`/`GetProcAddress`, not reimplement the raw transport. A second layer can hook or replay the recovered `0x40`-byte protocol for fuzzing in an isolated VM.

As of 2026-09-15, public tooling is extremely early. The public `WespConsumerPOC` covers registration, registered-client enumeration, removal, and one `ProcessCreate` monitor. It was runtime-tested on ARM64 client version `0.1.0.154553750`; its x64 target builds but was not runtime-tested. The supplied x64 client is newer, `0.1.0.156346177`. No public SDK is visible, so version pinning and recovered declarations are mandatory.

That leaves substantial novel space: no general client/rule/queue explorer, cross-client authorization auditor, schema diff tool, queue race harness, property/object browser, or full protocol fuzzer was found.

## Implemented project: `wesplab`

The toolkit now lives at `tools/wesplab/`. Version 0.2 includes dependency-free offline PE/protocol tooling, a C++ Windows runtime, native ARM64 build support, live discovery/capability commands, bounded notification capture/decoding, guarded client/queue/rule monitoring, multi-process authorization probes, a rule DSL and versioned IR, automated build and ETW-schema harvesting, searchable HTML timelines, optional symbolic wire capture/replay, and defensive integrity/availability scoring. Pointer-rich APIs that still lack runtime-confirmed layouts remain preserved as reproducible IR/captures rather than being invoked with guessed structures.

Implemented from the roadmap below: the build-aware parts of `wespdiff`; current/credential/SYSTEM execution for `wespauthz`; rule/filter validation for `wespgrammar`; generic opaque-preserving event decoding for `wespmon`; ETW schema extraction and correlation; the `wespwire` capture/relocation/replay skeleton; and the snapshot/hash/delivery portions of `wespwatch`. The correct Insider VM is still required to promote unconfirmed event layouts and filter descriptors into live adapters.

The long-term command surface remains:

```text
wesplab
├── doctor        sample hashes, versions, exports, privileges, PPL/test-signing
├── clients       list, describe, register, connect, unregister
├── capabilities  enumerate event/property support
├── rules         build, validate, list, apply, remove, export
├── queues        create, list, monitor, clear, stress, close
├── collections   create, list, dump, update, close
├── objects       reference and query process/thread/token/file/registry/etc.
├── context       enumerate and update client/object keys
├── snapshot      export WESP state to versioned JSON
├── diff          compare two snapshots or DLL/driver builds
├── trace         capture WESP Client + Driver TraceLogging
├── authz-test    exercise the permission/cross-client matrix
└── fuzz          grammar, wire, notification, and lifecycle harnesses
```

Read-only commands should be the default. Mutating commands should require `--write`, print the exact client/rule/queue target, save a before-snapshot, and offer cleanup. Fuzzing should refuse to start unless it detects a test VM marker supplied by the operator.

## Architecture

```text
CLI / JSON-RPC / tests
          |
          v
version-neutral domain model
clients · rules · filters · queues · properties · notifications
          |
          +----------------------------+
          |                            |
          v                            v
versioned Esp ABI adapter        ETW/TraceLogging adapter
LoadLibrary + GetProcAddress     Client + Driver providers
          |
          v
espclient.dll -> FltLib -> wesp.sys
          |
          v
optional lab-only wire interceptor/mutator
```

Do not link directly to undocumented exports in the first release. Dynamic resolution permits a clear missing-export error and makes multi-build support practical. `analysis/espclient.dll/espclient.def` can generate an import library later for exact-build test programs.

## Tool modules worth building

### 1. `wespdoctor`: compatibility and access preflight

Collect:

- OS build, architecture, Secure Boot, Code Integrity/test-signing state;
- current token elevation, integrity, protection level, groups, privileges, and `WESP://Permission` attribute presence/value;
- `wesp.sys` and `espclient.dll` file/product versions and hashes;
- all 120 expected exports and their RVAs;
- Filter Manager service/driver state;
- results of harmless connection kinds and read-only requests.

This prevents misleading research results caused by DLL/driver skew or the wrong security context. Output one JSON record suitable for attaching to bug reports.

### 2. `wespsnapshot`: state inventory and tamper detection

Use read-only exports to record:

- registered and connected client GUIDs;
- client descriptors and event capabilities;
- rule IDs and recovered descriptors where available;
- queue and collection IDs by lifetime;
- collection entries;
- client context keys;
- supported object/property matrices.

Normalize addresses and transient IDs, then diff snapshots. Defensive uses include detecting unexpected client removal, policy churn, queue disappearance, capability changes after an update, and version drift. Offensive testing can use the same output to prove whether one security principal can see or mutate another client's objects.

### 3. `wespmon`: general WESP event collector

Create queues and rules for selected event families, pre-arm multiple notification buffers, and emit JSONL/OTLP. Support callback and IOCP backends to compare behavior. Initial event packs:

- process/thread/image lifecycle;
- file create/write/rename/delete;
- registry create/set/delete/rename;
- process/thread handle access;
- pipe/mailslot activity;
- volume/disk and KTM operations.

Enrich notifications using object-reference/property APIs. Correlate the same activity with kernel ETW or Sysmon to quantify what WESP adds, loses, delays, or represents differently. This is both a defensive sensor prototype and a semantic-research platform.

### 4. `wespcanary`: prevention and health assertions

Install narrow rules around sacrificial resources and continuously verify expected behavior:

- a canary executable that should be blocked or reported;
- a canary registry key and file tree;
- a controlled handle-open attempt against a canary process;
- periodic benign events that prove the queue is still delivering.

Alert on rule removal, queue stall, latency spikes, dropped-notification changes, or a successful operation that policy should deny. This tests whether WESP-backed controls remain effective after service crashes, reconnects, updates, and resource pressure.

### 5. `wespauthz`: capability and cross-client isolation auditor

Run two or more clients from controlled security contexts and build a result matrix for every connection role and request family:

| Axis | Values |
|---|---|
| Token | standard user, elevated admin, SYSTEM |
| Protection | none, Antimalware PPL, WinTcb test process where available |
| Permission | absent, malformed, lower value, higher value |
| Code integrity | normal, test signing |
| Target | own client, other client, disconnected client, persisted client |
| Operation | observe, query, mutate, unregister, clear, close |

The tool should report allow/deny and exact HRESULT/NTSTATUS without trying to bypass the gate. The high-value question is whether lower-tier callers can alter another product's client, rules, collections, or queues.

### 6. `wespqueuecheck`: notification state-machine stress

Create deterministic tests for:

- callback-initiated disconnect (EC-01);
- IOCP closure during delivery (EC-03);
- clear/close/disconnect while payload request `0x1c` is active;
- duplicate complete, complete-after-reconnect, and re-arm-before-complete;
- free-while-armed and one buffer armed on two queues;
- state-change listener removal during its own callback;
- thread-pool widths from 1 to processor count under high event rate.

Track process memory, handles, pending buffers, delivery count, drops, queue state, and client/driver ETW. Run under Application Verifier, PageHeap, Driver Verifier, and WinDbg in a disposable VM.

### 7. `wespgrammar`: supported-input rule generator

Generate valid filter/rule trees exclusively through public constructors. Cover each leaf object family, comparison operator, action, event type, context update, collection reference, and Boolean combination. This gives:

- a conformance suite for reconstructed declarations;
- semantic mapping of numeric event/property enums;
- differential behavior across builds;
- a seed corpus for lower-level mutation.

Measure both API return values and observable kernel behavior. A successful API call is not proof that a rule matches or enforces as intended.

### 8. `wespwire`: lab-only protocol recorder and mutator

Intercept `FilterConnectCommunicationPort`, `FilterSendMessage`, and `FilterGetMessage` inside the test consumer. Record the 64-byte envelope plus deep copies of every pointed-to input before the call. Represent pointer relationships symbolically so captures can be relocated and replayed.

Mutation stages:

1. change only enums/flags while preserving layout;
2. alter counts, lengths, alignment, and pointer aliasing;
3. mutate nested rule/filter graphs and collection entries;
4. race buffer mutation against kernel copies;
5. combine messages with cancellation, reconnect, and persistence fault injection.

Prefer supported public-API seeds. Raw random 64-byte messages will mostly die in the outer parser and provide poor coverage.

### 9. `wespdiff`: build-to-build ABI and semantic differ

Given two `wesp.sys`/`espclient.dll` pairs:

- compare hashes, versions, PE mitigations, exports, imports, PDB symbols, strings, and function sizes;
- diff request/connection discriminants and validation ranges;
- enumerate ETW provider/event schemas;
- run the same capability/property/rule corpus and compare results;
- identify new event types, properties, actions, and permission behavior.

This may be the most publishable near-term tool because WESP is preview/undocumented and changes across builds. It also prevents researchers from treating an older public PoC as a stable SDK.

### 10. `wespwatch`: blue-team integrity monitor

Combine periodic read-only snapshots with real-time TraceLogging from `Microsoft.Windows.WESP.Client` and `Microsoft.Windows.WESP.Driver`. Alert on:

- client registration/unregistration outside maintenance windows;
- unexpected caller image/PID performing rule, queue, or collection mutations;
- repeated authorization failures or malformed requests;
- queue disconnects, clears, drops, and reconnect storms;
- rule count/hash changes;
- mismatch between WESP events and independent ETW/Sysmon canaries.

ETW is especially useful because it can be enabled dynamically and consumed in real time or from ETL. Treat it as audit telemetry, not a tamper-proof trust anchor if the adversary is already administrative.

## Novel research questions

### Authorization and isolation

1. Is the permission model two discrete roles or a partially ordered capability lattice?
2. Which exact message IDs differ between permission values `10,000,000` and `1,000,000,000`?
3. Is client ownership bound to GUID only, signer/PPL signer, service SID, process identity, or registration-time token?
4. Can one authorized client connect to, unregister, clear, or replace another client's objects?
5. Are cached capabilities revoked after token/security-attribute/PPL changes?

### Policy semantics

1. How are conflicting allow/block actions resolved across altitude order?
2. Which event families are pre-operation enforceable versus post-operation observational?
3. Are rule/collection updates atomic across memory, persistent store, and in-flight events?
4. What happens to enforcement while a client is disconnected, slow, or crashing?
5. Can context-key updates influence later events across clients or only inside one client namespace?

### Telemetry quality

1. Which process/file/registry/object properties are available before equivalent public ETW data?
2. What is lost through queue pressure, payload truncation, or property-selection rules?
3. Can WESP provide a lower-overhead defensive sensor than existing multi-provider ETW stacks?
4. How stable are object IDs and correlations across callbacks, process reuse, and reboot?

### Robustness

1. Can a reachable Rust panic in `wesp.sys` be triggered with an authorized but malformed message?
2. Are recursive Boolean filter graphs depth-limited before stack or BDD explosion?
3. Can sizing/retry races return inconsistent lengths that escape the second validation layer?
4. Do queue cancellation and payload retrieval create stale reference IDs or retained in-flight entries?
5. Does persistence recovery always fail closed after injected power loss at each commit stage?

## Implementation sequence

### Phase 0: versioned ABI package

- Reconstruct only the declarations required for `doctor`, client enumeration, and descriptor query.
- Dynamically resolve exports and validate exact file/product versions.
- Add `static_assert` for every recovered structure size/alignment.
- Keep one adapter namespace/directory per WESP build.

### Phase 1: read-only tooling

- Implement `doctor`, `clients list/describe`, `capabilities`, `snapshot`, `diff`, and ETW capture.
- This yields immediate defensive and research value with limited state-change risk.

### Phase 2: owned-object consumer

- Register a dedicated lab GUID.
- Add queue lifecycle, process-create monitoring, clean teardown, and automatic unregister.
- Generalize to event packs and property enrichment.

### Phase 3: policy and state

- Add filters/rules, collections, context keys, snapshot/restore, and canaries.
- Refuse mutation outside the tool-owned client unless `--cross-client-test` is explicit.

### Phase 4: test harnesses

- Add authorization matrix, grammar generation, lifecycle races, and persistence fault injection.
- Produce JUnit/JSON artifacts and automatically collect dumps/ETL.

### Phase 5: raw protocol research

- Add symbolic capture/replay and structured mutation around the recovered protocol.
- Keep this component separate from the general administration CLI and VM-gated.

## Build and test environment

- Windows Insider build containing the exact driver/client pair.
- Visual Studio 2022, MSVC v143, Windows SDK; a WDK is useful for debugging but the public PoC demonstrates it is not required merely to call the DLL.
- `fltuser.h`/`FltLib.lib` only for raw transport work; normal exported-API use can load `espclient.dll` dynamically.
- WinDbg kernel debugging and VM snapshots.
- Driver Verifier scoped to `wesp.sys`; Application Verifier/PageHeap for the consumer.
- WPR/WPA or a TDH-based real-time consumer for both WESP TraceLogging providers.

Microsoft documents that Filter Manager gives each connection private endpoints and supports `FilterSendMessage`, `FilterGetMessage`, replies, and IOCP-based high-volume consumption. That matches the recovered implementation and makes a multi-buffer asynchronous monitor feasible.

## Deliverables for a strong public project

- `include/wesp/<build>/espclient.h` — versioned recovered declarations.
- `src/abi/<build>/` — export resolver and structure converters.
- `src/cli/` — read-only-by-default commands.
- `src/trace/` — TraceLogging discovery/capture/JSON conversion.
- `src/lab/` — mutation, races, and authorization matrix; excluded from production builds.
- `schemas/` — JSON schema for snapshots, events, and test results.
- `corpus/` — valid public-API-generated seeds, no Microsoft binaries.
- `docs/compatibility.md` — exact tested builds and hashes.
- `docs/safety.md` — VM requirement, cleanup, mutation guardrails.
- CI for offline ABI/export checks; Windows Insider runtime tests remain opt-in/self-hosted.

## Sources

- Microsoft: [FilterConnectCommunicationPort](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterconnectcommunicationport)
- Microsoft: [Communication between user mode and minifilters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode)
- Microsoft: [ETW architecture and real-time consumption](https://learn.microsoft.com/en-us/windows-hardware/test/weg/instrumenting-your-code-with-etw)
- Jonathan Johnson: [A First Look Inside the Windows Endpoint Security Platform](https://jonny-jhnson.dev/blog/a-first-look-inside-the-windows-endpoint-security-platform/)
- Jonathan Johnson: [WespConsumerPOC](https://github.com/jonny-jhnson/WespConsumerPOC)
