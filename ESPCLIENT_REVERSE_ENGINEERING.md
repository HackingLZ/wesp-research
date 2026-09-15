# `espclient.dll` reverse-engineering dossier

## Bottom line

The supplied file is `espclient.dll` (not `expclient.dll`), Microsoft's user-mode client library for the Windows Endpoint Security Platform driver. It is an exact product-version match for the supplied `wesp.sys`: `0.1.0.156346177+c3490e8c`.

The DLL is not a thin import shim. It contains a C ABI, a C++ object/lifetime layer, substantial Rust serializers and validators, Filter Manager transport, notification delivery through thread-pool I/O, and TraceLogging. Its 120 exports expose essentially the complete WESP consumer surface: client registration, rules and filters, collections, event queues, event-object references, property queries, context keys, and utility functions.

The recovered architecture is:

```text
consumer process
  |
  +-- 120 exported Esp* functions
        |
        +-- C++ ownership/synchronization objects
        |     ClientObject / EventQueue / PortListener
        |
        +-- Rust validation and serialization
        |     rules / filters / context / property messages
        |
        +-- FilterConnectCommunicationPort("\\EspFilterPort")
        +-- FilterSendMessage(64-byte request envelope)
        +-- FilterGetMessage(async queue delivery)
                         |
                         v
                       wesp.sys
```

## Evidence and coverage

The exact Microsoft public PDB was recovered from the Microsoft symbol server and applied in Ghidra 12.0.3. The completed inventory contains:

| Artifact | Coverage |
|---|---:|
| Exported API functions | 120 |
| Ghidra-discovered functions | 1,521 |
| Direct call edges | 9,591 |
| External functions/imports | 103 |
| Defined strings | 4,957 |
| Decompiled functions that failed | 4 |

The complete pseudocode is in `analysis/espclient/ghidra/decompiled-all.c`; the four failures are recorded separately. Machine-readable function, call-graph, import, export, string, Rust-function, and signature inventories are under `analysis/espclient/`.

This is static analysis. Prototypes inferred without private type records are approximate, and runtime claims are explicitly identified as test candidates.

## Sample identity

| Property | Value |
|---|---|
| File | `espclient.dll` |
| Size | 1,122,960 bytes |
| SHA-256 | `90b9f908dbed63181ba7d71fd0b9aa51cc5674a9116c71bc44c612371abe8ec3` |
| Format | PE32+, AMD64, Windows GUI DLL |
| Image base | `0x180000000` |
| File version | `0.1.0.156346177` |
| Product version | `0.1.0.156346177+c3490e8c` |
| Description | Microsoft Windows Endpoint Security Platform Client DLL |
| Compiler/linker | Microsoft 14.51 |
| ETW provider | `Microsoft.Windows.WESP.Client` |
| Source evidence | Rust plus `client\\dll` and `client\\lib` C++ |
| PDB path | `C:\\__w\\1\\s\\bin\\x64_Release\\espclient.pdb` |

The PE reproducible-build timestamp decodes to 2000-08-13 and should not be interpreted as a build date.

### PDB provenance

| Property | Value |
|---|---|
| GUID | `DB1756D1-62D8-B71A-6CCE-A78DF8D0199B` |
| Symbol-server key | `DB1756D162D8B71A6CCEA78DF8D0199B1` |
| Local SHA-256 | `a0745bd1632399f732f266c89ec705e4bc0035ec6d72e8a39a99801845f75ef9` |
| Kind | Stripped Microsoft public PDB |

The PDB reports a transformed/public age while the image records age 1. Ghidra accepted it and the names map coherently throughout the image.

## Hardening and dependencies

The image has high-entropy ASLR, NX, Control Flow Guard with 334 guarded functions, CET compatibility, an EH continuation table, a `/GS` security cookie, and an Authenticode security directory. It has no TLS callbacks. The embedded manifest requests `asInvoker` and `uiAccess=false`.

There is no networking stack. The security-relevant imports are local Windows APIs:

- `FLTLIB.DLL`: `FilterConnectCommunicationPort`, `FilterSendMessage`, `FilterGetMessage`.
- Kernel32: handles, SRW locks, thread-pool I/O, IOCP, heap, cancellation, and wait-on-address primitives.
- Advapi32: ETW and SID helpers.
- NTDLL: path conversion and low-level runtime helpers.
- USER32: desktop open/close for desktop object references.
- RPCRT4: `UuidCreate` for caller-unspecified object identifiers.

## Connection protocol

All transport uses the Filter Manager port `\\EspFilterPort`. A caller first selects a connection role with a small context. The driver accepts kinds 0 through 6 and validates size, alignment, strings, token security attributes, protection state, and capability tier before returning a port handle.

| Kind | Role | Recovered layout |
|---:|---|---|
| 0 | Reserved/internal | Header only; no public DLL path observed |
| 1 | Register client | GUID, two 16-bit byte lengths, two UTF-16 strings; minimum `0x18` |
| 2 | Unregister client | GUID; `0x14` |
| 3 | Connect client | GUID; `0x14`; handle remains open |
| 4 | Connect event queue | Client GUID + queue GUID; `0x24` |
| 5 | Management query | Header-only context used for enumerate/query |
| 6 | Queue-state listener | Client GUID + queue GUID + two flag bytes; `0x28` |

Kinds 1, 2, and 5 create short-lived ports. Kind 3 becomes the long-lived control channel. Kinds 4 and 6 are distinct asynchronous delivery channels.

The port's default Filter Manager descriptor limits access to administrators and SYSTEM. The driver then reads the token security attribute named `WESP://Permission`, evaluates its numeric value, and checks protected-process/test-signing state. Authorization is captured into the connection object and `ClientMessage::verify_capabilities` gates each subsequent message.

## Request protocol

`FilterSendMessage` always receives a fixed `0x40`-byte outer request. The first machine word is the request discriminator. Remaining fields contain inline scalars and pointers/lengths for nested user buffers. The driver probes the outer input and output and uses bounded copy helpers for nested data; no blind kernel dereference of a user pointer was found.

The complete recovered discriminator table is in `analysis/espclient/protocol.tsv`. The public operations cover IDs `0x00..0x1c`; ID `0x05` remains unmapped to a public wrapper. Important IDs include:

| ID | Operation |
|---:|---|
| `0x00` | Update rules |
| `0x01` | Set event-object context |
| `0x02` | Complete async notification |
| `0x03` / `0x04` | Reference / close an event object |
| `0x06` | Query object properties |
| `0x07..0x10` | Client enumeration, descriptors, capabilities, rules, and context |
| `0x11..0x16` | Collection create/open/close/update/enumerate |
| `0x17..0x1b` | Queue clear/enumerate/create/open/close |
| `0x1c` | Fetch out-of-line notification payload |

Variable results use a caller buffer and returned length. `HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)` (`0x8007007a`) drives allocation-and-retry. `Esp::SendMessageWithRetry` starts at 256 bytes and makes at most ten attempts. Fixed-size replies are checked strictly; impossible lengths from the trusted driver cause fail-fast.

## Object and API model

### Clients

`EspRegisterClient` persists a GUID plus primary name and altitude-like alternate string. `EspConnectClient` returns an opaque shared client handle. A connected client can query its capabilities and manage rules, collections, queues, object references, properties, and context keys. Registration, unregistration, connected-client enumeration, registered-client enumeration, and descriptor query also have standalone management paths.

### Filters and rules

Filters are local immutable Rust-backed graphs until submitted. Leaf filters exist for event, client, token, mailslot, pipe, KTM transaction, desktop, registry-key object, registry key, disk, volume, file object, file, file stream, process, and thread properties. Generic filters and AND/OR/XOR/NOT combinators form expression trees. `EspCreateRule` binds rule metadata to a filter, and `EspUpdateRules` serializes batches into the driver.

The Rust layer validates descriptor discriminants, alignments, comparison types, strings, arrays, and graph structure before constructing the binary rule update. The kernel independently parses and validates it.

### Collections

Collections are GUID-addressed persistent/stable sets used by rule predicates. The library can create, open, update, enumerate, and close collections. Update modes are translated into Rust `StableCollectionUpdates` variants before request `0x14` is sent.

### Event-object references and properties

Reference factories cover process, thread, process/thread token, file/path/ID, file stream/path/ID, volume, disk, registry key, pipe, mailslot, and desktop. Each reference is represented to the client as an opaque wrapper around a kernel reference identifier.

Property support can be checked locally for 16 object families. Query calls share one Rust `EspRsSendQueryObjectProperties` dispatcher, which selects an object-family serializer and returns one allocation containing property records and relocated pointers. Callers release query/enumeration memory with `EspFreeMemory`.

### Context keys

Context keys attach typed client-defined state either to the connected client or to an event object. Both update paths validate alignment and all enum fields before serialization. Enumeration APIs return all keys for either scope.

## Notification delivery and lifecycle

1. Create or open a queue.
2. Connect it in callback or IOCP mode.
3. Allocate one or more `0x1010`-byte notification buffers.
4. Arm each buffer. `FilterGetMessage` is issued as overlapped thread-pool I/O.
5. On completion, fetch payload ID `0x1c` if the kernel header says the payload is out of line.
6. `EspRsInitNotification` validates and relocates embedded pointers, then dispatches the notification.
7. Complete the notification with request `0x02`, optionally re-arm, and eventually free it.

Callback mode invokes `void callback(ESP_EVENT_NOTIFICATION *, void *)`. IOCP mode posts a 32-byte public wrapper as the completion's `OVERLAPPED` pointer. Queue-state changes use a second port connection and callback.

`EspRsInitNotification` performs notable defense-in-depth: minimum-size and alignment checks, overflow checks, non-overlap checks between inline/out-of-line buffers, relocation-table bounds checks, property type range checks, and rejection of pointers that overlap relocation metadata.

Disconnect transitions the listener from active to disconnecting, cancels I/O, waits for the internal pending count, cancels/waits for thread-pool callbacks, optionally posts an IOCP shutdown sentinel, then closes the pool, I/O object, and port. A five-minute timeout ends in fail-fast.

## Important implementation functions

| Address | Function | Why it matters |
|---|---|---|
| `0x180002b00` | `send_update_rules` | Constructs request `0x00` |
| `0x180002bd0` | `send_create_collection` | Request `0x11`, strict response handling |
| `0x180002cc0` | `send_update_collection` | Request `0x14` |
| `0x180002d90` | `send_create_event_queue` | Request `0x19` |
| `0x1800285a0` | `EspRsGetNotificationPayload` | Request `0x1c` and output bounds |
| `0x18002b080` | `EspRsInitNotification` | Validates and relocates notification graphs |
| `0x1800bd808` | `Esp::SendMessageWithRetry` | Variable-output allocation/retry policy |
| `0x1800dadb0` | `ClientObject::Register` | Builds kind-1 connection context |
| `0x1800db180` | `ClientObject::Connect` | Long-lived kind-3 port |
| `0x1800dcf10` | `PortListener::ThreadPoolCallback` | Async callback boundary and pending count |
| `0x1800dd010` | `PortListener::ArmIo` | Issues `FilterGetMessage` |
| `0x1800dd1c0` | `PortListener::CompleteDisconnect` | Cancellation, wait, fail-fast, teardown |
| `0x1800ddab0` | `EventQueue::NotificationCallback` | Payload retrieval and callback/IOCP dispatch |
| `0x1800ddea0` | `EventQueue::Connect` | Kind-4 connection and delivery-mode setup |

The complete address/signature reference is `analysis/espclient/export-signatures.tsv`; all internal functions are in `analysis/espclient/ghidra/functions.tsv`.

## Interoperability

`analysis/espclient/espclient.def` lists every public export and can be passed to Microsoft's `lib.exe /def` or LLVM's `llvm-dlltool` to create an import library. Reconstructing a safe SDK still requires version-pinned C declarations for private descriptors and enums. Do not call the raw Rust `EspRs*` internals by address: they are not exported and are compiler-ABI/version dependent.

## Related public research

Microsoft describes WESP as the Windows resiliency mechanism for moving security products out of the kernel in its [Windows Resiliency Initiative overview](https://www.microsoft.com/en-us/windows/business/windows-resiliency-initiative). Independent runtime research documents the same port, permission attribute, PPL checks, and an earlier client build in [A First Look Inside the Windows Endpoint Security Platform](https://jonny-jhnson.dev/blog/a-first-look-inside-the-windows-endpoint-security-platform/) and its [WespConsumerPOC repository](https://github.com/jonny-jhnson/WespConsumerPOC). Those runtime results are useful corroboration, but they target a different build and should not replace version-specific tests.
