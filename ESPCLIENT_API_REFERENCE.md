# `espclient.dll` API reference

This is a recovered, version-specific reference for the 120 exported functions in `espclient.dll` `0.1.0.156346177+c3490e8c`. Names and addresses are exact; prototypes in `analysis/espclient.dll/export-signatures.tsv` are Ghidra approximations because the public PDB contains no private type records.

Common conventions:

- Status-returning functions use 32-bit `HRESULT` semantics even where Ghidra displays `long` or `ulonglong`.
- Handles are opaque user-mode wrapper pointers. They are family-specific and reference-counted; they are not interchangeable Windows handles.
- Memory returned by enumeration/property/descriptor APIs is released with `EspFreeMemory`.
- Filters and rules are built locally; rules take effect only after `EspUpdateRules`.
- Event notifications must follow allocate → arm → callback/IOCP → complete → re-arm or free.

## Client lifecycle and discovery

| Export | VA | Purpose |
|---|---:|---|
| `EspRegisterClient` | `0x1800d65e0` | Register/persist a client descriptor by GUID |
| `EspUnregisterClient` | `0x1800d62f0` | Unregister a client GUID |
| `EspConnectClient` | `0x1800d5df0` | Open the long-lived control connection and return a client handle |
| `EspDisconnectClient` | `0x1800d5b50` | Close a connected client handle's port |
| `EspEnumerateRegisteredClients` | `0x1800d5830` | Return registered client GUIDs |
| `EspEnumerateConnectedClients` | `0x1800d5510` | Return currently connected client GUIDs |
| `EspQueryClientDescriptor` | `0x1800d51a0` | Return a variable-length descriptor for a GUID |
| `EspGetEventCapabilities` | `0x1800cacb0` | Query supported/capability flags for an event type |

Normal setup is register once, connect by GUID, create a queue, connect/arm notifications, install rules, consume events, then reverse the lifecycle. Management enumeration and descriptor query use a short-lived kind-5 port.

## Rule lifecycle

| Export | VA | Purpose |
|---|---:|---|
| `EspCreateRule` | `0x1800cff60` | Construct a local Rust-backed rule from descriptor/filter data |
| `EspGetRuleId` | `0x1800cfdf0` | Read the GUID stored by a local rule object |
| `EspCloseRule` | `0x1800cfc90` | Release a local rule object |
| `EspUpdateRules` | `0x1800cf440` | Batch add/update/remove rules through request `0x00` |
| `EspRemoveRulesForClient` | `0x1800cef50` | Remove a selected set/mode through request `0x0d` |
| `EspRemoveAllRulesForClient` | `0x1800cf1d0` | Remove all rules through request `0x0c` |
| `EspEnumerateRuleIds` | `0x1800ce7f0` | Enumerate rule GUIDs by selector |
| `EspEnumerateAllRulesForClient` | `0x1800ceba0` | Return all rule identifiers/descriptors for the client |

`EspUpdateRules` is the main policy-control primitive. The library validates and serializes complex rule graphs; the driver reparses and commits them.

## Filter construction

All filter constructors return local immutable filter handles. Leaf functions select a property family, comparison type, and typed value. Composite functions combine handles. `EspCloseFilter` releases a handle.

| Family | Exports |
|---|---|
| Generic | `EspCreateFilter`, `EspCloseFilter` |
| Boolean | `EspCreateAndFilter`, `EspCreateOrFilter`, `EspCreateXorFilter`, `EspCreateNotFilter` |
| Core | `EspCreateEventFilter`, `EspCreateClientFilter`, `EspCreateTokenFilter` |
| IPC/transaction/desktop | `EspCreateMailslotFilter`, `EspCreatePipeFilter`, `EspCreateKtmTransactionFilter`, `EspCreateDesktopFilter` |
| Registry/storage | `EspCreateRegistryKeyObjectFilter`, `EspCreateRegistryKeyFilter`, `EspCreateDiskFilter`, `EspCreateVolumeFilter` |
| Filesystem | `EspCreateFileObjectFilter`, `EspCreateFileFilter`, `EspCreateFileStreamFilter` |
| Execution | `EspCreateProcessFilter`, `EspCreateThreadFilter` |

The leaf functions occupy `0x1800d0f00..0x1800d2d00`; the four composite constructors occupy `0x1800d03e0..0x1800d0c60`.

## Event queues

| Export | VA | Purpose |
|---|---:|---|
| `EspCreateEventQueue` | `0x1800d4780` | Create a GUID-addressed queue and return a queue handle |
| `EspOpenEventQueue` | `0x1800d3ec0` | Open an existing queue by GUID |
| `EspCloseEventQueue` | `0x1800d42f0` | Close the server-side queue and release wrapper state |
| `EspGetEventQueueId` | `0x1800d3a30` | Read the queue GUID |
| `EspEnumerateEventQueueIds` | `0x1800c3e90` | Enumerate queue GUIDs by lifetime |
| `EspClearEventQueue` | `0x1800d37a0` | Drop queued entries through request `0x17` |
| `EspConnectEventQueueWithCallback` | `0x1800d4660` | Use callback delivery with a configurable worker maximum |
| `EspConnectEventQueueWithIocp` | `0x1800d4520` | Use caller-facing IOCP delivery |
| `EspDisconnectEventQueue` | `0x1800d3ba0` | Cancel, join, and tear down delivery |
| `EspSetEventQueueStateChangeCallback` | `0x1800d3190` | Open kind-6 listener for queue-state changes |
| `EspRemoveEventQueueStateChangeCallback` | `0x1800d2ed0` | Disconnect the state-change listener |

Do not synchronously disconnect the queue from its callback; see EC-01 in `ESPCLIENT_SECURITY_REVIEW.md`.

## Notification buffers

| Export | VA | Purpose |
|---|---:|---|
| `EspAllocateEventNotification` | `0x1800d5070` | Allocate/zero the library's `0x1010`-byte receive object |
| `EspArmEventNotification` | `0x1800d4c70` | Issue an overlapped `FilterGetMessage` on a queue |
| `EspCompleteEventNotification` | `0x1800ce5a0` | Acknowledge the kernel notification with request `0x02` |
| `EspFreeEventNotification` | `0x1800d4f40` | Free out-of-line payload and receive object |

The callback-visible pointer is offset from an internal header. Passing any other allocation to arm/complete/free is unsafe.

## Collections

| Export | VA | Purpose |
|---|---:|---|
| `EspCreateCollection` | `0x1800c54e0` | Create a GUID-addressed stable collection |
| `EspOpenCollection` | `0x1800c4d90` | Open a collection by GUID |
| `EspCloseCollection` | `0x1800c4bd0` | Close/release a collection |
| `EspGetCollectionId` | `0x1800c5360` | Return its GUID |
| `EspGetCollectionType` | `0x1800c51f0` | Return the collection type enum |
| `EspUpdateCollection` | `0x1800c4900` | Add/remove/replace entries through request `0x14` |
| `EspEnumerateCollectionIds` | `0x1800c4590` | Enumerate GUIDs by lifetime |
| `EspEnumerateCollectionEntries` | `0x1800c4200` | Return serialized collection entries |

## Event-object references

Object-reference factories send request `0x03`; close sends `0x04`. Duplicate and get-object operations are local wrapper/reference-count operations.

| Family | Exports |
|---|---|
| Generic | `EspCreateEventObjectReference`, `EspCreateEventObjectReferenceById`, `EspDuplicateEventObjectReference`, `EspCloseEventObjectReference` |
| Introspection | `EspGetEventObjectFromReference`, `EspGetEventObjectId`, `EspGetEventObjectType` |
| Execution | `EspCreateProcessReference`, `EspCreateThreadReference`, `EspCreateProcessTokenReference`, `EspCreateThreadTokenReference` |
| File | `EspCreateFileReferenceById`, `EspCreateFileReferenceByPath`, `EspCreateFileStreamReferenceById`, `EspCreateFileStreamReferenceByPath` |
| Storage | `EspCreateVolumeReference`, `EspCreateDiskReference` |
| Named objects | `EspCreateRegistryKeyReference`, `EspCreatePipeReference`, `EspCreateMailslotReference`, `EspCreateDesktopReference` |

Factories validate obvious null/alignment/type constraints before selecting one of the Rust object-family serializers.

## Property support and queries

Support checks are local type-table queries. Query functions use request `0x06` and return library-owned property arrays.

| Object family | Support export | Query export |
|---|---|---|
| Client | `EspIsClientPropertySupported` | `EspQueryClientProperties` |
| Event | `EspIsEventPropertySupported` | represented in notification/event data |
| Token | `EspIsTokenPropertySupported` | `EspQueryTokenProperties` |
| Mailslot | `EspIsMailslotPropertySupported` | `EspQueryMailslotProperties` |
| Pipe | `EspIsPipePropertySupported` | `EspQueryPipeProperties` |
| KTM transaction | `EspIsKtmTransactionPropertySupported` | `EspQueryKtmTransactionProperties` |
| Desktop | `EspIsDesktopPropertySupported` | `EspQueryDesktopProperties` |
| Registry-key object | `EspIsRegistryKeyObjectPropertySupported` | `EspQueryRegistryKeyObjectProperties` |
| Registry key | `EspIsRegistryKeyPropertySupported` | `EspQueryRegistryKeyProperties` |
| Disk | `EspIsDiskPropertySupported` | `EspQueryDiskProperties` |
| Volume | `EspIsVolumePropertySupported` | `EspQueryVolumeProperties` |
| File object | `EspIsFileObjectPropertySupported` | `EspQueryFileObjectProperties` |
| File | `EspIsFilePropertySupported` | `EspQueryFileProperties` |
| File stream | `EspIsFileStreamPropertySupported` | `EspQueryFileStreamProperties` |
| Process | `EspIsProcessPropertySupported` | `EspQueryProcessProperties` |
| Thread | `EspIsThreadPropertySupported` | `EspQueryThreadProperties` |

The query result contains relocated pointers and must not be copied blindly across processes or persisted as-is.

## Context keys

| Export | Purpose |
|---|---|
| `EspSetClientContextKey` | Add/update/remove typed client-scoped state via request `0x0e` |
| `EspSetEventObjectContextKey` | Add/update/remove typed object-scoped state via request `0x01` |
| `EspEnumerateAllClientContextKeys` | Return every client key via `0x0f` |
| `EspEnumerateAllEventObjectContextKeys` | Return every key on an object via `0x10` |

The Rust constructor rejects misaligned descriptors and out-of-range lifetime, operation, value-type, and behavior enums.

## Utilities

| Export | Purpose |
|---|---|
| `EspInitUnicodeString` | Initialize the library's counted Unicode descriptor from a NUL-terminated string |
| `EspStringMatchesPattern` | Match a Unicode string against the platform's compiled/pattern descriptor |
| `EspFreeMemory` | Release variable result allocations returned by this DLL |

## Recovered internal layers

The exported C ABI generally follows this call chain:

```text
Esp* export in client\\dll\\api.cpp
  -> Esp::ClientObject / EventQueue / Collection C++ method
  -> EspRs* Rust FFI validator/serializer
  -> FilterSendMessage / FilterGetMessage
```

The non-exported `EspRs*` layer includes `EspRsCreateFilter`, `EspRsCreateCompositeFilter`, `EspRsCreateRule`, `EspRsSendUpdateRules`, the object/property dispatchers, all queue/collection send routines, `EspRsGetNotificationPayload`, and `EspRsInitNotification`. These addresses are useful for reversing and debugger breakpoints, not as a supported ABI.

## Build integration

`analysis/espclient.dll/espclient.def` is the authoritative export-name list. On a Windows development machine:

```bat
lib.exe /def:espclient.def /machine:x64 /out:espclient.lib
```

This creates only the import library. A consumer still needs accurate declarations for the exact DLL build. Start with dynamic loading and the narrow lifecycle functions, verify structure sizes at compile time, and refuse to run when the DLL/driver product versions differ.
