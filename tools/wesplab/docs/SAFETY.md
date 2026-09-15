# Safety model

`wesplab` assumes an authorized, disposable Windows VM. It is not a production administration utility.

## Gates

1. Read-only commands are the default.
2. Every mutating command requires `--write`.
3. Cross-client and event-monitor operations also require `C:\ProgramData\wesplab\LAB_MACHINE`.
4. The marker helper requires elevation and the explicit `-IUnderstandThisIsDisposable` acknowledgement.
5. Every runtime mutation refuses a DLL/driver pair that does not match the pinned ABI version.
6. The normal runtime never sends a hand-built raw `FilterSendMessage` request. Optional wire replay is a separate Frida adapter, read-only by default, and mutating replay requires the VM marker plus an exact-match `doctor` record.
7. No copied `espclient.dll` is loaded; the runtime uses `LOAD_LIBRARY_SEARCH_SYSTEM32`.

The marker is friction, not a security boundary. A snapshot/checkpoint outside the guest is still required before lifecycle, race, verifier, or fault-injection tests.

## Known client hazards

- EC-01: synchronously disconnecting an event queue from its own callback deadlocks and later fail-fasts. The monitor requests stop in the callback and performs disconnect on the controller thread.
- EC-02: `EspRegisterClient` scans name/altitude pointers without a bound. The toolkit passes fixed, compile-time NUL-terminated strings.
- EC-03: failed IOCP completion posting can strand state. The first monitor uses callback delivery; IOCP testing belongs in an isolated watchdog child.

## Cross-client testing

Start with `authz-probe`, which only enumerates and attempts a normal connection. If destructive authorization testing is necessary:

- take a host snapshot;
- create two wesplab-owned clients;
- record a before snapshot and ETW trace;
- target only the second test client;
- pass `--cross-client-test` explicitly;
- collect after-state and restore the host snapshot.

Never use an endpoint-security vendor’s real registered client as a mutation target.

## Wire replay

Attach only to a consumer you own. Validate every capture with `wire-validate`. Replay read-only requests first. Pointer-rich requests require a complete symbolic relocation list; a syntactically valid capture is not proof that every nested pointer was copied. Mutating request IDs require a host snapshot, the lab marker, `--allow-mutating`, and exact-version doctor JSON.
