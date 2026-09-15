# Validation status

## Completed locally

- CMake verifies that the packaged DEF contains exactly 120 exports.
- C++20 x64 cross-build succeeds under MinGW GCC with `-Wall -Wextra -Wpedantic -Werror`.
- C++20 ARM64 cross-build succeeds with Zig and executes natively on the ARM64 Parallels VM.
- All recovered structure size and offset assertions pass.
- The executable has ASLR, high-entropy VA, and NX compatibility flags.
- The offline parser reads the supplied x64 DLL without external packages.
- The parser reports the expected DLL hash, architecture, versions, and 120 exports.
- Eleven unit tests verify all 7 connect roles and 29 request IDs, bounded notification decoding, rule compilation, wire rejection, build diffs, authorization differentials, health/canary alerts, and HTML timeline generation.
- Every PowerShell helper parses without syntax errors.

## Windows ARM64 VM validation

Validated on Windows Insider build `29667.1000` (`rs_prerelease.260905-1914`) with WESP
`0.1.0.156346177+c3490e8c`:

- `doctor` resolved all 120 exports and confirmed the driver service was running.
- ARM64 SHA-256: `espclient.dll` `abaa0d1e...e4619`; `wesp.sys` `c8426fa3...a41dcd`.
- All 11 Python tests and all 16 offline CLI workflows passed natively on the VM.
- Build harvesting recovered all 120 exports without Visual Studio by using the built-in PE parser.
- The capability scan covered IDs 0 through 10000; supported IDs and flags are in `data/event-families-0.1.0.156346177.json`.
- All 16 property families were scanned through ID 512; results are in `data/property-support-0.1.0.156346177.json`.
- Enumeration selectors 1, 2, and 3 succeeded for rules, queues, and collections. Selector 0 returned `E_INVALIDARG`; the CLI now defaults to 1.
- A controlled ProcessCreate run captured 11 notifications for five canary iterations and cleaned up its temporary client, queue, rule, and callback state.
- Three consecutive queue lifecycles passed. The bounded health watcher produced three clean heartbeats, and the state watcher observed both registration and removal.
- The lab-gated cross-client unregister operation succeeded. This is a security-relevant authorization result, not by itself proof of exploitability.
- The rule wrapper compiled its DSL plan, captured a live ProcessCreate event, and left no temporary WESP objects behind.
- Elevated Administrator and SYSTEM could enumerate, connect, enumerate owned objects, and query capabilities. Integrity levels were recorded as High (`S-1-16-12288`) and System (`S-1-16-16384`).
- Both hidden TraceLogging provider IDs were recovered, `logman` capture passed, `tracerpt` produced CSV, and the toolkit generated the HTML timeline.

Raw evidence is retained in `C:\WespLab\validation` on the test VM. Microsoft binaries and
machine-specific raw evidence are intentionally not placed in the redistributable repository.

## Remaining validation limits

- Standard-user authorization has not been measured; current live results cover elevated Administrator and SYSTEM.
- Semantic payload layouts beyond the confirmed ProcessCreate prefix remain opaque and need controlled per-family stimuli.
- Manifest lookup does not work because both ETW sources are TraceLogging providers. Their recovered IDs are `{EA3FDB23-A523-45DB-BBC2-7B3BDDF65666}` (client) and `{EDFDCE69-B825-484F-BD28-2A91DACD4A0F}` (driver).
- Frida 17.6.2 from PyPI installs an x64 `_frida.pyd` and cannot attach to the native ARM64 consumer (`missing helper able to handle the given target`). The recorder and replay validator pass offline, but live wire attachment requires an upstream/native Windows ARM64 Frida build.
- The supplied x64 DLL is validly signed and version-matched, but Windows ARM64 rejected loading it in the emulated x64 consumer with `ERROR_BAD_EXE_FORMAT`, so it is not a viable helper workaround.
- Application Verifier and a second WESP build for build-to-build differential testing were not available on this VM.

An API call returning success is not proof that the corresponding event matches or enforces. Semantic tests need a controlled stimulus and an independent observation source.
