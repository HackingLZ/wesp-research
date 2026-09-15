# wesplab

`wesplab` is a version-pinned Windows Endpoint Security Platform research toolkit built from the reverse engineering in this repository. It targets `espclient.dll` / `wesp.sys` version `0.1.0.156346177+c3490e8c`, first observed in Windows Insider Experimental (Future Platforms) build 29661.1000.

This is now working source code, not only a proposal. Version 0.2 contains:

- `wesplab-runtime.exe`: Windows live diagnostics and API interaction;
- `wesplab.py`: dependency-free PE inspection, snapshot/diff, protocol lookup, and corpus metadata;
- PowerShell helpers for ARM64 builds, lab gating, ETW capture, remote inventory, and evidence collection;
- the exact 120-export manifest, 36 recovered protocol discriminants, and ABI signature evidence for the target build.
- bounded notification capture/decoding, build harvesting/diffing, a rule DSL, multi-principal authorization runs, ETW timelines, wire capture/replay, and defensive health reporting.

The DLL ABI is undocumented and unstable. Every live result must include the output of `doctor`; never interpret a failure from a mismatched build as a security boundary.

## Implemented commands

| Area | Command | State change |
|---|---|---:|
| Preflight | `wesplab-runtime doctor [--json]` | No |
| Clients | `clients registered|connected [--json]` | No |
| Clients | `watch-clients [SECONDS]` | No |
| State | `snapshot` | No |
| Capability discovery | `capabilities GUID FIRST LAST [--json]` | No |
| Rules/queues/collections | `ids GUID rules|queues|collections [SELECTOR] [--json]` | No |
| Object property schemas | `properties GUID FAMILY FIRST LAST [--json]` | No |
| Authorization | `authz-probe GUID` | No |
| Client lifecycle | `register [GUID] --write [--name TEXT] [--altitude TEXT]` | Yes |
| Client lifecycle | `remove GUID --write` | Yes |
| Cross-client test | `remove GUID --write --cross-client-test` | Yes, lab-gated |
| Monitoring | `monitor-process [SECONDS] --write` | Temporary, lab-gated |
| Monitoring | `monitor-process [SECONDS] --write --capture FILE.jsonl` | Temporary, lab-gated |
| Binary RE | `python wesplab.py inspect FILE` | No |
| Build diff | `python wesplab.py diff OLD NEW` | No |
| ABI check | `python wesplab.py abi-check espclient.dll` | No |
| Live-state diff | `python wesplab.py state-diff BEFORE AFTER` | No |
| Offline snapshot | `python wesplab.py snapshot FILE... -o snapshot.json` | Writes output only |
| Protocol lookup | `python wesplab.py protocol [--kind ...] [--id ...]` | No |
| Fuzz seed metadata | `python wesplab.py corpus -o corpus.json` | Writes output only |
| Notifications | `python wesplab.py notification-decode CAPTURE` | No |
| Build comparison | `python wesplab.py build-diff OLD NEW` | No |
| Rule DSL | `python wesplab.py rule-compile RULE.json` | No |
| ETW/evidence UI | `python wesplab.py timeline INPUT... -o timeline.html` | Writes output only |
| Wire format | `python wesplab.py wire-validate CAPTURE` | No |
| Defensive health | `python wesplab.py health INPUT...` | No |
| Authorization report | `python wesplab.py authz-report RESULTS.jsonl` | No |

Supported property families are `client`, `event`, `token`, `mailslot`, `pipe`, `ktm`, `desktop`, `registry-object`, `registry`, `disk`, `volume`, `file-object`, `file`, `stream`, `process`, and `thread`.

## Build

On the ARM64 WESP VM, use Visual Studio 2022 with the ARM64 C++ tools and a Windows SDK:

```powershell
pwsh .\scripts\build.ps1 -Configuration Release
```

For x64 from macOS with Homebrew MinGW:

```sh
cmake -S . -B build-x64 \
  -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-x64 --parallel
```

For a native ARM64 Windows executable from macOS with Homebrew Zig:

```sh
brew install zig
sh scripts/build-zig-arm64.sh
```

The executable dynamically loads `%SystemRoot%\System32\espclient.dll`; it does not use or ship a copied Microsoft DLL.

## Validation harnesses

Run `Test-WespLabOffline.ps1` for dependency-free CLI coverage,
`Test-WespLabDiscovery.ps1` for build-specific selectors/capabilities/properties,
and `Test-WespLabLive.ps1` for bounded notification, queue, state, health, and
cross-client lifecycle validation. `Test-WespLabWire.ps1` exercises the optional
Frida boundary recorder when a compatible native Frida build is available.

## First run

```powershell
.\wesplab-runtime.exe doctor --json
.\wesplab-runtime.exe clients registered --json
.\wesplab-runtime.exe snapshot > before.json
```

To enable commands intended only for a disposable VM:

```powershell
pwsh .\scripts\Initialize-WespLab.ps1 -IUnderstandThisIsDisposable
```

Then create a temporary tool-owned WESP client, queue, and ProcessCreate rule:

```powershell
.\wesplab-runtime.exe monitor-process 60 --write
.\wesplab-runtime.exe monitor-process 60 --write --capture .\notifications.jsonl
python .\wesplab.py notification-decode .\notifications.jsonl -o .\decoded.json
```

The monitor never disconnects from inside the callback, avoiding the confirmed EC-01 self-deadlock path. It stops delivery on the controlling thread, closes local handles, and unregisters its temporary client.

## Evidence workflow

```powershell
pwsh .\scripts\Invoke-WespTrace.ps1 Start -Output C:\WespLab\run.etl
.\wesplab-runtime.exe monitor-process 60 --write
pwsh .\scripts\Invoke-WespTrace.ps1 Stop -Output C:\WespLab\run.etl
pwsh .\scripts\Collect-WespLab.ps1
```

For build comparison:

```sh
python3 wesplab.py diff old-espclient.dll new-espclient.dll -o abi-diff.json
python3 wesplab.py protocol --kind request --id 0x1c
python3 wesplab.py corpus -o protocol-seeds.json
pwsh scripts/Export-WespBuild.ps1 -OutputDirectory C:\WespLab\build-29661
python3 wesplab.py build-diff old-build.json new-build.json -o changes.json
```

Compile and inspect a rule without touching WESP:

```sh
python3 wesplab.py rule-compile examples/process-create.rule.json -o rule-ir.json
```

The compiler supports Boolean filter trees and every recovered property family. It materializes only the runtime-confirmed unfiltered ProcessCreate notification rule; other valid plans remain IR until their build-specific descriptors are verified.

For authorization research, `Invoke-WespAuthzMatrix.ps1` always uses child processes and can test the current token, an explicit credential, and lab-gated SYSTEM. `authz-report` pivots the resulting JSONL by target/principal/operation and identifies HRESULT differentials. For tracing, `Invoke-WespTrace.ps1` captures both WESP providers and `Convert-WespTrace.ps1` generates searchable HTML.

The optional Frida adapter under `optional/frida/` records the private `FilterSendMessage` boundary, deep-copies configured pointer regions, and can relocate/replay a validated capture through a live port in the same authorized consumer. Mutating replay requires the VM marker and exact-match `doctor` evidence.

## Boundaries

Semantic decoding for non-ProcessCreate families, arbitrary live rule materialization, collection/context values, and pointer schemas for every private request still require runtime layout confirmation. The tools preserve opaque bytes and refuse unsupported live materialization instead of guessing.

See the repository [security policy](../../SECURITY.md) for responsible reporting guidance.

See [NOTIFICATIONS.md](docs/NOTIFICATIONS.md), [BUILD_PIPELINE.md](docs/BUILD_PIPELINE.md), [AUTHZ.md](docs/AUTHZ.md), [RULE_DSL.md](docs/RULE_DSL.md), [ETW_TIMELINE.md](docs/ETW_TIMELINE.md), [WIRE.md](docs/WIRE.md), [HEALTH.md](docs/HEALTH.md), [SAFETY.md](docs/SAFETY.md), and [VALIDATION.md](docs/VALIDATION.md).

## License

Toolkit code is MIT licensed. Microsoft binaries, symbols, and any other third-party code are not included or relicensed.
