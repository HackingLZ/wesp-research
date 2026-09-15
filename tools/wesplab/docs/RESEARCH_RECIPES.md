# Research recipes

## ABI drift

Collect each inbox DLL/driver pair without redistributing it, then run:

```text
wesplab.py snapshot old/espclient.dll old/wesp.sys -o old.json
wesplab.py snapshot new/espclient.dll new/wesp.sys -o new.json
wesplab.py diff old/espclient.dll new/espclient.dll -o client-diff.json
```

The current diff reports hashes, versions, architecture, and added/removed exports. Combine it with the Ghidra inventory scripts for function-level semantic diffing.

## Authorization matrix

Run the same client GUID list under each controlled token context:

```powershell
pwsh .\scripts\Invoke-WespAuthzMatrix.ps1 -ClientGuid $ownClient, $peerClient
```

Record standard user, elevated administrator, SYSTEM, test-signing, and eligible PPL contexts separately. `authz-probe` does not mutate the targets. Only move to a cross-client unregister test with two disposable wesplab-owned clients and a host snapshot.

## Queue lifecycle

After enabling the disposable-VM marker:

```powershell
pwsh .\scripts\Invoke-WespTrace.ps1 Start -Output C:\WespLab\queue.etl
pwsh .\scripts\Invoke-WespQueueStress.ps1 -Iterations 100 -Seconds 1
pwsh .\scripts\Invoke-WespTrace.ps1 Stop -Output C:\WespLab\queue.etl
```

The stress loop tests normal create/connect/arm/disconnect/close/unregister transitions. EC-01 callback-initiated disconnect should be tested in a dedicated watchdog child under a debugger, not in the general runtime.

## Sensor comparison

Run `monitor-process`, WESP ETW, and an independent process provider at the same time. Generate deterministic activity with `Invoke-WespCanary.ps1`. Compare event count, ordering, timestamps, image/command-line data, and drops.

## Protocol grammar

Generate one metadata record for every recovered connect/request discriminator:

```text
wesplab.py corpus -o protocol-seeds.json
```

These are not raw packets. Populate each seed from an authorized API-layer capture, replace pointers with symbolic object references, and replay only after exact-build verification. Favor valid structured seeds before length, aliasing, cancellation, and race mutations.
