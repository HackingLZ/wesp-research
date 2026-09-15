# Multi-principal authorization matrix

The worker records an independent process ID, user/SID, group-derived integrity SID, elevation, target GUID, exact HRESULTs, and raw parsing errors. The runtime probes management enumeration, target connection, owned rule/queue/collection enumeration, and ProcessCreate capability access.

```powershell
pwsh .\scripts\Invoke-WespAuthzMatrix.ps1 -ClientGuid $owned, $peer
pwsh .\scripts\Invoke-WespAuthzMatrix.ps1 -ClientGuid $owned, $peer -Credential $standardUser
pwsh .\scripts\Invoke-WespAuthzMatrix.ps1 -ClientGuid $owned, $peer -IncludeSystem
```

SYSTEM execution uses a short-lived scheduled task and requires elevation plus the disposable-VM marker. `-Credential` uses Windows logon rather than token impersonation. Run separate rows for owner, peer, disconnected, and persisted test clients. PPL and custom security-attribute cases require a separately signed launcher and are intentionally not faked by this script.

These probes are read-only. A successful connection is evidence of reachability, not authorization to mutate the target.

Summarize multiple runs with `python wesplab.py authz-report authz-results.jsonl -o authz-report.json`. The report pivots exact HRESULTs by target, principal, and operation and calls out differentials without labeling an access difference as a vulnerability by itself.
