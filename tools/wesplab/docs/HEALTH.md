# Defensive health monitoring

`Watch-WespHealth.ps1` emits a heartbeat containing registered/connected clients, query latency, expected-client presence, state changes, binary hashes, and optional hash-policy results.

```powershell
pwsh .\scripts\Watch-WespHealth.ps1 -IntervalSeconds 30 `
  -ExpectedClient '{YOUR-LAB-GUID}' `
  -ExpectedEspClientSha256 HASH -ExpectedDriverSha256 HASH
```

Score one or more heartbeat, notification, or state-change streams offline:

```sh
python wesplab.py health wesp-health.jsonl notifications.jsonl \
  --max-gap 60 --fail-on-alert -o health-report.json
```

The report surfaces notification drops, explicit errors, long delivery gaps, binary-integrity failures, missing expected clients, state changes, and latency summary statistics. A clean report means the supplied observations met the configured assertions; it does not make ETW or an administrator-controlled endpoint a tamper-proof trust anchor.

For a real canary, run `Invoke-WespCanary.ps1 -Output wesp-canary.jsonl` while notification capture and independent ETW/Sysmon collection are active. Supplying both the stimulus JSONL and decoded notification/ETW JSON to `health` flags generated markers that were not observed; `timeline` shows their ordering.
