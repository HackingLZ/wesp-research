# ETW schemas and correlated timelines

WESP uses manifestless TraceLogging. Capture by provider ID, not provider name:

- client: `{EA3FDB23-A523-45DB-BBC2-7B3BDDF65666}`
- driver: `{EDFDCE69-B825-484F-BD28-2A91DACD4A0F}`

`Export-WespBuild.ps1` attempts manifest metadata collection and records when it is unavailable. `Invoke-WespTrace.ps1` records both providers into ETL by GUID.

```powershell
pwsh .\scripts\Invoke-WespTrace.ps1 Start -Output C:\WespLab\run.etl
# run a controlled WESP test
pwsh .\scripts\Invoke-WespTrace.ps1 Stop -Output C:\WespLab\run.etl
pwsh .\scripts\Convert-WespTrace.ps1 -Etl C:\WespLab\run.etl
```

The converter uses the inbox `tracerpt.exe`, then the dependency-free timeline command to build a searchable, self-contained HTML file. `timeline` also accepts WespLab JSON/JSONL and multiple inputs, normalizes recognizable timestamps to UTC, orders all records, and retains the original record under `data`.

CSV column names vary across Windows builds. Unrecognized fields remain visible rather than discarded, while provider/event/time selection uses a small set of common tracerpt names.
