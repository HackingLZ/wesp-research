# Build harvesting and semantic diffs

Run the harvester once per Insider build:

```powershell
pwsh .\scripts\Export-WespBuild.ps1 -OutputDirectory C:\WespLab\build-29661
```

It records the Windows build, WESP binary hashes/versions/signers/exports, and full metadata for both WESP ETW providers. Microsoft binaries are not copied unless `-IncludeMicrosoftBinaries` is explicitly supplied; never commit copied inbox binaries.

Compare manifests offline:

```sh
python wesplab.py build-diff old/build.json new/build.json -o build-diff.json
```

The diff reports added/removed artifacts, hashes, versions, architecture, PE timestamps/image sizes/mitigation flags, signature changes, exports, and ETW schema drift. Preserve a `doctor --json` record and capability/property scans beside every build manifest so behavioral changes can be distinguished from ABI changes.
