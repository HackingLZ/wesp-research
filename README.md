# WESP reverse-engineering research

This repository contains a static reverse engineering and security review of Microsoft's Windows Endpoint Security Platform driver (`wesp.sys`) and its version-matched user-mode client (`espclient.dll`), build `0.1.0.156346177+c3490e8c`.

Start here:

- `REVERSE_ENGINEERING.md` — driver architecture and full narrative
- `ESPCLIENT_REVERSE_ENGINEERING.md` — client DLL architecture and wire protocol
- `ESPCLIENT_API_REFERENCE.md` — all 120 client exports grouped by purpose
- `ESPCLIENT_SECURITY_REVIEW.md` — confirmed defects, hypotheses, and runtime test plan
- `TOOLING_RESEARCH.md` — concrete offsec/defensive tools and implementation sequence
- `tools/wesplab/` — implemented live/offline research toolkit
- `IMPORTANT_FUNCTIONS.md` — curated driver function reference
- `slides/wesp-overview.html` — self-contained HTML presentation
- `ANALYSIS_INDEX.md` — machine-readable artifact guide

Repository layout:

- `analysis/wesp.sys/` — driver symbols and Ghidra inventories
- `analysis/espclient.dll/` — client DLL symbols, exports, protocol map, and Ghidra inventories
- `ghidra_scripts/` — scripts for reproducing inventories and local pseudocode
- `tools/wesplab/` — version-pinned research tooling
- `slides/` — self-contained HTML presentation

The Microsoft binaries, PDBs, Ghidra projects, and generated pseudocode volumes are intentionally not included. Acquire samples lawfully, verify them against `analysis/SAMPLE_SHA256SUMS`, and use `ghidra_scripts/` to reproduce the analysis locally. `SHA256SUMS` covers every distributed file except the manifest itself.

The reports distinguish static facts, inferred structure, and runtime hypotheses. No kernel exploit or production authorization bypass is claimed.

Security-reporting guidance is in [SECURITY.md](SECURITY.md). Toolkit code is MIT licensed under [tools/wesplab/LICENSE](tools/wesplab/LICENSE); Microsoft and other third-party artifacts are not included or relicensed.
