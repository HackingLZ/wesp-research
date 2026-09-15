# WESP reverse-engineering research

This folder is the repository-ready subset of a static reverse engineering and security review of Microsoft's Windows Endpoint Security Platform driver (`wesp.sys`) and its version-matched user-mode client (`espclient.dll`), build `0.1.0.156346177+c3490e8c`.

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

The Microsoft binaries and PDBs are intentionally not included. Acquire samples lawfully, verify the hashes in `analysis/SHA256SUMS`, retrieve exact public symbols, and run the scripts in `ghidra_scripts/` to reproduce the inventories/decompilation.

The reports distinguish static facts, inferred structure, and runtime hypotheses. No kernel exploit or production authorization bypass is claimed.
