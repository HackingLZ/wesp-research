# Analysis artifact index

Start with [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) for the driver and [ESPCLIENT_REVERSE_ENGINEERING.md](ESPCLIENT_REVERSE_ENGINEERING.md) for its version-matched user-mode library.

For a focused driver function review, use [IMPORTANT_FUNCTIONS.md](IMPORTANT_FUNCTIONS.md). The client API is grouped in [ESPCLIENT_API_REFERENCE.md](ESPCLIENT_API_REFERENCE.md), and security findings/test cases are in [ESPCLIENT_SECURITY_REVIEW.md](ESPCLIENT_SECURITY_REVIEW.md). The presentation is [slides/wesp-overview.html](slides/wesp-overview.html).

The offensive/defensive roadmap is [TOOLING_RESEARCH.md](TOOLING_RESEARCH.md). The implemented toolkit starts at [tools/wesplab/README.md](tools/wesplab/README.md).

## Source inputs (not distributed)

- `wesp.sys` — original input; SHA-256 `9ade5cd21e0ecb8245011eaaec047295686051e4b52af1b97552847fc3bca6b2`
- `wesp.pdb` — exact Microsoft public symbols; SHA-256 `3fed8f9d6f30f442f436bd3b674f03b7532a4f0223636d025fa7033b5c15c7fa`
- `espclient.dll` — version-matched client input; SHA-256 `90b9f908dbed63181ba7d71fd0b9aa51cc5674a9116c71bc44c612371abe8ec3`
- `espclient.pdb` — exact Microsoft public symbols; SHA-256 `a0745bd1632399f732f266c89ec705e4bc0035ec6d72e8a39a99801845f75ef9`

The same four identities are recorded in `analysis/SAMPLE_SHA256SUMS`. The completed Ghidra projects were local working state and are also not distributed.

## Machine-readable inventories

- `analysis/wesp.sys/ghidra/functions.tsv` — every local function
- `analysis/wesp.sys/ghidra/callgraph.tsv` — direct call graph
- `analysis/wesp.sys/ghidra/external-functions.tsv` — imports
- `analysis/wesp.sys/ghidra/exports.tsv` — exports and aliases
- `analysis/wesp.sys/ghidra/strings.tsv` — defined strings and reference counts
- `analysis/wesp.sys/ghidra/memory-blocks.tsv` — program memory map
- `analysis/wesp.sys/pdb-symbols.txt` — raw PDB symbols

The version-matched client inventories are under `analysis/espclient.dll/ghidra/`. Additional client artifacts are:

- `analysis/espclient.dll/export-signatures.tsv` — recovered export addresses and approximate prototypes
- `analysis/espclient.dll/rust-functions.tsv` — Rust-heavy subset of the function inventory
- `analysis/espclient.dll/protocol.tsv` — connection roles and all request discriminants
- `analysis/espclient.dll/espclient.def` — all 120 public exports for import-library generation
- `analysis/espclient.dll/pdb-symbols.txt` — raw client public PDB symbols

## Toolkit

- `tools/wesplab/README.md` — implemented commands and build instructions
- `tools/wesplab/include/wesplab/abi_0_1_0_156346177.hpp` — versioned recovered ABI
- `tools/wesplab/docs/SAFETY.md` — mutation gates and known hazards
- `tools/wesplab/docs/VALIDATION.md` — completed and pending validation
- `tools/wesplab/docs/NOTIFICATIONS.md` — capture and decoder contract
- `tools/wesplab/docs/BUILD_PIPELINE.md` — reproducible Insider build harvesting/diffs
- `tools/wesplab/docs/AUTHZ.md` — multi-principal isolation matrix
- `tools/wesplab/docs/RULE_DSL.md` — rule/filter language and live adapter boundary
- `tools/wesplab/docs/ETW_TIMELINE.md` — provider extraction and HTML correlation
- `tools/wesplab/docs/WIRE.md` — optional recorder, relocations, and replay safety
- `tools/wesplab/docs/HEALTH.md` — defensive integrity and delivery monitoring

## Local-only decompiled code

The large generated pseudocode volumes are not tracked. Locally, `DecompileWespAll.java` produced `decompiled-all.c` and `decompiled-rest.c` for the driver and `decompiled-all.c` for the DLL. The repository retains these compact failure inventories:

- `analysis/wesp.sys/ghidra/decompile-failures.tsv`
- `analysis/wesp.sys/ghidra/decompiled-rest.c.failures.tsv`
- `analysis/espclient.dll/ghidra/decompiled-all.c.failures.tsv`

Regenerate pseudocode from the exact samples, then search it by exact symbol or virtual address. Treat generated types as approximations and corroborate important details in Ghidra's listing/disassembly.

## Public-repo package

This repository is the clean redistribution subset. It contains authored reports, slides, Ghidra automation, hashes, and compact machine-readable inventories. It deliberately excludes Microsoft binaries/PDBs, local Ghidra project state, browser scratch files, and generated pseudocode volumes. Run `DecompileWespAll.java` against lawfully acquired samples to reproduce the pseudocode locally.

`SHA256SUMS` at the repository root verifies distributed content. `analysis/SAMPLE_SHA256SUMS` identifies the four external analysis inputs.

## Reusable Ghidra scripts

- `ghidra_scripts/ConfigureWespAnalysis.java`
- `ghidra_scripts/ExportWespInventory.java`
- `ghidra_scripts/DecompileWespAll.java`
