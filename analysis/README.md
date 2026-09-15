# Analysis artifacts

This directory separates the reverse-engineering output by analyzed binary:

- `wesp.sys/` contains driver PDB extracts and Ghidra inventories.
- `espclient.dll/` contains client DLL PDB extracts, Ghidra inventories, exports, and the recovered protocol map.

Microsoft binaries, PDBs, completed Ghidra projects, and large generated pseudocode volumes are not distributed. `SAMPLE_SHA256SUMS` identifies the exact external inputs used for this analysis. Use the scripts in `../ghidra_scripts/` to reproduce inventories and pseudocode from lawfully acquired matching samples.

The repository-level `../SHA256SUMS` manifest covers all distributed files except itself.
