# Versioned runtime data

These files are exact-build inputs consumed by `wesplab` and installed with the native runtime where applicable. Their version suffix ties them to `espclient.dll` / `wesp.sys` build `0.1.0.156346177`.

The DEF, export-signature, and protocol files intentionally mirror the corresponding research artifacts under `analysis/espclient.dll/`. Keeping a versioned runtime copy makes `tools/wesplab/` usable as a standalone source package while preserving the analysis directory as immutable evidence.

Do not replace these files with data from another Windows build without changing the version suffix, updating the ABI header, and validating the resulting toolkit against that exact build.
