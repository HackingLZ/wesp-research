// Disable analyzers that misinterpret large Rust dispatch tables and dominate headless runs.
//@category WESP

import ghidra.app.script.GhidraScript;

public class ConfigureWespAnalysis extends GhidraScript {
    @Override
    protected void run() throws Exception {
        setAnalysisOption(currentProgram, "Decompiler Switch Analysis", "false");
        println("WESP: disabled Decompiler Switch Analysis");
    }
}
