//@category WESP

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileWespAll extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 4) {
            throw new IllegalArgumentException("usage: DecompileWespAll.java <absolute-output-dir> [start-address-exclusive] [output-name] [skip-until-address]");
        }
        File outDir = new File(args[0]);
        outDir.mkdirs();
        long startExclusive = args.length >= 2 ? Long.parseUnsignedLong(args[1], 16) : 0;
        String outputName = args.length >= 3 ? args[2] : "decompiled-all.c";
        long skipUntil = args.length >= 4 ? Long.parseUnsignedLong(args[3], 16) : 0;

        DecompInterface decompiler = new DecompInterface();
        decompiler.setSimplificationStyle("decompile");
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("decompiler failed to open program");
        }

        int total = currentProgram.getFunctionManager().getFunctionCount();
        int completed = 0;
        int failed = 0;
        try (PrintWriter code = new PrintWriter(new File(outDir, outputName));
             PrintWriter errors = new PrintWriter(new File(outDir, outputName + ".failures.tsv"))) {
            errors.println("address\tname\treason");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal()) {
                    continue;
                }
                if (Long.compareUnsigned(f.getEntryPoint().getOffset(), startExclusive) <= 0) {
                    continue;
                }
                monitor.setMessage("Decompiling " + (++completed) + "/" + total + ": " + f.getName(true));
                long bodyBytes = f.getBody().getNumAddresses();
                long bodySpan = f.getBody().getMaxAddress().subtract(f.getBody().getMinAddress()) + 1;
                if (Long.compareUnsigned(f.getEntryPoint().getOffset(), skipUntil) < 0) {
                    failed++;
                    String reason = "skipped known malformed Rust monomorphization range";
                    code.printf("%n/* %s @ %s: %s */%n", f.getName(true), f.getEntryPoint(), reason);
                    errors.printf("%s\t%s\t%s%n", f.getEntryPoint(), f.getName(true), reason);
                    continue;
                }
                if (bodySpan > 8192 && bodySpan > bodyBytes * 2) {
                    failed++;
                    String reason = "skipped malformed/discontiguous body: bytes=" + bodyBytes + ", span=" + bodySpan;
                    code.printf("%n/* %s @ %s: %s */%n", f.getName(true), f.getEntryPoint(), reason);
                    errors.printf("%s\t%s\t%s%n", f.getEntryPoint(), f.getName(true), reason);
                    continue;
                }
                // Two seconds is ample for normal recovered functions and prevents malformed
                // Rust control-flow metadata from monopolizing a full-corpus export.
                DecompileResults result = decompiler.decompileFunction(f, 2, monitor);
                code.printf("%n/* ========================================================================%n");
                code.printf(" * %s @ %s, %d bytes%n", f.getName(true), f.getEntryPoint(), f.getBody().getNumAddresses());
                code.printf(" * ======================================================================== */%n");
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    code.println(result.getDecompiledFunction().getC());
                }
                else {
                    failed++;
                    String reason = result.getErrorMessage() == null ? "unknown" : result.getErrorMessage();
                    reason = reason.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
                    code.printf("/* DECOMPILATION FAILED: %s */%n", reason);
                    errors.printf("%s\t%s\t%s%n", f.getEntryPoint(), f.getName(true), reason);
                }
                if ((completed % 250) == 0) {
                    code.flush();
                    errors.flush();
                    println("WESP: decompiled " + completed + " functions; failures=" + failed);
                }
            }
        }
        decompiler.dispose();
        println("WESP: full decompilation complete; functions=" + completed + ", failures=" + failed);
    }
}
