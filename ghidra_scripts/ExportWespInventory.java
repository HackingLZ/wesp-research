//@category WESP

import java.io.File;
import java.io.PrintWriter;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportWespInventory extends GhidraScript {
    private static String clean(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: ExportWespInventory.java <absolute-output-dir>");
        }
        File outDir = new File(args[0]);
        outDir.mkdirs();

        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();

        try (PrintWriter out = new PrintWriter(new File(outDir, "memory-blocks.tsv"))) {
            out.println("name\tstart\tend\tsize\tr\tw\tx\tinitialized");
            for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                out.printf("%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s%n", clean(b.getName()), b.getStart(),
                    b.getEnd(), b.getSize(), b.isRead(), b.isWrite(), b.isExecute(), b.isInitialized());
            }
        }

        try (PrintWriter out = new PrintWriter(new File(outDir, "functions.tsv"))) {
            out.println("address\tsize\tname\tsignature\tthunk\texternal\tnoreturn");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                out.printf("%s\t%d\t%s\t%s\t%s\t%s\t%s%n", f.getEntryPoint(),
                    f.getBody().getNumAddresses(), clean(f.getName(true)), clean(f.getSignature()),
                    f.isThunk(), f.isExternal(), f.hasNoReturn());
            }
        }

        try (PrintWriter out = new PrintWriter(new File(outDir, "external-functions.tsv"))) {
            out.println("address\tname\tsignature");
            FunctionIterator it = currentProgram.getFunctionManager().getExternalFunctions();
            while (it.hasNext()) {
                Function f = it.next();
                out.printf("%s\t%s\t%s%n", f.getEntryPoint(), clean(f.getName(true)), clean(f.getSignature()));
            }
        }

        try (PrintWriter out = new PrintWriter(new File(outDir, "exports.tsv"))) {
            out.println("address\tname\tsource");
            SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.isExternalEntryPoint()) {
                    out.printf("%s\t%s\t%s%n", s.getAddress(), clean(s.getName(true)), s.getSource());
                }
            }
        }

        try (PrintWriter out = new PrintWriter(new File(outDir, "strings.tsv"))) {
            out.println("address\ttype\tlength\treferences\tvalue");
            Iterator<Data> it = listing.getDefinedData(true);
            while (it.hasNext()) {
                Data d = it.next();
                Object value = d.getValue();
                if (!(value instanceof String)) {
                    continue;
                }
                int count = 0;
                for (Reference ignored : refs.getReferencesTo(d.getAddress())) {
                    count++;
                }
                out.printf("%s\t%s\t%d\t%d\t%s%n", d.getAddress(), d.getDataType().getName(),
                    d.getLength(), count, clean(value));
            }
        }

        try (PrintWriter out = new PrintWriter(new File(outDir, "callgraph.tsv"))) {
            out.println("caller_address\tcaller\tcallsite\tcallee_address\tcallee");
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext()) {
                Function caller = fit.next();
                if (caller.isExternal()) {
                    continue;
                }
                for (Instruction ins : listing.getInstructions(caller.getBody(), true)) {
                    for (Reference r : refs.getReferencesFrom(ins.getAddress())) {
                        if (!r.getReferenceType().isCall()) {
                            continue;
                        }
                        Function callee = currentProgram.getFunctionManager().getFunctionAt(r.getToAddress());
                        out.printf("%s\t%s\t%s\t%s\t%s%n", caller.getEntryPoint(), clean(caller.getName(true)),
                            ins.getAddress(), r.getToAddress(), callee == null ? "<indirect-or-unknown>" : clean(callee.getName(true)));
                    }
                }
            }
        }

        println("WESP inventory exported to " + outDir.getAbsolutePath());
    }
}
