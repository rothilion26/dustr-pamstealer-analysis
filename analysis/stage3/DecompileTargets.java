// Decompiles the config-decryption routine and related functions to C files.
// Static only: Ghidra analyses the bytes, nothing is executed.
// Usage (postScript args): <outDir> <maxDepth> <maxFunctions> [rootAddr ...]
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompileTargets extends GhidraScript {

    private static final String[] ROOTS = {
        "0x10005cdc0", // string/config decrypt (splits on ':', hex-decodes)
        "0x10005c714", // caller passing the 0x1000b8d84 literal
        "0x10005d380", // uses the 16-byte "master" literal at 0x1000b8e20
        "0x10003cfb4", // passes the 56 KB encrypted blob
        "0x100044b1c", // receives the 56 KB blob
        "0x10008ce84", // contains ChaCha "expand 32-byte k" constants
        "0x100063974", // ChaCha-related
        "0x1000818d4", // ChaCha-related
        "0x100088c64", // SHA-256-related
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "decompiled");
        int maxDepth = args.length > 1 ? Integer.parseInt(args[1]) : 2;
        int maxFuncs = args.length > 2 ? Integer.parseInt(args[2]) : 250;
        outDir.mkdirs();

        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.openProgram(currentProgram);

        String[] roots = args.length > 3 ? java.util.Arrays.copyOfRange(args, 3, args.length) : ROOTS;
        FunctionManager fm = currentProgram.getFunctionManager();
        Deque<Object[]> queue = new ArrayDeque<>();
        for (String root : roots) {
            Address a = toAddr(root);
            Function f = fm.getFunctionContaining(a);
            if (f == null) {
                f = createFunction(a, null);
            }
            if (f != null) {
                queue.add(new Object[] {f, 0});
            } else {
                println("no function at " + root);
            }
        }

        Set<Function> done = new LinkedHashSet<>();
        try (PrintWriter index = new PrintWriter(new File(outDir, "INDEX.txt"))) {
            while (!queue.isEmpty() && done.size() < maxFuncs && !monitor.isCancelled()) {
                Object[] item = queue.poll();
                Function f = (Function) item[0];
                int depth = (Integer) item[1];
                if (!done.add(f)) {
                    continue;
                }
                DecompileResults res = decomp.decompileFunction(f, 180, monitor);
                String code = res.decompileCompleted()
                        ? res.getDecompiledFunction().getC()
                        : "// decompile failed: " + res.getErrorMessage();
                String name = f.getEntryPoint().toString();
                try (PrintWriter pw = new PrintWriter(new File(outDir, name + ".c"))) {
                    pw.println(code);
                }
                index.printf("%s depth=%d size=%d callers=%d%n", name, depth,
                        f.getBody().getNumAddresses(), f.getCallingFunctions(monitor).size());
                if (depth < maxDepth) {
                    for (Function callee : f.getCalledFunctions(monitor)) {
                        if (!callee.isExternal() && !callee.isThunk()) {
                            queue.add(new Object[] {callee, depth + 1});
                        }
                    }
                }
            }
        }
        decomp.dispose();
        println("decompiled " + done.size() + " functions into " + outDir.getAbsolutePath());
    }
}
