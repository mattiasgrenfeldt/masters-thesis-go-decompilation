import eval_extension.CppExporter;
import eval_extension.DataTypeWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableFilter;
import ghidra.program.model.symbol.SourceType;

import java.io.File;
import java.util.HashSet;

public class DecompileAndSave extends GhidraScript {
    @Override
    protected void run() throws Exception {
        // Deduplicate thunk functions. Apparently they can show up multiple times.
        FunctionManager fm = currentProgram.getFunctionManager();
        HashSet<String> thunks = new HashSet<>();
        HashSet<String> duplicates = new HashSet<>();
        for (Function f : fm.getFunctions(true)) {
            if (!f.isThunk()) {
                continue;
            }
            String name = f.getName();
            if (thunks.contains(name)) {
                duplicates.add(name);
            }
            thunks.add(name);
        }
        for (Function f : fm.getFunctions(true)) {
            String name = f.getName();
            if (duplicates.contains(name)) {
                f.setName(String.format("%s_%s", name, f.getEntryPoint()), SourceType.ANALYSIS);
            }
        }

        for (Function f : fm.getFunctions(true)) {
            // Make plate comments with entrypoints for each function.
            f.setComment(String.format(
                    "Function entrypoint: function:'%s' entrypoint:'%s'",
                    DataTypeWriter.cleanIdentifier(f.getName()),
                    f.getEntryPoint()));
            // Sometimes variable names overlap with type names and both are used.
            // For now just rename any variables with colliding names.
            for(Variable v : f.getVariables(new VarMatcher())){
                v.setName("_"+v.getName(), SourceType.ANALYSIS);
            }
        }

        CppExporter exporter = new CppExporter(false, true, false, true, false, "");
        File location = askFile("Provide export location (.c-file)", "Export");
        exporter.export(location, currentProgram, null, getMonitor());
    }

    public static class VarMatcher implements VariableFilter {
        @Override
        public boolean matches(Variable variable) {
            return variable.getName().equals("_PtFuncCompare");
        }
    }
}
