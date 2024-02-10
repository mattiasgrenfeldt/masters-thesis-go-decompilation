package extension;

import extension.metadata.Function;
import extension.metadata.Metadata;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.HashMap;

public class LibrarySignatureAnalyzer extends AbstractAnalyzer {

    public LibrarySignatureAnalyzer() {
        super("Go Library signature analyzer", "Applies function signatures from a library.", AnalyzerType.FUNCTION_ANALYZER);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        Metadata m = Metadata.parseLib("/path/to/go/src", log);
        DataTypeManager dtm = p.getDataTypeManager();
        StructCreator sc = new StructCreator(dtm, m.structures);
        try {
            sc.defineStructs(monitor);
        } catch (Exception e) {
            log.appendMsg("Error while defining data types");
            log.appendException(e);
            throw new RuntimeException(e);
        }

        HashMap<String, Function> funcs = new HashMap<>();
        for (Function f : m.functions) {
            funcs.put(f.name, f);
        }

        CallingConvention cc = new CallingConvention(p, sc);
        FunctionManager fm = p.getFunctionManager();
        monitor.setMessage("Applying function signatures...");
        monitor.initialize(fm.getFunctionCount());
        fm.getFunctions(true).forEach((f) -> {
            Function libF = funcs.get(f.getName());
            if (libF == null) {
                return;
            }
            try {
                cc.updateSignature(libF, f);
            } catch (Exception e) {
                log.appendException(e);
                throw new RuntimeException(e);
            }
        });
        return true;
    }

}
