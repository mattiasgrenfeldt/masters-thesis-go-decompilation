package extension;

import extension.metadata.Metadata;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.HashSet;

public class FunctionNameAnalyzer extends AbstractAnalyzer {

    public boolean addRegisterAssumptions = true;

    public FunctionNameAnalyzer() {
        super("Go function name analyzer", "Recovers function names", AnalyzerType.FUNCTION_ANALYZER);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        System.out.printf("[*] REGISTER ASSUMPTIONS: %s\n", addRegisterAssumptions);
        Address base = program.getImageBase();
        FunctionManager fm = program.getFunctionManager();
        Disassembler dis = Disassembler.getDisassembler(program, monitor, DisassemblerMessageListener.CONSOLE);
        Metadata m = Metadata.extract(program.getExecutablePath(), log);

        // Find duplicate function names. Duplicate functions should be disambiguated for the evaluation.
        HashSet<String> exists = new HashSet<>();
        HashSet<String> duplicates = new HashSet<>();
        for (extension.metadata.Function f : m.functions) {
            String name = f.name.replace(' ', '_');
            if (exists.contains(name)) {
                duplicates.add(name);
            }
            exists.add(name);
        }

        int success = 0, fail = 0;
        monitor.setMessage("Renaming and creating functions...");
        monitor.setProgress(0);
        monitor.setMaximum(m.functions.size());
        for (extension.metadata.Function f : m.functions) {
            // Replace middle dot https://www.compart.com/en/unicode/
            String name = f.name.replace(' ', '_').replace((char) 0xb7, '.');
            Address entry = base.getNewAddress(f.entry);
            Address end = base.getNewAddress(f.end - 1);
            if (addRegisterAssumptions) {
                try {
                    RegisterAssumptions.assume(program.getProgramContext(), entry, end);
                } catch (ContextChangeException e) {
                    log.appendMsg("Could not assume register values");
                    throw new RuntimeException(e);
                }
            }

            if (duplicates.contains(name)) {
                name += String.format("_%s", entry);
            }

            AddressSet body = new AddressSet(entry, end);

            Function f2 = fm.getFunctionAt(entry);
            if (f2 == null) {
                try {
                    fm.createFunction(name, entry, body, SourceType.ANALYSIS);
                    success++;
                } catch (OverlappingFunctionException | IllegalArgumentException e) {
                    log.appendMsg(String.format("Could not create function %s with body %s since there was an overlap", name, body));
                    log.appendException(e);
                    try {
                        program.getSymbolTable().createLabel(entry, name, SourceType.ANALYSIS);
                        fail++;
                    } catch (InvalidInputException ex) {
                        throw new RuntimeException(ex);
                    }
                } catch (InvalidInputException e) {
                    throw new RuntimeException(e);
                }
            } else {
                try {
                    f2.setName(name, SourceType.ANALYSIS);
                    success++;
                } catch (DuplicateNameException | InvalidInputException e) {
                    throw new RuntimeException(e);
                }
            }
            dis.disassemble(entry, body);
            monitor.incrementProgress(1);
        }
        log.appendMsg(String.format("Function naming: Success: %d Fail: %d", success, fail));
        return true;
    }
}
