import extension.FunctionNameAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

public class GoFunctionRenamer extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Running function name analyzer...");
        MessageLog log = new MessageLog();
        FunctionNameAnalyzer fn = new FunctionNameAnalyzer();
        fn.addRegisterAssumptions = askYesNo("Add register assumptions", "Should register assumptions be made?");
        fn.added(currentProgram, null, monitor, log);
    }
}
