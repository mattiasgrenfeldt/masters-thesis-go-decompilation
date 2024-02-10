import extension.NoReturnAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

public class GoNonReturningFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Running non-returning function analyzer...");
        MessageLog log = new MessageLog();
        NoReturnAnalyzer nr = new NoReturnAnalyzer();
        nr.added(currentProgram, null, monitor, log);
    }
}
