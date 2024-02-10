import extension.RuntimeFunctionAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

public class GoPolymorphicAnalyzer extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Running polymorphic runtime function analyzer...");
        MessageLog log = new MessageLog();
        RuntimeFunctionAnalyzer rt = new RuntimeFunctionAnalyzer();
        rt.added(currentProgram, null, monitor, log);
    }
}
