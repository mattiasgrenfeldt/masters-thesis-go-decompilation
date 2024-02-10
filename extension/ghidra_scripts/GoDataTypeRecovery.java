import extension.DatatypeAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

public class GoDataTypeRecovery extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Running data type analyzer...");
        MessageLog log = new MessageLog();
        DatatypeAnalyzer dt = new DatatypeAnalyzer();
        dt.added(currentProgram, null, monitor, log);
    }
}
