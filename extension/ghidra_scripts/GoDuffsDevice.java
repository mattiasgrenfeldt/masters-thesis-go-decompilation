import extension.DuffAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

public class GoDuffsDevice extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Running Duff's device analyzer...");
        MessageLog log = new MessageLog();
        DuffAnalyzer df = new DuffAnalyzer();
        df.added(currentProgram, null, monitor, log);
    }
}
