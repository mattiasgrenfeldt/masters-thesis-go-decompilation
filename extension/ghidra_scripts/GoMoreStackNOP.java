import extension.MoreStackAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

public class GoMoreStackNOP extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Running more_stack analyzer...");
        MessageLog log = new MessageLog();
        MoreStackAnalyzer ms = new MoreStackAnalyzer();
        ms.added(currentProgram, null, monitor, log);
    }
}
