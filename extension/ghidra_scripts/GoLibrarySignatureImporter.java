import extension.LibrarySignatureAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

public class GoLibrarySignatureImporter extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Running library signature analyzer...");
        MessageLog log = new MessageLog();
        LibrarySignatureAnalyzer ls = new LibrarySignatureAnalyzer();
        ls.added(currentProgram, null, monitor, log);
    }
}
