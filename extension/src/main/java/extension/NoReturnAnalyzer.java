package extension;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class NoReturnAnalyzer extends AbstractAnalyzer {

    // List copied from https://github.com/NationalSecurityAgency/ghidra/blob/87c16f9cd0439427b6c3196c9af2470770c4ef6d/Ghidra/Features/Base/data/GolangFunctionsThatDoNotReturn
    private static final String[] funcs = new String[]{
            "runtime.abort.abi0",
            "runtime.exit.abi0",
            "runtime.dieFromSignal",
            "runtime.exitThread",
            "runtime.fatal",
            "runtime.fatalthrow",
            "runtime.fatalpanic",
            "runtime.gopanic",
            "runtime.panicdivide",
            "runtime.throw",
            "runtime.goPanicIndex",
            "runtime.goPanicIndexU",
            "runtime.goPanicSliceAlen",
            "runtime.goPanicSliceAlenU",
            "runtime.goPanicSliceAcap",
            "runtime.goPanicSliceAcapU",
            "runtime.goPanicSliceB",
            "runtime.goPanicSliceBU",
            "runtime.goPanicSlice3Alen",
            "runtime.goPanicSlice3AlenU",
            "runtime.goPanicSlice3Acap",
            "runtime.goPanicSlice3AcapU",
            "runtime.goPanicSlice3B",
            "runtime.goPanicSlice3BU",
            "runtime.goPanicSlice3C",
            "runtime.goPanicSlice3CU",
            "runtime.goPanicSliceConvert",
            "runtime.panicIndex",
            "runtime.panicIndexU",
            "runtime.panicSliceAlen",
            "runtime.panicSliceAlenU",
            "runtime.panicSliceAcap",
            "runtime.panicSliceAcapU",
            "runtime.panicSliceB",
            "runtime.panicSliceBU",
            "runtime.panicSlice3Alen",
            "runtime.panicSlice3AlenU",
            "runtime.panicSlice3Acap",
            "runtime.panicSlice3AcapU",
            "runtime.panicSlice3B",
            "runtime.panicSlice3BU",
            "runtime.panicSlice3C",
            "runtime.panicSlice3CU",
            "runtime.panicSliceConvert",
            "runtime.panicdottypeE",
            "runtime.panicdottypeI",
            "runtime.panicnildottype",
            "runtime.panicoverflow",
            "runtime.panicfloat",
            "runtime.panicmem",
            "runtime.panicmemAddr",
            "runtime.panicshift",
            "runtime.goexit0",
            "runtime.goexit0.abi0",
            "runtime.goexit1",
            "runtime.goexit.abi0",
            "runtime.Goexit",
            "runtime.sigpanic",
            "runtime.sigpanic0.abi0",
            "os.Exit",
    };

    public NoReturnAnalyzer() {
        super("Go non-returning function analyzer", "Marks non-returning functions.", AnalyzerType.FUNCTION_ANALYZER);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        FunctionManager fm = p.getFunctionManager();
        SymbolTable st = p.getSymbolTable();
        for (String f : funcs) {
            for (Symbol s : st.getSymbols(f)) {
                Function res = fm.getFunctionAt(s.getAddress());
                if (res == null) {
                    continue;
                }
                res.setNoReturn(true);
            }
        }
        // TODO: should disassemble all functions here. Hmmm, or do functions become cleared in the post-analysis?
        return true;
    }
}
