package extension;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.Arrays;
import java.util.List;

public class DuffAnalyzer extends AbstractAnalyzer {

    /*
        duffcopy: https://github.com/golang/go/blob/go1.19.5/src/runtime/mkduff.go#L81-L97
        repeated 64 times
        004640b2 0f 10 06        MOVUPS     XMM0,xmmword ptr [RSI]
        004640b5 48 83 c6 10     ADD        RSI,0x10
        004640b9 0f 11 07        MOVUPS     xmmword ptr [RDI],XMM0
        004640bc 48 83 c7 10     ADD        RDI,0x10
        004640c0 c3              RET
     */
    private static final byte[] COPY_SEGMENT = new byte[]{15, 16, 6, 72, -125, -58, 16, 15, 17, 7, 72, -125, -57, 16};
    private static final int COPY_REPEAT = 64;

    /*
        duffzero: https://github.com/golang/go/blob/go1.19.5/src/runtime/mkduff.go#L65-L79
        repeated 16 times
        00463d19 44 0f 11 3f     MOVUPS     xmmword ptr [RDI],XMM15
        00463d1d 44 0f 11        MOVUPS     xmmword ptr [RDI + 0x10],XMM15
                 7f 10
        00463d22 44 0f 11        MOVUPS     xmmword ptr [RDI + 0x20],XMM15
                 7f 20
        00463d27 44 0f 11        MOVUPS     xmmword ptr [RDI + 0x30],XMM15
                 7f 30
        00463d2c 48 8d 7f 40     LEA        RDI,[RDI + 0x40]
        00463d30 c3              RET
     */
    private static final byte[] ZERO_SEGMENT = new byte[]{68, 15, 17, 63, 68, 15, 17, 127, 16, 68, 15, 17, 127, 32, 68, 15, 17, 127, 48, 72, -115, 127, 64};
    private static final int ZERO_REPEAT = 16;

    public DuffAnalyzer() {
        super("Go Duff's device analyzer", "Identifies runtime.duffcopy and runtime.duffzero and applies correct signatures.", AnalyzerType.FUNCTION_ANALYZER);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }

    private static byte[] repeat(byte[] b, int n) {
        int m = n * b.length;
        byte[] res = new byte[m + 1];
        for (int i = 0; i < m; i++) {
            res[i] = b[i % b.length];
        }
        res[m] = -61; // c3 RET
        return res;
    }

    private interface FuncCreator {
        void create(int segmentIndex, Address segmentStart) throws InvalidInputException, OverlappingFunctionException, DuplicateNameException;
    }

    private static boolean createDuff(Program p, TaskMonitor monitor, byte[] segment, int repeat, FuncCreator fc) throws Exception {
        byte[] body = repeat(segment, repeat);
        byte[] mask = new byte[body.length];
        Arrays.fill(mask, (byte) -1);
        // TODO: What if there are multiple hits? Then someone is trolling us.
        Address start = p.getMemory().findBytes(p.getMinAddress(), p.getMaxAddress(), body, mask, true, monitor);
        if (start == null) {
            return false;
        }
        Address end = start.add(body.length - 1);
        RegisterAssumptions.assume(p.getProgramContext(), start, end);
        AddressSet range = new AddressSet(start, end);
        FunctionManager fm = p.getFunctionManager();
        fm.getFunctionsOverlapping(range).forEachRemaining(f -> fm.removeFunction(f.getEntryPoint()));
        Disassembler.getDisassembler(p, monitor, DisassemblerMessageListener.CONSOLE).disassemble(start, range);
        for (int i = 0; i < repeat; i++) {
            fc.create(i, start.add((long) i * segment.length));
        }
        return true;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        FunctionManager fm = program.getFunctionManager();
        DataType voidPtr = new PointerDataType(new VoidDataType());
        try {
            if (!createDuff(program, monitor, COPY_SEGMENT, COPY_REPEAT, (i, start) -> {
                fm.createFunction(
                        String.format("duffcopy.%d", (COPY_REPEAT - i) * 16),
                        start,
                        new AddressSet(start, start.add(COPY_SEGMENT.length - 1)),
                        SourceType.ANALYSIS
                ).updateFunction(
                        "go-duff-copy",
                        new ReturnParameterImpl(new VoidDataType(), program),
                        Arrays.asList(
                                new ParameterImpl("dst", voidPtr, program, SourceType.ANALYSIS),
                                new ParameterImpl("src", voidPtr, program, SourceType.ANALYSIS)),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true,
                        SourceType.ANALYSIS);
            })) {
                log.appendMsg("Could not find runtime.duffcopy!");
            }
        } catch (Exception e) {
            log.appendMsg("Could not create runtime.duffcopy!");
            throw new RuntimeException(e);
        }

        try {
            long[] offsets = {4, 5, 5, 9};
            if (!createDuff(program, monitor, ZERO_SEGMENT, ZERO_REPEAT, (i, start) -> {
                int roundAmount = (ZERO_REPEAT - i) * 64;
                for (int j = 0; j < offsets.length; j++) {
                    fm.createFunction(
                            String.format("duffzero.%d", roundAmount - 16 * j),
                            start,
                            new AddressSet(start, start.add(offsets[j] - 1)),
                            SourceType.ANALYSIS
                    ).updateFunction(
                            "go-duff-zero",
                            new ReturnParameterImpl(new VoidDataType(), program),
                            List.of(new ParameterImpl("dst", voidPtr, program, SourceType.ANALYSIS)),
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                            true,
                            SourceType.ANALYSIS);
                    start = start.add(offsets[j]);
                }
            })) {
                log.appendMsg("Could not find runtime.duffzero!");
            }
        } catch (Exception e) {
            log.appendMsg("Could not create runtime.duffzero!");
            throw new RuntimeException(e);
        }
        return true;
    }
}
