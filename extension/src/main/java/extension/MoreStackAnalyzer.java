package extension;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MoreStackAnalyzer extends AbstractAnalyzer {
    public MoreStackAnalyzer() {
        super("Go morestack analyzer", "Removes jumps to runtime.morestack_noctxt.", AnalyzerType.INSTRUCTION_ANALYZER);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        Listing lst = p.getListing();
        Memory mem = p.getMemory();
        FunctionManager fm = p.getFunctionManager();
        Disassembler dis = Disassembler.getDisassembler(p, monitor, DisassemblerMessageListener.CONSOLE);
        dis.setRepeatPatternLimit(100);
        monitor.setMessage("NOPing out jumps to runtime.morestack_noctxt...");
        monitor.initialize(fm.getFunctionCount());
        int i = 0;
        for (Function f : fm.getFunctions(true)) {
            Address entry = f.getEntryPoint();
            Instruction[] insts = new Instruction[3];
            InstructionIterator it = lst.getInstructions(entry, true);
            for (int j = 0; j < 3 && it.hasNext(); j++) {
                insts[j] = it.next();
            }

            int max = -1;
            boolean matches = false;
            if (insts[0] != null
                    && insts[1] != null
                    && insts[0].toString().equals("CMP RSP,qword ptr [R14 + 0x10]")
                    && insts[1].getMnemonicString().equals("JBE")) {
                matches = true;
                max = 1;
            }
            if (insts[0] != null
                    && insts[1] != null
                    && insts[2] != null
                    && insts[0].getMnemonicString().equals("LEA")
                    && insts[0].getDefaultOperandRepresentation(0).equals("R12")
                    && insts[1].toString().equals("CMP R12,qword ptr [R14 + 0x10]")
                    && insts[2].getMnemonicString().equals("JBE")) {
                matches = true;
                max = 2;
            }

            if (matches) {
                Address end = insts[max].getMaxAddress();
                lst.clearCodeUnits(entry, end, false);
                int size = (int) end.subtract(entry) + 1;
                byte[] nop = new byte[size];
                for (int j = 0; j < size; j++) {
                    nop[j] = -112; // 0x90 - NOP
                }
                try {
                    mem.setBytes(entry, nop);
                } catch (MemoryAccessException e) {
                    log.appendException(e);
                    throw new RuntimeException(e);
                }
                // TODO: Figure out why sometimes this doesn't work.
                dis.disassemble(entry, new AddressSet(entry, end));
                StringBuilder comment = new StringBuilder("Original patched out assembly:\n");
                for (int j = 0; j < max + 1; j++) {
                    comment.append(insts[j].toString()).append("\n");
                }
                lst.setComment(end, CodeUnit.POST_COMMENT, comment.toString());
            }
            i++;
            if (i % 1000 == 0) {
                monitor.setProgress(i);
            }
        }
        return true;
    }
}
