package extension.runtimefunctions;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;

public class RuntimeMapassignFastStr extends RuntimeMapFastStr {

    public RuntimeMapassignFastStr(Program p) throws InvalidInputException {
        super(p);
    }

    @Override
    public String getName() {
        return "runtime.mapassign_faststr";
    }
}
