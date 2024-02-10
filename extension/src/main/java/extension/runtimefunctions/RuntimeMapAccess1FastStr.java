package extension.runtimefunctions;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;

public class RuntimeMapAccess1FastStr extends RuntimeMapFastStr {

    public RuntimeMapAccess1FastStr(Program p) throws InvalidInputException {
        super(p);
    }

    @Override
    public String getName() {
        return "runtime.mapaccess1_faststr";
    }
}
