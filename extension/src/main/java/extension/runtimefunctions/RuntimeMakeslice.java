package extension.runtimefunctions;

import extension.RequiredDataTypes;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

import java.util.Arrays;
import java.util.List;

public class RuntimeMakeslice implements RuntimeFunction {

    private final ReturnParameterImpl originalReturn;
    private final List<ParameterImpl> originalParameters;
    private final DataTypeManager dtm;

    public RuntimeMakeslice(Program p) throws InvalidInputException {
        dtm = p.getDataTypeManager();
        originalReturn = new ReturnParameterImpl(new PointerDataType(dtm), p);
        originalParameters = Arrays.asList(
                new ParameterImpl("g", RequiredDataTypes.runtimeGPtr, p, SourceType.ANALYSIS),
                new ParameterImpl("et", RequiredDataTypes.runtimeTypePtr, p, SourceType.ANALYSIS),
                new ParameterImpl("len", new LongDataType(dtm), p, SourceType.ANALYSIS),
                new ParameterImpl("cap", new LongDataType(dtm), p, SourceType.ANALYSIS)
        );
    }

    @Override
    public String getName() {
        return "runtime.makeslice";
    }

    @Override
    public ReturnParameterImpl getOriginalReturnParam() {
        return originalReturn;
    }

    @Override
    public List<ParameterImpl> getOriginalParameters() {
        return originalParameters;
    }

    @Override
    public int getConstArgOrdinal() {
        return 1;
    }

    @Override
    public SignatureTypes getNewDatatypes(DataType elem) {
        // TODO: if we knew the cap argument in the call, we could enhance the type to be a pointer to an array of cap
        // elements.
        return new SignatureTypes(null, new PointerDataType(elem, dtm));
    }
}
