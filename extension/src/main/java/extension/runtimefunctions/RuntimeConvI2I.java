package extension.runtimefunctions;

import extension.RequiredDataTypes;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

import java.util.Arrays;
import java.util.List;

public class RuntimeConvI2I implements RuntimeFunction {

    private final ReturnParameterImpl originalReturn;
    private final List<ParameterImpl> originalParameters;

    public RuntimeConvI2I(Program p) throws InvalidInputException {
        originalReturn = new ReturnParameterImpl(RequiredDataTypes.runtimeItabPtr, p);
        originalParameters = Arrays.asList(
                new ParameterImpl("g", RequiredDataTypes.runtimeGPtr, p, SourceType.ANALYSIS),
                new ParameterImpl("dst", RequiredDataTypes.runtimeTypePtr, p, SourceType.ANALYSIS),
                new ParameterImpl("src", RequiredDataTypes.runtimeItabPtr, p, SourceType.ANALYSIS));
    }

    @Override
    public String getName() {
        return "runtime.convI2I";
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
    public SignatureTypes getNewDatatypes(DataType t) {
        Structure s = (Structure) t;
        return new SignatureTypes(null, s.getComponent(0).getDataType());
    }
}
