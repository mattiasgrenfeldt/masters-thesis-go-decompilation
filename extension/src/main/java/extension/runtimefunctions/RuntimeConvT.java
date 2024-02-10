package extension.runtimefunctions;

import extension.RequiredDataTypes;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

import java.util.Arrays;
import java.util.List;

public class RuntimeConvT implements RuntimeFunction {

    private final ReturnParameterImpl originalReturn;
    private final List<ParameterImpl> originalParameters;
    private final DataTypeManager dtm;

    public RuntimeConvT(Program p) throws InvalidInputException {
        dtm = p.getDataTypeManager();
        originalReturn = new ReturnParameterImpl(new PointerDataType(dtm), p);
        originalParameters = Arrays.asList(
                new ParameterImpl("g", RequiredDataTypes.runtimeGPtr, p, SourceType.ANALYSIS),
                new ParameterImpl("t", RequiredDataTypes.runtimeTypePtr, p, SourceType.ANALYSIS),
                new ParameterImpl("v", new PointerDataType(dtm), p, SourceType.ANALYSIS));
    }

    @Override
    public String getName() {
        return "runtime.convT";
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
        DataType theType = new PointerDataType(t, dtm);
        return new SignatureTypes(new DataType[]{null, null, theType}, theType);
    }
}
