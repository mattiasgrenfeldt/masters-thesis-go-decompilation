package extension.runtimefunctions;

import extension.RequiredDataTypes;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

import java.util.Arrays;
import java.util.List;

public abstract class RuntimeMapFastStr implements RuntimeFunction {

    private final ReturnParameterImpl originalReturn;
    private final List<ParameterImpl> originalParameters;
    private final DataTypeManager dtm;

    public RuntimeMapFastStr(Program p) throws InvalidInputException {
        dtm = p.getDataTypeManager();
        originalReturn = new ReturnParameterImpl(new PointerDataType(p.getDataTypeManager()), p);
        originalParameters = Arrays.asList(
                new ParameterImpl("g", RequiredDataTypes.runtimeGPtr, p, SourceType.ANALYSIS),
                new ParameterImpl("t", RequiredDataTypes.runtimeTypePtr, p, SourceType.ANALYSIS),
                new ParameterImpl("h", RequiredDataTypes.runtimeHmapPtr, p, SourceType.ANALYSIS),
                new ParameterImpl("s", RequiredDataTypes.string, p, SourceType.ANALYSIS));
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
        DataType arg = new PointerDataType(t, dtm);
        Structure s = (Structure) t;
        Pointer bmapPtr = (Pointer) s.getComponent(5).getDataType();
        Structure bmap = (Structure) bmapPtr.getDataType();
        DataType ret;
        try {
            Array elems = (Array) bmap.getComponent(2).getDataType();
            ret = new PointerDataType(elems.getDataType(), dtm);
        } catch (IndexOutOfBoundsException e) {
            // The element in the map is an empty struct
            ret = new VoidDataType(dtm);
        }
        return new SignatureTypes(new DataType[]{null, null, arg, null}, ret);
    }
}
