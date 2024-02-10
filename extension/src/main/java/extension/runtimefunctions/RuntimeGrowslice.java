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

import static extension.metadata.Metadata.dataTypePath;

public class RuntimeGrowslice implements RuntimeFunction {

    private final DataTypeManager dtm;

    private final ReturnParameterImpl originalReturn;
    private final List<ParameterImpl> originalParameters;

    public RuntimeGrowslice(Program p) throws InvalidInputException {
        dtm = p.getDataTypeManager();
        originalReturn = new ReturnParameterImpl(RequiredDataTypes.runtimeSlice, p);
        originalParameters = Arrays.asList(
                new ParameterImpl("g", RequiredDataTypes.runtimeGPtr, p, SourceType.ANALYSIS),
                new ParameterImpl("et", RequiredDataTypes.runtimeTypePtr, p, SourceType.ANALYSIS),
                new ParameterImpl("old", RequiredDataTypes.runtimeSlice, p, SourceType.ANALYSIS),
                new ParameterImpl("cap", new LongDataType(dtm), p, SourceType.ANALYSIS));
    }

    @Override
    public String getName() {
        return "runtime.growslice";
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
        // The category path should be the same as for the element
        String name = elem.getName() + "_slice";
        CategoryPath path = elem.getCategoryPath();
        DataType t = dtm.getDataType(path, name);
        if (t != null) {
            return new SignatureTypes(new DataType[]{null, null, t, null}, t);
        }

        if (!path.getPath().startsWith("/Go/")) {
            // Is a primitive type or an array.
            DataTypePath dp = dataTypePath(name);
            path = dp.getCategoryPath();
            name = dp.getDataTypeName();
        }

        // TODO: factor this out into some function
        StructureDataType slice = new StructureDataType(path, name, 0, dtm);
        slice.add(new PointerDataType(elem, dtm), "data", "");
        slice.add(new LongDataType(dtm), "len", "");
        slice.add(new LongDataType(dtm), "cap", "");
        dtm.addDataType(slice, DataTypeConflictHandler.REPLACE_HANDLER);
        return new SignatureTypes(new DataType[]{null, null, slice, null}, slice);
    }
}
