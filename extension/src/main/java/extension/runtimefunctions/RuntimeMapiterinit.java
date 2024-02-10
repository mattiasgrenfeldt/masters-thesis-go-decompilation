package extension.runtimefunctions;

import extension.RequiredDataTypes;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

import java.util.Arrays;
import java.util.List;

import static extension.metadata.Metadata.dataTypePath;

public class RuntimeMapiterinit implements RuntimeFunction {

    private final DataTypeManager dtm;

    private final ReturnParameterImpl originalReturn;
    private final List<ParameterImpl> originalParameters;

    public RuntimeMapiterinit(Program p) throws InvalidInputException {
        dtm = p.getDataTypeManager();
        originalReturn = new ReturnParameterImpl(new VoidDataType(dtm), p);
        originalParameters = Arrays.asList(
                new ParameterImpl("g", RequiredDataTypes.runtimeGPtr, p, SourceType.ANALYSIS),
                new ParameterImpl("t", RequiredDataTypes.runtimeTypePtr, p, SourceType.ANALYSIS),
                new ParameterImpl("h", RequiredDataTypes.runtimeHmapPtr, p, SourceType.ANALYSIS),
                new ParameterImpl("it", RequiredDataTypes.runtimeHiterPtr, p, SourceType.ANALYSIS));
    }

    @Override
    public String getName() {
        return "runtime.mapiterinit";
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
        String name = "hiter." + elem.getName().substring(5);
        DataType hiter = dtm.getDataType(dataTypePath(name));
        if (hiter == null) {
            throw new RuntimeException(String.format("hiter not found for map %s", elem.getName()));
        }
        // TODO: have a global void data type somewhere
        return new SignatureTypes(new DataType[]{null, null, new PointerDataType(elem, dtm), new PointerDataType(hiter, dtm)}, new VoidDataType(dtm));
    }
}
