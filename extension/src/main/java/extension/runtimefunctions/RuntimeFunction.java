package extension.runtimefunctions;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;

import java.util.List;

public interface RuntimeFunction {

    String getName();

    ReturnParameterImpl getOriginalReturnParam();

    List<ParameterImpl> getOriginalParameters();

    int getConstArgOrdinal();

    SignatureTypes getNewDatatypes(DataType t);
}
