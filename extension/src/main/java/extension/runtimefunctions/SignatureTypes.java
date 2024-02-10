package extension.runtimefunctions;

import ghidra.program.model.data.DataType;

public class SignatureTypes {
    // TODO: make into a record

    public DataType[] args;
    public DataType ret;

    public SignatureTypes(DataType[] args, DataType ret) {
        this.args = args;
        this.ret = ret;
    }
}
