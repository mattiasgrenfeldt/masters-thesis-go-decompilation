package extension;

import ghidra.program.model.data.*;

public class RequiredDataTypes {

    public static StructureDataType runtimeSlice;
    public static PointerDataType runtimeTypePtr;
    public static StructureDataType string;

    public static PointerDataType runtimeGPtr;
    public static PointerDataType runtimeHmapPtr;
    public static PointerDataType runtimeHiterPtr;
    public static PointerDataType runtimeItabPtr;

    public static void createDataTypes(DataTypeManager dtm) {
        CategoryPath runtime = new CategoryPath("/Go/runtime");

        // TODO: add runtime.g.
        // Because I'm lazy and don't want to create the entire runtime.g datatype.
        runtimeGPtr = new PointerDataType(dtm.getDataType(runtime, "runtime.g"), dtm);
        runtimeHmapPtr = new PointerDataType(dtm.getDataType(runtime, "runtime.hmap"), dtm);
        runtimeHiterPtr = new PointerDataType(dtm.getDataType(runtime, "runtime.hiter"), dtm);
        runtimeItabPtr = new PointerDataType(dtm.getDataType(runtime, "runtime.itab"), dtm);

        string = new StructureDataType(new CategoryPath("/Go"), "gostring", 0, dtm);
        string.add(new PointerDataType(new CharDataType(), dtm), "str", "");
        string.add(new LongDataType(dtm), "len", "");
        dtm.addDataType(string, DataTypeConflictHandler.REPLACE_HANDLER);

        runtimeSlice = new StructureDataType(runtime, "runtime.slice", 0, dtm);
        runtimeSlice.add(new PointerDataType(dtm), "array", "");
        runtimeSlice.add(new LongDataType(dtm), "len", "");
        runtimeSlice.add(new LongDataType(dtm), "cap", "");
        dtm.addDataType(runtimeSlice, DataTypeConflictHandler.REPLACE_HANDLER);

        EnumDataType tflag = new EnumDataType(runtime, "runtime.tflag", 1, dtm);
        tflag.add("tflagUncommon", 1);
        tflag.add("tflagExtraStar", 1 << 1);
        tflag.add("tflagNamed", 1 << 2);
        tflag.add("tflagRegularMemory", 1 << 3);
        dtm.addDataType(tflag, DataTypeConflictHandler.REPLACE_HANDLER);

        EnumDataType kind = new EnumDataType(runtime, "runtime.kind", 1, dtm);
        String[] vals = {
                "kindInvalid",
                "kindBool",
                "kindInt",
                "kindInt8",
                "kindInt16",
                "kindInt32",
                "kindInt64",
                "kindUint",
                "kindUint8",
                "kindUint16",
                "kindUint32",
                "kindUint64",
                "kindUintptr",
                "kindFloat32",
                "kindFloat64",
                "kindComplex64",
                "kindComplex128",
                "kindArray",
                "kindChan",
                "kindFunc",
                "kindInterface",
                "kindMap",
                "kindPtr",
                "kindSlice",
                "kindString",
                "kindStruct",
                "kindUnsafePointer"
        };
        for (int i = 0; i < vals.length; i++) {
            kind.add(vals[i], i);
        }
        kind.add("kindDirectIface", 1 << 5);
        kind.add("kindGCProg", 1 << 6);
        dtm.addDataType(kind, DataTypeConflictHandler.REPLACE_HANDLER);

        StructureDataType _type = new StructureDataType(runtime, "runtime._type", 0, dtm);
        _type.add(new UnsignedLongDataType(dtm), "size", "");
        _type.add(new UnsignedLongDataType(dtm), "ptrdata", "");
        _type.add(new UnsignedIntegerDataType(dtm), "hash", "");
        _type.add(tflag, "tflag", "");
        _type.add(new ByteDataType(dtm), "align", "");
        _type.add(new ByteDataType(dtm), "fieldAlign", "");
        _type.add(kind, "kind", "");
        _type.add(new PointerDataType(dtm), "equal", "");
        _type.add(new PointerDataType(new ByteDataType(dtm), dtm), "gcdata", "");
        _type.add(new IntegerDataType(dtm), "str", "");
        _type.add(new IntegerDataType(dtm), "ptrToThis", "");
        dtm.addDataType(_type, DataTypeConflictHandler.REPLACE_HANDLER);
        runtimeTypePtr = new PointerDataType(_type, dtm);
    }
}
