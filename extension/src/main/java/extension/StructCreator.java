package extension;

import extension.metadata.Field;
import extension.metadata.Kind;
import extension.metadata.Type;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

import static extension.metadata.Metadata.dataTypePath;


public class StructCreator {

    private final DataTypeManager dtm;
    private final Map<String, List<Field>> structs;
    private final HashMap<String, DataType> isDefined = new HashMap<>();

    long structCounter = 0;
    long functionCounter = 0;

    private final DataType BOOL;
    private final DataType CHAR;
    private final DataType FLOAT;
    private final DataType DOUBLE;
    private final DataType BYTE;
    private final DataType SBYTE;
    private final DataType SHORT;
    private final DataType USHORT;
    private final DataType INT;
    private final DataType UINT;
    private final DataType LONG;
    private final DataType ULONG;
    private final DataType LONGLONG;
    private final DataType ULONGLONG;
    private final DataType VOIDPTR;
    private final DataType VOID;

    public StructCreator(DataTypeManager dtm, Map<String, List<Field>> structs) {
        this.dtm = dtm;
        this.structs = structs;

        BOOL = new BooleanDataType(dtm);
        CHAR = new CharDataType(dtm);
        FLOAT = new FloatDataType(dtm);
        DOUBLE = new DoubleDataType(dtm);
        BYTE = new ByteDataType(dtm);
        SBYTE = new SignedByteDataType(dtm);
        SHORT = new ShortDataType(dtm);
        USHORT = new UnsignedShortDataType(dtm);
        INT = new IntegerDataType(dtm);
        UINT = new UnsignedIntegerDataType(dtm);
        LONG = new LongDataType(dtm);
        ULONG = new UnsignedLongDataType(dtm);
        LONGLONG = new LongLongDataType(dtm);
        ULONGLONG = new UnsignedLongLongDataType(dtm);
        VOIDPTR = new PointerDataType(dtm);
        VOID = new VoidDataType(dtm);
    }

    public DataType getDataType(Type t) {
        // TODO: consider removing this and just having defineDataType.
        return switch (t.kind) {
            case BOOL -> BOOL;
            case CHAR -> CHAR;
            case FLOAT -> FLOAT;
            case DOUBLE -> DOUBLE;
            case BYTE -> BYTE;
            case SBYTE -> SBYTE;
            case SHORT -> SHORT;
            case USHORT -> USHORT;
            case INT -> INT;
            case UINT -> UINT;
            case LONG -> LONG;
            case ULONG -> ULONG;
            case LONGLONG -> LONGLONG;
            case ULONGLONG -> ULONGLONG;
            case VOIDPTR -> VOIDPTR;
            case POINTER -> new PointerDataType(getDataType(t.elem), dtm);
            case ARRAY -> {
                DataType elem = getDataType(t.elem);
                yield new ArrayDataType(elem, t.length, elem.getLength(), dtm);
            }
            case STRUCT -> dtm.getDataType(dataTypePath(t.name));
            case FUNC -> new PointerDataType(dtm.getDataType(dataTypePath(t.name)), dtm);
        };
    }

    // TODO: combine / clean up these two functions somehow
    private DataType defineDataType(Type t) throws Exception {
        return switch (t.kind) {
            case BOOL -> BOOL;
            case CHAR -> CHAR;
            case FLOAT -> FLOAT;
            case DOUBLE -> DOUBLE;
            case BYTE -> BYTE;
            case SBYTE -> SBYTE;
            case SHORT -> SHORT;
            case USHORT -> USHORT;
            case INT -> INT;
            case UINT -> UINT;
            case LONG -> LONG;
            case ULONG -> ULONG;
            case LONGLONG -> LONGLONG;
            case ULONGLONG -> ULONGLONG;
            case VOIDPTR -> VOIDPTR;
            case POINTER -> new PointerDataType(defineDataType(t.elem), dtm);
            case ARRAY -> {
                DataType elem = defineDataType(t.elem);
                yield new ArrayDataType(elem, t.length, elem.getLength(), dtm);
            }
            case STRUCT -> defineStruct(t.name, structs.get(t.name));
            case FUNC -> defineFunctionDefinition(t.name, t.args, t.returns);
        };
    }

    private DataType defineFunctionDefinition(String name, List<Field> args, List<Type> returns) throws Exception {
        DataType t = isDefined.get(name);
        if (t != null) {
            return t;
        }
        functionCounter++;

        DataTypePath typePath = dataTypePath(name);
        FunctionDefinitionDataType f = new FunctionDefinitionDataType(typePath.getCategoryPath(), typePath.getDataTypeName(), dtm);
        PointerDataType ptr = new PointerDataType(f, dtm);
        isDefined.put(name, ptr);
        f.setReturnType(createReturnStruct(name, returns).ret);

        // TODO: recreate as some stream thing
        if (args != null && args.size() > 0) {
            ParameterDefinition[] params = new ParameterDefinition[args.size()];
            // TODO: add the two default parameters: g pointer and pointer to data.
            for (int i = 0; i < args.size(); i++) {
                Field fl = args.get(i);
                if (fl.name == null || fl.name.isEmpty()) {
                    fl.name = String.format("param%d", i);
                }
                params[i] = new ParameterDefinitionImpl(fl.name, defineDataType(fl.type), "");
            }
            f.setArguments(params);
        }
        // NOTE: this should define f, not ptr!
        dtm.addDataType(f, DataTypeConflictHandler.REPLACE_HANDLER);
        return ptr;
    }

    public record RetStruct(DataType ret, boolean hasMultipleResults) {
    }

    public RetStruct createReturnStruct(String functionName, List<Type> returns) throws Exception {
        if (returns == null || returns.size() == 0) {
            return new RetStruct(VOID, false);
        }
        // Note: Ghidra can handle having Arrays as return values, but when the code is exported to be parsed by a C
        // parser, that does not work since C doesn't allow array returns.
        if (returns.size() == 1 && returns.get(0).kind != Kind.ARRAY) {
            return new RetStruct(defineDataType(returns.get(0)), false);
        }
        ArrayList<Field> fields = new ArrayList<>();
        for (int i = 0; i < returns.size(); i++) {
            fields.add(new Field(String.format("ret%d", i), returns.get(i)));
        }
        String name = functionName + "_ret";
        structs.put(name, fields); // Needed for sizeOf
        return new RetStruct(defineStruct(name, fields), true);
    }

    private DataType defineStruct(String name, List<Field> fields) throws Exception {
        DataType t = isDefined.getOrDefault(name, null);
        if (t != null) {
            // TODO: Does this work? Will it refer to the correct type?
            return t;
        }
        structCounter++;

        // Have to pre-calculate the size before defining any fields since some data structure might embed this
        // structure.
        DataTypePath typePath = dataTypePath(name);
        StructureDataType s = new StructureDataType(typePath.getCategoryPath(), typePath.getDataTypeName(), sizeOf(name), dtm);
        isDefined.put(name, s);
        if (fields != null) {
            int offset = 0;
            for (int i = 0; i < fields.size(); i++) {
                Field f = fields.get(i);
                DataType ft = defineDataType(f.type);
                s.replaceAtOffset(offset, ft, ft.getLength(), Util.safeIdentifier(f.name), "");
                offset += ft.getLength();
            }
        }
        dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
        return s;
    }

    public void defineStructs(TaskMonitor monitor) throws Exception {
        monitor.setMessage("Defining datatypes...");
        monitor.initialize(structs.size());
        // Needs to be a new hashset here since we are potentially modifying structs during the recursion, which would
        // lead to a ConcurrentModificationException.
        for (String key : new HashSet<>(structs.keySet())) {
            defineStruct(key, structs.get(key));
            monitor.incrementProgress(1);
        }
    }

    private int sizeOf(Type t) {
        // TODO: use sizes based on data organization
        return switch (t.kind) {
            case BOOL, CHAR, BYTE, SBYTE -> 1;
            case SHORT, USHORT -> 2;
            case FLOAT, INT, UINT -> 4;
            case POINTER, FUNC, VOIDPTR, DOUBLE, LONG, ULONG, LONGLONG, ULONGLONG -> 8;
            case ARRAY -> sizeOf(t.elem) * t.length;
            case STRUCT -> sizeOf(t.name);
        };
    }

    private final HashMap<String, Integer> structSizeOffsets = new HashMap<>();

    private int sizeOf(String name) {
        Integer size = structSizeOffsets.get(name);
        if (size != null) {
            return size;
        }
        // Since a structure will never embed itself, this won't cause infinite recursion.
        int s = structs.get(name).stream().mapToInt(f -> sizeOf(f.type)).sum();
        structSizeOffsets.put(name, s);
        return s;
    }
}
