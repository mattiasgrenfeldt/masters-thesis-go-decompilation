package extension.metadata;

public enum Kind {
    BOOL,
    CHAR,
    FLOAT,     // float32
    DOUBLE,    // float64
    BYTE,      // uint8
    SBYTE,     // int8
    SHORT,     // int16
    USHORT,    // uint16
    INT,       // int32
    UINT,      // uint32
    LONG,      // int
    ULONG,     // uint
    LONGLONG,  // int64
    ULONGLONG, // uint64
    VOIDPTR,   // uintptr
    POINTER,
    ARRAY,
    STRUCT,
    FUNC,
}
