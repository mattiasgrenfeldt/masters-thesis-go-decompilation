package golanganalyzerextension.datatype;

public enum Kind {
	Invalid,
	Bool, Int, Int8, Int16, Int32, Int64,
	Uint, Uint8, Uint16, Uint32, Uint64,
	Uintptr, Float32, Float64, Complex64, Complex128,
	Array, Chan, Func, Interface, Map,
	Ptr, Slice, String, Struct, UnsafePointer, MaxKind
}
