package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"

	"github.com/goretk/gore"
)

type kind uint8

const (
	KBool kind = iota
	KChar
	KFloat     // float32
	KDouble    // float64
	KByte      // uint8
	KSbyte     // int8
	KShort     // int16
	KUshort    // uint16
	KInt       // int32
	KUint      // uint32
	KLong      // int
	KUlong     // uint, uintptr
	KLonglong  // int64
	KUlonglong // uint64
	KVoidptr

	KPointer
	KArray
	KStruct
	KFunc
)

type typ struct {
	Kind kind   `json:"kind"`
	Name string `json:"name,omitempty"`
	// Elem describes the element type when Kind is KPointer or KArray
	Elem *typ `json:"elem,omitempty"`
	// Length gives the amount of elements, if Kind is KArray
	Length int `json:"length,omitempty"`
	// Args holds the argument types if Kind is KFunc
	Args []field `json:"args,omitempty"`
	// Returns holds the return types if Kind is KFunc
	Returns []typ `json:"returns,omitempty"`
}

func (t *typ) nameOrEmptyStruct() string {
	if t == nil {
		return "struct{}"
	}
	return t.Name
}

var (
	typString = &typ{Kind: KStruct, Name: "string"}
	typChar   = &typ{Kind: KChar}
	typBool   = &typ{Kind: KBool, Name: "bool"}
	// TODO: int or long as name here? Go type name or Ghidra type name
	// Is relevant for slices: int_slice or long_slice
	typLong      = &typ{Kind: KLong, Name: "long"}
	typSbyte     = &typ{Kind: KSbyte, Name: "sbyte"}
	typShort     = &typ{Kind: KShort, Name: "short"}
	typInt       = &typ{Kind: KInt, Name: "int"}
	typLonglong  = &typ{Kind: KLonglong, Name: "longlong"}
	typUlong     = &typ{Kind: KUlong, Name: "ulong"}
	typByte      = &typ{Kind: KByte, Name: "byte"}
	typUshort    = &typ{Kind: KUshort, Name: "ushort"}
	typUint      = &typ{Kind: KUint, Name: "uint"}
	typUlonglong = &typ{Kind: KUlonglong, Name: "ulonglong"}
	typFloat     = &typ{Kind: KFloat, Name: "float"}
	typDouble    = &typ{Kind: KDouble, Name: "double"}
)

func arrayTyp(elem *typ, length int) *typ {
	if elem == nil || length == 0 { // elem is an empty struct
		return nil
	}
	return &typ{
		Kind:   KArray,
		Name:   elem.Name + fmt.Sprintf("_array_%d", length),
		Elem:   elem,
		Length: length,
	}
}

type field struct {
	Name string `json:"name,omitempty"`
	// TODO: add field comment from library parsing
	Type typ `json:"type"`
}

type function struct {
	Name    string  `json:"name"`
	Entry   uint64  `json:"entry,omitempty"`
	End     uint64  `json:"end,omitempty"`
	Args    []field `json:"args,omitempty"`
	Returns []typ   `json:"returns,omitempty"`
	// TODO: handle methods
}

type structures map[string][]field

type metadata struct {
	Functions  []function `json:"functions"`
	Structures structures `json:"structures"`
	// Descriptors maps the address where the _type struct is to which typ is
	// described there.
	Descriptors map[uint64]*typ `json:"descriptors"`
}

func (m metadata) marshal() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

func randomSuffix() string {
	// The point of this is that if you see some unsupported or nil_pointer data
	// type you can see which other datatypes are refering to the same type.
	return fmt.Sprintf("_%d", rand.Int()%1000000)
}

func unsupportedTyp() *typ {
	return &typ{Kind: KVoidptr, Name: "unsupported" + randomSuffix()}
}

func pointerTyp(elem *typ) *typ {
	if elem == nil { // elem is an empty struct
		return &typ{Kind: KVoidptr}
	}
	return &typ{
		Kind: KPointer,
		Name: elem.Name + "_ptr",
		Elem: elem,
	}
}

func (s structures) makeString() *typ {
	s["string"] = []field{
		{Name: "str", Type: typ{Kind: KPointer, Elem: typChar}},
		{Name: "len", Type: *typLong},
	}
	return typString
}

func (s structures) makeComplex64() *typ {
	name := "complex64"
	s[name] = []field{
		{Name: "real", Type: *typFloat},
		{Name: "imag", Type: *typFloat},
	}
	return &typ{Kind: KStruct, Name: name}
}

func (s structures) makeComplex128() *typ {
	name := "complex128"
	s[name] = []field{
		{Name: "real", Type: *typDouble},
		{Name: "imag", Type: *typDouble},
	}
	return &typ{Kind: KStruct, Name: name}
}

func (s structures) makeSlice(elem *typ) *typ {
	name := elem.nameOrEmptyStruct() + "_slice"
	s[name] = []field{
		{Name: "data", Type: *pointerTyp(elem)},
		{Name: "len", Type: *typLong},
		{Name: "cap", Type: *typLong},
	}
	return &typ{Kind: KStruct, Name: name}
}

func (s structures) makeChan(elem *typ, d gore.ChanDir) *typ {
	// TODO: is direction ever relevant?
	dir := "both"
	if d == gore.ChanRecv {
		dir = "recv"
	} else if d == gore.ChanSend {
		dir = "send"
	}
	// define hchan https://github.com/golang/go/blob/go1.19.5/src/runtime/chan.go#L33-L52
	name := "hchan." + elem.nameOrEmptyStruct() + "_dir_" + dir
	s[name] = []field{
		{Name: "qcount", Type: *typUlong},
		{Name: "dataqsiz", Type: *typUlong},
		{Name: "buf", Type: *pointerTyp(elem)},
		{Name: "elemsize", Type: *typUshort},
		{Name: "closed", Type: *typUint},
		{Name: "elemtype", Type: typ{Kind: KVoidptr}},
		{Name: "sendx", Type: *typUlong},
		{Name: "recvx", Type: *typUlong},
		// TODO: Should probably inline the definition of runtime.waitq and
		// runtime.mutex here. For the case when symbol names have been
		// obfuscated.
		{Name: "recvq", Type: typ{Kind: KStruct, Name: "runtime.waitq"}},
		{Name: "sendq", Type: typ{Kind: KStruct, Name: "runtime.waitq"}},
		{Name: "lock", Type: typ{Kind: KStruct, Name: "runtime.mutex"}},
	}
	return &typ{Kind: KStruct, Name: name}
}

func (s structures) makeMap(key *typ, elem *typ) *typ {
	name := key.Name + "_to_" + elem.nameOrEmptyStruct()
	// define bmap https://github.com/golang/go/blob/go1.19.5/src/runtime/map.go#L149-L160
	bmap_fields := []field{
		{Name: "tophash", Type: *arrayTyp(typByte, 8)},
		{Name: "keys", Type: *arrayTyp(key, 8)},
	}
	// Check if elem is empty struct
	if et := arrayTyp(elem, 8); et != nil {
		bmap_fields = append(bmap_fields, field{Name: "elems", Type: *et})
	}
	bmap_name := "bmap." + name
	s[bmap_name] = bmap_fields
	bmap_ptr := pointerTyp(&typ{Kind: KStruct, Name: bmap_name})
	bmap_ptr_slice_ptr := typ{
		Kind: KPointer,
		Elem: s.makeSlice(bmap_ptr),
	}

	// define mapextra https://github.com/golang/go/blob/go1.19.5/src/runtime/map.go#L132-L147
	mapextra_name := "mapextra." + name
	s[mapextra_name] = []field{
		{Name: "overflow", Type: bmap_ptr_slice_ptr},
		{Name: "oldoverflow", Type: bmap_ptr_slice_ptr},
		{Name: "nextOverflow", Type: *bmap_ptr},
	}
	mapextra_t := typ{Kind: KStruct, Name: mapextra_name}

	// define hmap https://github.com/golang/go/blob/go1.19.5/src/runtime/map.go#L115-L130
	hmap_name := "hmap." + name
	s[hmap_name] = []field{
		{Name: "count", Type: *typLong},
		{Name: "flags", Type: *typByte},
		{Name: "B", Type: *typByte},
		{Name: "noverflow", Type: *typUshort},
		{Name: "hash0", Type: *typUint},
		{Name: "buckets", Type: *bmap_ptr},
		{Name: "oldbuckets", Type: *bmap_ptr},
		{Name: "nevacuate", Type: *typUlong},
		{Name: "extra", Type: *pointerTyp(&mapextra_t)},
	}
	hmap_t := typ{Kind: KStruct, Name: hmap_name}

	// define hiter https://github.com/golang/go/blob/go1.19.5/src/runtime/map.go#L162-L181
	s["hiter."+name] = []field{
		{Name: "key", Type: *pointerTyp(key)},
		{Name: "elem", Type: *pointerTyp(elem)},
		// t is of type *maptype. Not sure if we should create that or not.
		// Could make it a pointer to runtime._type and be done with it.
		{Name: "t", Type: typ{Kind: KVoidptr}},
		{Name: "h", Type: *pointerTyp(&hmap_t)},
		{Name: "buckets", Type: *bmap_ptr},
		{Name: "bptr", Type: *bmap_ptr},
		{Name: "overflow", Type: bmap_ptr_slice_ptr},
		{Name: "oldoverflow", Type: bmap_ptr_slice_ptr},
		{Name: "startBucket", Type: *typUlong},
		{Name: "offset", Type: *typByte},
		{Name: "wrapped", Type: *typBool},
		{Name: "B", Type: *typByte},
		{Name: "i", Type: *typByte},
		{Name: "bucket", Type: *typUlong},
		{Name: "checkBucket", Type: *typUlong},
	}
	return &hmap_t
}

func (s structures) makeStruct(name string, fields func() []field) *typ {
	if _, exists := s[name]; exists {
		// Avoids infinite recursion
		return &typ{Kind: KStruct, Name: name}
	}
	s[name] = []field{} // Ensure that s[name] is defined before call to fields()
	f := fields()
	if len(f) == 0 {
		// Example case where this happens:
		// type Func struct {
		//	opaque struct{} // unexported field to disallow conversions
		// }
		// We have not introduced references to this struct when calling
		// fields() since all the fields turned out to be empty.
		delete(s, name)
		return nil
	}
	s[name] = f
	return &typ{Kind: KStruct, Name: name}
}

func (s structures) makeEmptyInterface() *typ {
	name := "any_eface"
	s[name] = []field{
		// TODO: Should probably inline the definition of runtime._type
		// here. For the case when symbol names have been obfuscated.
		{Name: "_type", Type: *pointerTyp(&typ{Kind: KStruct, Name: "runtime._type"})},
		{Name: "data", Type: typ{Kind: KVoidptr}},
	}
	return &typ{Kind: KStruct, Name: name}
}

// makeError creates the error interface. This is hardcoded since it is so
// common. Also the real definition is in the builtin package, but the type is
// always referred to as just error.
func (s structures) makeError() *typ {
	return s.makeInterface("error", func() []field {
		return []field{
			{Name: "Error", Type: typ{
				Kind: KFunc,
				Name: "error.Error",
				// makeString is not called here since no addr is known for it,
				// so it could lead to the version of string without an addr
				// taking precedence. This assumes that makeString will be
				// called somewhere else at some point. It is very unllikely
				// that it would not happen.
				Returns: []typ{*typString},
			}},
		}
	})
}

// For the methods argument: the field.Name should be the name of the function
// and field.Type.Name should be the fully qualified name of the interface, plus
// a period (.), plus the name of the function (same as field.Name).
func (s structures) makeInterface(name string, methods func() []field) *typ {
	iface_name := name + "_iface"
	if _, exists := s[iface_name]; exists {
		// Avoid infinite recursion
		return &typ{Kind: KStruct, Name: iface_name}
	}
	s[iface_name] = []field{}

	// define itab https://github.com/golang/go/blob/go1.19.5/src/runtime/runtime2.go#L905-L915
	fields := []field{
		{Name: "inter", Type: typ{Kind: KVoidptr}},
		{Name: "_type", Type: typ{Kind: KVoidptr}},
		{Name: "hash", Type: typ{Kind: KUint}},
		{Name: "_", Type: *arrayTyp(typByte, 4)},
	}
	// Methods must be added in sorted order by name.
	m := methods()
	sort.Slice(m, func(i, j int) bool {
		return m[i].Name < m[j].Name
	})
	fields = append(fields, m...)
	itab_name := name + "_itab"
	s[itab_name] = fields
	itab_t := typ{Kind: KStruct, Name: itab_name}

	// define iface https://github.com/golang/go/blob/go1.19.5/src/runtime/runtime2.go#L202-L205
	s[iface_name] = []field{
		{Name: "tab", Type: *pointerTyp(&itab_t)},
		{Name: "data", Type: typ{Kind: KVoidptr}},
	}

	return &typ{Kind: KStruct, Name: iface_name}
}
