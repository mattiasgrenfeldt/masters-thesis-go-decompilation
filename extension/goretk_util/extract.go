package main

import (
	"debug/gosym"
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/goretk/gore"
)

func getFunctions(pclntab *gosym.Table) []function {
	var funcs []function
	for _, f := range pclntab.Funcs {
		funcs = append(funcs, function{
			Name:  f.Name,
			Entry: f.Entry,
			End:   f.End,
		})
	}
	return funcs
}

func getName(t *gore.GoType) string {
	name := t.Name
	if name == "interface {}" {
		name = "interface{}"
	}
	if strings.HasPrefix(name, "struct {") {
		// Anonymous struct, give it an anonymous name.
		// TODO: should I make this unique somehow so that it can't occur as a
		// normal name of a struct?
		name = fmt.Sprintf("anon_%x", t.Addr)
	}
	if t.PackagePath != "" {
		name = strings.TrimPrefix(name, path.Base(t.PackagePath)+".")
		name = t.PackagePath + "." + name
	}
	return strings.ReplaceAll(name, " ", "_")
}

func (g goreStructs) defineStruct(t *gore.GoType) *typ {
	if len(t.Fields) == 0 {
		// struct{} - empty struct
		return nil
	}
	return g.s.makeStruct(getName(t), func() []field {
		var fields []field
		for _, f := range t.Fields {
			ft := g.defineType(f)
			if ft == nil { // Field is an empty struct
				continue
			}
			fName := f.FieldName
			if f.FieldAnon {
				fName = ft.Name
			}
			fields = append(fields, field{Name: fName, Type: *ft})
		}
		return fields
	})
}

func (g goreStructs) defineInterface(t *gore.GoType) *typ {
	name := getName(t)
	return g.s.makeInterface(name, func() []field {
		var methods []field
		for _, m := range t.Methods {
			// TODO: handle m.IsVariadic
			var args []field
			for _, a := range m.Type.FuncArgs {
				// NOTE: This check is needed because the ResolveNow function in
				// this interface
				// https://pkg.go.dev/google.golang.org/grpc/balancer#ClientConn
				// takes a struct{} as argument.
				// ???
				if argT := g.defineType(a); argT != nil {
					args = append(args, field{Type: *argT})
				}
			}
			var returns []typ
			for _, r := range m.Type.FuncReturnVals {
				returns = append(returns, *g.defineType(r))
			}
			methods = append(methods, field{
				Name: m.Name,
				Type: typ{
					Kind:    KFunc,
					Name:    name + "." + m.Name,
					Args:    args,
					Returns: returns,
				},
			})
		}
		return methods
	})
}

func (g goreStructs) defineType(t *gore.GoType) *typ {
	if t == nil {
		// TODO: Why does this happen? Seems to only happen with elements of
		// pointers.
		// Happened with github.com/gohugoio/hugo/resources/page.Page_iface_slice
		// which also got label nil_pointer_slice.
		// The real type of the slice is:
		// type Pages []Page
		return &typ{Kind: KVoidptr, Name: "nil_pointer" + randomSuffix()}
	}

	var res *typ
	switch t.Kind {
	case reflect.Bool:
		res = typBool
	case reflect.Int:
		res = typLong
	case reflect.Int8:
		res = typSbyte
	case reflect.Int16:
		res = typShort
	case reflect.Int32:
		res = typInt
	case reflect.Int64:
		res = typLonglong
	case reflect.Uint:
		res = typUlong
	case reflect.Uint8:
		res = typByte
	case reflect.Uint16:
		res = typUshort
	case reflect.Uint32:
		res = typUint
	case reflect.Uint64:
		res = typUlonglong
	case reflect.Uintptr:
		res = typUlong
	case reflect.Float32:
		res = typFloat
	case reflect.Float64:
		res = typDouble
	case reflect.Complex64:
		return g.s.makeComplex64()
	case reflect.Complex128:
		return g.s.makeComplex128()
	case reflect.Pointer:
		// TODO: pointer _type descriptors overlap with others? Therefore we
		// don't include them.
		return pointerTyp(g.defineType(t.Element))
	case reflect.Array:
		res = arrayTyp(g.defineType(t.Element), t.Length)
	case reflect.Map:
		res = g.s.makeMap(g.defineType(t.Key), g.defineType(t.Element))
	case reflect.Chan:
		res = g.s.makeChan(g.defineType(t.Element), t.ChanDir)
	case reflect.Interface:
		res = g.defineInterface(t)
	case reflect.Slice:
		res = g.s.makeSlice(g.defineType(t.Element))
	case reflect.String:
		res = g.s.makeString()
	case reflect.Struct:
		res = g.defineStruct(t)
	default:
		// TODO: get rid of this
		return unsupportedTyp()
	}

	if res != nil {
		g.d[t.Addr] = res
	} else {
		g.d[t.Addr] = &typ{Kind: KStruct, Name: "struct{}"}
	}
	return res
}

type goreStructs struct {
	s structures
	d map[uint64]*typ
}

// TODO: handle typedefs
func getStructs(types []*gore.GoType) goreStructs {
	g := goreStructs{s: make(structures), d: make(map[uint64]*typ)}
	for _, t := range types {
		g.defineType(t)
	}
	return g
}

func metadataAsJSON(f *gore.GoFile) ([]byte, error) {
	pclntab, err := f.PCLNTab()
	if err != nil {
		return nil, fmt.Errorf("f.PCLNTab() got err: %v", err)
	}

	types, err := f.GetTypes()
	if err != nil {
		return nil, fmt.Errorf("f.GetTypes() got err: %v", err)
	}

	g := getStructs(types)
	return metadata{
		Functions:   getFunctions(pclntab),
		Structures:  g.s,
		Descriptors: g.d,
	}.marshal()
}
