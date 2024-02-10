package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/goretk/gore"
)

type libStructs struct {
	s     structures
	f     []function
	types map[string]ast.Expr
}

func parseLib(dir string) ([]byte, error) {
	// TODO: look in go.mod to get prefix name for entire package hierarchy
	packages := make(map[string]*ast.Package)
	err := fs.WalkDir(os.DirFS(dir), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		pkgs, err := parser.ParseDir(token.NewFileSet(), filepath.Join(dir, path), nil, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parser.ParseDir: %v\n", err)
			return nil
		}

		expectedPkg := filepath.Base(path)
		for name, pkg := range pkgs {
			if name == expectedPkg {
				packages[path] = pkg
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	tSpecs := make(map[string]ast.Expr)
	for path, pkg := range packages {
		for fname, f := range pkg.Files {
			if strings.HasSuffix(fname, "_test.go") {
				continue
			}
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, s := range gd.Specs {
					ts := s.(*ast.TypeSpec)
					if ts.TypeParams != nil {
						continue
					}
					tSpecs[path+"."+ts.Name.Name] = ts.Type
				}
			}
		}
	}

	l := libStructs{s: make(structures), types: tSpecs}
	for path, pkg := range packages {
		for fname, f := range pkg.Files {
			if strings.HasSuffix(fname, "_test.go") {
				continue
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok {
					continue
				}
				l.handleFuncDecl(path, fd)
			}
		}
	}

	return metadata{Functions: l.f, Structures: l.s}.marshal()
}

func pointerNonPointerVersion(t *typ) []*typ {
	if t.Kind == KPointer {
		t = t.Elem
	}
	return []*typ{pointerTyp(t), t}
}

func desuffix(name string) string {
	if strings.HasSuffix(name, "_ptr") {
		return fmt.Sprintf("(*%s)", strings.TrimSuffix(name, "_ptr"))
	}
	return name
}

func (l *libStructs) handleMethodDecl(pkgPath string, fd *ast.FuncDecl) {
	recv, _ := l.fieldListToTyps(pkgPath, "", fd.Recv)
	// recv should only be one in length here
	if len(recv) != 1 {
		fmt.Fprintf(os.Stderr, "funky: %s %v\n", pkgPath+"."+fd.Name.Name, len(recv))
		// TODO: handle top level type aliases
		return
	}
	// Even if the methods only has a pointer receiver the compiler might
	// generate a pointer receiver version as well. Therefore we add both.
	for _, t := range pointerNonPointerVersion(&recv[0].Type) {
		name := fmt.Sprintf("%s.%s.%s", pkgPath,
			desuffix(unqualifiedName(t.Name)), fd.Name.Name)
		args, returns := l.funcArgsRets(pkgPath, name, *fd.Type)
		if args == nil {
			continue
		}
		args = append([]field{{Name: recv[0].Name, Type: *t}}, args...)
		l.f = append(l.f, function{Name: name, Args: args, Returns: returns})
	}
}

func (l *libStructs) handleFuncDecl(pkgPath string, fd *ast.FuncDecl) {
	if fd.Recv != nil {
		l.handleMethodDecl(pkgPath, fd)
		return
	}
	name := pkgPath + "." + fd.Name.Name
	args, returns := l.funcArgsRets(pkgPath, name, *fd.Type)
	if args == nil {
		return
	}
	l.f = append(l.f, function{Name: name, Args: args, Returns: returns})
}

func (l libStructs) funcArgsRets(pkgPath string, parentName string, f ast.FuncType) ([]field, []typ) {
	if f.TypeParams != nil {
		return nil, nil
	}

	var returns []typ
	if f.Results != nil {
		fl, _ := l.fieldListToTyps(pkgPath, parentName, f.Results)
		for _, r := range fl {
			returns = append(returns, r.Type)
		}
	}

	args, stubFunction := l.fieldListToTyps(pkgPath, parentName, f.Params)
	if stubFunction {
		return nil, nil
	}
	return args, returns
}

func unqualifiedName(name string) string {
	parts := strings.Split(name, "/")
	last := parts[len(parts)-1]
	parts2 := strings.SplitN(last, ".", 2)
	return parts2[len(parts2)-1]
}

func (l libStructs) fieldToFields(pkgPath string, parentName string, f ast.Field) ([]field, bool) {
	if f.Names == nil || len(f.Names) == 0 {
		// Anonymous field, single return value or argument to stubbed
		// function
		ft := l.exprToTyp(pkgPath, f.Type, "") // interface methods should never be anonymous
		if ft == nil {
			return []field{}, false
		}
		return []field{{Name: unqualifiedName(ft.Name), Type: *ft}}, true
	}
	var fields []field
	for _, name := range f.Names {
		// For interfaces, parentName will be the fully qualified name of the
		// interface, therefore parentName+"."+name.Name will be the name of the
		// method in the interface.
		//
		// If we are defining struct fields and f.Type is a ast.StructType, then
		// this struct field has an anonymous struct as type.
		ft := l.exprToTyp(pkgPath, f.Type, parentName+"."+name.Name)
		if ft == nil { // Field is an empty struct
			continue
		}
		fields = append(fields, field{Name: name.Name, Type: *ft})
	}
	return fields, false
}

func (l libStructs) fieldListToTyps(pkgPath string, parentName string, fl *ast.FieldList) ([]field, bool) {
	if fl == nil || fl.List == nil {
		return []field{}, false
	}
	var fields []field
	hasAnonFields := false
	for _, f := range fl.List {
		f2, h2 := l.fieldToFields(pkgPath, parentName, *f)
		fields = append(fields, f2...)
		hasAnonFields = hasAnonFields || h2
	}
	return fields, hasAnonFields
}

func (l libStructs) interfaceToTyp(pkgPath string, name string, i ast.InterfaceType) *typ {
	// i.Methods.List is a "list of embedded interfaces, methods, or types"
	// We only want the methods for now.
	// TODO; make this work for embedded interfaces
	var methods []ast.Field
	if ml := i.Methods.List; ml != nil {
		for _, m := range ml {
			if _, ok := m.Type.(*ast.FuncType); ok {
				methods = append(methods, *m)
			}
		}
	}
	if len(methods) == 0 {
		return l.s.makeEmptyInterface()
	}
	return l.s.makeInterface(name, func() []field {
		var methods2 []field
		for _, m := range methods {
			args, returns := l.funcArgsRets(pkgPath, name, *m.Type.(*ast.FuncType))
			// Interfaces can't have anonymous functions, so there is at
			// least one name. They also can't have multiple methods with
			// only one type description.
			mName := m.Names[0].Name
			methods2 = append(methods2, field{
				Name: mName,
				Type: typ{
					Kind:    KFunc,
					Name:    name + "." + mName,
					Args:    args,
					Returns: returns,
				},
			})
		}
		return methods2
	})
}

func anonName() string {
	return "anon" + randomSuffix()
}

func (l libStructs) exprToTyp(pkgPath string, e ast.Expr, structIntName string) *typ {
	// TODO: split into multiple functions?
	// TODO: handle cross-package types. ast.Selector
	switch t := e.(type) {
	case *ast.Ident:
		switch t.Name {
		// TODO: built-in error
		case "string":
			return l.s.makeString()
		case "any":
			// "any" here should really be handled by typedefs, but whatever
			return l.s.makeEmptyInterface()
		case "bool":
			return typBool
		case "float32":
			return typFloat
		case "float64":
			return typDouble
		case "uint8", "byte":
			// "byte" here should really be handled by typedefs, but whatever
			return typByte
		case "int8":
			return typSbyte
		case "int16":
			return typShort
		case "uint16":
			return typUshort
		case "int32":
			return typInt
		case "uint32":
			return typUint
		case "int":
			return typLong
		case "uint":
			return typUlong
		case "uintptr":
			return typUlong
		case "int64":
			return typLonglong
		case "uint64":
			return typUlonglong
		case "complex64":
			return l.s.makeComplex64()
		case "complex128":
			return l.s.makeComplex128()
		case "error":
			return l.s.makeError()
		}
		name := pkgPath + "." + t.Name
		switch l.types[name].(type) {
		case *ast.StructType, *ast.InterfaceType:
			return l.exprToTyp(pkgPath, l.types[name], name)
		}
		return unsupportedTyp()
	case *ast.StructType:
		if structIntName == "" {
			structIntName = anonName()
		}
		if t.Fields == nil || t.Fields.List == nil || len(t.Fields.List) == 0 {
			// Empty struct
			return nil
		}
		// TODO: handle picking the right version of structs based on platform
		// for which the reverse engineered binary was compiled from. For
		// example picking between definitions of the same struct in files
		// x_windows.go and x_plan9.go
		return l.s.makeStruct(structIntName, func() []field {
			fields, _ := l.fieldListToTyps(pkgPath, structIntName, t.Fields)
			return fields
		})
	case *ast.StarExpr:
		return pointerTyp(l.exprToTyp(pkgPath, t.X, ""))
	case *ast.ArrayType:
		elem := l.exprToTyp(pkgPath, t.Elt, "")
		if t.Len == nil {
			return l.s.makeSlice(elem)
		} else {
			lit, ok := t.Len.(*ast.BasicLit)
			if !ok {
				return &typ{Kind: KVoidptr, Name: "unsupported_length_expr"}
			}
			length, err := strconv.ParseInt(lit.Value, 0, 64)
			if err != nil {
				panic(err)
			}
			return arrayTyp(elem, int(length))
		}
	case *ast.Ellipsis:
		return l.s.makeSlice(l.exprToTyp(pkgPath, t.Elt, ""))
	case *ast.MapType:
		return l.s.makeMap(l.exprToTyp(pkgPath, t.Key, ""),
			l.exprToTyp(pkgPath, t.Value, ""))
	case *ast.ChanType:
		d := gore.ChanBoth
		if t.Dir == ast.RECV {
			d = gore.ChanRecv
		} else if t.Dir == ast.SEND {
			d = gore.ChanSend
		}
		return l.s.makeChan(l.exprToTyp(pkgPath, t.Value, ""), d)
	case *ast.InterfaceType:
		return l.interfaceToTyp(pkgPath, structIntName, *t)
		//case *ast.FuncType:
		//	// TODO: can't handle FuncType's like this. Separate the handling when
		//	// making interfaces from functions as variables
		//	// TODO: Anything needs to be done for closures?
		//	args, returns := l.funcArgsRets(pkgPath, structIntName, *t)
		//	fmt.Printf("Making a function: %q\n", structIntName)
		//	return &typ{
		//		Kind:    KFunc,
		//		Name:    structIntName,
		//		Args:    args,
		//		Returns: returns,
		//	}
	}
	return &typ{Kind: KVoidptr, Name: "unsupported_expr"}
}
