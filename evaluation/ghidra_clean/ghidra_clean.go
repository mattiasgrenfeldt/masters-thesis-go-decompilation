package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
)

var (
	arrayReturn     = regexp.MustCompile(`\n[a-zA-Z0-9_]+([ \t]*\*)*([ \t]*\(\*+\))?([ \t]+\[[0-9]+\])+`)
	labelEndOfBlock = regexp.MustCompile(`\n[a-zA-Z0-9_]+:\n[ \t]*}`)
	globalVariables = regexp.MustCompile(`((PTR)?_)?DAT_[0-9a-f]+|stack0x[0-9a-f]+|switch[A-Z]_[0-9a-f]+__switchdata[A-Z]_[0-9a-f]+`)
	emptyCase       = regexp.MustCompile(`\n[ \t]*case[ \t]+((0x)?[a-f0-9]+|'.'):\n[ \t]*}\n`)
	switchCases     = regexp.MustCompile(`(switch[A-Z]_[0-9a-f]+)::(switchdata[A-Z]_[0-9a-f]+)`)
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: clean <input> <output>")
		os.Exit(1)
	}
	text, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	// Do some replacements
	text = bytes.ReplaceAll(text, []byte("µ"), []byte("mu"))
	text = bytes.ReplaceAll(text, []byte("go-duff-zero"), []byte(""))
	text = bytes.ReplaceAll(text, []byte("go-duff-copy"), []byte(""))
	text = bytes.ReplaceAll(text, []byte("__cdecl"), []byte(""))
	text = bytes.ReplaceAll(text, []byte(".conflict"), []byte("_conflict"))
	text = bytes.ReplaceAll(text, []byte("\nfloat4\n"), []byte("\ntypedef float float4;\n"))
	text = bytes.ReplaceAll(text, []byte("\nfloat8\n"), []byte("\ntypedef float float8;\n"))
	// Functions can't return arrays in C, but Ghidra thinks so.
	text = arrayReturn.ReplaceAllLiteral(text, []byte("\nundefined_array "))
	text = labelEndOfBlock.ReplaceAllLiteral(text, []byte("\n}"))
	text = switchCases.ReplaceAll(text, []byte("$1__$2"))
	// Pycparser doesn't like empty case statements.
	text = emptyCase.ReplaceAll(text, []byte("\n    case $1:\n    break;\n    }\n"))

	fout, err := os.Create(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer fout.Close()
	fout.WriteString(`// Used as replacement when functions return arrays.
typedef unsigned long long undefined_array;
typedef unsigned long long pointer32;
typedef unsigned long long pointer64;
typedef unsigned long long pointer;
typedef unsigned long long undefined7;
typedef unsigned long long undefined6;
typedef unsigned long long undefined5;
typedef unsigned int undefined3;
typedef unsigned long long uint7;
typedef unsigned long long uint6;
typedef unsigned long long uint5;
typedef unsigned int uint3;
typedef unsigned int uint;
typedef long long int7;
typedef long long int6;
typedef long long int5;
typedef int int3;
typedef char bool;
typedef signed char sbyte;
typedef unsigned short ushort;
typedef signed char    sbyte;
typedef signed int    sdword;
typedef signed int    sqword;
typedef signed short   sword;
typedef float float1;
typedef float float2;
typedef float float3;
typedef double float5;
typedef double float6;
typedef double float7;
typedef double float9;
typedef double float10;
`)
	for _, ident := range globalVariables.FindAll(text, -1) {
		fout.WriteString(fmt.Sprintf("unsigned long long %s;\n", ident))
	}
	fout.Write(text)
}
