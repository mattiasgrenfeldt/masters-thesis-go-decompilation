package main

import (
	"fmt"
	"os"

	"github.com/goretk/gore"
)

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
./goretk_util extract-metadata <filename>
./goretk_util parse-lib <dir>
./goretk_util version <filename>`)
	os.Exit(1)
}

func extractMetadata() {
	fname := os.Args[2]
	f, err := gore.Open(fname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open %s: %v\n", fname, err)
		os.Exit(1)
	}
	defer f.Close()

	b, err := metadataAsJSON(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting metadata: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}

func version(path string) (string, error) {
	f, err := gore.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open %s: %v\n", path, err)
		os.Exit(1)
	}
	defer f.Close()

	v, err := f.GetCompilerVersion()
	if err != nil {
		return "", err
	}
	return v.Name, nil
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	switch os.Args[1] {
	case "extract-metadata":
		extractMetadata()
	case "parse-lib":
		b, err := parseLib(os.Args[2])
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(b)
	case "version":
		v, err := version(os.Args[2])
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		fmt.Println(v)
	default:
		usage()
	}
}
