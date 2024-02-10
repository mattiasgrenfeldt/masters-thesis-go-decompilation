#!/bin/bash
buildExtension () {
    rm -rf dist/
    gradle
    rm -rf ~/.ghidra/.ghidra_$1/Extensions/eval_extension
    unzip dist/ghidra_$1_2023*_eval_extension.zip -d ~/.ghidra/.ghidra_$1/Extensions
}
buildExtension "10.2.3_PUBLIC"
buildExtension "10.3_PUBLIC"
