#!/bin/bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk/
rm -rf dist/
gradle
rm -rf ~/.ghidra/.ghidra_10.2.3_PUBLIC/Extensions/golang-ghidra
unzip dist/ghidra_10.2.3_PUBLIC_2023*_golang-ghidra.zip -d ~/.ghidra/.ghidra_10.2.3_PUBLIC/Extensions

