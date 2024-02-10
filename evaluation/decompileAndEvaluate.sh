#!/bin/bash

# NOTE: You need to change these!
GHIDRA_10_2_3_DIR="/path/to/ghidra_10.2.3_PUBLIC"
GHIDRA_10_3_DIR="/path/to/ghidra_10.3_PUBLIC"

# analyzeHeadless is documented in /path/to/ghidra/support/analyzeHeadlessREADME.html
ANALYZE_HEADLESS_10_2_3="$GHIDRA_10_2_3_DIR/support/analyzeHeadless \
  project_10_2_3 evalProj \
  -max-cpu 8 \
  -log application.log \
  -scriptLog script.log \
"
ANALYZE_HEADLESS_10_3="$GHIDRA_10_3_DIR/support/analyzeHeadless \
  project_10_3 evalProj \
  -max-cpu 8 \
  -log application.log \
  -scriptLog script.log \
"

decompileAndMeasure() {
  figlet "$2"
  # Ghidra fires up some automatic analysis after our postScripts have finished.
  # Therefore the DecompileAndSave script needs to run separately.
  rm "$decomp_dir/code.c"
  touch "$decomp_dir/code.c"
  full_path=$(realpath "$decomp_dir/code.c")
  if ! $1 -process  \
    -preScript DecompileAndSave.java "$full_path" \
    -readOnly \
    -noanalysis; then
    exit 1
  fi
  git -C "$decomp_dir" add code.c
  git -C "$decomp_dir" commit -m "$2"
  if ! ./evaluate.py ghidra "${name//./_}.${plugin//./_}.$2" "$full_path"; then
    exit 1
  fi
}

runScript() {
  if ! $1 -process \
    -noanalysis \
    -preScript $2; then
    exit 1
  fi
}

ourExtension() {
  plugin="our_extension"
  figlet "$plugin"
  git -C "$decomp_dir" checkout -b "$plugin"

  echo "[*] Importing binary into project..."
  if ! $ANALYZE_HEADLESS_10_2_3 -import $absolute_path \
    -overwrite \
    -processor "x86:LE:64:golang-1.19.5"; then
    exit 1
  fi
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "00.initial"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoFunctionRenamer.java true"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "01.GoFunctionRenamer"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoNonReturningFunctions.java"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "02.GoNonReturningFunctions"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoMoreStackNOP.java"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "03.GoMoreStackNOP"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoDuffsDevice.java"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "04.GoDuffsDevice"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoDataTypeRecovery.java"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "05.GoDataTypeRecovery"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoLibrarySignatureImporter.java"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "06.GoLibrarySignatureImporter"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoPolymorphicAnalyzer.java"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "07.GoPolymorphicAnalyzer"
}

mooncat() {
  plugin="mooncat"
  figlet "$plugin"
  git -C "$decomp_dir" checkout -b "$plugin"

  echo "[*] Importing binary into project..."
  if ! $ANALYZE_HEADLESS_10_2_3 -import $absolute_path \
    -overwrite; then
    exit 1
  fi
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "00.initial"

  runScript "$ANALYZE_HEADLESS_10_2_3" "Mooncat.java"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "01.Mooncat"
}

monoidic() {
  plugin="monoidic"
  figlet "$plugin"
  git -C "$decomp_dir" checkout -b "$plugin"

  echo "[*] Importing binary into project..."
  if ! $ANALYZE_HEADLESS_10_2_3 -import $absolute_path \
    -overwrite; then
    exit 1
  fi
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "00.initial"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoFunctionRenamer.java false"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "01.GoFunctionRenamer"

  # TODO: auto-detect version
  MONOIDIC_PARSE_JSON="/path/to/go-api-parser/results/go1.19.5.json"
  runScript "$ANALYZE_HEADLESS_10_2_3" "params.py $MONOIDIC_PARSE_JSON"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "02.Monoidic"
}

cyberkaida() {
  plugin="cyberkaida"
  figlet "$plugin"
  git -C "$decomp_dir" checkout -b "$plugin"

  echo "[*] Importing binary into project..."
  if ! $ANALYZE_HEADLESS_10_2_3 -import $absolute_path \
    -overwrite \
    -processor "x86:LE:64:golang" \
    -cspec "golang"; then
    exit 1
  fi
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "00.initial"

  # TODO: include this step for comparability?
  runScript "$ANALYZE_HEADLESS_10_2_3" "GoFunctionRenamer.java false"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "01.GoFunctionRenamer"
}

vanilla_10_2_3() {
  plugin="vanilla_10_2_3"
  figlet "$plugin"
  git -C "$decomp_dir" checkout -b "$plugin"

  echo "[*] Importing binary into project..."
  if ! $ANALYZE_HEADLESS_10_2_3 -import $absolute_path \
    -overwrite; then
    exit 1
  fi
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "00.initial"

  runScript "$ANALYZE_HEADLESS_10_2_3" "GoFunctionRenamer.java false"
  decompileAndMeasure "$ANALYZE_HEADLESS_10_2_3" "01.GoFunctionRenamer"
}

vanilla_10_3() {
  plugin="vanilla_10_3"
  figlet "$plugin"
  git -C "$decomp_dir" checkout -b "$plugin"

  echo "[*] Importing binary into project..."
  if ! $ANALYZE_HEADLESS_10_3 -import $absolute_path \
    -overwrite \
    -processor "x86:LE:64:default" \
    -cspec "golang"; then
    exit 1
  fi
  decompileAndMeasure "$ANALYZE_HEADLESS_10_3" "00.initial"
}

if [ $# -eq 0 ]
then
  echo "usage: ./runAll.sh <path-to-binary>"
  exit 1
fi

absolute_path=$(realpath $1)
name=$(basename $1)
figlet "$name"
echo $absolute_path

echo "[*] Setup git repo and project folder"
decomp_dir="decompile-$name"
rm -rf "$decomp_dir"
mkdir "$decomp_dir"
git -C "$decomp_dir" init
rm -rf project_10_2_3
mkdir project_10_2_3
rm -rf project_10_3
mkdir project_10_3

vanilla_10_3
ourExtension
monoidic
mooncat
cyberkaida
vanilla_10_2_3
