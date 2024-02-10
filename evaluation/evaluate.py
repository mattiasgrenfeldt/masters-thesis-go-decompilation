#!/usr/bin/env pypy3
from pycparser import c_parser, c_ast
import os, sys, re, subprocess, json

GLUE_FUNCTION = re.compile("^(CONCAT|SUB|ZEXT|SEXT|SBORROW|CARRY|SCARRY)[0-9]+$")
BUILTIN_TYPES = set([
    "__int128",
    "__int16",
    "__int32",
    "__int64",
    "__int8",
    "_BOOL1",
    "_BOOL2",
    "_BOOL4",
    "_BOOL8",
    "_BYTE",
    "_DWORD",
    "_OWORD",
    "_QWORD",
    "_TBYTE",
    "_UNKNOWN",
    "_WORD",
    "bool",
    "byte",
    "char",
    "complex16",
    "complex32",
    "complex8",
    "double",
    "dword",
    "float",
    "float10",
    "float12",
    "float14",
    "float16",
    "float2",
    "float32",
    "float4",
    "float6",
    "float64",
    "float8",
    "int",
    "int1",
    "int16",
    "int2",
    "int3",
    "int32",
    "int4",
    "int5",
    "int6",
    "int64",
    "int7",
    "int8",
    "ll",
    "long",
    "long|double",
    "long|long",
    "longlong",
    "pointer",
    "pointer16",
    "pointer24",
    "pointer32",
    "pointer40",
    "pointer48",
    "pointer56",
    "pointer64",
    "pointer8",
    "qword",
    "sbyte",
    "schar",
    "sdword",
    "short",
    "signed|__int128",
    "signed|char",
    "signed|int",
    "signed|long",
    "signed|long|long",
    "signed|short",
    "sint16",
    "sint32",
    "sint64",
    "sint8",
    "size_t",
    "sqword",
    "string",
    "sword",
    "uchar",
    "uint",
    "uint1",
    "uint16",
    "uint2",
    "uint3",
    "uint32",
    "uint4",
    "uint5",
    "uint6",
    "uint64",
    "uint7",
    "uint8",
    "uintptr",
    "ull",
    "ulong",
    "ulonglong",
    "undefined_array",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined3",
    "undefined4",
    "undefined5",
    "undefined6",
    "undefined7",
    "undefined8",
    "unsigned|__int128",
    "unsigned|char",
    "unsigned|int",
    "unsigned|long",
    "unsigned|long|long",
    "unsigned|short",
    "ushort",
    "void",
    "wchar_t",
    "wchar16",
    "wchar32",
    "word",
])

class Counter(c_ast.NodeVisitor):
    def __init__(self):
        self.lines = 0
        self.nodes = 0
        self.casts = 0
        self.variables = 0
        self.typedVariables = 0
        self.glueFunc = 0

        self.declDepth = 0
        self.minLine = 10000000000000000000000000000000000000000
        self.maxLine = 0

    def add(self, other):
        self.lines += other.lines
        self.nodes += other.nodes
        self.casts += other.casts
        self.variables += other.variables
        self.typedVariables += other.typedVariables
        self.glueFunc += other.glueFunc

    def to_dict(self):
        return {
            "lines": self.lines,
            "nodes": self.nodes,
            "casts": self.casts,
            "variables": self.variables,
            "typedVariables": self.typedVariables,
            "glueFunc": self.glueFunc,
        }

    def recordTypes(self, t):
        name = '|'.join(t)
        if self.declDepth > 0 and name not in BUILTIN_TYPES:
            self.typedVariables += 1

    def visit_Enum(self, node):
        self.recordTypes([node.name])
        self.generic_visit(node)

    def visit_Struct(self, node):
        # Check for anonymous struct declarations
        if node.name is not None:
            self.recordTypes([node.name])
        self.generic_visit(node)

    def visit_IdentifierType(self, node):
        self.recordTypes(node.names)
        self.generic_visit(node)

    def visit_Cast(self, node):
        self.casts += 1
        self.generic_visit(node)

    def visit_Decl(self, node):
        self.variables += 1
        self.declDepth += 1
        self.generic_visit(node)
        self.declDepth -= 1

    def visit_FuncCall(self, node):
        if node.name.__class__.__name__ == "ID" and GLUE_FUNCTION.match(node.name.name) != None:
            self.glueFunc += 1
        self.generic_visit(node)

    def generic_visit(self, node):
        self.nodes += 1
        if node.coord is not None and not (node.coord.line == 0 and node.coord.column == 1):
            self.minLine = min(self.minLine, node.coord.line)
            self.maxLine = max(self.maxLine, node.coord.line)

        for c in node:
            self.visit(c)

def all_func_defs(ast):
    return [x for _, x in ast.children() if x.__class__.__name__ == "FuncDef"]

def count(ast, entrypoints):
    results = {}
    func_defs = all_func_defs(ast)
    n = len(func_defs)
    for i, node in enumerate(func_defs):
        c = Counter()
        c.visit(node)
        c.lines = c.maxLine - c.minLine
        name = node.decl.name
        if name in results:
            raise Exception("Duplicate functions: " + name)
        d = c.to_dict()
        d["name"] = name
        results[entrypoints[name]] = d
    return results

def parse(cleaned_path):
    #p = subprocess.run(["cpp", "-D", "_WIN32", "-I", "/usr/x86_64-w64-mingw32/include", cleaned_path], text=True, check=True, capture_output=True)
    p = subprocess.run(["cpp", cleaned_path], text=True, check=True, capture_output=True)
    parser = c_parser.CParser()
    try:
        ast = parser.parse(p.stdout)
    except Exception as e:
        with open(cleaned_path.rstrip(".c") + ".processed.c", "w") as f:
            f.write(p.stdout)
        raise e
    return ast

GHIDRA_ENTRYPOINTS = r"/\* Function entrypoint:[ \t\n]+function:'([a-zA-Z0-9_]+)'[ \t\n]+entrypoint:'([0-9a-f]+)'[ \t\n]+\*/"
def ghidra_entrypoints(cleaned_c):
    return {name:int(addr, 16) for name, addr in re.findall(GHIDRA_ENTRYPOINTS, cleaned_c)}

def ida_entrypoints(cleaned_c, ast):
    func_defs = all_func_defs(ast)
    # Might be unnecessary to sort here.
    func_defs.sort(key=lambda f: f.coord.line)
    entrypoints = [
        (x.start(0), int(x.group(1), 16))
        for x in re.finditer(r"//----- \(([0-9A-F]+)\) -{52}\n// ", cleaned_c)
    ]
    n_entrypoints = len(entrypoints)
    n_func_defs = len(func_defs)

    result = {}
    pos = 0
    line = 1
    def_idx = 0
    entry_idx = -1
    while def_idx < n_func_defs:
        if line == func_defs[def_idx].coord.line:
            fname = func_defs[def_idx].decl.name
            entry = entrypoints[entry_idx][1]
            result[fname] = entry
            def_idx += 1
        pos = cleaned_c.find("\n", start=pos) + 1
        if pos == 0:
            break
        line += 1
        if entry_idx < n_entrypoints - 1 and entrypoints[entry_idx + 1][0] <= pos:
            entry_idx += 1
    return result

if len(sys.argv) < 4 or sys.argv[1] not in ["ghidra", "ida"]:
    print("usage: ./evaluate.py [ghidra|ida] <phase-name> <.c-file>")
    sys.exit(1)
cmd = sys.argv[1]
phase_name = sys.argv[2]
path = sys.argv[3]

print("[*] Cleaning...")
cleaned_path = path.rstrip(".c") + ".cleaned.c"
if cmd == "ghidra":
    subprocess.run(["./ghidra_clean/ghidra_clean", path, cleaned_path])
elif cmd == "ida":
    subprocess.run(["./ida_clean/ida_clean", path, cleaned_path])
else:
    assert False

print("[*] Parsing...")
ast = parse(cleaned_path)

print("[*] Counting...")
with open(cleaned_path) as f:
    cleaned_c = f.read()
if cmd == "ghidra":
    entrypoints = ghidra_entrypoints(cleaned_c)
elif cmd == "ida":
    entrypoints = ida_entrypoints(cleaned_c, ast)
else:
    assert False
results = count(ast, entrypoints)
json.dump(results, open(f"results/{cmd}.{phase_name}.json", "w"))
