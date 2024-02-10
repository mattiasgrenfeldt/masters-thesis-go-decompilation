package extension;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import java.util.Arrays;
import java.util.HashSet;

public class Util {
    public static String[] RESERVED_IDENTIFIERS_VALUES = new String[]{
            "auto",
            "break",
            "case",
            "char",
            "code",
            "const",
            "continue",
            "default",
            "do",
            "double",
            "else",
            "enum",
            "extern",
            "float",
            "for",
            "goto",
            "if",
            "inline",
            "int",
            "long",
            "register",
            "restrict",
            "return",
            "short",
            "signed",
            "sizeof",
            "static",
            "struct",
            "switch",
            "typedef",
            "union",
            "unix",
            "unsigned",
            "void",
            "volatile",
            "while",
    };
    public static HashSet<String> RESERVED_IDENTIFIERS = new HashSet<>(Arrays.asList(RESERVED_IDENTIFIERS_VALUES));

    public static String safeIdentifier(String ident) {
        if (RESERVED_IDENTIFIERS.contains(ident)) {
            return "_" + ident;
        }
        return ident;
    }

    public static Function funcByName(Program p, String funcName) throws Exception {
        // TODO: Is there an easier, built-in way to do all of this?
        FunctionManager fm = p.getFunctionManager();
        Function f = null;
        for (Symbol s : p.getSymbolTable().getSymbols(funcName)) {
            Function res = fm.getFunctionAt(s.getAddress());
            if (res == null) {
                continue;
            }
            if (f != null) {
                throw new Exception(String.format("Multiple functions called %s", funcName));
            }
            f = res;
        }
        return f;
    }
}
