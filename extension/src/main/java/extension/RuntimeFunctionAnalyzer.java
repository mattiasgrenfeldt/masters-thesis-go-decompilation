package extension;

import com.fasterxml.jackson.databind.ObjectMapper;
import extension.metadata.Type;
import extension.runtimefunctions.*;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.XReferenceUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class RuntimeFunctionAnalyzer extends AbstractAnalyzer {

    private final ObjectMapper mapper = new ObjectMapper();

    private StructCreator sc;
    private Program p;
    private FunctionManager fm;

    // Maps entrypoint of caller to the callsites within it
    private HashMap<Address, ArrayList<Callsite>> callsites;

    public RuntimeFunctionAnalyzer() {
        super("Go polymorphic runtime function analyzer", "Applies types to arguments and return values for some runtime functions.", AnalyzerType.FUNCTION_ANALYZER);
        setSupportsOneTimeAnalysis();
    }

    private List<Address> getCalls(Function f) throws Exception {
        // TODO: use p.getReferenceManager() instead
        return XReferenceUtils.getAllXrefs(new FunctionSignatureFieldLocation(p, f.getEntryPoint())).stream()
                .map(Reference::getFromAddress).toList();
    }

    private List<RuntimeFunction> getRuntimeFunctions() throws InvalidInputException {
        return List.of(
                new RuntimeNewobject(p),
                new RuntimeGrowslice(p),
                new RuntimeConvT(p),
                new RuntimeMapassignFastStr(p),
                new RuntimeMapAccess1FastStr(p),
                new RuntimeConvI2I(p),
                new RuntimeMapiterinit(p),
                new RuntimeMakeslice(p));
    }

    private record Callsite(Address callsite, Function callee, RuntimeFunction rf) {
    }

    @Override
    public boolean added(Program argP, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        p = argP;
        fm = p.getFunctionManager();
        DataTypeManager dtm = p.getDataTypeManager();
        sc = new StructCreator(dtm, null);
        RequiredDataTypes.createDataTypes(dtm);

        List<RuntimeFunction> functions;
        try {
            functions = getRuntimeFunctions();
        } catch (InvalidInputException e) {
            throw new RuntimeException(e);
        }

        Listing lst = p.getListing();
        HashSet<Function> callers = new HashSet<>();
        callsites = new HashMap<>();
        monitor.setMessage("Getting xrefs");
        monitor.setMaximum(functions.size());
        monitor.setProgress(0);
        for (RuntimeFunction rf : functions) {
            Function f;
            try {
                f = Util.funcByName(p, rf.getName());
                if (f == null) {
                    // Couldn't find any function with that name.
                    continue;
                }
                f.updateFunction(
                        CallingConvention.ABI_INTERNAL,
                        rf.getOriginalReturnParam(),
                        rf.getOriginalParameters(),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true,
                        SourceType.ANALYSIS);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            List<Address> xrefs;
            try {
                xrefs = getCalls(f);
            } catch (Exception e) {
                System.out.printf("Could not get xrefs for %s\n", rf.getName());
                throw new RuntimeException(e);
            }
            long numCalls = 0;
            for (Address call : xrefs) {
                Function caller = fm.getFunctionContaining(call);
                Instruction inst = lst.getInstructionAt(call);
                if (caller == null || inst == null || inst.getMnemonicString().equals("JMP")) {
                    // Call is not inside a defined function or is called with a JMP instruction.
                    continue;
                }
                numCalls++;
                callers.add(caller);
                ArrayList<Callsite> tmp = callsites.get(caller.getEntryPoint());
                if (tmp == null) {
                    tmp = new ArrayList<>();
                }
                tmp.add(new Callsite(call, f, rf));
                callsites.put(caller.getEntryPoint(), tmp);
            }

            System.out.printf("%s is called %d times\n", rf.getName(), numCalls);
            monitor.incrementProgress(1);
        }
        System.out.printf("Functions to symbolically propagate: %d\n", callers.size());

        monitor.initialize(callers.size());
        for (Function caller : callers) {
            try {
                annotateCaller(caller, monitor);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return true;
    }

    private void annotateCaller(Function caller, TaskMonitor monitor) throws Exception {
        // TODO: Maybe you can just look in the pcode ast since the constant should just be lying there.
        SymbolicPropogator sym = new SymbolicPropogator(p);
        sym.flowConstants(caller.getEntryPoint(), caller.getBody(), new ConstantPropagationContextEvaluator(), true, monitor);

        for (Callsite cs : callsites.get(caller.getEntryPoint())) {
            Parameter param = cs.callee.getParameter(cs.rf.getConstArgOrdinal());
            if (!param.isRegisterVariable()) {
                throw new Exception("Parameter is not a single register");
            }
            SymbolicPropogator.Value v = sym.getRegisterValue(cs.callsite, param.getRegister());
            if (v == null || v.isRegisterRelativeValue()) {
                continue;
            }
            long argVal = v.getValue();
            DataType t = getDataType(argVal);
            if (t == null) {
                // No datatype found
                continue;
            }
            SignatureTypes sig = cs.rf.getNewDatatypes(t);
            annotateCall(caller, cs.callee, sig, cs.callsite);
        }
    }

    private void annotateCall(Function caller, Function callee, SignatureTypes sig, Address call) throws Exception {
        FunctionDefinitionDataType fd = new FunctionDefinitionDataType(callee, true);
        if (sig.ret != null) {
            fd.setReturnType(sig.ret);
        }

        if (sig.args != null) {
            ParameterDefinition[] params = fd.getArguments();
            for (int i = 0; i < sig.args.length; i++) {
                if (sig.args[i] == null) {
                    continue;
                }
                params[i].setDataType(sig.args[i]);
            }
            fd.setArguments(params);
        }
        HighFunctionDBUtil.writeOverride(caller, call, fd);

        // TODO: Types of HighVariables for arguments is not changed.
        // TODO: implement for arguments !!! Return variables seem to take the type automatically.
    }

    private DataType getDataType(long typeAddr) throws Exception {
        StringPropertyMap propMap = p.getUsrPropertyManager().getStringPropertyMap(Type.TYPE_MAP);
        String jsonType = propMap.getString(p.getImageBase().getNewAddress(typeAddr));
        if (jsonType == null) {
            return null;
        }
        return sc.getDataType(mapper.readValue(jsonType, Type.class));
    }
}
