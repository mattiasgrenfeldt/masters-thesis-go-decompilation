package extension;

import extension.metadata.Field;
import extension.metadata.Function;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class CallingConvention {

    public static final String ABI_INTERNAL = "go-abiinternal";

    private Program p;
    private StructCreator sc;

    // Maps size to register list
    private HashMap<Integer, Register[]> registers = new HashMap<>();

    public CallingConvention(Program p, StructCreator sc) {
        // TODO: handle floating point arguments
        this.p = p;
        this.sc = sc;
        // Will need *runtime.g
        RequiredDataTypes.createDataTypes(p.getDataTypeManager());
        registers.put(1, new Register[]{
                p.getRegister("R14B"),
                p.getRegister("AL"),
                p.getRegister("BL"),
                p.getRegister("CL"),
                p.getRegister("DIL"),
                p.getRegister("SIL"),
                p.getRegister("R8B"),
                p.getRegister("R9B"),
                p.getRegister("R10B"),
                p.getRegister("R11B"),
        });
        registers.put(2, new Register[]{
                p.getRegister("R14W"),
                p.getRegister("AX"),
                p.getRegister("BX"),
                p.getRegister("CX"),
                p.getRegister("DI"),
                p.getRegister("SI"),
                p.getRegister("R8W"),
                p.getRegister("R9W"),
                p.getRegister("R10W"),
                p.getRegister("R11W"),
        });
        registers.put(4, new Register[]{
                p.getRegister("R14D"),
                p.getRegister("EAX"),
                p.getRegister("EBX"),
                p.getRegister("ECX"),
                p.getRegister("EDI"),
                p.getRegister("ESI"),
                p.getRegister("R8D"),
                p.getRegister("R9D"),
                p.getRegister("R10D"),
                p.getRegister("R11D"),
        });
        registers.put(8, new Register[]{
                p.getRegister("R14"),
                p.getRegister("RAX"),
                p.getRegister("RBX"),
                p.getRegister("RCX"),
                p.getRegister("RDI"),
                p.getRegister("RSI"),
                p.getRegister("R8"),
                p.getRegister("R9"),
                p.getRegister("R10"),
                p.getRegister("R11"),
        });
    }

    // Next integer register to be used.
    private int ri = 0;

    // Don't call this concurrently!
    public void updateSignature(Function libF, ghidra.program.model.listing.Function f) throws Exception {
        // 1. Run Go's "Function call argument and result passing" algorithm https://go.dev/s/regabi
        // 2. Assert if custom storage was needed
        // 3. If it was needed, assign parameters and results with the calculated storage.
        // 4. If it was not needed, discard the calculated storage and simply assign the parameters and results
        //    normally.
        // TODO: step 4

        // --- Parameters ---
        ArrayList<DataType> params = new ArrayList<>();
        // Add *runtime.g pointer. Called _g to avoid collisions.
        params.add(RequiredDataTypes.runtimeGPtr);
        ArrayList<String> fieldNames = new ArrayList<>();
        fieldNames.add("_g");
        if (libF.args != null) {
            for (Field arg : libF.args) {
                fieldNames.add(Util.safeIdentifier(arg.name));
                DataType d = sc.getDataType(arg.type);
                params.add(d);
            }
        }

        // Assign arguments to storage
        ri = 0;
        ArrayList<ParameterImpl> params2 = new ArrayList<>();
        for (int i = 0; i < params.size(); i++) {
            // Register-assign param
            int savedRi = ri;
            DataType p = params.get(i);
            List<Register> regs = registerAssign(p);
            if (regs == null) {
                ri = savedRi;
                // Stack assignment needed, or we've encountered an array with length 0. This is left for the future.
                // TODO: What do here?
                continue;
            }
            Collections.reverse(regs);

            String name = fieldNames.get(i);
            if (name.equals("_")) {
                name = String.format("_%d", i);
            }
            params2.add(new ParameterImpl(
                    name,
                    p,
                    new VariableStorage(this.p, regs.toArray(new Register[]{})),
                    this.p,
                    SourceType.ANALYSIS));
        }

        // --- Results ---
        StructCreator.RetStruct ret = sc.createReturnStruct(libF.name, libF.returns);
        List<DataType> results;
        if (ret.hasMultipleResults()) {
            results = Arrays.stream(((Structure) ret.ret()).getComponents()).map(DataTypeComponent::getDataType).toList();
        } else {
            results = List.of(ret.ret());
        }

        // Assign return values to storage
        ri = 1; // Start at 1, skip R14
        List<Register> resultRegs = new ArrayList<>();
        for (DataType result : results) {
            // Register-assign result
            int savedRi = ri;
            List<Register> regs = registerAssign(result);
            if (regs == null) {
                // Stack assignment needed, or we've encountered an array with length 0
                // Ghidra doesn't mix stack and register storage well for variables, so we give up and make the return
                // void.
                resultRegs.clear();
                break;
            }
            resultRegs.addAll(regs);
        }
        Collections.reverse(resultRegs);
        VariableStorage retStore;
        DataType retType;
        if (resultRegs.size() == 0) {
            retStore = VariableStorage.VOID_STORAGE;
            retType = new VoidDataType(p.getDataTypeManager());
        } else {
            retStore = new VariableStorage(p, resultRegs.toArray(new Register[]{}));
            retType = ret.ret();
        }

        f.updateFunction(ABI_INTERNAL,
                new ReturnParameterImpl(retType, retStore, p),
                params2,
                ghidra.program.model.listing.Function.FunctionUpdateType.CUSTOM_STORAGE,
                true,
                SourceType.ANALYSIS);
    }

    private List<Register> registerAssign(DataType t) {
        // TODO: put floating point values into float registers.
        if (ri >= registers.get(8).length) {
            return null;
        }
        if (t instanceof AbstractIntegerDataType
                || t instanceof Pointer
                || (t instanceof Array && ((Array) t).getNumElements() == 1)
                || t instanceof AbstractFloatDataType) {
            // Choose register based on size
            Register r = registers.get(t.getLength())[ri];
            ri++;
            return List.of(r);
        }
        if (t instanceof Structure s) {
            // Register-assign fields
            ArrayList<Register> res = new ArrayList<>();
            for (DataTypeComponent comp : s.getComponents()) {
                List<Register> r = registerAssign(comp.getDataType());
                if (r == null) {
                    return null;
                }
                res.addAll(r);
            }
            return res;
        }
        return null;
    }
}
