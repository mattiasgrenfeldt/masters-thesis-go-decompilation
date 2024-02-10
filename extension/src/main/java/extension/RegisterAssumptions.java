package extension;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.ProgramContext;

import java.math.BigInteger;

public class RegisterAssumptions {
    public static void assume(ProgramContext pc, Address start, Address end) throws ContextChangeException {
        pc.setValue(pc.getRegister("XMM15"), start, end, BigInteger.ZERO);
    }
}
