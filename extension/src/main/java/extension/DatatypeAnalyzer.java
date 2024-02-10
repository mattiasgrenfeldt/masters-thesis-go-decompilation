package extension;

import extension.metadata.Metadata;
import extension.metadata.Type;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.Map;

public class DatatypeAnalyzer extends AbstractAnalyzer {

    public DatatypeAnalyzer() {
        super("Go datatype analyzer", "Recreates data types", AnalyzerType.FUNCTION_ANALYZER);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        Metadata m = Metadata.extract(program.getExecutablePath(), log);
        DataTypeManager dtm = program.getDataTypeManager();
        StructCreator sc = new StructCreator(dtm, m.structures);
        try {
            sc.defineStructs(monitor);
        } catch (Exception e) {
            log.appendMsg("Error while defining data types");
            throw new RuntimeException(e);
        }

        // Want to use the nicer version of runtime._type which has enums, so create it here and overwrite the
        // automatically generated one.
        RequiredDataTypes.createDataTypes(dtm);
        monitor.setMessage("Labelling each runtime type...");
        monitor.initialize(m.structures.size());
        // Label and apply each runtime._type
        Address base = program.getImageBase();
        SymbolTable st = program.getSymbolTable();
        Listing lst = program.getListing();
        StringPropertyMap propMap;
        try {
            propMap = program.getUsrPropertyManager().createStringPropertyMap(Type.TYPE_MAP);
        } catch (DuplicateNameException e) {
            throw new RuntimeException(e);
        }
        DataType typeDescriptor = dtm.getDataType(new CategoryPath("/Go/runtime"), "runtime._type");
        for (Map.Entry<Long, Type> entry : m.descriptors.entrySet()) {
            Type t = entry.getValue();
            // TODO: this is probably not a good way to handle nil and unsupported.
            if (entry.getKey() == 0 || t.name.startsWith("nil_pointer_") || t.name.contains("unsupported")) {
                continue;
            }
            Address addr = base.getNewAddress(entry.getKey());
            try {
                // Adding the extra L prefix so that after exporting the decompilation to C code, the type name isn't
                // confused with the global variable that this label will show up as.
                st.createLabel(addr, "L" + t.name, SourceType.ANALYSIS);
                lst.clearCodeUnits(addr, addr.add(typeDescriptor.getLength()), false);
                lst.createData(addr, typeDescriptor);
                propMap.add(addr, t.toString());
            } catch (InvalidInputException | CodeUnitInsertionException e) {
                throw new RuntimeException(e);
            }
            monitor.incrementProgress(1);
        }

        return true;
    }
}