package extension.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.DataTypePath;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Metadata {
    public List<Function> functions;
    public Map<String, List<Field>> structures;
    public Map<Long, Type> descriptors;

    private static Path extensionRoot() {
        // Getting extension zip root path, the ugly way
        try {
            return Paths.get(Metadata.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent().getParent();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static Metadata extract(String executablePath, MessageLog log) {
        // TODO: handle relative executable paths.
        return goretk("extract-metadata", executablePath, log);
    }

    public static Metadata parseLib(String libDir, MessageLog log) {
        return goretk("parse-lib", libDir, log);
    }

    private static Metadata goretk(String cmd, String path, MessageLog log) {
        // TODO: pick right folder here instead of hardcoding it.
        String goretkUtilPath = extensionRoot().resolve("os/linux_x86_64/goretk_util").toString();
        ProcessBuilder pb = new ProcessBuilder(goretkUtilPath, cmd, path);
        Process p;
        try {
            p = pb.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        ObjectMapper mapper = new ObjectMapper();
        Metadata m;
        try {
            m = mapper.readValue(p.getInputStream(), Metadata.class);
        } catch (IOException e) {
            log.appendMsg("Could not read JSON from process");
            p.errorReader().lines().forEach(log::appendMsg);
            throw new RuntimeException(e);
        }
        try {
            p.waitFor();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return m;
    }

    public static DataTypePath dataTypePath(String name) {
        // Make CategoryPath
        String categoryPath;
        if (name.startsWith("hmap.") || name.startsWith("bmap.") || name.startsWith("hiter.") || name.startsWith("hchan.") || name.startsWith("mapextra.")) {
            categoryPath = "/Go/" + name.substring(0, name.indexOf('.'));
        } else {
            String[] parts = name.split("/");
            String last = parts[parts.length - 1];
            int idx = last.indexOf('.');
            if (idx != -1) {
                parts[parts.length - 1] = last.substring(0, idx);
            } else {
                parts = Arrays.copyOf(parts, parts.length - 1);
            }
            categoryPath = "/Go" + Arrays.stream(parts).reduce("", (a, b) -> a + "/" + b);
        }
        if (name.equals("string")) {
            name = "gostring";
        }
        return new DataTypePath(categoryPath, name);
    }
}
