package extension.metadata;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public class Type {
    public static final String TYPE_MAP = "go-type-property-map";

    public Kind kind;
    public String name;
    public Type elem;
    public int length;
    public List<Field> args;
    public List<Type> returns;

    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
