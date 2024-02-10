package extension.metadata;

import java.util.List;

public class Function {
    public String name;
    public long entry;
    public long end;
    public List<Field> args;
    public List<Type> returns;
}
