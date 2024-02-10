package extension.metadata;

public class Field {
    public String name;
    public Type type;

    // Needed for jackson
    public Field() {
    }

    public Field(String name, Type type) {
        this.name = name;
        this.type = type;
    }
}
