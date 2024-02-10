import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.CustomOption;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionsEditor;
import ghidra.util.HelpLocation;
import golanganalyzerextension.GolangAnalyzerExtensionAnalyzer;

import javax.swing.*;
import java.awt.*;
import java.beans.PropertyEditor;
import java.io.File;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

public class Mooncat extends GhidraScript {
    // TODO: move me to the forked mooncat plugin.
    @Override
    protected void run() throws Exception {
        GolangAnalyzerExtensionAnalyzer analyzer = new GolangAnalyzerExtensionAnalyzer();
        BooleanOptions opts = new BooleanOptions();
        analyzer.registerOptions(opts, currentProgram);
        opts.options.put("Rename functions", true);
        opts.options.put("Correct arguments", true);
        opts.options.put("Add function comments", false);
        opts.options.put("Disassemble functions", true);
        opts.options.put("Add data types", true);
        opts.options.put("Search strings", true);
        analyzer.optionsChanged(opts, currentProgram);
        analyzer.added(currentProgram, null, getMonitor(), new MessageLog());
    }

    static class BooleanOptions implements Options {

        public final HashMap<String, Boolean> options = new HashMap<>();

        @Override
        public String getName() {
            return null;
        }

        @Override
        public String getID(String s) {
            return null;
        }

        @Override
        public OptionType getType(String s) {
            return null;
        }

        @Override
        public PropertyEditor getPropertyEditor(String s) {
            return null;
        }

        @Override
        public PropertyEditor getRegisteredPropertyEditor(String s) {
            return null;
        }

        @Override
        public List<Options> getChildOptions() {
            return null;
        }

        @Override
        public List<String> getLeafOptionNames() {
            return null;
        }

        @Override
        public void setOptionsHelpLocation(HelpLocation helpLocation) {

        }

        @Override
        public HelpLocation getOptionsHelpLocation() {
            return null;
        }

        @Override
        public HelpLocation getHelpLocation(String s) {
            return null;
        }

        @Override
        public void registerOption(String optionName, Object defaultValue, HelpLocation help, String description) {
            options.put(optionName, (Boolean) defaultValue);
        }

        @Override
        public void registerOption(String s, OptionType optionType, Object o, HelpLocation helpLocation, String s1) {

        }

        @Override
        public void registerOption(String s, OptionType optionType, Object o, HelpLocation helpLocation, String s1, PropertyEditor propertyEditor) {

        }

        @Override
        public void registerOptionsEditor(OptionsEditor optionsEditor) {

        }

        @Override
        public OptionsEditor getOptionsEditor() {
            return null;
        }

        @Override
        public void putObject(String s, Object o) {

        }

        @Override
        public Object getObject(String s, Object o) {
            return null;
        }

        @Override
        public boolean getBoolean(String s, boolean b) {
            return options.getOrDefault(s, b);
        }

        @Override
        public byte[] getByteArray(String s, byte[] bytes) {
            return new byte[0];
        }

        @Override
        public int getInt(String s, int i) {
            return 0;
        }

        @Override
        public double getDouble(String s, double v) {
            return 0;
        }

        @Override
        public float getFloat(String s, float v) {
            return 0;
        }

        @Override
        public long getLong(String s, long l) {
            return 0;
        }

        @Override
        public CustomOption getCustomOption(String s, CustomOption customOption) {
            return null;
        }

        @Override
        public Color getColor(String s, Color color) {
            return null;
        }

        @Override
        public File getFile(String s, File file) {
            return null;
        }

        @Override
        public Date getDate(String s, Date date) {
            return null;
        }

        @Override
        public Font getFont(String s, Font font) {
            return null;
        }

        @Override
        public KeyStroke getKeyStroke(String s, KeyStroke keyStroke) {
            return null;
        }

        @Override
        public String getString(String s, String s1) {
            return null;
        }

        @Override
        public <T extends Enum<T>> T getEnum(String s, T t) {
            return null;
        }

        @Override
        public void setLong(String s, long l) {

        }

        @Override
        public void setBoolean(String s, boolean b) {

        }

        @Override
        public void setInt(String s, int i) {

        }

        @Override
        public void setDouble(String s, double v) {

        }

        @Override
        public void setFloat(String s, float v) {

        }

        @Override
        public void setCustomOption(String s, CustomOption customOption) {

        }

        @Override
        public void setByteArray(String s, byte[] bytes) {

        }

        @Override
        public void setFile(String s, File file) {

        }

        @Override
        public void setDate(String s, Date date) {

        }

        @Override
        public void setColor(String s, Color color) {

        }

        @Override
        public void setFont(String s, Font font) {

        }

        @Override
        public void setKeyStroke(String s, KeyStroke keyStroke) {

        }

        @Override
        public void setString(String s, String s1) {

        }

        @Override
        public <T extends Enum<T>> void setEnum(String s, T t) {

        }

        @Override
        public void removeOption(String s) {

        }

        @Override
        public List<String> getOptionNames() {
            return null;
        }

        @Override
        public boolean contains(String s) {
            return false;
        }

        @Override
        public String getDescription(String s) {
            return null;
        }

        @Override
        public boolean isRegistered(String s) {
            return false;
        }

        @Override
        public boolean isDefaultValue(String s) {
            return false;
        }

        @Override
        public void restoreDefaultValues() {

        }

        @Override
        public void restoreDefaultValue(String s) {

        }

        @Override
        public Options getOptions(String s) {
            return null;
        }

        @Override
        public void createAlias(String s, Options options, String s1) {

        }

        @Override
        public boolean isAlias(String s) {
            return false;
        }

        @Override
        public Object getDefaultValue(String s) {
            return null;
        }

        @Override
        public String getValueAsString(String s) {
            return null;
        }

        @Override
        public String getDefaultValueAsString(String s) {
            return null;
        }
    }
}
