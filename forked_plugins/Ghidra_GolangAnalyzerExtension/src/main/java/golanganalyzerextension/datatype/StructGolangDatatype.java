package golanganalyzerextension.datatype;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import golanganalyzerextension.DatatypeHolder;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;


public class StructGolangDatatype extends GolangDatatype {
	private String pkg_name;
	private List<StructField> field_list;

	StructGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	public String get_pkg_name() {
		return pkg_name;
	}

	public List<StructField> get_field_list(){
		return field_list;
	}

	@Override
	public void make_datatype(DatatypeHolder datatype_searcher) {
		StructureDataType structure_datatype=new StructureDataType(name, 0);

		// ver <= go1.8.*
		int pre_field_end=0;

		for(StructField field : field_list) {
			DataType field_datatype=datatype_searcher.get_datatype_by_key(field.get_type_key());
			if(field_datatype!=null && !field_datatype.isZeroLength() && !(field_datatype instanceof VoidDataType)) {
				int offset=field.get_offset();
				if(offset<pre_field_end) {
					offset<<=1;
				}
				structure_datatype.insertAtOffset(offset, field_datatype, field_datatype.getLength(), field.get_name(), null);
				pre_field_end=offset+field_datatype.getLength();
			}
		}
		for(int i=structure_datatype.getLength(); i<size; i++) {
			structure_datatype.add(DataType.DEFAULT, 1);
		}
		datatype=structure_datatype;
	}

	@Override
	void parse_datatype() throws BinaryAccessException {
		if(is_go16) {
			parse_datatype_go16();
			return;
		}
		int pointer_size=go_bin.get_pointer_size();

		long pkg_path_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		long fields_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
		long fields_len=go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);

		pkg_name="";
		if(pkg_path_addr_value!=0) {
			pkg_name=get_type_string(go_bin.get_address(type_base_addr, pkg_path_addr_value-type_base_addr.getOffset()), 0);
		}
		field_list=new ArrayList<StructField>();
		for(int i=0;i<fields_len;i++) {
			long field_name_addr_value=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset(), pointer_size);
			long field_type_addr_value=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()+pointer_size, pointer_size);
			long field_type_key=field_type_addr_value-type_base_addr.getOffset();
			long offset_embed=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()+pointer_size*2, pointer_size);

			String field_name=get_type_string(go_bin.get_address(type_base_addr, field_name_addr_value-type_base_addr.getOffset()), 0);
			dependence_type_key_list.add(field_type_key);
			field_list.add(new StructField(go_bin, field_name, field_type_key, (int)offset_embed));
		}

		if(check_tflag(tflag, Tflag.Uncommon)) {
			uncommon_base_addr=go_bin.get_address(ext_base_addr, pointer_size*4);
		}
	}

	private void parse_datatype_go16() throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long fields_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		long fields_len=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);

		pkg_name="";
		field_list=new ArrayList<StructField>();
		for(int i=0;i<fields_len;i++) {
			long field_name_addr_value=go_bin.get_address_value(type_base_addr, fields_addr_value+i*5*pointer_size-type_base_addr.getOffset(), pointer_size);
			long field_type_addr_value=go_bin.get_address_value(type_base_addr, fields_addr_value+i*5*pointer_size-type_base_addr.getOffset()+pointer_size*2, pointer_size);
			long field_type_key=field_type_addr_value-type_base_addr.getOffset();
			long offset_embed=go_bin.get_address_value(type_base_addr, fields_addr_value+i*5*pointer_size-type_base_addr.getOffset()+pointer_size*4, pointer_size);

			String field_name="";
			if(field_name_addr_value!=0) {
				field_name=go_bin.read_string_struct(go_bin.get_address(type_base_addr, field_name_addr_value-type_base_addr.getOffset()), pointer_size);
			}
			dependence_type_key_list.add(field_type_key);
			field_list.add(new StructField(go_bin, field_name, field_type_key, (int)offset_embed));
		}
	}
}
