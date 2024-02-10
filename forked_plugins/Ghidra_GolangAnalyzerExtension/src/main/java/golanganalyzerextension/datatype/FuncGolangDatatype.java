package golanganalyzerextension.datatype;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import golanganalyzerextension.DatatypeHolder;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;


public class FuncGolangDatatype extends GolangDatatype {
	private List<Long> in_type_key_list;
	private List<Long> out_type_key_list;

	FuncGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public void make_datatype(DatatypeHolder datatype_searcher) {
		datatype=new PointerDataType(new VoidDataType(), go_bin.get_pointer_size());
	}

	@Override
	void parse_datatype() throws BinaryAccessException {
		if(is_go16) {
			parse_datatype_go16();
			return;
		}
		int pointer_size=go_bin.get_pointer_size();

		int in_len=(short)go_bin.get_address_value(ext_base_addr, 2);
		int out_len=(short)go_bin.get_address_value(ext_base_addr, 2, 2);
		out_len=(short)(out_len&0x1f);
		in_type_key_list = new ArrayList<Long>();
		out_type_key_list = new ArrayList<Long>();
		for(int i=0;i<in_len;i++) {
			long in_type_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size+i*pointer_size, pointer_size);
			long in_type_key=in_type_addr_value-type_base_addr.getOffset();
			if(in_type_key>0) {
				dependence_type_key_list.add(in_type_key);
			}
			in_type_key_list.add(in_type_key);
		}
		for(int i=0;i<out_len;i++) {
			long out_type_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size+in_len*pointer_size+i*pointer_size, pointer_size);
			long out_type_key=out_type_addr_value-type_base_addr.getOffset();
			if(out_type_key>0) {
				dependence_type_key_list.add(out_type_key);
			}
			out_type_key_list.add(out_type_key);
		}

		if(check_tflag(tflag, Tflag.Uncommon)) {
			uncommon_base_addr=go_bin.get_address(ext_base_addr, 2*2);
		}
	}

	private void parse_datatype_go16() throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long in_len=(int)go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);
		long out_len=(int)go_bin.get_address_value(ext_base_addr, pointer_size*5, pointer_size);

		in_type_key_list = new ArrayList<Long>();
		out_type_key_list = new ArrayList<Long>();
		for(int i=0;i<in_len;i++) {
			long in_type_key=go_bin.get_address_value(go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size)+i*pointer_size, pointer_size)-type_base_addr.getOffset();
			if(in_type_key!=0) {
				dependence_type_key_list.add(in_type_key);
			}
			in_type_key_list.add(in_type_key);
		}
		for(int i=0;i<out_len;i++) {
			long out_type_key=go_bin.get_address_value(go_bin.get_address_value(ext_base_addr, pointer_size*4, pointer_size)+i*pointer_size, pointer_size)-type_base_addr.getOffset();
			if(out_type_key!=0) {
				dependence_type_key_list.add(out_type_key);
			}
			out_type_key_list.add(out_type_key);
		}
	}
}
