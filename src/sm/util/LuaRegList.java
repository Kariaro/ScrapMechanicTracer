package sm.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * This class reads a table of {@link LuaReg} objects.
 * 
 * <pre>
 * .. .. .. ..  char* s_pointerName
 * .. .. .. ..  addr  s_pointerFunc
 * </pre>
 * 
 * @author HardCoded
 */
public class LuaRegList implements Iterable<LuaReg> {
	private List<LuaReg> list = new ArrayList<LuaReg>();
	
	public LuaRegList(String addr) {
		this(Util.getAddress(addr));
	}
	
	public LuaRegList(Address addr) {
		for(int i = 0; i < 256; i++) {
			String tmp_name = null;
			String tmp_func = null;
			try {
				tmp_name = Util.readTerminatedString(Util.getAddressPointer(addr), 256);
				tmp_func = String.valueOf(Util.getAddressFromPointer(addr.add(4)));
			} catch(MemoryAccessException e) {
				e.printStackTrace();
				break;
			}
			
			if(tmp_name == null || tmp_func == null) break;
			LuaReg ref = new LuaReg(addr.toString(), tmp_name, tmp_func);
			list.add(ref);
			addr = addr.add(8);
		}
	}
	
	public int size() {
		return list.size();
	}
	
	public LuaReg get(int index) {
		if(index < 0 || index >= list.size()) {
			return null;
		}
		return list.get(index);
	}
	
	public List<LuaReg> getList() {
		return Collections.unmodifiableList(list);
	}

	@Override
	public Iterator<LuaReg> iterator() {
		return new Iterator<LuaReg>() {
			private int index = 0;
			
			@Override
			public LuaReg next() {
				return list.get(index++);
			}
			
			@Override
			public boolean hasNext() {
				return index < list.size();
			}
		};
	}
}