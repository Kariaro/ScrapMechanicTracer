package sm;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.program.model.mem.MemoryAccessException;
import sm.util.LuaReg;
import sm.util.LuaRegList;
import sm.util.SMUtil;
import sm.util.Util;

public class SMContainerBuilder {
	private SMContainer container;
	private List<SMObject> list;
	private boolean build;
	
	private SMContainerBuilder() {
		container = new SMContainer();
		list = new ArrayList<SMObject>();
	}
	
	public static SMContainerBuilder create() {
		return new SMContainerBuilder();
	}
	
	public SMContainerBuilder loadSM(String address) {
		if(build) throw new IllegalAccessError("Object was already built");
		
		LuaRegList refs = new LuaRegList(address);
		
		try {
			for(LuaReg ref : refs) {
				list.add(SMUtil.loadSMObject(ref));
			}
		} catch(MemoryAccessException e) {
			e.printStackTrace();
		}
		
		return this;
	}
	
	public SMContainerBuilder calculate() {
		for(SMObject obj : list) {
			String path = Util.readTerminatedString(obj.getName());
			
			SMClassObject clazz = container.addClass(path);
			clazz.loadSettings(obj);
			clazz.loadConstants(obj);
			clazz.loadFunctions(obj);
		}
		
		return this;
	}
	
	public SMContainerBuilder runTests() {
		Set<SMFunctionObject> set = container.getAllFunctions();
		String setstr = set.toString();
		setstr = setstr.substring(1, setstr.length() - 1);
		setstr = setstr.replace(", ", "\n");
		System.out.println("Functions:");
		System.out.println(setstr);
		
		
		//System.out.println(container);
		return this;
	}
	
	/**
	 * @return A newly created {@link SMContainer}
	 */
	public SMContainer build() {
		if(build) throw new IllegalAccessError("Object was already built");
		build = true;
		
		SMContainer result = container;
		container = null;
		list = null;
		
		return result;
	}
}
