package sm.hardcoded.plugin.tracer;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

class LuaTypes {
	public static LuaTypes INSTANCE;
	
	static {
		if(INSTANCE == null) {
			INSTANCE = new LuaTypes();
		}
	}
	
	public Map<Integer, Type> types;
	public LuaTypes() {
		types = new HashMap<>();
		addType("none", -1);
		addType("nil", 0);
		addType("boolean", 1);
		addType("lightuserdata", 2);
		addType("number", 3);
			// addType("integer", 3);
		
		addType("string", 4);
		addType("table", 5);
		addType("function", 6);
		addType("userdata", 7);
		addType("thread", 8);
	}
	
	public void addType(String name, int id) {
		Type type = new Type(name, id);
		types.put(id, type);
	}
	
	public Type getType(int index) {
		return types.get(index);
	}
	
	public void addType(ScrapMechanicPlugin plugin, String address) {
		ProgramMemory memory = plugin.getProgramMemory();
		AddressFactory factory = plugin.getCurrentProgram().getAddressFactory();
		
		Address addr = memory.readAddress(factory.getAddress(address));
		String name = memory.readTerminatedString(addr);
		int id = memory.readInt(addr.add(4));
		
		// System.out.println("type -> " + address + " n:\"" + name +"\" i:" + Integer.toHexString(id));
		if(name != null) {
			addType(name, id);
		}
	}
	
	public class Type {
		private final String name;
		private final int id;
		
		public Type(String name, int index) {
			this.name = name;
			this.id = index;
		}
		
		public int getIndex() {
			return id;
		}
		
		public int hashCode() {
			return id;
		}
		
		public String getPrettyName() {
			String last = name.substring(1);
			
			// This is a hack
			if(name.equals("guiinterface")) return "GuiInterface";
			if(name.equals("aistate")) return "AiState";
			if(name.equals("pathnode")) return "PathNode";
			if(name.equals("areatrigger")) return "AreaTrigger";
			if(name.equals("raycastresult")) return "RaycastResult";
			
			return Character.toUpperCase(name.charAt(0)) + last;
		}
		
		public String toString() {
			return name;
		}
	}
}
